use ecdsa_tss::signer_rpc::{CoordinatorToSignerMsg, SignerToCoordinatorMsg};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::{
    crypto::*,
    signer::manager::{ManagerRequest, RequestEx},
    types::{
        error::SessionError,
        message::{
            DKGBaseMessage, DKGFinal, DKGRequestEx, DKGRequestWrapEx, DKGStageEx, MessageEx,
            TargetOrBroadcast,
        },
    },
    utils,
};
use std::time;

use super::SignerStateEx;
pub(crate) struct DKGSessionEx<VII: ValidatorIdentityIdentity> {
    base_info: DKGBaseMessage<VII, u16>,
    dkg_state: SignerStateEx<ecdsa_tss::signer_rpc::KeyPackage>,
    out_tx: UnboundedSender<ManagerRequest<VII>>,
    out_rx: UnboundedReceiver<ecdsa_tss::signer_rpc::SignerToCoordinatorMsg>,
    in_tx: UnboundedSender<ecdsa_tss::signer_rpc::CoordinatorToSignerMsg>,
}
impl<VII: ValidatorIdentityIdentity> DKGSessionEx<VII> {
    pub(crate) async fn new_from_request(
        request: DKGRequestEx<VII>,
        mut in_rx: UnboundedReceiver<DKGRequestEx<VII>>,
        out_tx: UnboundedSender<RequestEx<VII>>,
    ) -> Result<(DKGBaseMessage<VII, u16>, DKGFinal), SessionError> {
        let DKGBaseMessage {
            participants,
            identifier,
            identity,
            min_signers,
            ..
        } = request.base_info.clone();
        participants.check_identifier_identity_exists(&identifier, &identity)?;
        participants.check_min_signers(min_signers)?;
        if let DKGStageEx::Init = request.stage.clone() {
            let client =
                ecdsa_tss::EcdsaTssSignerClient::new(common::Settings::global().signer.ecdsa_port)
                    .await
                    .map_err(|e| SessionError::ExternalError(e.to_string()))?;
            let curve_id = match request.base_info.crypto_type {
                CryptoType::EcdsaSecp256k1 => 0,
                _ => {
                    return Err(SessionError::InvalidRequest(format!(
                        "invalid crypto type: {:?}",
                        request.base_info.crypto_type
                    )));
                }
            };
            let base_info = ecdsa_tss::signer_rpc::BaseInfo {
                id: request.base_info.identifier as u32,
                curve_id: curve_id,
                threshold: request.base_info.min_signers as u32,
                ids: participants.iter().map(|p| (*p.0) as u32).collect(),
            };
            let timeout =
                time::Duration::from_secs(common::Settings::global().signer.ecdsa_dkg_timeout);
            let (in_tx_client, in_rx_client) =
                tokio::sync::mpsc::unbounded_channel::<CoordinatorToSignerMsg>();
            let (out_tx_client, mut out_rx_client) =
                tokio::sync::mpsc::unbounded_channel::<SignerToCoordinatorMsg>();
            let message_base_info = request.base_info.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        out = out_rx_client.recv() =>{
                            match out {
                                Some(out) => {
                                    let dkg_request_wrap = DKGRequestEx {
                                        base_info: message_base_info.clone(),
                                    stage: DKGStageEx::Intermediate(MessageEx {
                                        from: message_base_info.identifier,
                                        target: if out.is_broadcast {
                                            TargetOrBroadcast::Broadcast
                                        } else {
                                            TargetOrBroadcast::Target { to: out.to as u16 }
                                        },
                                        message: out.msg,
                                    }),
                                }.into_request_wrap();
                                match dkg_request_wrap {
                                    Ok(dkg_request_wrap) => {
                                        out_tx.send(RequestEx::DKGEx(dkg_request_wrap, utils::new_oneshot_to_receive_success_or_error())).unwrap();
                                    }
                                    Err(e) => {
                                        tracing::warn!("Failed to convert DKG request: {:?}", e);
                                        continue;
                                        }
                                    }
                                }
                                None => {
                                    tracing::info!("out_rx is closed");
                                    return;
                                }
                            }
                        }
                        input = in_rx.recv()=>{
                            match input {
                                Some(input) => {
                                    match input.stage {
                                        DKGStageEx::Intermediate(message_ex) => {
                                            in_tx_client.send(CoordinatorToSignerMsg {
                                                msg: message_ex.message,
                                                is_broadcast: if message_ex.target == TargetOrBroadcast::Broadcast {
                                                    true
                                                } else {
                                                    false
                                                },
                                                from: input.base_info.identifier as u32,
                                            }).unwrap();
                                        }
                                        _ => {
                                            tracing::warn!("invalid stage: {:?}", input.stage);
                                            continue;
                                        }
                                    };
                                }
                                None => {
                                    tracing::info!("in_rx is closed");
                                    return;
                                }
                            }
                        }
                    }
                }
            });
            let result = client
                .dkg(base_info, in_rx_client, out_tx_client, timeout)
                .await;
            match result {
                Ok(key_package) => {
                    return Ok((
                        request.base_info.clone(),
                        DKGFinal {
                            key_package: key_package.key_package,
                            public_key: key_package.public_key,
                        },
                    ));
                }
                Err(e) => {
                    return Err(SessionError::ExternalError(e.to_string()));
                }
            }
        } else {
            return Err(SessionError::InvalidRequest(format!(
                "new request is not DKGRequestEx::Init {:?}",
                request
            )));
        }
    }
}
