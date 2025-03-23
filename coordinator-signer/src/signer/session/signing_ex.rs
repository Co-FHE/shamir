use ecdsa_tss::signer_rpc::{CoordinatorToSignerMsg, SignerToCoordinatorMsg};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::{
    crypto::{pk_to_pkid, CryptoType},
    signer::{manager::RequestEx, PkId, ValidatorIdentityIdentity},
    types::{
        error::SessionError,
        message::{
            DKGBaseMessage, MessageEx, SignatureEx, SigningBaseMessage, SigningRequestEx,
            SigningRequestWrapEx, SigningStageEx, TargetOrBroadcast,
        },
        SubsessionId,
    },
    utils,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SigningSignerExBase<VII: ValidatorIdentityIdentity> {
    pub(crate) key_package: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) pkid: PkId,
    #[serde(with = "dkg_base_message_serde")]
    pub(crate) base_info: DKGBaseMessage<VII, u16>,
}
use crate::types::message::dkg_base_message_serde;

impl<VII: ValidatorIdentityIdentity> SigningSignerExBase<VII> {
    pub(crate) fn new(
        key_package: Vec<u8>,
        public_key: Vec<u8>,
        base_info: DKGBaseMessage<VII, u16>,
    ) -> Result<Self, SessionError> {
        Ok(Self {
            key_package,
            public_key: public_key.clone(),
            pkid: pk_to_pkid(base_info.crypto_type, &public_key)?,
            base_info,
        })
    }
    // pub(crate) fn to_signing_base_message(
    //     &self,
    //     subsession_id: SubsessionId,
    // ) -> SigningBaseMessage<VII, u16, Vec<u8>> {
    //     SigningBaseMessage {
    //         crypto_type: self.base_info.crypto_type,
    //         participants: self.base_info.participants.clone(),
    //         pkid: self.pkid.clone(),
    //         subsession_id: subsession_id,
    //         identifier: self.base_info.identifier,
    //         identity: self.base_info.identity.clone(),
    //         public_key: self.public_key.clone(),
    //         min_signers: self.base_info.min_signers,
    //     }
    // }
}

#[derive(Debug, Clone)]
pub(crate) struct SigningSessionEx<VII: ValidatorIdentityIdentity> {
    pub(crate) base: SigningSignerExBase<VII>,
    pub(crate) subsessions: BTreeMap<SubsessionId, UnboundedSender<CoordinatorToSignerMsg>>,
}
impl<VII: ValidatorIdentityIdentity> SigningSessionEx<VII> {
    pub(crate) fn new(
        public_key_package: Vec<u8>,
        key_package: Vec<u8>,
        base_info: DKGBaseMessage<VII, u16>,
    ) -> Result<Self, SessionError> {
        Ok(Self {
            base: SigningSignerExBase::new(key_package, public_key_package, base_info)?,
            subsessions: BTreeMap::new(),
        })
    }
    pub(crate) fn deserialize(bytes: &[u8]) -> Result<Self, SessionError> {
        let base = bincode::deserialize(bytes)
            .map_err(|e| SessionError::DeserializationError(e.to_string()))?;
        Ok(Self {
            base,
            subsessions: BTreeMap::new(),
        })
    }
    pub(crate) fn serialize(&self) -> Result<Vec<u8>, SessionError> {
        Ok(bincode::serialize(&self.base)
            .map_err(|e| SessionError::SerializationError(e.to_string()))?)
    }
    pub(crate) fn check_serialize_deserialize(&self) -> Result<(), SessionError> {
        let serialized = self.serialize()?;
        let deserialized = Self::deserialize(&serialized)?;
        assert_eq!(self.base, deserialized.base);
        Ok(())
    }
    pub(crate) fn new_subsession_in_channel(
        &mut self,
        subsession_id: SubsessionId,
    ) -> Option<UnboundedReceiver<CoordinatorToSignerMsg>> {
        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel::<CoordinatorToSignerMsg>();
        // if subsession_id already exists, return None else insert and return in_rx
        if self.subsessions.contains_key(&subsession_id) {
            None
        } else {
            self.subsessions.insert(subsession_id, in_tx.clone());
            Some(in_rx)
        }
    }
    pub(crate) async fn new_from_request(
        request: SigningRequestEx<VII>,
        base: SigningSignerExBase<VII>,
        out_tx: UnboundedSender<RequestEx<VII>>,
        in_rx: UnboundedReceiver<CoordinatorToSignerMsg>,
    ) -> Result<SigningRequestWrapEx<VII>, SessionError> {
        let SigningBaseMessage {
            participants,
            identifier,
            identity,
            ..
        } = request.base_info.clone();
        // todo: check pkid
        participants.check_identifier_identity_exists(&identifier, &identity)?;
        if let SigningStageEx::Init(msg, derive) = request.stage {
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
            let base_info = ecdsa_tss::signer_rpc::SigningInfo {
                base_info: Some(ecdsa_tss::signer_rpc::BaseInfo {
                    id: request.base_info.identifier as u32,
                    curve_id: curve_id,
                    threshold: request.base_info.min_signers as u32,
                    ids: participants.iter().map(|p| (*p.0) as u32).collect(),
                }),
                key_package: Some(ecdsa_tss::signer_rpc::KeyPackage {
                    key_package: base.key_package.clone(),
                    public_key: base.public_key.clone(),
                }),
                message: msg,
                derivation_delta: utils::derived_data(derive),
            };
            let timeout =
                time::Duration::from_secs(common::Settings::global().signer.ecdsa_sign_timeout);
            let (out_tx_client, mut out_rx_client) =
                tokio::sync::mpsc::unbounded_channel::<SignerToCoordinatorMsg>();
            let message_base_info = request.base_info.clone();
            tokio::spawn(async move {
                loop {
                    let out = out_rx_client.recv().await;
                    match out {
                        Some(out) => {
                            let signing_request_ex = SigningRequestEx {
                                base_info: message_base_info.clone(),
                                stage: SigningStageEx::Intermediate(MessageEx {
                                    from: message_base_info.identifier,
                                    target: if out.is_broadcast {
                                        TargetOrBroadcast::Broadcast
                                    } else {
                                        TargetOrBroadcast::Target { to: out.to as u16 }
                                    },
                                    message: out.msg,
                                }),
                            }
                            .into_request_wrap();
                            match signing_request_ex {
                                Ok(signing_request_wrap) => {
                                    out_tx
                                        .send(RequestEx::SigningEx(
                                            signing_request_wrap,
                                            utils::new_oneshot_to_receive_success_or_error(),
                                        ))
                                        .unwrap();
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to convert Signing request: {:?}", e);
                                    continue;
                                }
                            }
                        }
                        None => {
                            tracing::info!("out_rx is closed");
                            return;
                        }
                    }
                    // input = in_rx.recv()=>{
                    //     match input {
                    //         Some(input) => {
                    //             match input.stage {
                    //                 SigningStageEx::Intermediate(message_ex) => {
                    //                     in_tx_client
                    //                         .send(message_ex)
                    //                         .unwrap();
                    //                 }
                    //                 _ => {
                    //                     tracing::warn!("invalid stage: {:?}", input.stage);
                    //                     continue;
                    //                 }
                    //             };
                    //         }
                    //         None => {
                    //             tracing::info!("in_rx is closed");
                    //             return;
                    //         }
                    //     }
                    // }
                }
            });
            let result = client.sign(base_info, in_rx, out_tx_client, timeout).await;
            match result {
                Ok(signature) => {
                    return Ok(SigningRequestEx {
                        base_info: request.base_info.clone(),
                        stage: SigningStageEx::Final(SignatureEx {
                            signature: signature.signature,
                            public_key: signature.public_key,
                            public_key_derived: signature.public_key_derived,
                        }),
                    }
                    .into_request_wrap()?);
                }

                Err(e) => {
                    return Err(SessionError::ExternalError(e.to_string()));
                }
            }
        } else {
            return Err(SessionError::InvalidRequest(format!(
                "request must be init {:?}",
                request
            )));
        }
    }
    pub(crate) fn pkid(&self) -> PkId {
        self.base.pkid.clone()
    }
}
