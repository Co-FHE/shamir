use coordinator_signer::crypto::p2p_identity::P2pIdentity;
use coordinator_signer::crypto::{CryptoType, PkId};
use coordinator_signer::node::Node;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use warp::reply::Json;
use warp::Filter;
#[derive(Deserialize)]
struct GetPublicKeyRequest {
    crypto_type: String,
    tweak: Option<String>,
}

#[derive(Deserialize)]
struct SignRequest {
    crypto_type: String,
    message: String,
    tweak: Option<String>,
}

#[derive(Serialize)]
struct GetPublicKeyResponse {
    status: String,
    result: String,
}

#[derive(Serialize)]
struct SignResponse {
    status: String,
    signature: String,
    verification: String,
}
async fn get_first_pk(
    node: Arc<Node<P2pIdentity>>,
    crypto_type: CryptoType,
) -> Result<PkId, anyhow::Error> {
    let resp = node.lspk_async().await?;
    let pkid = resp.get(&crypto_type);
    if let Some(pkid) = pkid {
        if pkid.len() > 0 {
            Ok(pkid[0].clone())
        } else {
            Err(anyhow::anyhow!("no pkid found"))
        }
    } else {
        Err(anyhow::anyhow!("crypto type not found"))
    }
}
pub async fn start_webserver(node: Arc<Node<P2pIdentity>>, port: u16) -> Result<(), anyhow::Error> {
    let node_sign = node.clone();
    let node_pk = node.clone();
    let handle_pk = warp::path("pk")
        .and(warp::get())
        .and(warp::query::<GetPublicKeyRequest>())
        .and_then(move |request: GetPublicKeyRequest| {
            // `move` here forces ownership of the request
            let node = node_pk.clone(); // Clone the Arc, not the inner Node

            async move {
                let crypto_type = CryptoType::from_str(&request.crypto_type);
                match crypto_type {
                    Ok(crypto_type) => {
                        let pkid = get_first_pk(node.clone(), crypto_type).await;
                        if let Err(e) = pkid {
                            return Ok(warp::reply::json(&GetPublicKeyResponse {
                                status: "error".to_string(),
                                result: e.to_string(),
                            }) as Json);
                        }
                        let pkid = pkid.unwrap();
                        let resp = node
                            .pk_async(
                                pkid,
                                request.tweak.map(|t| t.as_bytes().to_vec()),
                                Some(Duration::from_secs(10)),
                            )
                            .await;
                        let result = resp;
                        match result {
                            Ok(result) => {
                                Ok::<_, warp::Rejection>(warp::reply::json(&GetPublicKeyResponse {
                                    status: "success".to_string(),
                                    result: hex::encode(result.group_public_key_tweak),
                                }) as Json)
                            } // Ensure the return type implements Reply
                            Err(e) => Ok(warp::reply::json(&GetPublicKeyResponse {
                                status: "error".to_string(),
                                result: e.to_string(),
                            }) as Json),
                        }
                    }
                    Err(e) => {
                        return Ok(warp::reply::json(&GetPublicKeyResponse {
                            status: "error".to_string(),
                            result: e.to_string(),
                        }) as Json);
                    }
                }
            }
        });
    let handle_sign = warp::path("sign")
        .and(warp::get())
        .and(warp::query::<SignRequest>())
        .and_then(move |request: SignRequest| {
            let node = node_sign.clone();
            async move {
                let crypto_type = CryptoType::from_str(&request.crypto_type);
                if let Err(e) = crypto_type {
                    return Ok::<_, warp::Rejection>(warp::reply::json(&SignResponse {
                        status: "error".to_string(),
                        signature: "".to_string(),
                        verification: e.to_string(),
                    }) as Json);
                }
                let crypto_type = crypto_type.unwrap();
                let pkid = get_first_pk(node.clone(), crypto_type).await;
                if let Err(e) = pkid {
                    return Ok(warp::reply::json(&SignResponse {
                        status: "error".to_string(),
                        signature: "".to_string(),
                        verification: e.to_string(),
                    }) as Json);
                }
                let pkid = pkid.unwrap();
                let tweak = request.tweak.map(|t| t.as_bytes().to_vec());

                let resp = node
                    .sign_async(
                        pkid,
                        request.message.as_bytes().to_vec(),
                        tweak,
                        Some(Duration::from_secs(10)),
                    )
                    .await;
                let result = resp;
                match result {
                    Ok(result) => Ok(warp::reply::json(&SignResponse {
                        status: "success".to_string(),
                        signature: hex::encode(result.signature()),
                        verification: result
                            ._verify()
                            .map_or_else(|e| e.to_string(), |_| "success".to_string()),
                    }) as Json),
                    Err(e) => Ok(warp::reply::json(&SignResponse {
                        status: "error".to_string(),
                        signature: e.to_string(),
                        verification: e.to_string(),
                    }) as Json),
                }
            }
        });

    // Combine all routes
    let routes = handle_pk.or(handle_sign);

    // Start web server
    warp::serve(routes).run(([127, 0, 0, 1], port)).await;

    Ok(())
}
