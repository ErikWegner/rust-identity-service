use std::pin::Pin;

use futures::{future::Shared, lock::Mutex, FutureExt};

type Token = String;

pub(crate) struct OidcClientState {
    mutex: Mutex<
        Option<
            Shared<
                Pin<
                    Box<
                        dyn futures::Future<
                                Output = Result<std::string::String, std::string::String>,
                            > + std::marker::Send,
                    >,
                >,
            >,
        >,
    >,
}

impl OidcClientState {
    pub(crate) fn init() -> OidcClientState {
        OidcClientState {
            mutex: Mutex::new(None),
        }
    }
}

async fn retrieve_token(token_endpoint: String) -> Result<Token, String> {
    let client = reqwest::Client::new();
    let res = client
        .post(token_endpoint)
        .body("the exact body that is sent")
        .send()
        .await;
    match res {
        Ok(o) => Ok(o.text().await.unwrap()),
        Err(e) => Err(e.to_string()),
    }
}

pub(crate) async fn get_client_token(
    oidc_client_state: &OidcClientState,
    token_endpoint: String,
) -> Result<Token, String> {
    let mut pending_request = oidc_client_state.mutex.lock().await;
    let fut = if pending_request.is_some() {
        pending_request.clone().unwrap()
    } else {
        let token_request = retrieve_token(token_endpoint.clone()).boxed().shared();
        let _ = pending_request.insert(token_request.clone());
        token_request
    };

    drop(pending_request);
    let result = fut.await;
    result
}
