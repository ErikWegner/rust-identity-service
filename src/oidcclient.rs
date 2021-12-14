use std::pin::Pin;

use futures::{future::Shared, lock::Mutex, FutureExt};
use tokio::time::{sleep, Duration};

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

async fn retrieve_token() -> Result<Token, String> {
    sleep(Duration::from_secs(2)).await;
    Ok(String::from("token"))
}

pub(crate) async fn get_client_token(oidc_client_state: &OidcClientState) -> Result<Token, String> {
    let mut pending_request = oidc_client_state.mutex.lock().await;
    let fut = if pending_request.is_some() {
        pending_request.clone().unwrap()
    } else {
        let token_request = retrieve_token().boxed().shared();
        let _ = pending_request.insert(token_request.clone());
        token_request
    };

    drop(pending_request);
    let result = fut.await;
    result
}
