use std::pin::Pin;

use futures::{future::Shared, lock::Mutex, FutureExt};

pub struct ClientCredentials {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
}

impl Clone for ClientCredentials {
    fn clone(&self) -> Self {
        Self {
            token_url: self.token_url.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
        }
    }
}

type Token = String;

type TokenRetriever = Shared<
    Pin<Box<dyn futures::Future<Output = Result<Token, std::string::String>> + std::marker::Send>>,
>;

pub(crate) struct OidcClientState {
    mutex: Mutex<Option<TokenRetriever>>,
    client_credentials: ClientCredentials,
}

impl OidcClientState {
    pub(crate) fn init(client_credentials: ClientCredentials) -> OidcClientState {
        OidcClientState {
            mutex: Mutex::new(None),
            client_credentials,
        }
    }
}

async fn retrieve_token(client_credentials: ClientCredentials) -> Result<Token, String> {
    let form = reqwest::multipart::Form::new()
        .text("grant_type", "client_credentials")
        .text("client_id", client_credentials.client_id.clone())
        .text("client_secret", client_credentials.client_secret.clone())
        .text("scope", "openid");

    let client = reqwest::Client::new();
    let res = client
        .post(client_credentials.token_url.clone())
        .multipart(form)
        .send()
        .await;
    match res {
        Ok(o) => Ok(o.text().await.unwrap()),
        Err(e) => Err(e.to_string()),
    }
}

pub(crate) async fn get_client_token(oidc_client_state: &OidcClientState) -> Result<Token, String> {
    let mut pending_request = oidc_client_state.mutex.lock().await;
    let fut = if pending_request.is_some() {
        pending_request.clone().unwrap()
    } else {
        let client_credentials = oidc_client_state.client_credentials.clone();
        let token_request = retrieve_token(client_credentials).boxed().shared();
        let _ = pending_request.insert(token_request.clone());
        token_request
    };

    drop(pending_request);
    let result = fut.await;
    result
}
