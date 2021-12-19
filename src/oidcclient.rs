use std::{collections::HashMap, pin::Pin, sync::Arc};

use futures::{future::Shared, lock::Mutex, FutureExt};
use reqwest::StatusCode;
use serde::Deserialize;

pub struct ClientCredentials {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
}

type Token = String;

type TokenRetriever = Shared<
    Pin<Box<dyn futures::Future<Output = Result<Token, std::string::String>> + std::marker::Send>>,
>;

pub(crate) struct OidcClientState {
    mutex: Mutex<Option<TokenRetriever>>,
    client_credentials: Arc<ClientCredentials>,
}

impl OidcClientState {
    pub(crate) fn new(client_credentials: Arc<ClientCredentials>) -> OidcClientState {
        OidcClientState {
            mutex: Mutex::new(None),
            client_credentials: client_credentials.clone(),
        }
    }

    fn arccc(&self) -> Arc<ClientCredentials> {
        self.client_credentials.clone()
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

async fn retrieve_token(client_credentials: Arc<ClientCredentials>) -> Result<Token, String> {
    let mut form_data = HashMap::new();

    form_data.insert("grant_type", "client_credentials");
    form_data.insert("client_id", client_credentials.client_id.as_str());
    form_data.insert("client_secret", client_credentials.client_secret.as_str());
    form_data.insert("scope", "openid");

    let client = reqwest::Client::new();
    let res = client
        .post(client_credentials.token_url.clone())
        .form(&form_data)
        .send()
        .await;
    match res {
        Ok(o) => {
            if o.status() != StatusCode::OK {
                return Err(o.text().await.unwrap());
            }
            let token_response = o.json::<TokenResponse>().await;
            match token_response {
                Ok(tokendata) => Ok(tokendata.access_token),
                Err(e) => Err(e.to_string()),
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

pub(crate) async fn get_client_token(
    oidc_client_state: Arc<OidcClientState>,
) -> Result<Token, String> {
    let mut pending_request = oidc_client_state.mutex.lock().await;
    let c = oidc_client_state.clone();
    let fut = if pending_request.is_some() {
        pending_request.clone().unwrap()
    } else {
        let token_request = retrieve_token(c.arccc()).boxed().shared();
        let _ = pending_request.insert(token_request.clone());
        token_request
    };

    drop(pending_request);
    let result = fut.await;

    let mut pending_request = oidc_client_state.mutex.lock().await;
    *pending_request = None;
    drop(pending_request);

    result
}

pub(crate) async fn acg_flow_step_2(
    client_credentials: &ClientCredentials,
    redirect_uri: String,
    code: String,
) -> Result<Token, (u16, String)> {
    let mut form_data = HashMap::new();
    form_data.insert("grant_type", "authorization_code");
    form_data.insert("client_id", client_credentials.client_id.as_str());
    form_data.insert("client_secret", client_credentials.client_secret.as_str());
    form_data.insert("redirect_uri", redirect_uri.as_str());
    form_data.insert("code", code.as_str());

    let client = reqwest::Client::new();
    let res = client
        .post(client_credentials.token_url.clone())
        .form(&form_data)
        .send()
        .await;
    match res {
        Ok(o) => {
            if o.status() != StatusCode::OK {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    o.text().await.unwrap(),
                ));
            }
            let token_response = o.json::<TokenResponse>().await;
            match token_response {
                Ok(tokendata) => Ok(tokendata.access_token),
                Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR.as_u16(), e.to_string())),
            }
        }
        Err(e) => Err((
            e.status()
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
                .as_u16(),
            e.to_string(),
        )),
    }
}
