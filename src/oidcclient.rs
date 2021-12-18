use std::{collections::HashMap, pin::Pin};

use futures::{future::Shared, lock::Mutex, FutureExt};
use reqwest::StatusCode;
use serde::Deserialize;

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
    pub(crate) fn init(client_credentials: &ClientCredentials) -> OidcClientState {
        OidcClientState {
            mutex: Mutex::new(None),
            client_credentials: client_credentials.clone(),
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
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

pub(crate) async fn acg_flow_step_2(
    client_credentials: ClientCredentials,
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
