use std::{collections::HashMap, pin::Pin, sync::Arc, time::Duration};

use async_std::future;
use futures::{future::Shared, lock::Mutex, FutureExt};
use parking_lot::RwLock;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::redis::Redis;

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
    pub(crate) query_token: RwLock<Option<String>>,
}

impl OidcClientState {
    pub(crate) fn new(client_credentials: Arc<ClientCredentials>) -> OidcClientState {
        OidcClientState {
            mutex: Mutex::new(None),
            client_credentials,
            query_token: RwLock::new(None),
        }
    }

    fn arccc(&self) -> Arc<ClientCredentials> {
        self.client_credentials.clone()
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: String,
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

#[derive(Deserialize)]
pub(crate) struct GroupResponse {
    name: String,
    path: String,
}

pub(crate) async fn try_query_groups(
    subject: &str,
    group_query_url: &str,
    token: &str,
    redis: &Redis,
) -> Vec<String> {
    let dur = Duration::from_millis(150);
    let redis_try_result = future::timeout(dur, query_groups_from_redis(redis, subject)).await;

    if let Ok(Some(redis_cached_groups)) = redis_try_result {
        return redis_cached_groups;
    }

    let keycloak_result = query_groups_from_keycloak(subject, group_query_url, token).await;
    update_cache(redis, subject, &keycloak_result).await;
    keycloak_result
}

async fn query_groups_from_redis(redis: &Redis, subject: &str) -> Option<Vec<String>> {
    redis.get_cache_result(subject).await
}

async fn update_cache(redis: &Redis, subject: &str, groups: &[String]) {
    redis.set_cache_result(subject, groups).await
}

async fn query_groups_from_keycloak(
    subject: &str,
    group_query_url: &str,
    token: &str,
) -> Vec<String> {
    let client = reqwest::Client::new();
    let res = client
        .get(group_query_url.replace("{SUBJECT}", subject))
        .bearer_auth(token)
        .timeout(Duration::from_secs(2))
        .send()
        .await;
    match res {
        Ok(o) => {
            if o.status() != StatusCode::OK {
                return Vec::new();
            }
            let od = o.json::<Vec<GroupResponse>>().await;
            match od {
                Ok(groups) => groups
                    .iter()
                    .filter_map(|f| {
                        // Only use groups at level 1
                        if f.path.rfind('/') == Some(0) {
                            Some(f.name.clone())
                        } else {
                            None
                        }
                    })
                    .collect(),
                Err(_) => Vec::new(),
            }
        }
        Err(_) => Vec::new(),
    }
}
