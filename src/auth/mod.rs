mod login;
mod oidcclient;

pub use oidcclient::OIDCClient;

use anyhow::Result;
use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Extension, Router,
};
use axum_macros::debug_handler;
use axum_sessions::extractors::WritableSession;
use openidconnect::{
    core::CoreIdToken, url::Url, AccessToken, CsrfToken, Nonce, PkceCodeVerifier, RefreshToken,
};
use redis::Client;
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tracing::info;

use crate::session::{purge_store_and_regenerate_session, RidserSessionLayer};

use self::login::login;

#[derive(Debug, Clone)]
pub(crate) struct AuthorizeData {
    auth_url: String,
    csrf_token: String,
    nonce: String,
    pkce_verifier: String,
}

impl AuthorizeData {
    pub(crate) fn new(
        auth_url: Url,
        csrf_token: CsrfToken,
        nonce: Nonce,
        pkce_verifier: PkceCodeVerifier,
    ) -> Self {
        Self {
            auth_url: auth_url.to_string(),
            csrf_token: csrf_token.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: pkce_verifier.secret().to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TokenExchangeData {
    code: String,
    nonce: String,
    pkce_verifier: String,
    redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionTokens {
    access_token: String,
    refresh_token: Option<String>,
    id_token: String,
}

impl SessionTokens {
    pub(crate) fn new(
        access_token: &AccessToken,
        refresh_token: Option<&RefreshToken>,
        id_token: &CoreIdToken,
    ) -> Self {
        Self {
            access_token: access_token.secret().to_string(),
            refresh_token: refresh_token.map(|r| r.secret().to_string()),
            id_token: id_token.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct CallbackQueryParams {
    code: String,
    state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginCallbackSessionParameters {
    app_uri: String,
    nonce: String,
    csrf_token: String,
    pkce_verifier: String,
    redirect_uri: String,
    scopes: String,
}

#[debug_handler]
pub(crate) async fn callback(
    Extension(oidc_client): Extension<OIDCClient>,
    Extension(client): Extension<Client>,
    mut session: WritableSession,
    callback_query_params: Query<CallbackQueryParams>,
) -> Result<Response, Response> {
    let login_callback_session_params = session
        .get::<LoginCallbackSessionParameters>("ridser_logincallback_parameters")
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid session").into_response())?;
    session.remove("ridser_logincallback_parameters");

    if callback_query_params.state != login_callback_session_params.csrf_token {
        return Err((StatusCode::BAD_REQUEST, "Invalid request").into_response());
    }

    let jwt = oidc_client
        .exchange_code(TokenExchangeData {
            code: callback_query_params.code.clone(),
            nonce: login_callback_session_params.nonce,
            pkce_verifier: login_callback_session_params.pkce_verifier,
            redirect_uri: login_callback_session_params.redirect_uri.clone(),
        })
        .await
        .map_err(|e| {
            info!("Failed to exchange code: {:?}", e);
            (StatusCode::UNAUTHORIZED, "Login failure").into_response()
        })?;

    purge_store_and_regenerate_session(&mut session, client).await;

    let _ = session.insert("ridser_jwt", jwt);

    Ok(Redirect::to(&login_callback_session_params.app_uri).into_response())
}

pub(crate) fn auth_routes(
    oidc_client: OIDCClient,
    session_layer: &RidserSessionLayer,
    client: Client,
) -> Router {
    Router::new()
        .route(
            "/login",
            get(login).layer(
                ServiceBuilder::new()
                    .layer(Extension(oidc_client.clone()))
                    .layer(Extension(client.clone())),
            ),
        )
        .route(
            "/callback",
            get(callback).layer(
                ServiceBuilder::new()
                    .layer(Extension(oidc_client))
                    .layer(Extension(client)),
            ),
        )
        .layer(session_layer.clone())
}
