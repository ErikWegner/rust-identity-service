use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Extension,
};
use axum_macros::debug_handler;
use axum_sessions::extractors::WritableSession;
use redis::Client;
use serde::Deserialize;
use tracing::info;

use crate::{
    auth::{LoginCallbackSessionParameters, OIDCClient},
    session::{
        purge_store_and_regenerate_session, SESSION_KEY_CSRF_TOKEN, SESSION_KEY_JWT,
        SESSION_KEY_USERID,
    },
};

use super::{random_alphanumeric_string, SessionTokens};

#[derive(Debug, Deserialize)]
pub(crate) struct CallbackQueryParams {
    code: String,
    state: String,
}

#[derive(Debug, Clone)]
pub(crate) struct TokenExchangeData {
    pub(crate) code: String,
    pub(crate) nonce: String,
    pub(crate) pkce_verifier: String,
    pub(crate) redirect_uri: String,
}

pub(super) async fn callback_post_token_exchange(
    session: &mut WritableSession,
    client: &Client,
    jwt: SessionTokens,
    userid: String,
) {
    purge_store_and_regenerate_session(session, client).await;

    let _ = session.insert(SESSION_KEY_JWT, jwt);
    let _ = session.insert(SESSION_KEY_CSRF_TOKEN, random_alphanumeric_string(24));
    let _ = session.insert(SESSION_KEY_USERID, userid);
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

    let (jwt, userid) = oidc_client
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

    callback_post_token_exchange(&mut session, &client, jwt, userid).await;

    Ok(Redirect::to(&login_callback_session_params.app_uri).into_response())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axum::{
        body::Body,
        http::{
            header::{COOKIE, LOCATION, SET_COOKIE},
            Request,
        },
    };
    use hyper::Uri;
    use tower::{Service, ServiceExt};

    use crate::auth::tests::MockSetup;

    use super::*;

    #[tokio::test]
    async fn test_callback_provides_session() {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();
        let code: String = random_alphanumeric_string(20);

        // Act
        let request = Request::builder().uri("/auth/login?app_uri=http://example.com&redirect_uri=http://example.com&scope=openid".to_string()).body(Body::empty()).unwrap();
        let response1 = app.ready().await.unwrap().call(request).await.unwrap();
        let cookie1 = response1.headers().get(SET_COOKIE).unwrap();
        let redirect_uri1 = response1.headers().get(LOCATION).unwrap();
        let uri = Uri::from_str(redirect_uri1.to_str().unwrap()).unwrap();
        let state: String = uri
            .query()
            .unwrap_or_default()
            .split('&')
            .find(|s| s.starts_with("state="))
            .expect("Redirect uri should have state")
            .split('=')
            .skip(1)
            .take(1)
            .collect();

        m.setup_id_token_nonce(redirect_uri1).await;

        let request = Request::builder()
            .uri(format!("/auth/callback?code={code}&state={state}"))
            .header(COOKIE, cookie1.clone())
            .body(Body::empty())
            .unwrap();
        let response2 = app.ready().await.unwrap().call(request).await.unwrap();
        let status2 = response2.status();
        let headers2 = response2.headers().clone();
        let body = String::from_utf8(
            hyper::body::to_bytes(response2.into_body())
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        // Assert
        assert_eq!(
            status2,
            StatusCode::SEE_OTHER,
            "response2 should be redirect, but {}",
            body
        );
        let cookie2 = headers2.get(SET_COOKIE).unwrap();
        assert_ne!(
            cookie1.to_str().unwrap(),
            cookie2.to_str().unwrap(),
            "Second cookie should be different"
        );
    }
}
