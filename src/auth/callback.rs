use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Extension,
};
use axum_macros::debug_handler;
use reqwest::Url;
use serde::Deserialize;
use tower_sessions::Session;
use tower_sessions_redis_store::fred::clients::Pool;
use tracing::{error, info};

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
    code: Option<String>,
    error: Option<String>,
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
    session: &Session,
    pool: Pool,
    jwt: SessionTokens,
    userid: String,
) {
    purge_store_and_regenerate_session(session, pool.next()).await;

    let _ = session.insert(SESSION_KEY_JWT, jwt).await;
    let _ = session
        .insert(SESSION_KEY_CSRF_TOKEN, random_alphanumeric_string(24))
        .await;
    let _ = session.insert(SESSION_KEY_USERID, userid).await;
}

#[debug_handler]
pub(crate) async fn callback(
    Extension(oidc_client): Extension<OIDCClient>,
    Extension(client): Extension<Pool>,
    session: Session,
    callback_query_params: Query<CallbackQueryParams>,
) -> Result<Response, Response> {
    let login_callback_session_params = session
        .get::<LoginCallbackSessionParameters>("ridser_logincallback_parameters")
        .await
        .map_err(|redis_err| {
            error!("Reading redis error in callback: {:?}", redis_err);
            (StatusCode::INTERNAL_SERVER_ERROR, "Invalid session").into_response()
        })?
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid session").into_response())?;
    let _: Result<Option<()>, _> = session.remove("ridser_logincallback_parameters").await;
    if callback_query_params.state != login_callback_session_params.csrf_token {
        return Err((StatusCode::BAD_REQUEST, "Invalid request").into_response());
    }

    // If callback contains an error, redirect to the app with the error message.
    if let Some(error) = &callback_query_params.error {
        let u = Url::parse(&login_callback_session_params.app_uri).map(|u| {
            // append error details to the redirect URI
            let mut url = u.clone();
            url.query_pairs_mut().append_pair("error", error.as_str());
            url.to_string()
        });
        return match u {
            Ok(app_uri) => Ok(Redirect::to(app_uri.as_str()).into_response()),
            Err(e) => {
                error!(
                    "Failed to parse redirect URI: {} {:?}",
                    &login_callback_session_params.app_uri, e
                );
                Err((StatusCode::BAD_REQUEST, "Invalid app_uri").into_response())
            }
        };
    }

    let (jwt, userid) = oidc_client
        .exchange_code(TokenExchangeData {
            code: callback_query_params.code.clone().unwrap_or_default(),
            nonce: login_callback_session_params.nonce,
            pkce_verifier: login_callback_session_params.pkce_verifier,
            redirect_uri: login_callback_session_params.redirect_uri.clone(),
        })
        .await
        .map_err(|e| {
            info!("Failed to exchange code: {:?}", e);
            (StatusCode::UNAUTHORIZED, "Login failure").into_response()
        })?;

    callback_post_token_exchange(&session, client, jwt, userid).await;

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
    use http_body_util::BodyExt; // for `collect`
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
        let response1 = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
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
        let response2 = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        let status2 = response2.status();
        let headers2 = response2.headers().clone();
        let body = String::from_utf8(
            response2
                .into_body()
                .collect()
                .await
                .expect("collect")
                .to_bytes()
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
