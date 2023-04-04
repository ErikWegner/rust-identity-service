use anyhow::Result;
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
use tracing::{debug, error};

use crate::{auth::LoginCallbackSessionParameters, session::purge_store_and_regenerate_session};

use super::OIDCClient;

#[derive(Debug, Deserialize)]
pub(crate) struct LoginQueryParams {
    #[serde(rename = "app_uri")]
    app_uri: String,
    #[serde(rename = "redirect_uri")]
    redirect_uri: String,
    #[serde(rename = "scope")]
    scope: String,
}

#[debug_handler]
pub(crate) async fn login(
    Extension(oidc_client): Extension<OIDCClient>,
    Extension(client): Extension<Client>,
    mut session: WritableSession,
    login_query_params: Query<LoginQueryParams>,
) -> Result<Response, Response> {
    purge_store_and_regenerate_session(&mut session, client).await;
    let d = oidc_client
        .authorize_data(&login_query_params.redirect_uri, &login_query_params.scope)
        .await
        .map_err(|e| {
            error!("Failed to build authoriaztion url {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Server failure").into_response()
        })?;
    let auth_url = d.auth_url.as_str();

    let _ = session.insert(
        "ridser_logincallback_parameters",
        LoginCallbackSessionParameters {
            app_uri: login_query_params.app_uri.clone(),
            nonce: d.nonce,
            csrf_token: d.csrf_token,
            pkce_verifier: d.pkce_verifier,
            redirect_uri: login_query_params.redirect_uri.clone(),
            scopes: login_query_params.scope.clone(),
        },
    );

    debug!("login redirecting to {}", auth_url);
    Ok(Redirect::to(auth_url).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use crate::auth::tests::MockSetup;

    use super::*;

    // Tokio async test
    #[tokio::test]
    async fn test_login_sends_redirect() {
        // Arrange
        let m = MockSetup::new().await;
        let app = m.router();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/login?app_uri=http://example.com&redirect_uri=http://example.com&scope=openid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = String::from_utf8(
            hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        // Assert
        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "response should be redirect, but {}",
            body
        );
    }
}
