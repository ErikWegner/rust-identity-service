use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_macros::debug_handler;
use axum_sessions::extractors::WritableSession;
use serde::Deserialize;
use tracing::warn;

use crate::session::SESSION_KEY_JWT;

use super::SessionTokens;

#[derive(Clone, Debug)]
pub enum LogoutBehavior {
    FrontChannelLogoutWithIdToken,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct LogoutQueryParams {
    /// User accessible uri of the front end. After logout succeeds,
    /// user will be redirected to this url.
    #[serde(rename = "app_uri")]
    app_uri: String,
    /// User accessible uri of the single sign on system. During
    /// logout, user will be redirected to this url to end the
    /// sso-session.
    #[serde(rename = "redirect_uri")]
    redirect_uri: String,
}

#[derive(Clone, Debug)]
pub struct LogoutAppSettings {
    pub(crate) logout_uri: String,
    pub(crate) _behavior: LogoutBehavior,
}

#[debug_handler]
pub(crate) async fn logout(
    State(logout_app_settings): State<LogoutAppSettings>,
    mut session: WritableSession,
    logout_query_params: Query<LogoutQueryParams>,
) -> Response {
    let _ = session.insert("ridser_logout_app_uri", logout_query_params.app_uri.clone());
    let logout_uri = logout_app_settings.logout_uri;
    let session_tokens: Option<SessionTokens> = session.get(SESSION_KEY_JWT);
    let id_token = session_tokens.map(|st| st.id_token).unwrap_or_default();
    let post_logout_redirect_uri = logout_query_params.redirect_uri.clone();
    let uri = format!(
        "{logout_uri}?id_token_hint={id_token}&post_logout_redirect_uri={post_logout_redirect_uri}"
    );

    Redirect::to(uri.as_str()).into_response()
}

#[debug_handler]
pub(crate) async fn logout_callback(mut session: WritableSession) -> Response {
    let app_uri = session
        .get::<String>("ridser_logout_app_uri")
        .unwrap_or_else(|| {
            warn!("ridser_logout_app_uri not found in session");
            "/".to_string()
        });

    session.destroy();
    Redirect::to(&app_uri).into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{
            header::{COOKIE, LOCATION, SET_COOKIE},
            Request, StatusCode,
        },
    };
    use tower::{Service, ServiceExt};

    use crate::auth::{random_alphanumeric_string, tests::MockSetup};

    #[tokio::test]
    async fn test_handles_anonymous_state() {
        // Arrange
        let m = MockSetup::new().await;
        let app = m.router();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/logout?app_uri=http://example.com&redirect_uri=http://example.com")
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

    #[tokio::test]
    async fn test_handles_authenticated_state() {
        // Arrange
        let m = MockSetup::new().await;
        let app = m.router();
        let session_cookie = m.setup_authenticated_state().await;

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/logout?app_uri=http://example.com&redirect_uri=http://example.com")
                    .header(COOKIE, session_cookie)
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

    #[tokio::test]
    async fn test_handles_app_redirect() {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();
        let session_cookie = m.setup_authenticated_state().await;
        let app_uri = format!("http://example.com/app/{}", random_alphanumeric_string(8));

        // Act
        let _response_logout1 = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .uri(format!(
                        "/auth/logout?app_uri={app_uri}&redirect_uri=http://example.com"
                    ))
                    .header(COOKIE, session_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let response = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .uri(format!("/auth/logoutcallback"))
                    .header(COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let location = response
            .headers()
            .get(LOCATION)
            .map(|hv| hv.to_str().unwrap().to_string());
        let cookie = response
            .headers()
            .get(SET_COOKIE)
            .map(|hv| hv.to_str().unwrap().to_string())
            .unwrap_or_default();
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
        assert_eq!(
            Some(app_uri.to_string()),
            location,
            "Should redirect to the app uri"
        );
        assert!(
            cookie.contains("; Max-Age=0;"),
            "Cookie should be marked to be expired, but {}",
            cookie
        );
    }
}
