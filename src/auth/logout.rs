use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use axum_macros::debug_handler;
use cookie::Cookie;
use serde::Deserialize;
use time::Duration;
use tower_sessions::Session;
use tracing::{trace, warn};

use crate::session::SESSION_KEY_JWT;

use super::SessionTokens;

const COOKIE_NAME_LOGOUT_APP_URI: &str = "ridser_logout_app_uri";
const LOGOUT_APP_URI_COOKIE_TTL: i64 = 60;

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

#[derive(Debug)]
pub struct LogoutAppSettings {
    pub(crate) client_id: String,
    pub(crate) logout_uri: String,
    pub(crate) _behavior: LogoutBehavior,
    pub(crate) allowed_app_uris_match: Vec<String>,
}

impl LogoutAppSettings {
    pub(crate) fn is_app_uri_allowed(&self, app_uri: &String) -> bool {
        trace!("is_app_uri_allowed: app_uri: {}", app_uri);
        self.allowed_app_uris_match.contains(app_uri)
    }
}

#[debug_handler]
pub(crate) async fn logout(
    State(logout_app_settings): State<Arc<LogoutAppSettings>>,
    session: Session,
    logout_query_params: Query<LogoutQueryParams>,
) -> Response {
    let app_uri = &logout_query_params.app_uri;
    let redirect_uri = &logout_query_params.redirect_uri;

    let logout_uri = &logout_app_settings.logout_uri;
    let session_tokens: Option<SessionTokens> = session.get(SESSION_KEY_JWT).await.unwrap_or(None);
    let id_token = session_tokens.map(|st| st.id_token).unwrap_or_default();
    let uri = if id_token.is_empty() {
        format!(
            "{logout_uri}?post_logout_redirect_uri={redirect_uri}&client_id={}",
            logout_app_settings.client_id
        )
    } else {
        format!("{logout_uri}?id_token_hint={id_token}&post_logout_redirect_uri={redirect_uri}")
    };

    let app_uri_cookie = Cookie::build((COOKIE_NAME_LOGOUT_APP_URI, app_uri.as_str()))
        .path("/auth")
        .same_site(cookie::SameSite::Lax)
        .max_age(Duration::seconds(LOGOUT_APP_URI_COOKIE_TTL))
        .secure(true)
        .http_only(true)
        .build();

    let _ = session.flush().await;

    (
        StatusCode::SEE_OTHER,
        [
            ("location", uri.as_str()),
            ("set-cookie", &app_uri_cookie.to_string()),
        ],
    )
        .into_response()
}

#[debug_handler]
pub(crate) async fn logout_callback(
    State(logout_app_settings): State<Arc<LogoutAppSettings>>,
    session: Session,
    jar: CookieJar,
) -> Response {
    let _ = session.flush().await;

    let app_uri = jar
        .get(COOKIE_NAME_LOGOUT_APP_URI)
        .map(|c| c.value().to_string())
        .unwrap_or_else(|| {
            warn!("ridser_logout_app_uri cookie not found");
            "/".to_string()
        });

    let clear_cookie = Cookie::build((COOKIE_NAME_LOGOUT_APP_URI, ""))
        .path("/auth")
        .max_age(Duration::seconds(0))
        .build();

    if !logout_app_settings.is_app_uri_allowed(&app_uri) {
        return (StatusCode::BAD_REQUEST, "Invalid app_uri").into_response();
    }

    (
        StatusCode::SEE_OTHER,
        [
            ("location", app_uri.as_str()),
            ("set-cookie", &clear_cookie.to_string()),
        ],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{
            Request, StatusCode,
            header::{COOKIE, LOCATION, SET_COOKIE},
        },
    };
    use http_body_util::BodyExt;
    use tower::{Service, ServiceExt};

    use crate::auth::tests::MockSetup;

    #[tokio::test]
    async fn test_handles_anonymous_state_with_valid_app_uris() {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();
        let urilist = vec![
            "http://logout.example.com".to_string(),
            "http://example.org/it/index".to_string(),
        ];

        for app_uri in urilist {
            // Act
            let response = ServiceExt::<Request<Body>>::ready(&mut app)
                .await
                .unwrap()
                .call(
                    Request::builder()
                        .uri(format!(
                            "/auth/logout?app_uri={app_uri}&redirect_uri=http://example.com"
                        ))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let set_cookie = response
                .headers()
                .get(SET_COOKIE)
                .map(|hv| hv.to_str().unwrap().to_string())
                .unwrap_or_default();
            let body = String::from_utf8(
                response
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
                status,
                StatusCode::SEE_OTHER,
                "response should be redirect, but {body}"
            );
            assert!(
                set_cookie.contains("ridser_logout_app_uri="),
                "Should set app_uri cookie, but {set_cookie}"
            );
            assert!(
                set_cookie.contains("Max-Age=60"),
                "Cookie should have 60s TTL, but {set_cookie}"
            );
        }
    }

    #[tokio::test]
    async fn test_handles_anonymous_state_with_invalid_app_uris() {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();
        let urilist = vec![
            /* Only a path */
            "/".to_string(),
            /* Different domain */
            "http://start.com/".to_string(),
            /* Path does not exactly match */
            "http://example.org/it/index2".to_string(),
            "http://example.org/it/index/".to_string(),
            "http://logout.example.com/".to_string(),
            /* Port */
            "http://logout.example.com:8000".to_string(),
            /* Protocol */
            "https://logout.example.com".to_string(),
        ];

        for app_uri in urilist {
            // Act
            let response = ServiceExt::<Request<Body>>::ready(&mut app)
                .await
                .unwrap()
                .call(
                    Request::builder()
                        .uri(format!(
                            "/auth/logout?app_uri={app_uri}&redirect_uri=http://example.com"
                        ))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = String::from_utf8(
                response
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
                status,
                StatusCode::SEE_OTHER,
                "Should be SEE OTHER for app_uri {app_uri}, body was {body}"
            );
        }
    }

    #[tokio::test]
    async fn test_handles_authenticated_state() {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();
        let session_cookie = m.setup_authenticated_state(&mut app).await;

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/logout?app_uri=http://logout.example.com&redirect_uri=http://example.com")
                    .header(COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let set_cookie = response
            .headers()
            .get(SET_COOKIE)
            .map(|hv| hv.to_str().unwrap().to_string())
            .unwrap_or_default();
        let body = String::from_utf8(
            response
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
            status,
            StatusCode::SEE_OTHER,
            "response should be redirect, but {body}"
        );
        assert!(
            set_cookie.contains("ridser_logout_app_uri="),
            "Should set app_uri cookie, but {set_cookie}"
        );
    }

    #[tokio::test]
    async fn test_handles_app_redirect() {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();
        let session_cookie = m.setup_authenticated_state(&mut app).await;
        let app_uri = "http://logout.example.com".to_string();

        // Act - call logout
        let logout_response = ServiceExt::<Request<Body>>::ready(&mut app)
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

        let logout_set_cookie = logout_response
            .headers()
            .get(SET_COOKIE)
            .map(|hv| hv.to_str().unwrap().to_string())
            .unwrap_or_default();

        // Extract the app_uri cookie value from Set-Cookie header
        let app_uri_cookie_value = logout_set_cookie
            .split(';')
            .find(|part| part.trim().starts_with("ridser_logout_app_uri="))
            .map(|part| {
                part.trim()
                    .strip_prefix("ridser_logout_app_uri=")
                    .unwrap()
                    .to_string()
            })
            .unwrap_or_default();

        // Act - call logoutcallback with the app_uri cookie
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(
                Request::builder()
                    .uri("/auth/logoutcallback".to_string())
                    .header(
                        COOKIE,
                        format!("ridser_logout_app_uri={app_uri_cookie_value}"),
                    )
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
            response
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
            status,
            StatusCode::SEE_OTHER,
            "response should be redirect, but {body}"
        );
        assert_eq!(
            Some(app_uri.to_string()),
            location,
            "Should redirect to the app uri"
        );
        assert!(
            cookie.contains("Max-Age=0"),
            "Cookie should be marked to be expired, but {cookie}"
        );
    }
}
