use axum::Json;
use axum_sessions::extractors::ReadableSession;
use serde::Deserialize;
use serde::Serialize;

use crate::session::SESSION_KEY_JWT;

use super::SessionTokens;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StatusResponse {
    pub(crate) expires_in: Option<u64>,
    pub(crate) refresh_expires_in: Option<u64>,
    pub(crate) authenticated: bool,
}

fn status_response_map(session_tokens: Option<SessionTokens>) -> StatusResponse {
    session_tokens
        .map(|st| {
            let now = std::time::SystemTime::now();
            StatusResponse {
                expires_in: st.expires_at.duration_since(now).map(|d| d.as_secs()).ok(),
                refresh_expires_in: st
                    .refresh_expires_at
                    .duration_since(now)
                    .map(|d| d.as_secs())
                    .ok(),
                authenticated: true,
            }
        })
        .unwrap_or_else(|| StatusResponse {
            expires_in: None,
            refresh_expires_in: None,
            authenticated: false,
        })
}

pub(crate) async fn status(session: ReadableSession) -> Json<StatusResponse> {
    let session_tokens: Option<SessionTokens> = session.get(SESSION_KEY_JWT);
    let p = status_response_map(session_tokens);
    Json(p)
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::header::COOKIE, http::Request, http::StatusCode};
    use tower::ServiceExt;

    use crate::auth::tests::MockSetup;

    use super::*;

    #[tokio::test]
    async fn test_handles_anonymous_state() {
        // Arrange
        let m = MockSetup::new().await;
        let app = m.router();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/status")
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
            StatusCode::OK,
            "response should be ok, but {}",
            body
        );
        let s: StatusResponse =
            serde_json::from_str(body.as_str()).expect("Body should deserialize");
        assert!(!s.authenticated, "Should not be authenticated");
    }

    #[tokio::test]
    async fn test_handles_authenticated_state() {
        // Arrange
        let m = MockSetup::new().await;
        let app = m.router();
        let session_cookie = m.setup_authenticated_state().await;
        let session_cookie = format!("{}={}", "testing.sid", session_cookie);
        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/status")
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
            StatusCode::OK,
            "response should be ok, but {}",
            body
        );
        let s: StatusResponse =
            serde_json::from_str(body.as_str()).expect("Body should deserialize");
        assert!(s.authenticated, "Should be authenticated");
        assert!(s.expires_in.unwrap() > 2, "Should be greater 14 seconds");
        assert!(
            s.refresh_expires_in.unwrap() > 498,
            "Should be greater 498 seconds"
        );
    }
}
