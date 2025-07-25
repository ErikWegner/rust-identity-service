use axum::Json;
use axum_macros::debug_handler;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

use crate::session::SESSION_KEY_CSRF_TOKEN;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CsrfTokenResponse {
    token: String,
}

#[debug_handler]
pub(crate) async fn csrftoken(session: Session) -> Json<CsrfTokenResponse> {
    let session_csrf_token: String = session
        .get(SESSION_KEY_CSRF_TOKEN)
        .await
        .unwrap_or(None)
        .unwrap_or_default();
    Json(CsrfTokenResponse {
        token: session_csrf_token,
    })
}

#[cfg(test)]
mod tests {
    use crate::auth::{csrftoken::CsrfTokenResponse, tests::MockSetup};
    use axum::{body::Body, http::header::COOKIE, http::Request, http::StatusCode};
    use http_body_util::BodyExt;
    use tower::{Service, ServiceExt};

    #[tokio::test]
    async fn it_returns_empty_value_for_anonymous_access() {
        // Arrange
        let m = MockSetup::new().await;
        let app = m.router();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/csrftoken")
                    .method("POST")
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
        assert_eq!(status, StatusCode::OK, "response should be ok, but {body}");
        let c: CsrfTokenResponse = serde_json::from_str(&body).expect("Body should deserialize");
        assert!(c.token.is_empty(), "token should be empty, but {body}");
    }

    #[tokio::test]
    async fn it_returns_a_value_for_authenticated_requests() {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();
        let session_cookie = m.setup_authenticated_state(&mut app).await;

        // Act
        let response = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(
                Request::builder()
                    .uri("/auth/csrftoken")
                    .method("POST")
                    .header(COOKIE, session_cookie)
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
        assert_eq!(status, StatusCode::OK, "response should be ok, but {body}");
        let c: CsrfTokenResponse = serde_json::from_str(&body).expect("Body should deserialize");
        assert!(!c.token.is_empty(), "Token should not be empty");
    }
}
