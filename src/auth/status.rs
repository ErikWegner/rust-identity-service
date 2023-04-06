use axum::Json;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StatusResponse {
    pub(crate) expires_in: Option<usize>,
    pub(crate) refresh_expires_in: Option<usize>,
    pub(crate) authenticated: bool,
}

pub(crate) async fn status() -> Json<StatusResponse> {
    Json(StatusResponse {
        expires_in: None,
        refresh_expires_in: None,
        authenticated: false,
    })
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request, http::StatusCode};
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
}
