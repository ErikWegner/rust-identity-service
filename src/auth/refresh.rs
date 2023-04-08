use std::sync::{Arc, Mutex};

use anyhow::Result;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension,
};
use axum_macros::debug_handler;
use axum_sessions::extractors::WritableSession;
use tracing::debug;

use crate::{
    auth::SessionTokens,
    session::{SESSION_KEY_JWT, SESSION_KEY_USERID},
};

use super::OIDCClient;

#[derive(Debug, Clone)]
pub(crate) struct RefreshLockManager {
    inner: Arc<Mutex<Vec<String>>>,
    remaining_secs_threshold: u64,
}

impl RefreshLockManager {
    pub(crate) fn new(remaining_secs_threshold: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(vec![])),
            remaining_secs_threshold,
        }
    }

    fn user_is_refreshing(&self, userid: &String) -> bool {
        let refreshing_users = self.inner.lock().unwrap();
        refreshing_users.contains(userid)
    }

    fn set_user_is_refreshing(&self, userid: &str) {
        let userid = userid.to_string();
        let mut refreshing_users = self.inner.lock().unwrap();
        refreshing_users.push(userid);
    }

    fn remove_user_is_refreshing(&self, userid: &str) {
        let mut refreshing_users = self.inner.lock().unwrap();
        refreshing_users.retain(|u| u != userid);
    }
}

#[debug_handler]
pub(crate) async fn refresh(
    Extension(refresh_lock): Extension<RefreshLockManager>,
    Extension(client): Extension<OIDCClient>,
    mut session: WritableSession,
) -> Result<Response, Response> {
    let userid = session.get::<String>(SESSION_KEY_USERID).ok_or_else(|| {
        debug!("No user id in session");
        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    })?;

    if refresh_lock.user_is_refreshing(&userid) {
        return Err((StatusCode::CONFLICT, "Refresh pending...").into_response());
    }

    let session_tokens: SessionTokens = session.get(SESSION_KEY_JWT).ok_or_else(|| {
        debug!("No tokens in session");
        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    })?;

    if session_tokens.ttl_gt(refresh_lock.remaining_secs_threshold) {
        return Err((StatusCode::BAD_REQUEST, "Refresh too early".to_string()).into_response());
    }

    let refresh_token = session_tokens
        .refresh_token()
        .map(|s| s.to_string())
        .ok_or_else(|| {
            debug!("No refresh token in session");
            (StatusCode::BAD_REQUEST, "Refresh token missing").into_response()
        })?
        .clone();

    let response = tokio::spawn(async move {
        refresh_lock.set_user_is_refreshing(&userid);

        let jwt = client.refresh_token(refresh_token.as_str()).await;
        let response = match jwt {
            Ok(jwt) => {
                let _ = session.insert(SESSION_KEY_JWT, jwt);
                (StatusCode::OK, "Refresh successful".to_string()).into_response()
            }
            Err(e) => {
                debug!("Failed to refresh token: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    "Failed to refresh token".to_string(),
                )
                    .into_response()
            }
        };

        refresh_lock.remove_user_is_refreshing(&userid);
        response
    })
    .await
    .expect("Thread panicked");

    Ok(response)
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::header::COOKIE, http::Request, http::StatusCode};
    use tower::ServiceExt;

    use crate::auth::tests::MockSetup;

    use super::*;

    #[tokio::test]
    async fn test_refresh() {
        // Arrange
        let m = MockSetup::new().await;
        let app = m.router();
        let session_cookie = m.setup_authenticated_state().await;

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/refresh")
                    .header(COOKIE, session_cookie)
                    .method("POST")
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
    }
}
