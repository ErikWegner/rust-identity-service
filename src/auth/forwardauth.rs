use std::sync::Arc;

use axum::{
    extract::State,
    http::{
        HeaderValue, Method, StatusCode,
        header::{self, AUTHORIZATION, COOKIE},
    },
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use axum_macros::debug_handler;
use tower_sessions::Session;
use tracing::{debug, error};

use crate::{
    auth::SessionTokens,
    http::HEADER_KEY_CSRF_TOKEN,
    session::{SESSION_KEY_CSRF_TOKEN, SESSION_KEY_JWT},
};

pub(crate) struct ForwardAuthState {
    pub(crate) cookie_name: String,
}

#[debug_handler]
pub(crate) async fn forwardauth(
    State(forwardauth_config): State<Arc<ForwardAuthState>>,
    session: Session,
    jar: CookieJar,
    req: axum::extract::Request,
) -> Result<impl IntoResponse, Response> {
    if req.method() != Method::GET {
        // Check CSRF token
        let request_csrf_token = req.headers().get(HEADER_KEY_CSRF_TOKEN);
        let session_csrf_token: Option<String> =
            session.get(SESSION_KEY_CSRF_TOKEN).await.unwrap_or(None);
        if request_csrf_token.is_none()
            || session_csrf_token.is_none()
            || request_csrf_token.unwrap().as_bytes() != session_csrf_token.unwrap().as_bytes()
        {
            return Err((StatusCode::FORBIDDEN, "Missing or invalid CSRF token").into_response());
        }
    }

    let needle = forwardauth_config.cookie_name.as_str();
    let remaining_cookies = jar
        .iter()
        // Filter out cookies that are not valid for the proxy
        .filter(|h| !h.name().starts_with(needle))
        .cloned()
        .collect::<Vec<_>>();
    // TODO: remove CSRF-Token header
    // TOOD: check that session cookie is removed

    let mut headers = req.headers().clone();
    headers.remove(COOKIE);
    if !remaining_cookies.is_empty() {
        let new_cookie_value = remaining_cookies
            .iter()
            .map(|c| c.encoded().to_string())
            .collect::<Vec<String>>()
            .join("; ");
        headers.insert(
            COOKIE,
            HeaderValue::from_str(new_cookie_value.as_str()).map_err(|e| {
                debug!("Invalid cookie {:?}", e);
                (StatusCode::BAD_REQUEST, "Invalid cookie").into_response()
            })?,
        );
    }

    let jwt: Option<SessionTokens> = session.get(SESSION_KEY_JWT).await.unwrap_or(None);
    if let Some(session_tokens) = jwt {
        headers.append(
            AUTHORIZATION,
            HeaderValue::from_bytes(format!("Bearer {}", session_tokens.access_token()).as_bytes())
                .map_err(|e| {
                    error!("Failed to set authorization header: {:?}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Cannot proxy authentication".to_string(),
                    )
                        .into_response()
                })?,
        );
    }
    headers.remove(HEADER_KEY_CSRF_TOKEN);

    headers.insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
    Ok((headers, "OK"))
}
