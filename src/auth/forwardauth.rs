use std::sync::Arc;

use axum::{
    extract::State,
    http::{
        HeaderValue, StatusCode,
        header::{self, AUTHORIZATION, COOKIE, HeaderMap},
    },
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use axum_macros::debug_handler;
use tower_sessions::Session;
use tracing::error;

use crate::{
    auth::SessionTokens,
    http::HEADER_KEY_CSRF_TOKEN,
    session::{SESSION_KEY_CSRF_TOKEN, SESSION_KEY_JWT},
};

pub(crate) struct ForwardAuthState {
    pub(crate) cookie_name: String,
}

const FORWARDED_METHOD_HEADER: &str = "X-Forwarded-Method";

#[debug_handler]
pub(crate) async fn forwardauth(
    State(forwardauth_config): State<Arc<ForwardAuthState>>,
    headers: HeaderMap,
    session: Session,
    jar: CookieJar,
    req: axum::extract::Request,
) -> Result<impl IntoResponse, Response> {
    let jwt: Option<SessionTokens> = session.get(SESSION_KEY_JWT).await.unwrap_or(None);
    if jwt.is_none() {
        return Err((StatusCode::UNAUTHORIZED, "Unauthorized").into_response());
    }

    let req_method = headers.get(FORWARDED_METHOD_HEADER);
    if req_method.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Missing {FORWARDED_METHOD_HEADER} header",
        )
            .into_response());
    }
    if let Some(method_value) = req_method
        && let Ok(method) = method_value.to_str()
        && method.to_uppercase() != "GET"
    {
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

    let mut headers = req.headers().clone();
    headers.remove(COOKIE);
    if !remaining_cookies.is_empty() {
        let new_cookie_values = remaining_cookies
            .iter()
            .map(|c| c.encoded().to_string())
            .collect::<Vec<String>>();
        for new_cookie_value in new_cookie_values {
            headers.append(COOKIE, new_cookie_value.parse().unwrap());
        }
    }

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

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::Request,
        http::StatusCode,
        http::header::{AUTHORIZATION, COOKIE, HeaderMap},
    };
    use cookie::{Cookie, CookieJar};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::{
        auth::{forwardauth::FORWARDED_METHOD_HEADER, tests::MockSetup},
        http::HEADER_KEY_CSRF_TOKEN,
    };

    const FORWARDAUTHPATH: &str = "/auth";

    #[tokio::test]
    async fn test_handles_anonymous_state() {
        // Arrange
        let m = MockSetup::new().await;
        let app = m.router();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri(FORWARDAUTHPATH)
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
            StatusCode::UNAUTHORIZED,
            "response should be UNAUTHORIZED, but {body}"
        );
    }

    #[tokio::test]
    async fn test_handles_authenticated_state() {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();
        let session_cookie = m.setup_authenticated_state(&mut app).await;
        let csrftoken = m.get_csrf_token(&mut app, &session_cookie).await;

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri(FORWARDAUTHPATH)
                    .header(COOKIE, session_cookie)
                    .header(FORWARDED_METHOD_HEADER, "post")
                    .header(HEADER_KEY_CSRF_TOKEN, &csrftoken)
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
    }

    #[tokio::test]
    async fn test_handles_get_without_csrf_token() {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();
        let session_cookie = m.setup_authenticated_state(&mut app).await;

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri(FORWARDAUTHPATH)
                    .header(COOKIE, session_cookie)
                    .header(FORWARDED_METHOD_HEADER, "get")
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
    }

    fn has_auth_header(headers: &HeaderMap) -> bool {
        let auth_header = headers.get(AUTHORIZATION);
        if let Some(auth_header) = auth_header {
            return auth_header.to_str().unwrap().starts_with("Bearer ");
        }
        return false;
    }

    #[tokio::test]
    async fn test_adds_auth_header_removes_cookie() -> Result<(), Box<dyn std::error::Error>> {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();
        let session_cookie = m.setup_authenticated_state(&mut app).await;
        let csrftoken = m.get_csrf_token(&mut app, &session_cookie).await;
        let mut request_cookies = CookieJar::new();
        request_cookies.add_original(("keep_me", "keep_that_cookie"));
        request_cookies.add_original(("second", "another value to keep"));
        request_cookies.add_original(Cookie::parse(session_cookie.clone())?);
        request_cookies.add_original(("afterauthcookie", "kept_this_cookie"));
        let mut req_builder = Request::builder()
            .uri(FORWARDAUTHPATH)
            .header(FORWARDED_METHOD_HEADER, "post")
            .header(HEADER_KEY_CSRF_TOKEN, &csrftoken);
        let mut added_cookie_headers = 0;
        for cookie in request_cookies.iter() {
            req_builder = req_builder.header(COOKIE, cookie.to_string());
            added_cookie_headers += 1;
        }

        // Act
        let response = app
            .oneshot(req_builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        has_auth_header(response.headers());
        let cookie_response_headers = response
            .headers()
            .get_all(COOKIE)
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let mut response_cookies = CookieJar::new();
        for cookie_header in cookie_response_headers {
            let response_cookie = Cookie::parse(cookie_header.to_str()?.to_string())?;
            response_cookies.add_original(response_cookie);
        }
        let response_cookies_count = response_cookies.iter().count();
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
        assert_eq!(
            added_cookie_headers, 4,
            "expected four cookie headers to be added, but {added_cookie_headers} found"
        );
        assert_eq!(
            response_cookies_count,
            3,
            "expected three cookies in the response, but {response_cookies_count} found, {:?}",
            response_cookies
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_removes_csrf_header() -> Result<(), Box<dyn std::error::Error>> {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();
        let session_cookie = m.setup_authenticated_state(&mut app).await;
        let csrftoken = m.get_csrf_token(&mut app, &session_cookie).await;
        let additional_headers = vec![
            ("X-Custom-Header", "custom_value"),
            ("X-Another-Custom-Header", "another_custom_value"),
            ("X-Custom-Header-2", "custom_value_2"),
            ("X-Another-Custom-Header-2", "another_custom_value_2"),
            ("X-Custom-Header-3", "custom_value_3"),
        ];
        let mut req_builder = Request::builder()
            .uri(FORWARDAUTHPATH)
            .header(COOKIE, session_cookie)
            .header(FORWARDED_METHOD_HEADER, "post")
            .header(HEADER_KEY_CSRF_TOKEN, &csrftoken);
        let mut added_custom_headers = 0;
        for header in &additional_headers {
            req_builder = req_builder.header(header.0, header.1);
            added_custom_headers += 1;
        }

        // Act
        let response = app
            .oneshot(req_builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        has_auth_header(response.headers());
        let headers = response.headers().clone();
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
        assert_eq!(
            added_custom_headers, 5,
            "expected five custom headers to be added, but {added_custom_headers} found"
        );
        for custom_header in &additional_headers {
            let h = headers.get(custom_header.0);
            assert!(
                h.is_some(),
                "Custom header '{}' should be present in the response",
                custom_header.0
            );
            assert_eq!(
                h.unwrap(),
                custom_header.1,
                "Custom header '{}' mismatch",
                custom_header.0,
            );
        }
        assert!(
            !headers.contains_key(HEADER_KEY_CSRF_TOKEN),
            "CSRF token should have been removed"
        );
        Ok(())
    }
}
