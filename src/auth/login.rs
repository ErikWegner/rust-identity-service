use anyhow::Result;
use axum::{
    Extension,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_macros::debug_handler;
use serde::Deserialize;
use tower_sessions::Session;
use tower_sessions_redis_store::fred::clients::Pool;
use tracing::{debug, error, trace};

use crate::{
    auth::{
        LoginCallbackSessionParameters, oidcclient::AuthorizeRequestData,
        random_alphanumeric_string,
    },
    session::purge_store_and_regenerate_session,
};

use super::OIDCClient;

#[derive(Debug, Deserialize)]
pub(crate) struct LoginQueryParams {
    #[serde(rename = "app_uri")]
    app_uri: String,
    #[serde(rename = "redirect_uri")]
    redirect_uri: String,
    #[serde(rename = "scope")]
    scope: String,
    #[serde(rename = "ui_locales")]
    ui_locales: Option<String>,
    #[serde(rename = "prompt")]
    prompt: Option<String>,
    #[serde(rename = "kc_idp_hint")]
    kc_idp_hint: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LoginAppSettings {
    allowed_app_uris_match: Vec<String>,
    allowed_app_uris_startswith: Vec<String>,
}

impl LoginAppSettings {
    pub fn new(allowed_app_uris: Vec<String>) -> Self {
        let mut allowed_app_uris_match: Vec<String> = Vec::new();
        let mut allowed_app_uris_startswith: Vec<String> = Vec::new();
        for allowed_app_uri in allowed_app_uris {
            if allowed_app_uri.ends_with('*') {
                let allowed_app_uri = allowed_app_uri[0..(allowed_app_uri.len() - 1)].to_string();
                debug!("Allowed prefix for app_uri: {}", allowed_app_uri);
                allowed_app_uris_startswith.push(allowed_app_uri);
            } else {
                debug!("Allowed app uri: {}", allowed_app_uri);
                allowed_app_uris_match.push(allowed_app_uri.clone())
            }
        }
        Self {
            allowed_app_uris_match,
            allowed_app_uris_startswith,
        }
    }

    pub(crate) fn is_app_uri_allowed(&self, app_uri: &str) -> bool {
        trace!("is_app_uri_allowed: app_uri: {}", app_uri);
        let t = app_uri.to_string();
        if self.allowed_app_uris_match.contains(&t) {
            return true;
        }
        self.allowed_app_uris_startswith
            .iter()
            .any(|allowed_app_uri| t.starts_with(allowed_app_uri))
    }
}

#[debug_handler]
pub(crate) async fn login(
    State(login_app_settings): State<LoginAppSettings>,
    Extension(oidc_client): Extension<OIDCClient>,
    Extension(client): Extension<Pool>,
    session: Session,
    login_query_params: Query<LoginQueryParams>,
) -> Result<Response, Response> {
    if !login_app_settings.is_app_uri_allowed(login_query_params.app_uri.as_str()) {
        debug!("app_uri {} is not allowed", login_query_params.app_uri);
        return Err((StatusCode::BAD_REQUEST, "Invalid app_uri").into_response());
    }
    purge_store_and_regenerate_session(&session, client.next()).await;
    let state: String = random_alphanumeric_string(20);
    let d = oidc_client
        .authorize_data(AuthorizeRequestData {
            redirect_uri: login_query_params.redirect_uri.clone(),
            scope: login_query_params.scope.clone(),
            state,
            ui_locales: login_query_params.ui_locales.clone(),
            prompt: login_query_params.prompt.clone(),
            kc_idp_hint: login_query_params.kc_idp_hint.clone(),
        })
        .await
        .map_err(|e| {
            error!("Failed to build authorization url {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Server failure").into_response()
        })?;
    let auth_url = d.auth_url.as_str();

    let _ = session
        .insert(
            "ridser_logincallback_parameters",
            LoginCallbackSessionParameters {
                app_uri: login_query_params.app_uri.clone(),
                nonce: d.nonce,
                csrf_token: d.csrf_token,
                pkce_verifier: d.pkce_verifier,
                redirect_uri: login_query_params.redirect_uri.clone(),
                scopes: login_query_params.scope.clone(),
            },
        )
        .await;

    debug!("login redirecting to {}", auth_url);
    Ok(Redirect::to(auth_url).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{
            Request,
            header::{COOKIE, LOCATION, SET_COOKIE},
        },
    };
    use http_body_util::BodyExt;
    use tower::{Service, ServiceExt};

    use crate::auth::tests::MockSetup;

    use super::*;

    #[tokio::test]
    async fn test_login_sends_redirect() {
        // Arrange
        let m = MockSetup::new().await;
        let app = m.router();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/login?app_uri=http://example.com&redirect_uri=http://example.com&scope=openid&state=xyz")
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
            "response should be redirect, but {body}"
        );
    }

    #[tokio::test]
    async fn test_login_sends_new_session_cookie() {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();
        let uri = "/auth/login?app_uri=http://example.com&redirect_uri=http://example.com&scope=openid&state=xyz";

        // Act
        let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let response1 = ServiceExt::<Request<Body>>::ready(&mut app)
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        let status1 = response1.status();
        let cookie1 = response1.headers().get(SET_COOKIE).unwrap();

        let request = Request::builder()
            .uri(uri)
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
        let cookie2 = response2.headers().get(SET_COOKIE).unwrap();

        // Assert
        assert_eq!(
            status1,
            StatusCode::SEE_OTHER,
            "response1 should be redirect"
        );
        assert_eq!(
            status2,
            StatusCode::SEE_OTHER,
            "response2 should be redirect"
        );
        assert_ne!(
            cookie1.to_str().unwrap(),
            cookie2.to_str().unwrap(),
            "Second cookie should be different"
        );
    }

    #[tokio::test]
    async fn test_app_uri_invalid() {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();

        let urilist = vec![
            /* Different protocol */
            "https://example.com",
            /* Path appended without wildcard */
            "http://example.com/",
            "http://example.org/my/app",
            /* Different domain */
            "http://example.fr",
            /* Different port */
            "http://example.com:8080",
        ];

        for app_uri in urilist {
            // Act
            let response = ServiceExt::<Request<Body>>::ready(&mut app).await.unwrap().call(
                Request::builder()
                    .uri(format!("/auth/login?app_uri={app_uri}&redirect_uri=http://example.com&scope=openid&state=xyz"))
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
                StatusCode::BAD_REQUEST,
                "Request should be denied, body was: {body}"
            );
        }
    }

    #[tokio::test]
    async fn test_app_uri_valid() {
        // Arrange
        let m = MockSetup::new().await;
        let mut app = m.router();

        let urilist = vec![
            /* Exact match */
            "http://example.com",
            /* Paths matching the wildcard */
            "http://example.org/my/app/*",
            "http://example.org/my/app/",
            "http://example.org/my/app/abc/",
            "http://example.org/my/app/kp/h?id=34",
        ];

        for app_uri in urilist {
            // Act
            let response = ServiceExt::<Request<Body>>::ready(&mut app).await.unwrap().call(
                Request::builder()
                    .uri(format!("/auth/login?app_uri={app_uri}&redirect_uri=http://example.com&scope=openid&state=xyz"))
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
                "response should be redirect, but {body}"
            );
        }
    }

    #[tokio::test]
    async fn test_login_sends_redirect_with_ui_locales() {
        // Arrange
        let m = MockSetup::new().await;
        let app = m.router();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/login?app_uri=http://example.com&redirect_uri=http://example.com&scope=openid&state=xyz&ui_locales=de")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let url = response
            .headers()
            .get(LOCATION)
            .expect("header value")
            .to_str()
            .expect("to str")
            .split('?')
            .next_back()
            .expect("last");

        // Assert
        assert!(
            url.contains("ui_locales=de"),
            "url should contain ui_locales: {url}"
        );
    }

    #[tokio::test]
    async fn test_login_sends_redirect_with_prompt_none() {
        // Arrange
        let m = MockSetup::new().await;
        let app = m.router();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/login?app_uri=http://example.com&redirect_uri=http://example.com&scope=openid&state=xyz&prompt=none")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let url = response
            .headers()
            .get(LOCATION)
            .expect("header value")
            .to_str()
            .expect("to str")
            .split('?')
            .next_back()
            .expect("last");

        // Assert
        assert!(
            url.contains("prompt=none"),
            "url should contain prompt: {url}"
        );
    }

    #[tokio::test]
    async fn test_login_sends_redirect_with_kc_idp_hint() {
        // Arrange
        let m = MockSetup::new().await;
        let app = m.router();

        // Act
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/login?app_uri=http://example.com&redirect_uri=http://example.com&scope=openid&state=xyz&kc_idp_hint=some-idp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let url = response
            .headers()
            .get(LOCATION)
            .expect("header value")
            .to_str()
            .expect("to str")
            .split('?')
            .next_back()
            .expect("last");

        // Assert
        assert!(
            url.contains("kc_idp_hint=some-idp"),
            "url should contain kc_idp_hint: {url}"
        );
    }
}
