mod callback;
mod csrftoken;
mod login;
mod logout;
mod oidcclient;
mod refresh;
mod status;

use std::time::SystemTime;

pub use login::LoginAppSettings;
pub use logout::LogoutAppSettings;
pub use logout::LogoutBehavior;
pub use oidcclient::OIDCClient;

use axum::{
    extract::FromRef,
    routing::{get, post},
    Extension, Router,
};

use openidconnect::{
    core::CoreIdToken, url::Url, AccessToken, CsrfToken, Nonce, PkceCodeVerifier, RefreshToken,
};
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tower_sessions_redis_store::fred::clients::RedisPool;

use crate::session::RidserSessionLayer;

use self::logout::logout_callback;
use self::{
    callback::callback,
    csrftoken::csrftoken,
    login::login,
    logout::logout,
    refresh::{refresh, RefreshLockManager},
    status::status,
};

#[derive(Debug, Clone)]
pub(crate) struct AuthorizeData {
    auth_url: String,
    csrf_token: String,
    nonce: String,
    pkce_verifier: String,
}

impl AuthorizeData {
    pub(crate) fn new(
        auth_url: Url,
        csrf_token: CsrfToken,
        nonce: Nonce,
        pkce_verifier: PkceCodeVerifier,
    ) -> Self {
        Self {
            auth_url: auth_url.to_string(),
            csrf_token: csrf_token.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: pkce_verifier.secret().to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionTokens {
    access_token: String,
    refresh_token: Option<String>,
    id_token: String,
    expires_at: SystemTime,
    refresh_expires_at: SystemTime,
}

impl SessionTokens {
    pub(crate) fn new(
        access_token: &AccessToken,
        refresh_token: Option<&RefreshToken>,
        id_token: &CoreIdToken,
        expires_at: SystemTime,
        refresh_expires_at: SystemTime,
    ) -> Self {
        Self {
            access_token: access_token.secret().to_string(),
            refresh_token: refresh_token.map(|r| r.secret().to_string()),
            id_token: id_token.to_string(),
            expires_at,
            refresh_expires_at,
            // expires_at: now + Duration::from_secs(expires_in as u64),
            // refresh_expires_at: now + Duration::from_secs(refresh_expires_in as u64),
        }
    }

    pub(crate) fn access_token(&self) -> &str {
        &self.access_token
    }

    pub(crate) fn refresh_token(&self) -> Option<String> {
        self.refresh_token.as_ref().cloned()
    }

    pub(crate) fn ttl_gt(&self, threshold: u64) -> bool {
        let now = SystemTime::now();
        self.expires_at
            .duration_since(now)
            .map(|st| st.as_secs())
            .unwrap_or_default()
            > threshold
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginCallbackSessionParameters {
    app_uri: String,
    nonce: String,
    csrf_token: String,
    pkce_verifier: String,
    redirect_uri: String,
    scopes: String,
}

#[derive(Clone)]
pub(crate) struct AppConfigurationState {
    pub(crate) login_app_settings: LoginAppSettings,
    pub(crate) logout_app_settings: LogoutAppSettings,
}

impl FromRef<AppConfigurationState> for LoginAppSettings {
    fn from_ref(app_state: &AppConfigurationState) -> Self {
        app_state.login_app_settings.clone()
    }
}

impl FromRef<AppConfigurationState> for LogoutAppSettings {
    fn from_ref(app_state: &AppConfigurationState) -> LogoutAppSettings {
        app_state.logout_app_settings.clone()
    }
}

pub(crate) fn auth_routes(
    oidc_client: OIDCClient,
    session_layer: &RidserSessionLayer,
    client: RedisPool,
    remaining_secs_threshold: u64,
    app_config: AppConfigurationState,
) -> Router {
    let rlm = RefreshLockManager::new(remaining_secs_threshold);
    Router::new()
        .route(
            "/login",
            get(login).layer(
                ServiceBuilder::new()
                    .layer(Extension(oidc_client.clone()))
                    .layer(Extension(client.clone())),
            ),
        )
        .route(
            "/callback",
            get(callback).layer(
                ServiceBuilder::new()
                    .layer(Extension(oidc_client.clone()))
                    .layer(Extension(client.clone())),
            ),
        )
        .route(
            "/refresh",
            post(refresh).layer(
                ServiceBuilder::new()
                    .layer(Extension(rlm))
                    .layer(Extension(oidc_client)),
            ),
        )
        .route("/csrftoken", post(csrftoken))
        .route("/status", get(status))
        .route("/logout", get(logout))
        .route("/logoutcallback", get(logout_callback))
        .layer(session_layer.clone())
        .with_state(app_config)
}

pub(crate) fn random_alphanumeric_string(length: usize) -> String {
    rand::Rng::sample_iter(rand::thread_rng(), &rand::distributions::Alphanumeric)
        .take(length)
        .map(char::from)
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::SystemTime};

    use axum::{body::Body, extract::FromRequestParts, http::HeaderValue, Router};
    use chrono::Utc;
    use http_body_util::BodyExt;
    use hyper::{
        header::{COOKIE, LOCATION, SET_COOKIE},
        Request,
    };
    use once_cell::sync::Lazy;
    use openidconnect::{
        core::{
            CoreClaimName, CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJsonWebKeySet,
            CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType,
            CoreRsaPrivateSigningKey, CoreSubjectIdentifierType, CoreTokenResponse, CoreTokenType,
        },
        AccessToken, Audience, AuthUrl, EmptyAdditionalClaims, EmptyAdditionalProviderMetadata,
        EmptyExtraTokenFields, EndUserEmail, IdToken, IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl,
        Nonce, PrivateSigningKey, RefreshToken, ResponseTypes, Scope, StandardClaims,
        SubjectIdentifier, TokenUrl, UserInfoUrl,
    };
    use tower::{Service, ServiceExt};
    use tower_sessions::{session::Id, Session};
    use tower_sessions_redis_store::{fred::clients::RedisPool, RedisStore};
    use tracing_subscriber::filter::EnvFilter;
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::session::{redis_cons, RidserSessionLayer, SessionSetup};

    use super::{
        auth_routes,
        callback::callback_post_token_exchange,
        logout::{LogoutAppSettings, LogoutBehavior},
        random_alphanumeric_string, AppConfigurationState, LoginAppSettings, OIDCClient,
        SessionTokens,
    };

    static GLOBAL_LOGGER_SETUP: Lazy<Arc<bool>> = Lazy::new(|| {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::builder()
                    .with_default_directive("ridser=debug".parse().expect("Directive should parse"))
                    .from_env_lossy(),
            )
            .init();
        Arc::new(true)
    });

    fn oidc_body(issuer: &str) -> String {
        let provider_metadata = CoreProviderMetadata::new(
            // Parameters required by the OpenID Connect Discovery spec.
            IssuerUrl::new(issuer.to_string()).expect("Invalid issuer URL"),
            AuthUrl::new(format!("{issuer}/authorize")).expect("Auth URL is invalid"),
            // Use the JsonWebKeySet struct to serve the JWK Set at this URL.
            JsonWebKeySetUrl::new(format!("{issuer}/.well-known/jwks.json"))
                .expect("JWK Set URL is invalid"),
            // Supported response types (flows).
            vec![
                // Recommended: support the code flow.
                ResponseTypes::new(vec![CoreResponseType::Code]),
                // Optional: support the implicit flow.
                //ResponseTypes::new(vec![CoreResponseType::Token, CoreResponseType::IdToken]), // Other flows including hybrid flows may also be specified here.
            ],
            // For user privacy, the Pairwise subject identifier type is preferred. This prevents
            // distinct relying parties (clients) from knowing whether their users represent the same
            // real identities. This identifier type is only useful for relying parties that don't
            // receive the 'email', 'profile' or other personally-identifying scopes.
            // The Public subject identifier type is also supported.
            vec![CoreSubjectIdentifierType::Pairwise],
            // Support the RS256 signature algorithm.
            vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
            // OpenID Connect Providers may supply custom metadata by providing a struct that
            // implements the AdditionalProviderMetadata trait. This requires manually using the
            // generic ProviderMetadata struct rather than the CoreProviderMetadata type alias,
            // however.
            EmptyAdditionalProviderMetadata {},
        )
        // Specify the token endpoint (required for the code flow).
        .set_token_endpoint(Some(
            TokenUrl::new(format!("{issuer}/token")).expect("Invalid token URL"),
        ))
        // Recommended: support the UserInfo endpoint.
        .set_userinfo_endpoint(Some(
            UserInfoUrl::new(format!("{issuer}/userinfo")).expect("userinfo endpoint is invalid"),
        ))
        // Recommended: specify the supported scopes.
        .set_scopes_supported(Some(vec![
            Scope::new("openid".to_string()),
            Scope::new("email".to_string()),
            Scope::new("profile".to_string()),
        ]))
        // Recommended: specify the supported ID token claims.
        .set_claims_supported(Some(vec![
            // Providers may also define an enum instead of using CoreClaimName.
            CoreClaimName::new("sub".to_string()),
            CoreClaimName::new("aud".to_string()),
            CoreClaimName::new("email".to_string()),
            CoreClaimName::new("email_verified".to_string()),
            CoreClaimName::new("exp".to_string()),
            CoreClaimName::new("iat".to_string()),
            CoreClaimName::new("iss".to_string()),
            CoreClaimName::new("name".to_string()),
            CoreClaimName::new("given_name".to_string()),
            CoreClaimName::new("family_name".to_string()),
            CoreClaimName::new("picture".to_string()),
            CoreClaimName::new("locale".to_string()),
        ]));

        serde_json::to_string(&provider_metadata).expect("Serialize ProviderMetadata")
    }

    fn oidc_keys() -> String {
        let rsa_pem = include_bytes!("../../test.pem");
        let rsa_pem: String = String::from_utf8(rsa_pem.to_vec()).expect("Read test.pem");
        let jwks = CoreJsonWebKeySet::new(vec![
            // RSA keys may also be constructed directly using CoreJsonWebKey::new_rsa(). Providers
            // aiming to support other key types may provide their own implementation of the
            // JsonWebKey trait or submit a PR to add the desired support to this crate.
            CoreRsaPrivateSigningKey::from_pem(
                &rsa_pem,
                Some(JsonWebKeyId::new("key1".to_string())),
            )
            .expect("Invalid RSA private key")
            .as_verification_key(),
        ]);

        serde_json::to_string(&jwks).expect("Serialize JSON Web Key Set")
    }

    fn id_token(
        issuer: &str,
        client_id: &str,
        nonce: &str,
        access_token: &AccessToken,
    ) -> IdToken<
        EmptyAdditionalClaims,
        openidconnect::core::CoreGenderClaim,
        openidconnect::core::CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
        openidconnect::core::CoreJsonWebKeyType,
    > {
        let rsa_pem = include_bytes!("../../test.pem");
        let rsa_pem: String = String::from_utf8(rsa_pem.to_vec()).expect("Read test.pem");
        CoreIdToken::new(
            CoreIdTokenClaims::new(
                // Specify the issuer URL for the OpenID Connect Provider.
                IssuerUrl::new(issuer.to_string()).expect("Invalid issuer URL"),
                // The audience is usually a single entry with the client ID of the client for whom
                // the ID token is intended. This is a required claim.
                vec![Audience::new(client_id.to_string())],
                // The ID token expiration is usually much shorter than that of the access or refresh
                // tokens issued to clients.
                Utc::now() + chrono::Duration::seconds(300),
                // The issue time is usually the current time.
                Utc::now(),
                // Set the standard claims defined by the OpenID Connect Core spec.
                StandardClaims::new(
                    // Stable subject identifiers are recommended in place of e-mail addresses or other
                    // potentially unstable identifiers. This is the only required claim.
                    SubjectIdentifier::new("5f83e0ca-2b8e-4e8c-ba0a-f80fe9bc3632".to_string()),
                )
                // Optional: specify the user's e-mail address. This should only be provided if the
                // client has been granted the 'profile' or 'email' scopes.
                .set_email(Some(EndUserEmail::new("bob@example.com".to_string())))
                // Optional: specify whether the provider has verified the user's e-mail address.
                .set_email_verified(Some(true)),
                // OpenID Connect Providers may supply custom claims by providing a struct that
                // implements the AdditionalClaims trait. This requires manually using the
                // generic IdTokenClaims struct rather than the CoreIdTokenClaims type alias,
                // however.
                EmptyAdditionalClaims {},
            )
            .set_nonce(Some(Nonce::new(nonce.to_string()))),
            // The private key used for signing the ID token. For confidential clients (those able
            // to maintain a client secret), a CoreHmacKey can also be used, in conjunction
            // with one of the CoreJwsSigningAlgorithm::HmacSha* signing algorithms. When using an
            // HMAC-based signing algorithm, the UTF-8 representation of the client secret should
            // be used as the HMAC key.
            &CoreRsaPrivateSigningKey::from_pem(
                &rsa_pem,
                Some(JsonWebKeyId::new("key1".to_string())),
            )
            .expect("Invalid RSA private key"),
            // Uses the RS256 signature algorithm. This crate supports any RS*, PS*, or HS*
            // signature algorithm.
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            // When returning the ID token alongside an access token (e.g., in the Authorization Code
            // flow), it is recommended to pass the access token here to set the `at_hash` claim
            // automatically.
            Some(access_token),
            // When returning the ID token alongside an authorization code (e.g., in the implicit
            // flow), it is recommended to pass the authorization code here to set the `c_hash` claim
            // automatically.
            None,
        )
        .expect("Invalid ID token")
    }

    fn oidc_token(issuer: &str, client_id: &str, nonce: &str) -> String {
        let opaque_access_token = random_alphanumeric_string(32);
        let access_token = AccessToken::new(opaque_access_token);

        let id_token = id_token(issuer, client_id, nonce, &access_token);

        let token_response = CoreTokenResponse::new(
            access_token,
            CoreTokenType::Bearer,
            CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
        );
        serde_json::to_string(&token_response).expect("Serialize token response")
    }

    pub struct MockSetup {
        client_id: String,
        cookie_name: String,
        issuer_url: String,
        mock_server: MockServer,
        oidc_client: OIDCClient,
        redis_pool: RedisPool,
        session_secret: String,
        session_layer: RidserSessionLayer,
        session_store: RedisStore<RedisPool>,
    }

    impl MockSetup {
        pub(crate) async fn new() -> Self {
            let _b = GLOBAL_LOGGER_SETUP.clone();
            let mock_server = MockServer::start().await;
            let issuer_url = format!("{}/testing-issuer", mock_server.uri());
            let cookie_name = format!("{}.sid", random_alphanumeric_string(8));
            let client_id = "test-client".to_string();
            let client_secret: String = random_alphanumeric_string(20);
            Mock::given(method("GET"))
                .and(path("/testing-issuer/.well-known/openid-configuration"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_raw(oidc_body(&issuer_url), "application/json"),
                )
                .mount(&mock_server)
                .await;
            Mock::given(method("GET"))
                .and(path("/testing-issuer/.well-known/jwks.json"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(oidc_keys(), "application/json"),
                )
                .mount(&mock_server)
                .await;
            let auth_url = format!("{}/authorize", mock_server.uri());
            let oidc_client =
                OIDCClient::build(&issuer_url, &client_id, &client_secret, Some(auth_url))
                    .await
                    .expect("OIDCClient creation failed");

            let session_secret: String = random_alphanumeric_string(64);
            let (session_store, redis_pool) = redis_cons(
                std::env::var("RIDSER_TEST_REDIS_URL")
                    .unwrap_or_else(|_| "redis:6379".to_string())
                    .as_ref(),
            )
            .await
            .expect("Redis setup failed");
            let session_setup = SessionSetup {
                secret: session_secret.clone(),
                cookie_name: cookie_name.clone(),
                cookie_path: "/".to_string(),
                ttl: Some(time::Duration::new(300, 0)),
            };
            let session_layer = session_setup
                .get_session_layer(session_store.clone())
                .expect("Session setup failed");

            Self {
                cookie_name,
                client_id,
                issuer_url,
                mock_server,
                redis_pool,
                oidc_client,
                session_layer,
                session_secret,
                session_store,
            }
        }

        pub fn router(&self) -> Router {
            let redis_pool = self.redis_pool.clone();
            let app_config = AppConfigurationState {
                login_app_settings: LoginAppSettings::new(vec![
                    "http://example.com".to_string(),
                    "http://example.org/my/app/*".to_string(),
                ]),
                logout_app_settings: LogoutAppSettings {
                    logout_uri: format!("{}/logout", self.mock_server.uri()),
                    _behavior: LogoutBehavior::FrontChannelLogoutWithIdToken,
                    allowed_app_uris_match: vec![
                        "http://logout.example.com".to_string(),
                        "http://example.org/it/index".to_string(),
                    ],
                },
            };
            Router::new().nest(
                "/auth",
                auth_routes(
                    self.oidc_client.clone(),
                    &self.session_layer,
                    redis_pool,
                    20,
                    app_config,
                ),
            )
        }

        pub async fn setup_id_token_nonce(&self, header: &HeaderValue) {
            let nonce: String = header
                .to_str()
                .unwrap()
                .split('&')
                .find(|s| s.starts_with("nonce"))
                .expect("Redirect uri should have nonce")
                .split('=')
                .skip(1)
                .take(1)
                .collect();
            Mock::given(method("POST"))
                .and(path("/testing-issuer/token"))
                .respond_with(ResponseTemplate::new(200).set_body_raw(
                    oidc_token(&self.issuer_url, &self.client_id, &nonce),
                    "application/json",
                ))
                .mount(&self.mock_server)
                .await;
        }

        pub async fn setup_refresh_token_response(&self, nonce: &str) {
            Mock::given(method("POST"))
                .and(path("/testing-issuer/token"))
                .respond_with(ResponseTemplate::new(200).set_body_raw(
                    oidc_token(&self.issuer_url, &self.client_id, nonce),
                    "application/json",
                ))
                .mount(&self.mock_server)
                .await;
        }

        pub async fn setup_authenticated_state(&self, app: &mut Router) -> String {
            // Call login to create a session
            let login_request = Request::builder()
                .uri("/auth/login?app_uri=http%3A%2F%2Fexample.com&redirect_uri=http%3A%2F%2Fexample.org%2F&scope=openid")
                .body(Body::empty())
                .unwrap();
            let login_response = ServiceExt::<Request<Body>>::ready(app)
                .await
                .unwrap()
                .call(login_request)
                .await
                .unwrap();
            // Assert redirect
            assert_eq!(
                303,
                login_response.status().as_u16(),
                "No redirect: {}",
                String::from_utf8(
                    login_response
                        .into_body()
                        .collect()
                        .await
                        .unwrap()
                        .to_bytes()
                        .to_vec()
                )
                .unwrap_or_else(|e| format!("utf8 error: {e}"))
            );
            let location = login_response
                .headers()
                .get(LOCATION)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            // Extract state from redirect uri
            let state: String = location
                .split('&')
                .find(|s| s.starts_with("state"))
                .expect("Redirect uri should have nonce")
                .split('=')
                .skip(1)
                .take(1)
                .collect();
            // Extract nonce from redirect uri
            let nonce: String = location
                .split('&')
                .find(|s| s.starts_with("nonce"))
                .expect("Redirect uri should have nonce")
                .split('=')
                .skip(1)
                .take(1)
                .collect();

            // Extract session cookie
            let session_cookie = login_response
                .headers()
                .get(SET_COOKIE)
                .expect("Login response should have a session cookie")
                .to_str()
                .expect("Session cookie should be a string")
                .split(';')
                .find(|s| s.starts_with(&self.cookie_name))
                .expect("Login response should have a session cookie");

            // prepare mock server for token exchange
            let code = random_alphanumeric_string(32);
            Mock::given(method("POST"))
                .and(path("/testing-issuer/token"))
                .and(query_param("code", &code))
                .respond_with(ResponseTemplate::new(200).set_body_raw(
                    oidc_token(&self.issuer_url, &self.client_id, &nonce),
                    "application/json",
                ))
                .mount(&self.mock_server)
                .await;

            // Run callback request
            let callback_request = Request::builder()
                .uri(format!("/auth/callback?code={code}&state={state}",))
                .header(COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap();
            let callback_response = ServiceExt::<Request<Body>>::ready(app)
                .await
                .unwrap()
                .call(callback_request)
                .await
                .unwrap();
            // Extract session cookie for authenticated state
            let authenticated_cookie = login_response
                .headers()
                .get(SET_COOKIE)
                .expect("Callback response should have a session cookie")
                .to_str()
                .expect("Session cookie should be a string")
                .split(';')
                .find(|s| s.starts_with(&self.cookie_name))
                .expect("Callback response should have a session cookie");

            assert_eq!(
                callback_response.status(),
                200,
                "Response not ok: {}",
                String::from_utf8(
                    callback_response
                        .into_body()
                        .collect()
                        .await
                        .unwrap()
                        .to_bytes()
                        .to_vec()
                )
                .unwrap_or_else(|e| format!("utf8 error: {e}"))
            );

            authenticated_cookie.to_string()
        }

        pub async fn setup_authenticated_state_to_be_replaced(&self) -> String {
            let id = Id::default();
            // Generate a session cookie
            let session = Session::new(Some(id), Arc::new(self.session_store.clone()), None);
            // Generate JWT
            let access_token = AccessToken::new("some-opaque-access-token".to_string());
            let refresh_token = RefreshToken::new("some-opaque-refresh-token".to_string());
            let refresh_token = Some(&refresh_token);
            let id_token = id_token(self.issuer_url.as_str(), "unittest", "nonce", &access_token);
            let jwt = SessionTokens::new(
                &access_token,
                refresh_token,
                &id_token,
                SystemTime::now() + std::time::Duration::from_secs(15),
                SystemTime::now() + std::time::Duration::from_secs(500),
            );
            // Execute same code as the `callback` handler

            let request = Request::builder().method("GET").uri("/").body(()).unwrap();
            let mut request_parts = request.into_parts().0;
            request_parts.extensions.insert(session);
            let state = ();
            let mut ws = Session::from_request_parts(&mut request_parts, &state)
                .await
                .unwrap();
            callback_post_token_exchange(
                &mut ws,
                self.redis_pool.clone(),
                jwt,
                "testbot".to_string(),
            )
            .await;
            String::new()
        }
    }
}
