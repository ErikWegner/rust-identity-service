mod login;
mod oidcclient;

pub use oidcclient::OIDCClient;

use anyhow::Result;
use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Extension, Router,
};
use axum_macros::debug_handler;
use axum_sessions::extractors::WritableSession;
use openidconnect::{
    core::CoreIdToken, url::Url, AccessToken, CsrfToken, Nonce, PkceCodeVerifier, RefreshToken,
};
use redis::Client;
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tracing::info;

use crate::session::{purge_store_and_regenerate_session, RidserSessionLayer};

use self::login::login;

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

#[derive(Debug, Clone)]
pub(crate) struct TokenExchangeData {
    code: String,
    nonce: String,
    pkce_verifier: String,
    redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionTokens {
    access_token: String,
    refresh_token: Option<String>,
    id_token: String,
}

impl SessionTokens {
    pub(crate) fn new(
        access_token: &AccessToken,
        refresh_token: Option<&RefreshToken>,
        id_token: &CoreIdToken,
    ) -> Self {
        Self {
            access_token: access_token.secret().to_string(),
            refresh_token: refresh_token.map(|r| r.secret().to_string()),
            id_token: id_token.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct CallbackQueryParams {
    code: String,
    state: String,
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

#[debug_handler]
pub(crate) async fn callback(
    Extension(oidc_client): Extension<OIDCClient>,
    Extension(client): Extension<Client>,
    mut session: WritableSession,
    callback_query_params: Query<CallbackQueryParams>,
) -> Result<Response, Response> {
    let login_callback_session_params = session
        .get::<LoginCallbackSessionParameters>("ridser_logincallback_parameters")
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid session").into_response())?;
    session.remove("ridser_logincallback_parameters");

    if callback_query_params.state != login_callback_session_params.csrf_token {
        return Err((StatusCode::BAD_REQUEST, "Invalid request").into_response());
    }

    let jwt = oidc_client
        .exchange_code(TokenExchangeData {
            code: callback_query_params.code.clone(),
            nonce: login_callback_session_params.nonce,
            pkce_verifier: login_callback_session_params.pkce_verifier,
            redirect_uri: login_callback_session_params.redirect_uri.clone(),
        })
        .await
        .map_err(|e| {
            info!("Failed to exchange code: {:?}", e);
            (StatusCode::UNAUTHORIZED, "Login failure").into_response()
        })?;

    purge_store_and_regenerate_session(&mut session, client).await;

    let _ = session.insert("ridser_jwt", jwt);

    Ok(Redirect::to(&login_callback_session_params.app_uri).into_response())
}

pub(crate) fn auth_routes(
    oidc_client: OIDCClient,
    session_layer: &RidserSessionLayer,
    client: Client,
) -> Router {
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
                    .layer(Extension(oidc_client))
                    .layer(Extension(client)),
            ),
        )
        .layer(session_layer.clone())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::Router;
    use openidconnect::{
        core::{
            CoreClaimName, CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreProviderMetadata,
            CoreResponseType, CoreRsaPrivateSigningKey, CoreSubjectIdentifierType,
        },
        AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl,
        PrivateSigningKey, ResponseTypes, Scope, TokenUrl, UserInfoUrl,
    };
    use rand::{distributions::Alphanumeric, Rng};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::session::{redis_cons, SessionSetup};

    use super::{auth_routes, OIDCClient};

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
            vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
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

    pub struct MockSetup {
        issuer: String,
        server: MockServer,
        oidc_client: OIDCClient,
        session_layer: axum_sessions::SessionLayer<async_redis_session::RedisSessionStore>,
        redis_client: redis::Client,
    }

    impl MockSetup {
        pub(crate) async fn new() -> Self {
            let mock_server = MockServer::start().await;
            let issuer_url = format!("{}/testing-issuer", mock_server.uri());
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
            let client_id = "test-client".to_string();
            let client_secret: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(20)
                .map(char::from)
                .collect();
            let auth_url = format!("{}/authorize", mock_server.uri());
            let oidc_client =
                OIDCClient::build(&issuer_url, &client_id, &client_secret, Some(auth_url))
                    .await
                    .expect("OIDCClient creation failed");

            let session_secret: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(64)
                .map(char::from)
                .collect();
            let (session_store, redis_client) =
                redis_cons("redis://redis/").expect("Redis setup failed");
            let session_setup = SessionSetup {
                secret: session_secret,
                cookie_name: "testing.sid".to_string(),
                cookie_path: "/".to_string(),
                ttl: Some(Duration::from_secs(300)),
            };
            let session_layer = session_setup
                .get_session_layer(session_store)
                .expect("Session setup failed");

            Self {
                redis_client,
                issuer: issuer_url,
                oidc_client,
                server: mock_server,
                session_layer,
            }
        }

        pub fn router(&self) -> Router {
            Router::new().nest(
                "/auth",
                auth_routes(
                    self.oidc_client.clone(),
                    &self.session_layer,
                    self.redis_client.clone(),
                ),
            )
        }
    }
}
