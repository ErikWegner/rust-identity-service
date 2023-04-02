use std::borrow::Cow;

use anyhow::Result;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Extension,
};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    url::Url,
    ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope,
};
use tracing::{debug, error};

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
pub(crate) struct OIDCClient {
    client: CoreClient,
}

impl OIDCClient {
    pub(crate) async fn build(
        issuer_url: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Self> {
        debug!("🔎 Loading discovery document from {}", issuer_url);
        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(issuer_url.to_string())?,
            async_http_client,
        )
        .await?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new("http://redirect".to_string())?);
        Ok(OIDCClient { client })
    }

    pub(crate) async fn authorize_data(&self, redirect_url: &str) -> Result<AuthorizeData> {
        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate the full authorization URL.
        let (auth_url, csrf_token, nonce) = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            // Set the desired scopes.
            .add_scope(Scope::new("openid".to_string()))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .set_redirect_uri(Cow::Owned(RedirectUrl::new(redirect_url.to_string())?))
            .url();

        Ok(AuthorizeData::new(
            auth_url,
            csrf_token,
            nonce,
            pkce_verifier,
        ))
    }
}

pub(crate) async fn login(Extension(oidc_client): Extension<OIDCClient>) -> Response {
    let d = oidc_client.authorize_data("http://redirect").await;
    if d.is_err() {
        error!("Failed to build authoriaztion url {:?}", d.err());
        return (StatusCode::INTERNAL_SERVER_ERROR, "Server failure").into_response();
    }
    let d = d.unwrap();
    let auth_url = d.auth_url.as_str();

    tracing::debug!("login redirecting to {}", auth_url);
    Redirect::to(auth_url).into_response()
}
