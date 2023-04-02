use std::borrow::Cow;

use anyhow::{Context, Result};
use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Extension,
};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    url::Url,
    AuthUrl, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope,
};
use serde::Deserialize;
use tracing::{debug, error, trace};

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
        authorization_endpoint: Option<String>,
    ) -> Result<Self> {
        debug!("🔎 Loading discovery document from {}", issuer_url);
        let mut provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(issuer_url.to_string())?,
            async_http_client,
        )
        .await
        .with_context(|| format!("Loading issuer data from {issuer_url}"))?;

        if let Some(authorization_endpoint_url) = authorization_endpoint {
            trace!(
                "Setting authorization endpoint to {}",
                authorization_endpoint_url
            );
            provider_metadata = provider_metadata.set_authorization_endpoint(
                AuthUrl::new(authorization_endpoint_url.clone()).with_context(|| {
                    format!(
                        "Authorization endpoint is not valid: {}",
                        authorization_endpoint_url
                    )
                })?,
            );
        }

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new("http://redirect".to_string())?);
        Ok(OIDCClient { client })
    }

    pub(crate) async fn authorize_data(
        &self,
        redirect_url: &str,
        scope: &str,
    ) -> Result<AuthorizeData> {
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
            .add_scope(Scope::new(scope.to_string()))
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

#[derive(Debug, Deserialize)]
pub(crate) struct LoginQueryParams {
    #[serde(rename = "redirect_uri")]
    redirect_uri: String,
    #[serde(rename = "scope")]
    scope: String,
}

pub(crate) async fn login(
    Extension(oidc_client): Extension<OIDCClient>,
    login_query_params: Query<LoginQueryParams>,
) -> Result<Response, Response> {
    let d = oidc_client
        .authorize_data(&login_query_params.redirect_uri, &login_query_params.scope)
        .await
        .map_err(|e| {
            error!("Failed to build authoriaztion url {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Server failure").into_response();
        })?;
    let auth_url = d.auth_url.as_str();

    tracing::debug!("login redirecting to {}", auth_url);
    Ok(Redirect::to(auth_url).into_response())
}
