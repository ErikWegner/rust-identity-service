use std::{
    borrow::Cow,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use axum_sessions::async_session::base64;
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    AccessTokenHash, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl,
    Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use super::{callback::TokenExchangeData, AuthorizeData, SessionTokens};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExpFieldInJWT {
    pub(crate) exp: u64,
}

pub(crate) struct AuthorizeRequestData {
    pub(crate) redirect_uri: String,
    pub(crate) state: String,
    pub(crate) scope: String,
}

#[derive(Debug, Clone)]
pub struct OIDCClient {
    client: CoreClient,
}

fn jwt_exp(jwt: &str) -> Result<u64> {
    let payload = jwt.split(".").skip(1).next().unwrap_or_default();
    let payload = base64::decode(payload)?;
    let payload = String::from_utf8(payload)?;
    let jwtdecoded: ExpFieldInJWT = serde_json::from_str(payload.as_str())?;
    Ok(jwtdecoded.exp)
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
        );
        Ok(OIDCClient { client })
    }

    pub(crate) async fn authorize_data(
        &self,
        authorize_request: AuthorizeRequestData,
    ) -> Result<AuthorizeData> {
        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate the full authorization URL.
        let (auth_url, csrf_token, nonce) = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                || CsrfToken::new(authorize_request.state),
                Nonce::new_random,
            )
            // Set the desired scopes.
            .add_scope(Scope::new(authorize_request.scope))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .set_redirect_uri(Cow::Owned(RedirectUrl::new(
                authorize_request.redirect_uri,
            )?))
            .url();

        Ok(AuthorizeData::new(
            auth_url,
            csrf_token,
            nonce,
            pkce_verifier,
        ))
    }

    pub(crate) async fn exchange_code(&self, data: TokenExchangeData) -> Result<SessionTokens> {
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(data.code))
            .set_redirect_uri(Cow::Owned(RedirectUrl::new(data.redirect_uri.to_string())?))
            // Set the PKCE code verifier.
            .set_pkce_verifier(PkceCodeVerifier::new(data.pkce_verifier))
            .request_async(async_http_client)
            .await
            .map_err(|e| {
                match e {
                    openidconnect::RequestTokenError::ServerResponse(response) => {
                        debug!("Server response: {:?}", response);
                    }
                    openidconnect::RequestTokenError::Request(err) => {
                        debug!("Request error: {:?}", err)
                    }
                    openidconnect::RequestTokenError::Parse(serde_error, _) => {
                        debug!("Parse error: {:?}", serde_error)
                    }
                    openidconnect::RequestTokenError::Other(err) => {
                        debug!("Other error: {:?}", err)
                    }
                }
                anyhow!("Token exchange failed")
            })?;

        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow!("Server did not return an ID token"))?;
        let claims = id_token.claims(&self.client.id_token_verifier(), &Nonce::new(data.nonce))?;
        // Verify the access token hash to ensure that the access token hasn't been substituted for
        // another user's.
        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                &id_token.signing_alg()?,
            )?;
            if actual_access_token_hash != *expected_access_token_hash {
                return Err(anyhow!("Invalid access token"));
            }
        }

        debug!("Login successful {:?}", claims);

        let expires_at = if let Ok(exp) = jwt_exp(token_response.access_token().secret()) {
            UNIX_EPOCH + Duration::from_secs(exp)
        } else {
            token_response
                .expires_in()
                .map(|exp| SystemTime::now() + exp)
                .unwrap_or_else(|| SystemTime::now())
        };

        let refresh_expires_at = token_response
            .refresh_token()
            .and_then(|rt| jwt_exp(rt.secret()).ok())
            .map(|exp| UNIX_EPOCH + Duration::from_secs(exp))
            .unwrap_or_else(|| SystemTime::now());

        Ok(SessionTokens::new(
            token_response.access_token(),
            token_response.refresh_token(),
            id_token,
            expires_at,
            refresh_expires_at,
        ))
    }
}
