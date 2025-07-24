use std::{
    borrow::Cow,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use oauth2::{basic::BasicTokenType, EndpointMaybeSet, EndpointNotSet, EndpointSet};
use openidconnect::{
    core::{
        CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm, CoreProviderMetadata,
    },
    AccessTokenHash, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EmptyAdditionalClaims, EmptyExtraTokenFields, IdTokenFields, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope,
    StandardTokenResponse, TokenResponse,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use super::{callback::TokenExchangeData, AuthorizeData, SessionTokens};

type KeycloakTokenResponse = StandardTokenResponse<
    IdTokenFields<
        EmptyAdditionalClaims,
        EmptyExtraTokenFields,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >,
    BasicTokenType,
>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExpFieldInJWT {
    pub(crate) exp: u64,
}

pub struct AuthorizeRequestData {
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub ui_locales: Option<String>,
    pub prompt: Option<String>,
    pub kc_idp_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OIDCClient {
    http_client: reqwest::Client,
    client: CoreClient<
        EndpointSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointMaybeSet,
        EndpointMaybeSet,
    >,
}

fn jwt_exp(jwt: &str) -> Result<u64> {
    let payload = jwt.split('.').nth(1).unwrap_or_default();
    let payload = STANDARD_NO_PAD.decode(payload)?;
    let payload = String::from_utf8(payload)?;
    let jwtdecoded: ExpFieldInJWT = serde_json::from_str(payload.as_str())?;
    Ok(jwtdecoded.exp)
}

fn token_response_to_session_tokens(
    token_response: &KeycloakTokenResponse,
) -> Result<SessionTokens> {
    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow!("Server did not return an ID token"))?;

    let expires_at = if let Ok(exp) = jwt_exp(token_response.access_token().secret()) {
        UNIX_EPOCH + Duration::from_secs(exp)
    } else {
        token_response
            .expires_in()
            .map(|exp| SystemTime::now() + exp)
            .unwrap_or_else(SystemTime::now)
    };

    let refresh_expires_at = token_response
        .refresh_token()
        .and_then(|rt| jwt_exp(rt.secret()).ok())
        .map(|exp| UNIX_EPOCH + Duration::from_secs(exp))
        .unwrap_or_else(SystemTime::now);

    Ok(SessionTokens::new(
        token_response.access_token(),
        token_response.refresh_token(),
        id_token,
        expires_at,
        refresh_expires_at,
    ))
}

impl OIDCClient {
    pub(crate) async fn build(
        issuer_url: &str,
        client_id: &str,
        client_secret: &str,
        authorization_endpoint: Option<String>,
    ) -> Result<Self> {
        let http_client = {
            let danger_accept_invalid_certs = std::env::var("RIDSER_DANGER_ACCEPT_INVALID_CERTS")
                .unwrap_or_default()
                .to_lowercase()
                == "true";
            reqwest::ClientBuilder::new()
                .danger_accept_invalid_certs(danger_accept_invalid_certs)
                // Following redirects opens the client up to SSRF vulnerabilities.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("Failed to create http client")?
        };

        debug!("🔎 Loading discovery document from {}", issuer_url);
        let mut provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(issuer_url.to_string())?,
            &http_client,
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
                        "Authorization endpoint is not valid: {authorization_endpoint_url}"
                    )
                })?,
            );
        }

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
        );
        Ok(OIDCClient {
            client,
            http_client,
        })
    }

    pub(crate) async fn authorize_data(
        &self,
        authorize_request: AuthorizeRequestData,
    ) -> Result<AuthorizeData> {
        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate the full authorization URL.
        let mut b = self
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
            )?));
        if let Some(prompt) = authorize_request.prompt {
            if prompt == "none" {
                b = b.add_prompt(openidconnect::core::CoreAuthPrompt::None);
            }
        }
        if let Some(ui_locale) = authorize_request.ui_locales {
            b = b.add_ui_locale(openidconnect::LanguageTag::new(ui_locale));
        }
        if let Some(kc_idp_hint) = authorize_request.kc_idp_hint {
            b = b.add_extra_param("kc_idp_hint", kc_idp_hint);
        }

        let (auth_url, csrf_token, nonce) = b.url();

        Ok(AuthorizeData::new(
            auth_url,
            csrf_token,
            nonce,
            pkce_verifier,
        ))
    }

    pub(crate) async fn exchange_code(
        &self,
        data: TokenExchangeData,
    ) -> Result<(SessionTokens, String)> {
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(data.code))?
            .set_redirect_uri(Cow::Owned(RedirectUrl::new(data.redirect_uri.to_string())?))
            // Set the PKCE code verifier.
            .set_pkce_verifier(PkceCodeVerifier::new(data.pkce_verifier))
            .request_async(&self.http_client)
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
        let id_token_verifier = self.client.id_token_verifier();
        let claims = id_token.claims(&id_token_verifier, &Nonce::new(data.nonce))?;
        // Verify the access token hash to ensure that the access token hasn't been substituted for
        // another user's.
        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                id_token.signing_alg()?,
                id_token.signing_key(&id_token_verifier)?,
            )?;
            if actual_access_token_hash != *expected_access_token_hash {
                return Err(anyhow!("Invalid access token"));
            }
        }

        debug!("Login successful {:?}", claims);

        token_response_to_session_tokens(&token_response)
            .map(|tr| (tr, claims.subject().to_string()))
    }

    pub(crate) async fn refresh_token(&self, refresh_token: &str) -> Result<SessionTokens> {
        self.client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))?
            .request_async(&self.http_client)
            .await
            .map_err(|tokenerror| {
                match tokenerror {
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
                };

                anyhow!("Token exchange failed")
            })
            .and_then(|tr| token_response_to_session_tokens(&tr))
    }
}
