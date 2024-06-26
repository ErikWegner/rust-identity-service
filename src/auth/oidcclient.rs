use std::{
    borrow::Cow,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use oauth2::{basic::BasicTokenType, HttpRequest, HttpResponse};
use openidconnect::{
    core::{
        CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreJsonWebKeyType,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
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
        CoreJsonWebKeyType,
    >,
    BasicTokenType,
>;

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
    let payload = jwt.split('.').nth(1).unwrap_or_default();
    let payload = BASE64_STANDARD.decode(payload)?;
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

async fn async_insecure_http_client(
    request: HttpRequest,
) -> Result<HttpResponse, oauth2::reqwest::Error<reqwest::Error>> {
    let client = {
        let builder = reqwest::Client::builder().danger_accept_invalid_certs(true);

        // Following redirects opens the client up to SSRF vulnerabilities.
        // but this is not possible to prevent on wasm targets
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.redirect(reqwest::redirect::Policy::none());

        builder.build().map_err(oauth2::reqwest::Error::Reqwest)?
    };

    let mut request_builder = client
        .request(request.method, request.url.as_str())
        .body(request.body);
    for (name, value) in &request.headers {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }
    let request = request_builder
        .build()
        .map_err(oauth2::reqwest::Error::Reqwest)?;

    let response = client
        .execute(request)
        .await
        .map_err(oauth2::reqwest::Error::Reqwest)?;

    let status_code = response.status();
    let headers = response.headers().to_owned();
    let chunks = response
        .bytes()
        .await
        .map_err(oauth2::reqwest::Error::Reqwest)?;
    Ok(HttpResponse {
        status_code,
        headers,
        body: chunks.to_vec(),
    })
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
            async_insecure_http_client,
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

    pub(crate) async fn exchange_code(
        &self,
        data: TokenExchangeData,
    ) -> Result<(SessionTokens, String)> {
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(data.code))
            .set_redirect_uri(Cow::Owned(RedirectUrl::new(data.redirect_uri.to_string())?))
            // Set the PKCE code verifier.
            .set_pkce_verifier(PkceCodeVerifier::new(data.pkce_verifier))
            .request_async(async_insecure_http_client)
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

        token_response_to_session_tokens(&token_response)
            .map(|tr| (tr, claims.subject().to_string()))
    }

    pub(crate) async fn refresh_token(&self, refresh_token: &str) -> Result<SessionTokens> {
        self.client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request_async(async_insecure_http_client)
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
