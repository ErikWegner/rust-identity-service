use std::borrow::Cow;

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Extension,
};
use axum_sessions::extractors::WritableSession;
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreProviderMetadata},
    reqwest::async_http_client,
    url::Url,
    AccessToken, AccessTokenHash, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    RefreshToken, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, trace};

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
        );
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
                    openidconnect::RequestTokenError::Request(_) => todo!(),
                    openidconnect::RequestTokenError::Parse(_, _) => todo!(),
                    openidconnect::RequestTokenError::Other(_) => todo!(),
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

        Ok(SessionTokens::new(
            token_response.access_token(),
            token_response.refresh_token(),
            id_token,
        ))
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginQueryParams {
    #[serde(rename = "app_uri")]
    app_uri: String,
    #[serde(rename = "redirect_uri")]
    redirect_uri: String,
    #[serde(rename = "scope")]
    scope: String,
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

pub(crate) async fn login(
    Extension(oidc_client): Extension<OIDCClient>,
    mut session: WritableSession,
    login_query_params: Query<LoginQueryParams>,
) -> Result<Response, Response> {
    session.regenerate();
    let d = oidc_client
        .authorize_data(&login_query_params.redirect_uri, &login_query_params.scope)
        .await
        .map_err(|e| {
            error!("Failed to build authoriaztion url {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Server failure").into_response()
        })?;
    let auth_url = d.auth_url.as_str();

    let _ = session.insert(
        "ridser_logincallback_parameters",
        LoginCallbackSessionParameters {
            app_uri: login_query_params.app_uri.clone(),
            nonce: d.nonce,
            csrf_token: d.csrf_token,
            pkce_verifier: d.pkce_verifier,
            redirect_uri: login_query_params.redirect_uri.clone(),
            scopes: login_query_params.scope.clone(),
        },
    );

    debug!("login redirecting to {}", auth_url);
    Ok(Redirect::to(auth_url).into_response())
}

pub(crate) async fn callback(
    Extension(oidc_client): Extension<OIDCClient>,
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

    session.regenerate();

    let _ = session.insert("ridser_jwt", jwt);

    Ok(Redirect::to(&login_callback_session_params.app_uri).into_response())
}
