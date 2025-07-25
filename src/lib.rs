use std::env;

use anyhow::{Context, Result};
use session::{SameSiteSetting, SessionSetup};
use tokio::signal;
use tracing::{debug, warn};

use crate::{
    auth::{
        AppConfigurationState, LoginAppSettings, LogoutAppSettings, LogoutBehavior, OIDCClient,
    },
    http::{app, ProxyConfig},
    session::redis_cons,
};

mod auth;
mod http;
mod monitoring;
mod session;

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install shutdown handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    debug!("⏹️ signal received, starting graceful shutdown");
}

fn oidc_client_from_env() -> Result<String> {
    env::var("RIDSER_OIDC_CLIENT_ID").context("missing RIDSER_OIDC_CLIENT_ID")
}

async fn init_oidc_client(client_id: &str) -> Result<OIDCClient> {
    let issuer_url =
        env::var("RIDSER_OIDC_ISSUER_URL").context("missing RIDSER_OIDC_ISSUER_URL")?;
    let client_secret =
        env::var("RIDSER_OIDC_CLIENT_SECRET").context("missing RIDSER_OIDC_CLIENT_SECRET")?;
    let auth_url = env::var("RIDSER_OIDC_AUTH_URL").ok();
    OIDCClient::build(&issuer_url, client_id, &client_secret, auth_url).await
}

fn init_session_vars() -> Result<SessionSetup> {
    let secure_cookie = env::var("RIDSER_SESSION_SECURE_COOKIE_DISABLED")
        .unwrap_or_else(|_| String::new())
        .to_lowercase()
        != "true";
    if !secure_cookie {
        warn!("Disabling secure cookies is not recommended in production.");
    }

    let same_site =
        SameSiteSetting::from_env_string(env::var("RIDSER_SESSION_COOKIE_SAMESITE").ok());

    Ok(SessionSetup {
        cookie_name: env::var("RIDSER_SESSION_COOKIE_NAME")
            .unwrap_or_else(|_| "ridser.sid".to_string()),
        cookie_path: env::var("RIDSER_SESSION_COOKIE_PATH").unwrap_or_else(|_| "/".to_string()),
        secret: env::var("RIDSER_SESSION_SECRET").context("missing RIDSER_SESSION_SECRET")?,
        ttl: None,
        secure_cookie,
        same_site,
    })
}

pub async fn run_ridser() -> Result<(), Box<dyn std::error::Error>> {
    let connection_url = env::var("RIDSER_REDIS_URL").context("missing RIDSER_REDIS_URL")?;
    let (store, client) = redis_cons(&connection_url).await?;
    let session_setup = init_session_vars()?;
    let session_layer = session_setup.get_session_layer(store)?;
    let client_id = oidc_client_from_env()?;
    let oidc_client = init_oidc_client(&client_id).await?;
    let proxy_rules: Vec<_> = dotenvy::vars()
        .filter_map(|(key, value)| {
            if key.starts_with("RIDSER_PROXY_TARGET_RULE_") && value.contains("=>") {
                Some(value)
            } else {
                None
            }
        })
        .collect();
    let proxy_config: ProxyConfig = ProxyConfig::try_init(
        env::var("RIDSER_PROXY_TARGET").context("missing RIDSER_PROXY_TARGET")?,
        &session_setup.cookie_name,
        proxy_rules,
    )?;
    let remaining_secs_threshold = env::var("RIDSER_SESSION_REFRESH_THRESHOLD")
        .context("Missing RIDSER_SESSION_REFRESH_THRESHOLD")?
        .parse::<_>()
        .context("Cannot parse RIDSER_SESSION_REFRESH_THRESHOLD")?;
    let app_config = AppConfigurationState {
        login_app_settings: LoginAppSettings::new(
            env::var("RIDSER_LOGIN_REDIRECT_APP_URIS")
                .context("missing RIDSER_LOGIN_REDIRECT_APP_URIS")?
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
        ),
        logout_app_settings: LogoutAppSettings {
            client_id,
            logout_uri: env::var("RIDSER_LOGOUT_SSO_URI")
                .context("Missing RIDSER_LOGOUT_SSO_URI")?,
            _behavior: LogoutBehavior::FrontChannelLogoutWithIdToken,
            allowed_app_uris_match: env::var("RIDSER_LOGOUT_REDIRECT_APP_URIS")
                .context("Missing RIDSER_LOGOUT_REDIRECT_APP_URIS")?
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
        },
    };

    let app = app(
        oidc_client,
        &session_layer,
        &proxy_config,
        client,
        remaining_secs_threshold,
        app_config,
    );

    let listener = http::port_listener().await?;
    let bind_addr = listener
        .local_addr()
        .context("Retrieve listening address")?;
    tracing::info!("💈 Listening on http://{}", &bind_addr);

    axum::serve(listener, app?.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("error running server")?;
    Ok(())
}
