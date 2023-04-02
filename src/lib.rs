use std::env;

use anyhow::{Context, Result};
use http::socket_addr;
use session::SessionSetup;
use tokio::signal;
use tracing::debug;

use crate::{auth::OIDCClient, http::app, session::redis_cons};

mod auth;
mod http;
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

async fn init_oidc_client() -> Result<OIDCClient> {
    let issuer_url =
        env::var("RIDSER_OIDC_ISSUER_URL").context("missing RIDSER_OIDC_ISSUER_URL")?;
    let client_id = env::var("RIDSER_OIDC_CLIENT_ID").context("missing RIDSER_OIDC_CLIENT_ID")?;
    let client_secret =
        env::var("RIDSER_OIDC_CLIENT_SECRET").context("missing RIDSER_OIDC_CLIENT_SECRET")?;
    let auth_url = env::var("RIDSER_OIDC_AUTH_URL").ok();
    OIDCClient::build(&issuer_url, &client_id, &client_secret, auth_url).await
}

fn init_session_vars() -> Result<SessionSetup> {
    Ok(SessionSetup {
        cookie_name: env::var("RIDSER_SESSION_COOKIE_NAME")
            .unwrap_or_else(|_| "ridser.sid".to_string()),
        cookie_path: env::var("RIDSER_SESSION_COOKIE_PATH").unwrap_or_else(|_| "/".to_string()),
        secret: env::var("RIDSER_SESSION_SECRET").context("missing RIDSER_SESSION_SECRET")?,
        ttl: None,
    })
}

pub async fn run_ridser() -> Result<(), Box<dyn std::error::Error>> {
    let connection_url = env::var("RIDSER_REDIS_URL").context("missing RIDSER_REDIS_URL")?;
    let (store, _client) = redis_cons(&connection_url)?;
    let session_setup = init_session_vars()?;
    let session_layer = session_setup.get_session_layer(store)?;
    let oidc_client = init_oidc_client().await?;
    let bind_addr = socket_addr()?;
    let app = app(oidc_client, &session_layer);

    tracing::info!("💈 Listening on http://{}", &bind_addr);
    axum::Server::bind(&bind_addr)
        .serve(app?.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}
