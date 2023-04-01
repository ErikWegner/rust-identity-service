use std::env;

use anyhow::{Context, Result};
use http::socket_addr;
use tokio::signal;
use tracing::debug;

use crate::{auth::OIDCClient, http::app};

mod auth;
mod http;

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

    debug!("🔽 signal received, starting graceful shutdown");
}

async fn init_oidc_client() -> Result<OIDCClient> {
    let issuer_url =
        env::var("RIDSER_OIDC_ISSUER_URL").context("missing RIDSER_OIDC_ISSUER_URL")?;
    let client_id = env::var("RIDSER_OIDC_CLIENT_ID").context("missing RIDSER_OIDC_CLIENT_ID")?;
    let client_secret =
        env::var("RIDSER_OIDC_CLIENT_SECRET").context("missing RIDSER_OIDC_CLIENT_SECRET")?;
    OIDCClient::build(&issuer_url, &client_id, &client_secret).await
}

pub async fn run_ridser() -> Result<(), Box<dyn std::error::Error>> {
    let oidc_client = init_oidc_client().await?;
    let bind_addr = socket_addr()?;
    let app = app(oidc_client);

    tracing::info!("💈 Listening on http://{}", &bind_addr);
    axum::Server::bind(&bind_addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}
