use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use anyhow::{Context, Result};
use axum::{routing::get, Extension, Router};
use tower_http::services::{ServeDir, ServeFile};

use crate::auth::{login, OIDCClient};

pub(crate) fn socket_addr() -> Result<SocketAddr> {
    let port_str = dotenvy::var("RIDSER_BIND_PORT").unwrap_or_else(|_| String::from("3000"));
    let port_parsed = port_str
        .parse::<u16>()
        .context("RIDSER_BIND_PORT must be a number between 1 and 65535")?;

    let interface_addr = dotenvy::var("RIDSER_BIND_ADDRESS").unwrap_or_else(|_| String::from("::"));
    let ip = IpAddr::from_str(interface_addr.as_str())
        .with_context(|| format!("Invalid address {}", interface_addr))?;
    Ok(SocketAddr::new(ip, port_parsed))
}

fn health_routes() -> Router {
    Router::new()
        .route("/up", get(|| async { "up" }))
        .route("/health", get(|| async { "health" }))
}

fn auth_routes(oidc_client: OIDCClient) -> Router {
    Router::new().route("/login", get(login).layer(Extension(oidc_client)))
}

pub(crate) fn app(oidc_client: OIDCClient) -> Router {
    let serve_dir = ServeDir::new("files").not_found_service(ServeFile::new("files/index.html"));
    Router::new()
        .nest("/app", health_routes())
        .nest("/auth", auth_routes(oidc_client))
        .fallback_service(serve_dir)
}
