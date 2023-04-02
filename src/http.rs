use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use anyhow::{Context, Result};
use axum::{routing::get, Extension, Router};
use tower_http::services::{ServeDir, ServeFile};
use tracing::{debug, warn};

use crate::{
    auth::{login, OIDCClient},
    session::RidserSessionLayer,
};

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

fn auth_routes(oidc_client: OIDCClient, session_layer: &RidserSessionLayer) -> Router {
    Router::new()
        .route("/login", get(login).layer(Extension(oidc_client)))
        .layer(session_layer.clone())
}

fn walk_dir(path: &str) -> Result<Vec<String>> {
    let files = std::fs::read_dir(path).context("Reading `files` directory")?;
    let mut paths = Vec::new();
    for entry in files {
        match entry {
            Ok(entry) => {
                if entry.file_type()?.is_dir() {
                    let mut subresult = walk_dir(&entry.path().to_string_lossy())?;
                    paths.append(&mut subresult);
                }

                if entry.file_name() == "index.html" {
                    paths.push(path.strip_prefix("files").unwrap().to_string());
                }
            }
            Err(e) => warn!("File system error: {:?}", e),
        }
    }

    Ok(paths)
}

pub(crate) fn app(oidc_client: OIDCClient, session_layer: &RidserSessionLayer) -> Result<Router> {
    let spa_apps = walk_dir("files")?;
    let mut app = Router::new()
        .nest("/app", health_routes())
        .nest("/auth", auth_routes(oidc_client, session_layer));

    for spa_app in spa_apps {
        let uri_path = if spa_app.is_empty() {
            "/".to_string()
        } else {
            spa_app.clone()
        };
        let fs_path = format!("files{}", spa_app);
        debug!("Serving route {uri_path} from fs {fs_path}");
        let serve_dir = ServeDir::new(fs_path.clone())
            .not_found_service(ServeFile::new(format!("{fs_path}/index.html")));

        app = app.nest_service(&uri_path, serve_dir);
    }

    Ok(app)
}
