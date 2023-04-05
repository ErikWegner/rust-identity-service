use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use anyhow::{anyhow, Context, Result};
use axum::{
    body::Body,
    http::{
        header::{AUTHORIZATION, COOKIE, HOST},
        HeaderValue, Method, Request, StatusCode, Uri,
    },
    response::{IntoResponse, Response},
    routing::{delete, get},
    Extension, Router,
};
use axum_extra::extract::CookieJar;
use axum_macros::debug_handler;
use axum_sessions::extractors::WritableSession;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use redis::Client;
use tower::ServiceBuilder;
use tower_http::services::{ServeDir, ServeFile};
use tracing::{debug, error, warn};

use crate::{
    auth::{auth_routes, OIDCClient, SessionTokens},
    session::{RidserSessionLayer, SESSION_KEY_CSRF_TOKEN, SESSION_KEY_JWT},
};

pub(crate) static HEADER_KEY_CSRF_TOKEN: &str = "x-csrf-token";

#[derive(Debug, Clone)]
pub(crate) struct ProxyConfig {
    base_url: String,
    cookie_name: String,
}

impl ProxyConfig {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    pub(crate) fn try_init(base_url: String, cookie_name: &str) -> Result<Self> {
        let uri = Uri::from_str(base_url.as_str())?;
        let host = uri.host();
        if host.is_none() {
            return Err(anyhow!("Missing host"));
        }
        Ok(Self {
            base_url,
            cookie_name: cookie_name.to_string(),
        })
    }
}

trait ToCookieHeader {
    fn to_cookie_header(&self) -> String;
}

impl ToCookieHeader for CookieJar {
    fn to_cookie_header(&self) -> String {
        todo!()
    }
}

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

fn api_proxy(session_layer: &RidserSessionLayer, proxy_config: &ProxyConfig) -> Router {
    let proxy_client_https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let proxy_client = hyper::Client::builder().build::<_, hyper::Body>(proxy_client_https);
    Router::new()
        .route(
            "/*path",
            delete(proxy)
                .get(proxy)
                .options(proxy)
                .patch(proxy)
                .post(proxy)
                .put(proxy),
        )
        .layer(
            ServiceBuilder::new()
                .layer(session_layer.clone())
                .layer(Extension(proxy_config.clone()))
                .layer(Extension(proxy_client)),
        )
}

#[debug_handler]
async fn proxy(
    Extension(proxy_config): Extension<ProxyConfig>,
    Extension(client): Extension<hyper::client::Client<HttpsConnector<HttpConnector>>>,
    session: WritableSession,
    jar: CookieJar,
    mut req: Request<Body>,
) -> Result<Response<hyper::Body>, Response> {
    if req.method() != Method::GET {
        // Check CSRF token
        let request_csrf_token = req.headers().get(HEADER_KEY_CSRF_TOKEN);
        let session_csrf_token: Option<String> = session.get(SESSION_KEY_CSRF_TOKEN);
        if request_csrf_token.is_none()
            || session_csrf_token.is_none()
            || request_csrf_token.unwrap().as_bytes() != session_csrf_token.unwrap().as_bytes()
        {
            return Err((StatusCode::FORBIDDEN, "Missing or invalid CSRF token").into_response());
        }
    }

    let path_query = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or_else(|| req.uri().path());
    let uri = format!("{}{}", proxy_config.base_url(), path_query);
    debug!("Proxy {} request to new uri `{}`", req.method(), uri);
    let proxy_uri = Uri::try_from(uri.as_str()).map_err(|e| {
        debug!("Invalid proxy uri {:?}", e);
        (StatusCode::BAD_REQUEST, "Invalid proxy uri").into_response()
    })?;
    let proxy_host = proxy_uri.host().unwrap();
    *req.uri_mut() = proxy_uri.clone();
    req.headers_mut()
        .insert(HOST, HeaderValue::from_str(proxy_host).unwrap());

    let needle = proxy_config.cookie_name.as_str();
    let remaining_cookies = jar
        .iter()
        // Filter out cookies that are not valid for the proxy
        .filter(|h| !h.name().starts_with(needle))
        .cloned()
        .collect::<Vec<_>>();
    req.headers_mut().remove(COOKIE);
    if !remaining_cookies.is_empty() {
        let new_cookie_value = remaining_cookies
            .iter()
            .map(|c| c.encoded().to_string())
            .collect::<Vec<String>>()
            .join("; ");
        req.headers_mut().insert(
            COOKIE,
            HeaderValue::from_str(new_cookie_value.as_str()).map_err(|e| {
                debug!("Invalid cookie {:?}", e);
                (StatusCode::BAD_REQUEST, "Invalid cookie").into_response()
            })?,
        );
    }

    let jwt: Option<SessionTokens> = session.get(SESSION_KEY_JWT);
    if let Some(session_tokens) = jwt {
        req.headers_mut().append(
            AUTHORIZATION,
            HeaderValue::from_bytes(format!("Bearer {}", session_tokens.access_token()).as_bytes())
                .map_err(|e| {
                    error!("Failed to set authorization header: {:?}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Cannot proxy authentication".to_string(),
                    )
                        .into_response()
                })?,
        );
    }

    client.request(req).await.map_err(|e| {
        error!("Failed to proxy request: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Cannot proxy request".to_string(),
        )
            .into_response()
    })
}

pub(crate) fn app(
    oidc_client: OIDCClient,
    session_layer: &RidserSessionLayer,
    proxy_config: &ProxyConfig,
    client: Client,
) -> Result<Router> {
    let spa_apps = walk_dir("files")?;
    let mut app = Router::new()
        .nest("/api", api_proxy(session_layer, proxy_config))
        .nest("/app", health_routes())
        .nest("/auth", auth_routes(oidc_client, session_layer, client));

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
