use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{anyhow, Context, Result};
use axum::{
    body::Body,
    http::{
        header::{AUTHORIZATION, COOKIE, HOST},
        HeaderValue, Method, StatusCode, Uri,
    },
    response::{IntoResponse, Response},
    routing::delete,
    Extension, Router,
};
use axum_extra::extract::CookieJar;
use axum_macros::debug_handler;
use hyper_rustls::HttpsConnector;
use tower::ServiceBuilder;
use tower_http::services::{ServeDir, ServeFile};
use tower_sessions::Session;
use tower_sessions_redis_store::fred::clients::RedisPool;
use tracing::{debug, error, warn};

use crate::{
    auth::{auth_routes, AppConfigurationState, OIDCClient, SessionTokens},
    monitoring::health_routes,
    session::{RidserSessionLayer, SESSION_KEY_CSRF_TOKEN, SESSION_KEY_JWT},
};

pub(crate) static HEADER_KEY_CSRF_TOKEN: &str = "x-csrf-token";

pub(crate) type ProxyClient = hyper_util::client::legacy::Client<
    HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Body,
>;

#[derive(Debug, Clone)]
pub(crate) struct ExtraProxyRoute {
    path: String,
    target: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ProxyConfig {
    base_url: String,
    cookie_name: String,
    extra_routes: Vec<ExtraProxyRoute>,
}

impl ProxyConfig {
    fn rewrite_uri(&self, uri: &str) -> String {
        self.extra_routes
            .iter()
            .find_map(|x| {
                if uri.starts_with(x.path.as_str()) {
                    let striplen = x.path.len();
                    let path = &uri.to_string()[striplen..];
                    Some(format!("{}{}", x.target.as_str(), path))
                } else {
                    None
                }
            })
            .unwrap_or(format!("{}{}", &self.base_url, uri))
    }

    pub(crate) fn try_init(
        base_url: String,
        cookie_name: &str,
        extra_routes: Vec<String>,
    ) -> Result<Self> {
        let uri = Uri::from_str(base_url.as_str())?;
        let host = uri.host();
        if host.is_none() {
            return Err(anyhow!("Missing host"));
        }
        let extra_routes = extra_routes
            .into_iter()
            .filter_map(|s| {
                s.split_once("=>").map(|(path, target)| ExtraProxyRoute {
                    path: path.to_string(),
                    target: target.to_string(),
                })
            })
            .collect();
        Ok(Self {
            base_url,
            cookie_name: cookie_name.to_string(),
            extra_routes,
        })
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

fn walk_dir(path: &str) -> Result<Vec<PathBuf>> {
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
                    paths.push(
                        entry
                            .path()
                            .parent()
                            .expect("Parent path is accessible")
                            .to_owned(),
                    );
                }
            }
            Err(e) => warn!("File system error: {:?}", e),
        }
    }

    Ok(paths)
}

fn api_proxy(
    session_layer: &RidserSessionLayer,
    proxy_config: &ProxyConfig,
) -> anyhow::Result<Router> {
    proxy_config.extra_routes.iter().for_each(|er| {
        debug!("Adding extra route: {:?}", er);
    });
    let proxy_client_https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .context("Certificate roots")?
        .https_or_http()
        .enable_http1()
        .build();
    let proxy_client: ProxyClient =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(proxy_client_https);
    Ok(Router::new()
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
        ))
}

#[debug_handler]
async fn proxy(
    Extension(proxy_config): Extension<ProxyConfig>,
    Extension(client): Extension<ProxyClient>,
    session: Session,
    jar: CookieJar,
    mut req: axum::extract::Request,
) -> Result<Response, Response> {
    if req.method() != Method::GET {
        // Check CSRF token
        let request_csrf_token = req.headers().get(HEADER_KEY_CSRF_TOKEN);
        let session_csrf_token: Option<String> =
            session.get(SESSION_KEY_CSRF_TOKEN).await.unwrap_or(None);
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

    let uri = proxy_config.rewrite_uri(path_query);
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

    let jwt: Option<SessionTokens> = session.get(SESSION_KEY_JWT).await.unwrap_or(None);
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
    req.headers_mut().remove(HEADER_KEY_CSRF_TOKEN);

    Ok(client
        .request(req)
        .await
        .map_err(|e| {
            error!("Failed to proxy request: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Cannot proxy request".to_string(),
            )
                .into_response()
        })?
        .into_response())
}

pub(crate) fn app(
    oidc_client: OIDCClient,
    session_layer: &RidserSessionLayer,
    proxy_config: &ProxyConfig,
    client: RedisPool,
    remaining_secs_threshold: u64,
    app_config: AppConfigurationState,
) -> Result<Router> {
    let spa_apps = walk_dir("files")?;
    let mut app = Router::new()
        .nest("/api", api_proxy(session_layer, proxy_config)?)
        .nest("/app", health_routes(client.clone()))
        .nest(
            "/auth",
            auth_routes(
                oidc_client,
                session_layer,
                client.clone(),
                remaining_secs_threshold,
                app_config,
            ),
        );

    for spa_app in spa_apps {
        let components: Vec<_> = spa_app
            .components()
            .skip(1) // first component is `/files` folder
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .collect();
        let uri_path = if components.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", components.join("/"))
        };
        let fs_path = spa_app.as_path();
        debug!("Serving route {uri_path} from folder {:?}", fs_path);
        let mut fallback = spa_app.clone();
        fallback.push("index.html");
        let serve_dir = ServeDir::new(fs_path).not_found_service(ServeFile::new(fallback));

        app = app.nest_service(&uri_path, serve_dir);
    }

    Ok(app)
}
