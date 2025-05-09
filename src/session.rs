use time::Duration;

use anyhow::{Context, Result};
use cookie::Key;
use tower_sessions::{service::PrivateCookie, Expiry, Session, SessionManagerLayer};
use tower_sessions_redis_store::{fred::prelude::*, RedisStore};
use tracing::debug;

pub(crate) type RidserSessionLayer = SessionManagerLayer<RedisStore<Pool>, PrivateCookie>;

pub(crate) static SESSION_KEY_CSRF_TOKEN: &str = "ridser_csrf_token";
pub(crate) static SESSION_KEY_JWT: &str = "ridser_jwt";
pub(crate) static SESSION_KEY_USERID: &str = "ridser_userid";

#[derive(Debug, Clone)]
pub(crate) struct SessionSetup {
    pub(crate) secret: String,
    pub(crate) cookie_name: String,
    pub(crate) cookie_path: String,
    pub(crate) ttl: Option<Duration>,
    pub(crate) secure_cookie: bool,
}

impl SessionSetup {
    pub(crate) fn get_session_layer(&self, store: RedisStore<Pool>) -> Result<RidserSessionLayer> {
        debug!("📦 Preparing session");
        let session_layer = SessionManagerLayer::new(store)
            .with_private(Key::from(self.secret.as_bytes()))
            .with_name(self.cookie_name.clone())
            .with_secure(self.secure_cookie)
            .with_path(self.cookie_path.clone())
            .with_same_site(tower_sessions::cookie::SameSite::Strict)
            .with_expiry(Expiry::OnInactivity(
                self.ttl.unwrap_or_else(|| Duration::hours(1)),
            ));

        Ok(session_layer)
    }
}

pub(crate) async fn redis_cons(connection_url: &str) -> Result<(RedisStore<Pool>, Pool)> {
    debug!(
        "📦 Establishing redis session connection to {}",
        connection_url
    );

    let pool = Pool::new(
        Config::from_url(connection_url).context("Invalid redis connection url")?,
        Some(PerformanceConfig {
            default_command_timeout: core::time::Duration::from_millis(300),
            ..Default::default()
        }),
        None,
        Some(ReconnectPolicy::new_constant(0, 5_000)),
        6,
    )
    .context("Redis setup")?;
    let _redis_conn = pool.connect();
    pool.wait_for_connect()
        .await
        .context("Initial connection attempt to redis")?;

    let session_store = RedisStore::new(pool.clone());
    Ok((session_store, pool))
}

/// Remove the data associated with the session identifier from the store.
/// Create a new session
pub(crate) async fn purge_store_and_regenerate_session(session: &Session, client: &Client) {
    if let Some(key) = session.id() {
        let key = key.to_string();
        let _: Result<(), _> = client.del::<_, String>(key).await;
    }
    let _: Result<(), _> = session.flush().await;
    let _ = session.save().await;
}
