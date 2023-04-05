use std::time::Duration;

use anyhow::{Context, Result};
use async_redis_session::RedisSessionStore;
use axum_sessions::{extractors::WritableSession, PersistencePolicy, SameSite, SessionLayer};
use redis::{AsyncCommands, Client};
use tracing::debug;

pub(crate) type RidserSessionLayer = SessionLayer<RedisSessionStore>;

pub(crate) static SESSION_KEY_CSRF_TOKEN: &str = "ridser_csrf_token";
pub(crate) static SESSION_KEY_JWT: &str = "ridser_jwt";

#[derive(Debug, Clone)]
pub(crate) struct SessionSetup {
    pub(crate) secret: String,
    pub(crate) cookie_name: String,
    pub(crate) cookie_path: String,
    pub(crate) ttl: Option<Duration>,
}

impl SessionSetup {
    pub(crate) fn get_session_layer(&self, store: RedisSessionStore) -> Result<RidserSessionLayer> {
        debug!("📦 Preparing session");
        let session_layer = SessionLayer::new(store, self.secret.as_bytes())
            .with_cookie_name(self.cookie_name.clone())
            .with_persistence_policy(PersistencePolicy::ChangedOnly)
            .with_secure(true)
            .with_cookie_path(self.cookie_path.clone())
            .with_same_site_policy(SameSite::None)
            .with_session_ttl(self.ttl);

        Ok(session_layer)
    }
}

pub(crate) fn redis_cons(connection_url: &str) -> Result<(RedisSessionStore, Client)> {
    debug!(
        "📦 Establishing redis session connection to {}",
        connection_url
    );
    let store = RedisSessionStore::new(connection_url)
        .with_context(|| format!("Failed to connect to redis at {connection_url}"))?;
    let client = Client::open(connection_url)
        .with_context(|| format!("Failed to connect to redis at {connection_url}"))?;
    let _ = client
        .get_connection_with_timeout(Duration::from_secs(1))
        .with_context(|| format!("Redis configured to use {connection_url}"))?;
    Ok((store, client))
}

/// Remove the data associated with the session identifier from the store.
/// Create a new session
pub(crate) async fn purge_store_and_regenerate_session(
    session: &mut WritableSession,
    client: Client,
) {
    if let Ok(mut connection) = client.get_async_connection().await {
        let key = session.id().to_string();
        let _ = connection.del::<_, String>(&key).await;
    }
    session.regenerate();
}
