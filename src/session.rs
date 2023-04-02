use std::time::Duration;

use anyhow::{Context, Result};
use async_redis_session::RedisSessionStore;
use axum_sessions::{PersistencePolicy, SameSite, SessionLayer};
use redis::Client;
use tracing::debug;

pub(crate) type RidserSessionLayer = SessionLayer<RedisSessionStore>;

#[derive(Debug, Clone)]
pub(crate) struct SessionSetup {
    pub(crate) secret: String,
    pub(crate) cookie_name: String,
    pub(crate) cookie_path: String,
    pub(crate) ttl: Option<Duration>,
}

impl SessionSetup {
    pub(crate) fn get_session_layer(self, store: RedisSessionStore) -> Result<RidserSessionLayer> {
        debug!("📦 Preparing session");
        let session_layer = SessionLayer::new(store, self.secret.as_bytes())
            .with_cookie_name(self.cookie_name)
            .with_persistence_policy(PersistencePolicy::ChangedOnly)
            .with_secure(true)
            .with_cookie_path(self.cookie_path)
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
    Ok((store, client))
}
