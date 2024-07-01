use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use tower_sessions_redis_store::fred::{clients::RedisPool, interfaces::ClientLike};
use tracing::error;

async fn health_check(Extension(pool): Extension<RedisPool>) -> Response {
    let client = pool.next_connected();
    let con: Result<(), _> = client.ping().await;

    if let Err(err) = con {
        error!("Failed to connect to redis: {:?}", err);
        return (StatusCode::SERVICE_UNAVAILABLE, "Unhealthy").into_response();
    }

    (StatusCode::OK, "OK").into_response()
}

pub(crate) fn health_routes(client: RedisPool) -> Router {
    Router::new()
        .route("/up", get(|| async { "up" }))
        .route("/health", get(health_check).layer(Extension(client)))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tokio::time::timeout;
    use tower::ServiceExt;
    use tower_sessions_redis_store::fred::types::{
        PerformanceConfig, ReconnectPolicy, RedisConfig,
    };

    use super::*;

    async fn redis_client(connection_url: &str) -> RedisPool {
        let conf = RedisConfig::from_url(connection_url).expect("Parsing redis connection url");
        let redis_pool = RedisPool::new(
            conf,
            Some(PerformanceConfig {
                default_command_timeout: core::time::Duration::from_millis(300),

                ..Default::default()
            }),
            None,
            Some(ReconnectPolicy::new_constant(0, 5_000)),
            6,
        )
        .expect("Redis setup");

        let connect_pool = redis_pool.clone();

        if (timeout(core::time::Duration::from_secs(1), connect_pool.connect()).await).is_err() {
            tracing::warn!("Failed to connect to redis");
        }

        redis_pool
    }

    #[tokio::test]
    async fn test_up() {
        let client = redis_client(
            std::env::var("RIDSER_TEST_REDIS_URL")
                .unwrap_or_else(|_| "redis://redis:6379".to_string())
                .as_ref(),
        )
        .await;
        let app = health_routes(client);

        let response = app
            .oneshot(Request::builder().uri("/up").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect")
            .to_bytes()
            .to_vec();
        assert_eq!(&body[..], b"up");
    }

    #[tokio::test]
    async fn test_health() {
        let pool = redis_client(
            std::env::var("RIDSER_TEST_REDIS_URL")
                .unwrap_or_else(|_| "redis://redis:6379".to_string())
                .as_ref(),
        )
        .await;
        // let _ = pool.connect();
        let app = health_routes(pool);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .expect("collect")
                .to_bytes()
                .to_vec(),
        )
        .unwrap();

        assert_eq!(status, StatusCode::OK, "Expected 200 OK, but {}", body);
        assert_eq!(body, "OK");
    }

    #[tokio::test]
    async fn test_health_checks_redis() {
        let client = redis_client("redis://redis-wrong-host:6379").await;
        let app = health_routes(client);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .expect("collect")
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "Expected 503, but {}",
            body
        );

        assert_eq!(body, "Unhealthy");
    }
}
