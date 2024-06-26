use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use tower_sessions_redis_store::fred::prelude::{ClientLike, RedisPool};
use tracing::error;

async fn health_check(Extension(pool): Extension<RedisPool>) -> Response {
    let con: Result<(), _> = pool.next().ping().await;
    if let Err(err) = con {
        error!("Failed to ping redis: {:?}", err);
        return (StatusCode::SERVICE_UNAVAILABLE, "Unhealthy").into_response();
    }

    (StatusCode::OK, "OK").into_response()
}

pub(crate) fn health_routes(client: &RedisPool) -> Router {
    Router::new().route("/up", get(|| async { "up" })).route(
        "/health",
        get(health_check).layer(Extension(client.clone())),
    )
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_sessions_redis_store::fred::types::{RedisConfig, Server, ServerConfig};

    use super::*;

    fn redis_client(connection_url: &str) -> RedisPool {
        RedisPool::new(
            RedisConfig {
                server: ServerConfig::Centralized {
                    server: Server::try_from(connection_url).expect("Parsing redis connection url"),
                },
                ..Default::default()
            },
            None,
            None,
            None,
            6,
        )
        .expect("Redis setup")
    }

    #[tokio::test]
    async fn test_up() {
        let client = redis_client("redis://redis");
        let app = health_routes(&client);

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
        let client = redis_client("redis://redis");
        let app = health_routes(&client);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
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
        assert_eq!(&body[..], b"OK");
    }

    #[tokio::test]
    async fn test_health_checks_redis() {
        let client = redis_client("redis://redis-wrong-host/");
        let app = health_routes(&client);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect")
            .to_bytes()
            .to_vec();
        assert_eq!(&body[..], b"Unhealthy");
    }
}
