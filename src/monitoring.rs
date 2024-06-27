use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use tower_sessions_redis_store::fred::{
    clients::{RedisClient, RedisPool},
    interfaces::ClientLike,
};
use tracing::error;

async fn health_check(Extension(client): Extension<RedisClient>) -> Response {
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
    use tower::ServiceExt;

    use super::*;

    fn redis_client() -> Client {
        Client::open(
            std::env::var("RIDSER_TEST_REDIS_URL")
                .unwrap_or_else(|_| "redis://redis/".to_string())
                .as_ref(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_up() {
        let client = redis_client();
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
        let client = redis_client();
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
        let client = Client::open("redis://redis-wrong-host/").unwrap();
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
