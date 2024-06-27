use std::time::Duration;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use redis::Client;
use tracing::error;

async fn health_check(Extension(client): Extension<Client>) -> Response {
    let con = client.get_connection_with_timeout(Duration::from_millis(300));
    if let Err(err) = con {
        error!("Failed to connect to redis: {:?}", err);
        return (StatusCode::SERVICE_UNAVAILABLE, "Unhealthy").into_response();
    }

    (StatusCode::OK, "OK").into_response()
}

pub(crate) fn health_routes(client: &Client) -> Router {
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&body[..], b"Unhealthy");
    }
}
