use axum::{routing::get, Router};
use http::socket_addr;
use tokio::signal;
use tower_http::services::{ServeDir, ServeFile};

pub(crate) mod http;

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    println!("signal received, starting graceful shutdown");
}

fn health_routes() -> Router {
    Router::new()
        .route("/up", get(|| async { "up" }))
        .route("/health", get(|| async { "health" }))
}

fn app() -> Router {
    let serve_dir = ServeDir::new("files").not_found_service(ServeFile::new("files/index.html"));
    Router::new()
        .nest("/app", health_routes())
        .fallback_service(serve_dir)
}

pub async fn run_ridser() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = socket_addr()?;
    let app = app();

    tracing::info!("💈 Listening on http://{}", &bind_addr);
    axum::Server::bind(&bind_addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}
