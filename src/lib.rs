use axum::Router;
use http::socket_addr;
use tokio::signal;

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

fn app() -> Router {
    Router::new()
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
