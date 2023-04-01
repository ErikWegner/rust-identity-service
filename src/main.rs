use ridser::run_ridser;
use tracing::{error, trace};

#[tokio::main]
async fn main() {
    // Initializing .env first enables setting the RUST_LOG env var.
    let _ = dotenvy::dotenv();

    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();
    trace!("🔥 Starting initialization");

    run_ridser().await.unwrap_or_else(|e| {
        error!("💀 Failed to run: {:?}", e);
    });
}
