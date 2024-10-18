use mimalloc::MiMalloc;
use ridser::run_ridser;
use tracing::{error, trace};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() {
    // Initializing .env first enables setting the RUST_LOG env var.
    let _ = dotenvy::dotenv();

    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();
    trace!("🔥 Starting initialization");

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    run_ridser().await.unwrap_or_else(|e| {
        error!("💀 Failed to run: {:?}", e);
    });
}
