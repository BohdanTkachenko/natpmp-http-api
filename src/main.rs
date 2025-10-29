use clap::Parser;
use natpmp_http_api::{AppState, ClientFactory, NatpmpPortMappingService};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "natpmp-http-api")]
#[command(about = "NAT-PMP HTTP API Server for Kubernetes")]
struct Args {
    /// NAT-PMP gateway IP address
    #[arg(long, required = true, env = "NATPMP_GATEWAY")]
    gateway: IpAddr,

    /// HTTP API bind address
    #[arg(long, default_value = "0.0.0.0", env = "API_BIND_ADDRESS")]
    bind_address: IpAddr,

    /// HTTP API port
    #[arg(long, default_value = "8080", env = "API_PORT")]
    port: u16,

    /// Maximum NAT-PMP mapping duration in seconds (-1 to disable limit)
    #[arg(long, default_value = "300", env = "NATPMP_MAX_DURATION")]
    max_duration: i32,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info", env = "LOG_LEVEL")]
    log_level: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                if args.log_level == "debug" {
                    "debug".into()
                } else {
                    format!("natpmp_http_api={},tower_http=info", args.log_level).into()
                }
            }),
        )
        .init();

    // Convert IpAddr to Ipv4Addr for NAT-PMP
    let gateway_v4 = match args.gateway {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => {
            error!("IPv6 gateways are not supported");
            std::process::exit(1);
        }
    };

    let client_factory: ClientFactory = Arc::new(move || {
        NatpmpPortMappingService::new(gateway_v4)
            .map(|c| Box::new(c) as Box<dyn natpmp_http_api::PortMappingService>)
    });

    let state = AppState {
        gateway: args.gateway,
        max_duration: if args.max_duration == -1 {
            None
        } else {
            Some(args.max_duration as u32)
        },
        token: std::env::var("API_TOKEN").ok(),
        client_factory,
    };

    // Build our application with routes
    let app = natpmp_http_api::create_router(state).layer(
        TraceLayer::new_for_http()
            .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO))
            .on_request(tower_http::trace::DefaultOnRequest::new().level(tracing::Level::INFO))
            .on_response(tower_http::trace::DefaultOnResponse::new().level(tracing::Level::INFO)),
    );

    let bind_addr = format!("{}:{}", args.bind_address, args.port);
    let listener = TcpListener::bind(&bind_addr).await.unwrap();

    let token_env = std::env::var("API_TOKEN").ok();
    if token_env.is_some() {
        info!(
            "Starting NAT-PMP HTTP API on {} with gateway {} (auth enabled)",
            bind_addr, args.gateway
        );
    } else {
        warn!(
            "Starting NAT-PMP HTTP API on {} with gateway {} (no auth - consider using API_TOKEN)",
            bind_addr, args.gateway
        );
    }

    // Setup graceful shutdown for multiple signals
    let shutdown_signal = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};

            let mut sigint =
                signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");
            let mut sigterm =
                signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");

            tokio::select! {
                _ = sigint.recv() => info!("Received SIGINT, initiating graceful shutdown..."),
                _ = sigterm.recv() => info!("Received SIGTERM, initiating graceful shutdown..."),
            }
        }

        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install signal handler");
            info!("Received shutdown signal, initiating graceful shutdown...");
        }
    };

    // Run server with graceful shutdown
    let server = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal);

    if let Err(e) = server.await {
        error!("Server error: {}", e);
    } else {
        info!("Server shutdown complete");
    }
}
