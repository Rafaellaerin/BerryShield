mod model;
mod score;

use axum::{
    extract::DefaultBodyLimit,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use model::{ScoreRequest, ScoreResponse};
use serde::Serialize;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;

#[derive(Serialize)]
struct Health {
    ok: bool,
    service: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health { ok: true, service: "berryshield-risk-engine" })
}

async fn score_handler(Json(req): Json<ScoreRequest>) -> Result<Json<ScoreResponse>, StatusCode> {
    if req.site.thresholds.pow < 0
        || req.site.thresholds.pow >= req.site.thresholds.interactive
        || req.site.thresholds.interactive >= req.site.thresholds.block
        || req.site.thresholds.block > 100
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(score::score(&req.input, &req.site)))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/score", post(score_handler))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = std::env::var("RISK_ENGINE_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8082".into())
        .parse()
        .expect("valid RISK_ENGINE_ADDR");

    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    tracing::info!(%addr, "berryshield-risk-engine listening");
    axum::serve(listener, app).await.expect("serve");
}
