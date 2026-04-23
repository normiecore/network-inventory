//! Axum web layer: serves the single-page UI and a few JSON endpoints.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde::Serialize;
use sqlx::SqlitePool;
use tokio::sync::Notify;

use crate::db;
use crate::scanner::ONLINE_WINDOW_MINUTES;

/// Injected into every handler.
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    /// Notified whenever someone hits POST /api/scan. The background scheduler
    /// listens and triggers an immediate scan.
    pub scan_trigger: Arc<Notify>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/devices", get(list_devices))
        .route("/api/stats", get(stats))
        .route("/api/scan", post(trigger_scan))
        .with_state(state)
}

/// Inline the HTML at compile time so the binary has no runtime asset deps.
const INDEX_HTML: &str = include_str!("../static/index.html");

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

#[derive(Serialize)]
struct DeviceView {
    id: i64,
    mac: String,
    ip: String,
    hostname: Option<String>,
    vendor: Option<String>,
    first_seen: String,
    last_seen: String,
    /// "online" | "offline" | "new"
    status: &'static str,
}

async fn list_devices(
    State(state): State<AppState>,
) -> Result<Json<Vec<DeviceView>>, ApiError> {
    let devices = db::list_devices(&state.pool).await?;
    let now = Utc::now();
    let online_cutoff = now - Duration::minutes(ONLINE_WINDOW_MINUTES);
    let new_cutoff = now - Duration::hours(24);

    let views: Vec<DeviceView> = devices
        .into_iter()
        .map(|d| {
            // Status logic per spec:
            //   online  => last_seen within last 15 min
            //   new     => first_seen within last 24 h  (trumps offline)
            //   offline => otherwise
            let status = if d.last_seen >= online_cutoff {
                "online"
            } else if d.first_seen >= new_cutoff {
                "new"
            } else {
                "offline"
            };
            DeviceView {
                id: d.id,
                mac: d.mac,
                ip: d.ip,
                hostname: d.hostname,
                vendor: d.vendor,
                first_seen: d.first_seen.to_rfc3339(),
                last_seen: d.last_seen.to_rfc3339(),
                status,
            }
        })
        .collect();

    Ok(Json(views))
}

#[derive(Serialize)]
struct Stats {
    total: usize,
    online: usize,
    new_last_24h: usize,
    unknown_vendor: usize,
    last_scan_started: Option<String>,
    last_scan_completed: Option<String>,
    last_scan_found: Option<i64>,
}

async fn stats(State(state): State<AppState>) -> Result<Json<Stats>, ApiError> {
    let devices = db::list_devices(&state.pool).await?;
    let now = Utc::now();
    let online_cutoff = now - Duration::minutes(ONLINE_WINDOW_MINUTES);
    let new_cutoff = now - Duration::hours(24);

    let total = devices.len();
    let online = devices.iter().filter(|d| d.last_seen >= online_cutoff).count();
    let new_last_24h = devices
        .iter()
        .filter(|d| d.first_seen >= new_cutoff)
        .count();
    let unknown_vendor = devices
        .iter()
        .filter(|d| d.vendor.as_deref().map(str::is_empty).unwrap_or(true))
        .count();

    let latest = db::latest_scan(&state.pool).await?;
    let (started, completed, found) = match latest {
        Some(s) => (
            Some(s.started_at.to_rfc3339()),
            s.completed_at.map(|d| d.to_rfc3339()),
            Some(s.devices_found),
        ),
        None => (None, None, None),
    };

    Ok(Json(Stats {
        total,
        online,
        new_last_24h,
        unknown_vendor,
        last_scan_started: started,
        last_scan_completed: completed,
        last_scan_found: found,
    }))
}

async fn trigger_scan(State(state): State<AppState>) -> impl IntoResponse {
    state.scan_trigger.notify_one();
    (StatusCode::ACCEPTED, Json(serde_json::json!({"ok": true})))
}

// ---- error plumbing ----

pub struct ApiError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("api error: {:#}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}
