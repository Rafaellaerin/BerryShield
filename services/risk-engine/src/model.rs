use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct BehaviorSignals {
    #[serde(default)] pub dwell_ms: i64,
    #[serde(default)] pub pointer_events: i64,
    #[serde(default)] pub pointer_distance: f64,
    #[serde(default)] pub pointer_variance: f64,
    #[serde(default)] pub key_events: i64,
    #[serde(default)] pub key_interval_mean_ms: f64,
    #[serde(default)] pub key_interval_std_ms: f64,
    #[serde(default)] pub focus_transitions: i64,
    #[serde(default)] pub visibility_changes: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ClientSignals {
    #[serde(default)] pub sdk_version: String,
    #[serde(default)] pub user_agent: String,
    #[serde(default)] pub platform: String,
    #[serde(default)] pub languages: Vec<String>,
    #[serde(default)] pub timezone: String,
    #[serde(default)] pub screen_width_bucket: i64,
    #[serde(default)] pub screen_height_bucket: i64,
    #[serde(default)] pub color_depth: i64,
    #[serde(default)] pub hardware_concurrency: i64,
    #[serde(default)] pub device_memory_gb: f64,
    #[serde(default)] pub max_touch_points: i64,
    #[serde(default)] pub webdriver: bool,
    #[serde(default)] pub secure_context: bool,
    #[serde(default)] pub cookie_enabled: bool,
    #[serde(default)] pub local_storage_ok: bool,
    #[serde(default)] pub session_storage_ok: bool,
    #[serde(default)] pub wasm_available: bool,
    #[serde(default)] pub wasm_mix: u32,
    #[serde(default)] pub webcrypto_available: bool,
    #[serde(default)] pub performance_jitter: f64,
    #[serde(default)] pub behavior: BehaviorSignals,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Telemetry {
    #[serde(default)] pub client: ClientSignals,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Reputation {
    #[serde(default)] pub score: i64,
    #[serde(default)] pub proxy: bool,
    #[serde(default)] pub vpn: bool,
    #[serde(default)] pub tor: bool,
    #[serde(default)] pub hosting: bool,
    #[serde(default)] pub abuse_score: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RiskInput {
    #[serde(default)] pub ip: String,
    #[serde(default)] pub user_agent: String,
    #[serde(default)] pub accept_language: String,
    #[serde(default)] pub sec_ch_ua: String,
    #[serde(default)] pub sec_ch_platform: String,
    #[serde(default)] pub request_rate: i64,
    #[serde(default)] pub telemetry: Telemetry,
    #[serde(default)] pub reputation: Reputation,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Thresholds {
    pub pow: i64,
    pub interactive: i64,
    pub block: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SitePolicy {
    pub rate_limit_per_minute: i64,
    pub thresholds: Thresholds,
}

#[derive(Debug, Deserialize)]
pub struct ScoreRequest {
    pub input: RiskInput,
    pub site: SitePolicy,
}

#[derive(Debug, Serialize)]
pub struct ScoreResponse {
    pub score: i64,
    pub decision: &'static str,
    pub tags: Vec<&'static str>,
}
