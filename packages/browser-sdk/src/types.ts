export interface BehaviorSignals {
  dwell_ms: number;
  pointer_events: number;
  pointer_distance: number;
  pointer_variance: number;
  key_events: number;
  key_interval_mean_ms: number;
  key_interval_std_ms: number;
  focus_transitions: number;
  visibility_changes: number;
}

export interface ClientSignals {
  sdk_version: string;
  user_agent: string;
  platform: string;
  languages: string[];
  timezone: string;
  screen_width_bucket: number;
  screen_height_bucket: number;
  color_depth: number;
  hardware_concurrency: number;
  device_memory_gb: number;
  max_touch_points: number;
  webdriver: boolean;
  secure_context: boolean;
  cookie_enabled: boolean;
  local_storage_ok: boolean;
  session_storage_ok: boolean;
  webgl_vendor_hash?: string;
  webgl_renderer_hash?: string;
  wasm_available: boolean;
  wasm_mix?: number;
  webcrypto_available: boolean;
  performance_jitter: number;
  behavior: BehaviorSignals;
}

export interface BerryShieldOptions {
  siteKey: string;
  endpoint?: string;
  wasmProbeUrl?: string;
  timeoutMs?: number;
  interactiveContainer?: HTMLElement;
}

export interface ChallengeResponse {
  decision: "allow" | "pow" | "interactive" | "block";
  challenge_id?: string;
  kind?: "pow" | "interactive";
  expires_at?: string;
  params?: Record<string, unknown>;
  token?: string;
}
