package model

import "time"

type BehaviorSignals struct {
	DwellMS           int     `json:"dwell_ms"`
	PointerEvents     int     `json:"pointer_events"`
	PointerDistance   float64 `json:"pointer_distance"`
	PointerVariance   float64 `json:"pointer_variance"`
	KeyEvents         int     `json:"key_events"`
	KeyIntervalMeanMS float64 `json:"key_interval_mean_ms"`
	KeyIntervalStdMS  float64 `json:"key_interval_std_ms"`
	FocusTransitions  int     `json:"focus_transitions"`
	VisibilityChanges int     `json:"visibility_changes"`
}

type ClientSignals struct {
	SDKVersion          string          `json:"sdk_version"`
	UserAgent           string          `json:"user_agent"`
	Platform            string          `json:"platform"`
	Languages           []string        `json:"languages"`
	Timezone            string          `json:"timezone"`
	ScreenWidthBucket   int             `json:"screen_width_bucket"`
	ScreenHeightBucket  int             `json:"screen_height_bucket"`
	ColorDepth          int             `json:"color_depth"`
	HardwareConcurrency int             `json:"hardware_concurrency"`
	DeviceMemoryGB      float64         `json:"device_memory_gb"`
	MaxTouchPoints      int             `json:"max_touch_points"`
	Webdriver           bool            `json:"webdriver"`
	SecureContext       bool            `json:"secure_context"`
	CookieEnabled       bool            `json:"cookie_enabled"`
	LocalStorageOK      bool            `json:"local_storage_ok"`
	SessionStorageOK    bool            `json:"session_storage_ok"`
	WebGLVendorHash     string          `json:"webgl_vendor_hash,omitempty"`
	WebGLRendererHash   string          `json:"webgl_renderer_hash,omitempty"`
	WASMAvailable       bool            `json:"wasm_available"`
	WASMMix             uint32          `json:"wasm_mix,omitempty"`
	WebCryptoAvailable  bool            `json:"webcrypto_available"`
	PerformanceJitter   float64         `json:"performance_jitter"`
	Behavior            BehaviorSignals `json:"behavior"`
}

type Telemetry struct {
	Client ClientSignals `json:"client"`
}

type ChallengeRequest struct {
	SiteKey   string    `json:"site_key"`
	Action    string    `json:"action"`
	Hostname  string    `json:"hostname"`
	SessionID string    `json:"session_id"`
	Telemetry Telemetry `json:"telemetry"`
}

type Reputation struct {
	Score      int      `json:"score"`
	Proxy      bool     `json:"proxy"`
	VPN        bool     `json:"vpn"`
	Tor        bool     `json:"tor"`
	Hosting    bool     `json:"hosting"`
	AbuseScore int      `json:"abuse_score"`
	Country    string   `json:"country,omitempty"`
	ASN        string   `json:"asn,omitempty"`
	Providers  []string `json:"providers,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

type RiskInput struct {
	IP             string     `json:"ip"`
	UserAgent      string     `json:"user_agent"`
	AcceptLanguage string     `json:"accept_language"`
	SecCHUA        string     `json:"sec_ch_ua"`
	SecCHPlatform  string     `json:"sec_ch_platform"`
	RequestRate    int        `json:"request_rate"`
	Telemetry      Telemetry  `json:"telemetry"`
	Reputation     Reputation `json:"reputation"`
}

type RiskDecision struct {
	Score    int      `json:"score"`
	Decision string   `json:"decision"`
	Tags     []string `json:"tags"`
}

type Challenge struct {
	ID        string         `json:"challenge_id"`
	SiteKey   string         `json:"-"`
	Action    string         `json:"-"`
	Hostname  string         `json:"-"`
	SessionID string         `json:"-"`
	IPBind    string         `json:"-"`
	RiskScore int            `json:"-"`
	RiskTags  []string       `json:"-"`
	Kind      string         `json:"kind"`
	Params    map[string]any `json:"params,omitempty"`
	CreatedAt time.Time      `json:"-"`
	ExpiresAt time.Time      `json:"expires_at"`
	Attempts  int            `json:"-"`
}

type ChallengeResponse struct {
	Decision    string         `json:"decision"`
	ChallengeID string         `json:"challenge_id,omitempty"`
	Kind        string         `json:"kind,omitempty"`
	ExpiresAt   time.Time      `json:"expires_at,omitempty"`
	Params      map[string]any `json:"params,omitempty"`
	Token       string         `json:"token,omitempty"`
}

type Proof struct {
	Kind            string  `json:"kind"`
	Nonce           uint64  `json:"nonce,omitempty"`
	HoldMS          int     `json:"hold_ms,omitempty"`
	EventCount      int     `json:"event_count,omitempty"`
	PointerVariance float64 `json:"pointer_variance,omitempty"`
}

type VerifyChallengeRequest struct {
	SessionID string `json:"session_id"`
	Proof     Proof  `json:"proof"`
}

type VerifyChallengeResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	Error   string `json:"error,omitempty"`
}

type TokenClaims struct {
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	SiteKey       string `json:"site_key"`
	Action        string `json:"action"`
	Hostname      string `json:"hostname"`
	JTI           string `json:"jti"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
	RiskScore     int    `json:"risk_score"`
	RiskBucket    string `json:"risk_bucket"`
	ChallengeKind string `json:"challenge_kind"`
	IPBind        string `json:"ip_bind,omitempty"`
}

type SiteVerifyRequest struct {
	Secret           string `json:"secret"`
	Response         string `json:"response"`
	RemoteIP         string `json:"remoteip,omitempty"`
	ExpectedAction   string `json:"expected_action,omitempty"`
	ExpectedHostname string `json:"expected_hostname,omitempty"`
}

type SiteVerifyResponse struct {
	Success       bool     `json:"success"`
	ChallengeTS   string   `json:"challenge_ts,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	Action        string   `json:"action,omitempty"`
	RiskScore     int      `json:"risk_score,omitempty"`
	RiskBucket    string   `json:"risk_bucket,omitempty"`
	ChallengeKind string   `json:"challenge_kind,omitempty"`
	ErrorCodes    []string `json:"error-codes"`
}
