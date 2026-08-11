package risk

import (
	"math"
	"strings"

	"github.com/berryshield/berryshield/services/gateway/internal/config"
	"github.com/berryshield/berryshield/services/gateway/internal/model"
)

type Scorer interface {
	Score(model.RiskInput, config.Site) model.RiskDecision
}

type Local struct{}

func NewLocal() Local { return Local{} }

func (Local) Score(in model.RiskInput, site config.Site) model.RiskDecision {
	score := 0.0
	var tags []string
	c := in.Telemetry.Client
	b := c.Behavior

	add := func(points float64, tag string) {
		score += points
		tags = append(tags, tag)
	}

	if c.Webdriver {
		add(32, "webdriver-exposed")
	}
	if strings.TrimSpace(in.UserAgent) == "" || strings.TrimSpace(c.UserAgent) == "" {
		add(18, "missing-user-agent")
	}
	ua := strings.ToLower(in.UserAgent + " " + c.UserAgent)
	for _, needle := range []string{"headlesschrome", "phantomjs", "python-requests", "curl/", "wget/"} {
		if strings.Contains(ua, needle) {
			add(30, "automation-user-agent")
			break
		}
	}
	if !c.SecureContext {
		add(5, "non-secure-context")
	}
	if !c.WebCryptoAvailable {
		add(5, "webcrypto-unavailable")
	}
	if !c.WASMAvailable {
		add(3, "wasm-unavailable")
	}
	if c.HardwareConcurrency < 0 || c.HardwareConcurrency > 256 {
		add(10, "invalid-hardware-concurrency")
	}
	if c.ScreenWidthBucket < 0 || c.ScreenHeightBucket < 0 {
		add(8, "invalid-screen")
	}
	if len(c.Languages) == 0 && strings.TrimSpace(in.AcceptLanguage) != "" {
		add(5, "language-inconsistency")
	}
	if c.Platform != "" && in.SecCHPlatform != "" {
		a := normalizePlatform(c.Platform)
		h := normalizePlatform(in.SecCHPlatform)
		if a != "" && h != "" && a != h {
			add(12, "platform-inconsistency")
		}
	}

	// Behavioral signals intentionally have low weight to avoid punishing
	// keyboard-only users, assistive technology, or users who do not move a mouse.
	if b.DwellMS > 1500 && b.PointerEvents == 0 && b.KeyEvents == 0 {
		add(4, "no-observed-interaction")
	}
	if b.PointerEvents > 5000 && b.DwellMS < 1000 {
		add(8, "impossible-pointer-density")
	}
	if math.IsNaN(b.PointerVariance) || math.IsInf(b.PointerVariance, 0) {
		add(15, "invalid-behavior-metrics")
	}

	if in.Reputation.Score > 0 {
		add(float64(in.Reputation.Score)*0.48, "network-reputation")
	}
	if in.Reputation.Tor {
		add(22, "tor-exit")
	}
	if in.Reputation.Hosting {
		add(10, "hosting-network")
	}
	if in.Reputation.Proxy || in.Reputation.VPN {
		add(7, "proxy-or-vpn")
	}
	if in.Reputation.AbuseScore >= 80 {
		add(12, "high-abuse-score")
	}
	if in.RequestRate > site.RateLimitPerMinute/2 {
		add(8, "elevated-request-rate")
	}

	n := int(math.Round(math.Max(0, math.Min(100, score))))
	decision := "allow"
	switch {
	case n >= site.Thresholds.Block:
		decision = "block"
	case n >= site.Thresholds.Interactive:
		decision = "interactive"
	case n >= site.Thresholds.Pow:
		decision = "pow"
	}
	return model.RiskDecision{Score: n, Decision: decision, Tags: unique(tags)}
}

func normalizePlatform(v string) string {
	v = strings.ToLower(strings.Trim(v, "\"' "))
	switch {
	case strings.Contains(v, "win"):
		return "windows"
	case strings.Contains(v, "mac"):
		return "macos"
	case strings.Contains(v, "android"):
		return "android"
	case strings.Contains(v, "ios") || strings.Contains(v, "iphone") || strings.Contains(v, "ipad"):
		return "ios"
	case strings.Contains(v, "linux"):
		return "linux"
	default:
		return ""
	}
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
