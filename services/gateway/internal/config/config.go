package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

type Thresholds struct {
	Pow         int `json:"pow"`
	Interactive int `json:"interactive"`
	Block       int `json:"block"`
}

type Site struct {
	Key                 string     `json:"site_key"`
	Secret              string     `json:"secret"`
	Hostnames           []string   `json:"hostnames"`
	TokenTTLSeconds     int        `json:"token_ttl_seconds"`
	ChallengeTTLSeconds int        `json:"challenge_ttl_seconds"`
	RateLimitPerMinute  int        `json:"rate_limit_per_minute"`
	BindIPPrefix        bool       `json:"bind_ip_prefix"`
	Thresholds          Thresholds `json:"thresholds"`
}

type Registry struct {
	mu    sync.RWMutex
	sites map[string]Site
}

func NewRegistry(sites []Site) *Registry {
	r := &Registry{sites: make(map[string]Site)}
	for _, s := range sites {
		r.sites[s.Key] = s
	}
	return r
}

func (r *Registry) Get(key string) (Site, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sites[key]
	return s, ok
}

func (r *Registry) GetBySecret(secret string) (Site, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.sites {
		if constantTimeStringEqual(s.Secret, secret) {
			return s, true
		}
	}
	return Site{}, false
}

func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var x byte
	for i := 0; i < len(a); i++ {
		x |= a[i] ^ b[i]
	}
	return x == 0
}

type Runtime struct {
	Addr                string
	Environment         string
	SigningSecret       string
	SigningKeyID        string
	SigningPreviousKeys map[string]string
	BindingSecret       string
	Sites               *Registry
	ReputationURL       string
	RiskEngineURL       string
	TrustedProxyCIDRs   []*net.IPNet
	MaxBodyBytes        int64
}

func Load() (Runtime, error) {
	env := getenv("BERRYSHIELD_ENV", "development")
	signing := os.Getenv("BERRYSHIELD_SIGNING_SECRET")
	if signing == "" {
		if env == "production" {
			return Runtime{}, errors.New("BERRYSHIELD_SIGNING_SECRET is required in production")
		}
		signing = "development-only-change-me-32-bytes-minimum"
	}
	if len(signing) < 32 {
		return Runtime{}, errors.New("BERRYSHIELD_SIGNING_SECRET must be at least 32 bytes")
	}

	sites, err := loadSites()
	if err != nil {
		return Runtime{}, err
	}
	trusted, err := parseCIDRs(os.Getenv("BERRYSHIELD_TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return Runtime{}, fmt.Errorf("trusted proxy CIDRs: %w", err)
	}
	keyID := getenv("BERRYSHIELD_SIGNING_KID", "dev-v1")
	previous, err := parsePreviousSigningKeys(os.Getenv("BERRYSHIELD_PREVIOUS_SIGNING_KEYS_JSON"), keyID)
	if err != nil {
		return Runtime{}, err
	}
	binding := os.Getenv("BERRYSHIELD_BINDING_SECRET")
	if binding == "" {
		binding = signing
	}
	if len(binding) < 32 {
		return Runtime{}, errors.New("BERRYSHIELD_BINDING_SECRET must be at least 32 bytes")
	}
	maxBody := int64(getenvInt("BERRYSHIELD_MAX_BODY_BYTES", 65536))
	return Runtime{
		Addr:                getenv("BERRYSHIELD_ADDR", ":8080"),
		Environment:         env,
		SigningSecret:       signing,
		SigningKeyID:        keyID,
		SigningPreviousKeys: previous,
		BindingSecret:       binding,
		Sites:               NewRegistry(sites),
		ReputationURL:       strings.TrimRight(os.Getenv("BERRYSHIELD_REPUTATION_URL"), "/"),
		RiskEngineURL:       strings.TrimRight(os.Getenv("BERRYSHIELD_RISK_ENGINE_URL"), "/"),
		TrustedProxyCIDRs:   trusted,
		MaxBodyBytes:        maxBody,
	}, nil
}

func loadSites() ([]Site, error) {
	if path := os.Getenv("BERRYSHIELD_SITES_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var sites []Site
		if err := json.Unmarshal(b, &sites); err != nil {
			return nil, fmt.Errorf("decode sites file: %w", err)
		}
		if len(sites) == 0 {
			return nil, errors.New("sites file contains no sites")
		}
		for i := range sites {
			applySiteDefaults(&sites[i])
		}
		if err := validateSites(sites, envIsProduction()); err != nil {
			return nil, err
		}
		return sites, nil
	}

	s := Site{
		Key:          getenv("BERRYSHIELD_SITE_KEY", "bs_dev_public"),
		Secret:       getenv("BERRYSHIELD_SITE_SECRET", "bs_dev_secret_change_me"),
		Hostnames:    splitCSV(getenv("BERRYSHIELD_ALLOWED_HOSTS", "localhost,127.0.0.1")),
		BindIPPrefix: getenvBool("BERRYSHIELD_BIND_IP_PREFIX", true),
	}
	applySiteDefaults(&s)
	if err := validateSites([]Site{s}, envIsProduction()); err != nil {
		return nil, err
	}
	return []Site{s}, nil
}

func parsePreviousSigningKeys(raw, activeKID string) (map[string]string, error) {
	out := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("BERRYSHIELD_PREVIOUS_SIGNING_KEYS_JSON: %w", err)
	}
	for kid, secret := range out {
		if strings.TrimSpace(kid) == "" || kid == activeKID {
			return nil, fmt.Errorf("BERRYSHIELD_PREVIOUS_SIGNING_KEYS_JSON: invalid or active kid %q", kid)
		}
		if len(secret) < 32 {
			return nil, fmt.Errorf("BERRYSHIELD_PREVIOUS_SIGNING_KEYS_JSON: key %q must be at least 32 bytes", kid)
		}
	}
	return out, nil
}

func (r Runtime) IPBindingSecret() string {
	if r.BindingSecret != "" {
		return r.BindingSecret
	}
	return r.SigningSecret
}

func envIsProduction() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("BERRYSHIELD_ENV")), "production")
}

func validateSites(sites []Site, production bool) error {
	seenKeys := map[string]struct{}{}
	seenSecrets := map[string]struct{}{}
	for i, s := range sites {
		if strings.TrimSpace(s.Key) == "" || len(s.Key) > 128 {
			return fmt.Errorf("site[%d]: invalid site_key", i)
		}
		if len(s.Secret) < 16 {
			return fmt.Errorf("site[%d]: secret must be at least 16 bytes", i)
		}
		if production && (s.Secret == "bs_dev_secret_change_me" || strings.Contains(strings.ToLower(s.Secret), "change_me")) {
			return fmt.Errorf("site[%d]: development secret is forbidden in production", i)
		}
		if len(s.Hostnames) == 0 {
			return fmt.Errorf("site[%d]: at least one hostname is required", i)
		}
		if !(0 < s.Thresholds.Pow && s.Thresholds.Pow < s.Thresholds.Interactive && s.Thresholds.Interactive < s.Thresholds.Block && s.Thresholds.Block <= 100) {
			return fmt.Errorf("site[%d]: thresholds must satisfy 0 < pow < interactive < block <= 100", i)
		}
		if s.TokenTTLSeconds < 30 || s.TokenTTLSeconds > 600 {
			return fmt.Errorf("site[%d]: token_ttl_seconds must be between 30 and 600", i)
		}
		if s.ChallengeTTLSeconds < 30 || s.ChallengeTTLSeconds > 900 {
			return fmt.Errorf("site[%d]: challenge_ttl_seconds must be between 30 and 900", i)
		}
		if _, ok := seenKeys[s.Key]; ok {
			return fmt.Errorf("site[%d]: duplicate site_key", i)
		}
		if _, ok := seenSecrets[s.Secret]; ok {
			return fmt.Errorf("site[%d]: duplicate site secret", i)
		}
		seenKeys[s.Key] = struct{}{}
		seenSecrets[s.Secret] = struct{}{}
	}
	return nil
}

func applySiteDefaults(s *Site) {
	if s.TokenTTLSeconds <= 0 {
		s.TokenTTLSeconds = 120
	}
	if s.ChallengeTTLSeconds <= 0 {
		s.ChallengeTTLSeconds = 180
	}
	if s.RateLimitPerMinute <= 0 {
		s.RateLimitPerMinute = 60
	}
	if s.Thresholds.Pow <= 0 {
		s.Thresholds.Pow = 30
	}
	if s.Thresholds.Interactive <= 0 {
		s.Thresholds.Interactive = 62
	}
	if s.Thresholds.Block <= 0 {
		s.Thresholds.Block = 92
	}
}

func NormalizeHostname(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(host, ".")
	return host
}

func (s Site) AllowsHostname(host string) bool {
	host = NormalizeHostname(host)
	for _, allowed := range s.Hostnames {
		a := strings.ToLower(strings.TrimSpace(allowed))
		if strings.HasPrefix(a, "*.") {
			suffix := "." + NormalizeHostname(strings.TrimPrefix(a, "*."))
			if strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".") {
				return true
			}
			continue
		}
		if NormalizeHostname(a) == host {
			return true
		}
	}
	return false
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func getenvInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func getenvBool(k string, d bool) bool {
	if v := strings.TrimSpace(strings.ToLower(os.Getenv(k))); v != "" {
		return v == "1" || v == "true" || v == "yes" || v == "on"
	}
	return d
}

func splitCSV(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseCIDRs(v string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range splitCSV(v) {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}
