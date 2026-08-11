package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/berryshield/berryshield/services/gateway/internal/challenge"
	"github.com/berryshield/berryshield/services/gateway/internal/config"
	"github.com/berryshield/berryshield/services/gateway/internal/metrics"
	"github.com/berryshield/berryshield/services/gateway/internal/model"
	"github.com/berryshield/berryshield/services/gateway/internal/reputation"
	"github.com/berryshield/berryshield/services/gateway/internal/risk"
	"github.com/berryshield/berryshield/services/gateway/internal/store"
	"github.com/berryshield/berryshield/services/gateway/internal/token"
	"github.com/berryshield/berryshield/services/gateway/internal/util"
)

var actionRE = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,64}$`)

type Server struct {
	cfg    config.Runtime
	store  *store.Memory
	signer *token.Signer
	rep    *reputation.Client
	scorer risk.Scorer
	stats  *metrics.Metrics
	logger *log.Logger
}

func New(cfg config.Runtime, logger *log.Logger) *Server {
	local := risk.NewLocal()
	var scorer risk.Scorer = local
	if cfg.RiskEngineURL != "" {
		scorer = risk.NewRemote(cfg.RiskEngineURL, local)
	}
	return &Server{
		cfg: cfg, store: store.NewMemory(),
		signer: token.NewSignerWithKeys(cfg.SigningSecret, cfg.SigningKeyID, cfg.SigningPreviousKeys),
		rep:    reputation.New(cfg.ReputationURL),
		scorer: scorer,
		stats:  &metrics.Metrics{},
		logger: logger,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /metrics", s.stats.Handler)
	mux.HandleFunc("POST /v1/challenge", s.issueChallenge)
	mux.HandleFunc("OPTIONS /v1/challenge", s.options)
	mux.HandleFunc("POST /v1/challenge/{id}/verify", s.verifyChallenge)
	mux.HandleFunc("OPTIONS /v1/challenge/{id}/verify", s.options)
	mux.HandleFunc("POST /v1/siteverify", s.siteVerify)
	return s.security(s.recoverer(mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "berryshield-gateway"})
}

func (s *Server) issueChallenge(w http.ResponseWriter, r *http.Request) {
	s.stats.Requests.Add(1)
	var req model.ChallengeRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		return
	}
	site, ok := s.cfg.Sites.Get(req.SiteKey)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid-site-key")
		return
	}
	if !actionRE.MatchString(req.Action) {
		writeError(w, http.StatusBadRequest, "invalid-action")
		return
	}
	if !site.AllowsHostname(req.Hostname) {
		writeError(w, http.StatusBadRequest, "hostname-not-allowed")
		return
	}
	req.Hostname = config.NormalizeHostname(req.Hostname)
	if req.SessionID == "" || len(req.SessionID) > 128 {
		writeError(w, http.StatusBadRequest, "invalid-session-id")
		return
	}
	if !s.originAllowedForHostname(r, site, req.Hostname) {
		writeError(w, http.StatusForbidden, "origin-not-allowed")
		return
	}
	s.setCORS(w, r)

	ip := util.ClientIP(r, s.cfg.TrustedProxyCIDRs)
	rateKey := site.Key + ":" + util.Prefix(ip) + ":" + req.Action
	allowed, count := s.store.AllowRate(rateKey, site.RateLimitPerMinute, time.Minute)
	if !allowed {
		s.stats.RateLimited.Add(1)
		writeError(w, http.StatusTooManyRequests, "rate-limited")
		return
	}

	repCtx, cancel := context.WithTimeout(r.Context(), 750*time.Millisecond)
	rep := s.rep.Lookup(repCtx, ip, r.UserAgent(), r.Header.Get("Accept-Language"))
	cancel()

	in := model.RiskInput{
		IP:             ip,
		UserAgent:      r.UserAgent(),
		AcceptLanguage: r.Header.Get("Accept-Language"),
		SecCHUA:        r.Header.Get("Sec-CH-UA"),
		SecCHPlatform:  r.Header.Get("Sec-CH-UA-Platform"),
		RequestRate:    count,
		Telemetry:      req.Telemetry,
		Reputation:     rep,
	}
	decision := s.scorer.Score(in, site)
	s.stats.Challenges.Add(1)

	ipBind := ""
	if site.BindIPPrefix {
		ipBind = util.BindIP(s.cfg.IPBindingSecret(), ip)
	}
	switch decision.Decision {
	case "block":
		s.stats.Blocked.Add(1)
		writeJSON(w, http.StatusForbidden, model.ChallengeResponse{Decision: "block"})
		return
	case "allow":
		s.stats.Allowed.Add(1)
		tok, _, err := token.Mint(
			s.signer, site.Key, req.Action, req.Hostname, ipBind,
			"passive", decision.Score, time.Duration(site.TokenTTLSeconds)*time.Second,
		)
		if err != nil {
			s.logger.Printf("mint token: %v", err)
			writeError(w, http.StatusInternalServerError, "internal-error")
			return
		}
		writeJSON(w, http.StatusOK, model.ChallengeResponse{Decision: "allow", Token: tok})
		return
	case "pow", "interactive":
		if decision.Decision == "pow" {
			s.stats.Pow.Add(1)
		} else {
			s.stats.Interactive.Add(1)
		}
		c, err := challenge.New(
			decision.Decision, site.Key, req.Action, req.Hostname, req.SessionID,
			ipBind, decision.Score, decision.Tags,
			time.Duration(site.ChallengeTTLSeconds)*time.Second,
		)
		if err != nil {
			s.logger.Printf("new challenge: %v", err)
			writeError(w, http.StatusInternalServerError, "internal-error")
			return
		}
		s.store.PutChallenge(c)
		writeJSON(w, http.StatusOK, model.ChallengeResponse{
			Decision:    decision.Decision,
			ChallengeID: c.ID, Kind: c.Kind, ExpiresAt: c.ExpiresAt, Params: c.Params,
		})
		return
	default:
		writeError(w, http.StatusInternalServerError, "invalid-decision")
	}
}

func (s *Server) verifyChallenge(w http.ResponseWriter, r *http.Request) {
	s.stats.Requests.Add(1)
	id := r.PathValue("id")
	if id == "" || len(id) > 96 {
		writeError(w, http.StatusBadRequest, "invalid-challenge-id")
		return
	}
	c, ok := s.store.GetChallenge(id)
	if !ok {
		writeError(w, http.StatusBadRequest, "challenge-not-found-or-expired")
		return
	}
	site, ok := s.cfg.Sites.Get(c.SiteKey)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid-site-key")
		return
	}
	if !s.originAllowedForHostname(r, site, c.Hostname) {
		writeError(w, http.StatusForbidden, "origin-not-allowed")
		return
	}
	s.setCORS(w, r)
	ip := util.ClientIP(r, s.cfg.TrustedProxyCIDRs)
	if site.BindIPPrefix && util.BindIP(s.cfg.IPBindingSecret(), ip) != c.IPBind {
		s.store.FailChallenge(id, 3)
		writeError(w, http.StatusBadRequest, "network-binding-mismatch")
		return
	}

	var req model.VerifyChallengeRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		return
	}
	if req.SessionID == "" || req.SessionID != c.SessionID {
		s.store.FailChallenge(id, 3)
		writeError(w, http.StatusBadRequest, "session-binding-mismatch")
		return
	}
	if err := challenge.Verify(c, req.Proof); err != nil {
		s.store.FailChallenge(id, 3)
		writeJSON(w, http.StatusBadRequest, model.VerifyChallengeResponse{
			Success: false, Error: "invalid-proof",
		})
		return
	}
	if !s.store.ConsumeChallenge(id) {
		writeError(w, http.StatusBadRequest, "challenge-already-consumed")
		return
	}
	tok, _, err := token.Mint(
		s.signer, c.SiteKey, c.Action, c.Hostname, c.IPBind,
		c.Kind, c.RiskScore, time.Duration(site.TokenTTLSeconds)*time.Second,
	)
	if err != nil {
		s.logger.Printf("mint token: %v", err)
		writeError(w, http.StatusInternalServerError, "internal-error")
		return
	}
	writeJSON(w, http.StatusOK, model.VerifyChallengeResponse{Success: true, Token: tok})
}

func (s *Server) siteVerify(w http.ResponseWriter, r *http.Request) {
	s.stats.Requests.Add(1)
	req, err := s.parseSiteVerify(w, r)
	if err != nil {
		s.stats.VerifyFailure.Add(1)
		writeJSON(w, http.StatusBadRequest, model.SiteVerifyResponse{
			Success: false, ErrorCodes: []string{"bad-request"},
		})
		return
	}
	site, ok := s.cfg.Sites.GetBySecret(req.Secret)
	if !ok {
		s.stats.VerifyFailure.Add(1)
		writeJSON(w, http.StatusOK, model.SiteVerifyResponse{
			Success: false, ErrorCodes: []string{"invalid-input-secret"},
		})
		return
	}
	claims, err := s.signer.Verify(req.Response, time.Now().UTC())
	if err != nil {
		s.stats.VerifyFailure.Add(1)
		code := "invalid-input-response"
		if strings.Contains(err.Error(), "expired") {
			code = "timeout-or-duplicate"
		}
		writeJSON(w, http.StatusOK, model.SiteVerifyResponse{
			Success: false, ErrorCodes: []string{code},
		})
		return
	}
	if claims.SiteKey != site.Key {
		s.stats.VerifyFailure.Add(1)
		writeJSON(w, http.StatusOK, model.SiteVerifyResponse{
			Success: false, ErrorCodes: []string{"sitekey-secret-mismatch"},
		})
		return
	}
	if req.ExpectedAction == "" {
		s.stats.VerifyFailure.Add(1)
		writeJSON(w, http.StatusOK, model.SiteVerifyResponse{
			Success: false, ErrorCodes: []string{"missing-expected-action"},
		})
		return
	}
	if req.ExpectedHostname == "" {
		s.stats.VerifyFailure.Add(1)
		writeJSON(w, http.StatusOK, model.SiteVerifyResponse{
			Success: false, ErrorCodes: []string{"missing-expected-hostname"},
		})
		return
	}
	if req.ExpectedAction != claims.Action {
		s.stats.VerifyFailure.Add(1)
		writeJSON(w, http.StatusOK, model.SiteVerifyResponse{
			Success: false, ErrorCodes: []string{"action-mismatch"},
		})
		return
	}
	if config.NormalizeHostname(req.ExpectedHostname) != config.NormalizeHostname(claims.Hostname) {
		s.stats.VerifyFailure.Add(1)
		writeJSON(w, http.StatusOK, model.SiteVerifyResponse{
			Success: false, ErrorCodes: []string{"hostname-mismatch"},
		})
		return
	}
	if site.BindIPPrefix {
		if req.RemoteIP == "" {
			s.stats.VerifyFailure.Add(1)
			writeJSON(w, http.StatusOK, model.SiteVerifyResponse{
				Success: false, ErrorCodes: []string{"missing-remoteip"},
			})
			return
		}
		if util.BindIP(s.cfg.IPBindingSecret(), req.RemoteIP) != claims.IPBind {
			s.stats.VerifyFailure.Add(1)
			writeJSON(w, http.StatusOK, model.SiteVerifyResponse{
				Success: false, ErrorCodes: []string{"remoteip-mismatch"},
			})
			return
		}
	}
	if !s.store.ConsumeJTI(claims.JTI, time.Unix(claims.ExpiresAt, 0)) {
		s.stats.Replays.Add(1)
		s.stats.VerifyFailure.Add(1)
		writeJSON(w, http.StatusOK, model.SiteVerifyResponse{
			Success: false, ErrorCodes: []string{"timeout-or-duplicate"},
		})
		return
	}
	s.stats.VerifySuccess.Add(1)
	writeJSON(w, http.StatusOK, model.SiteVerifyResponse{
		Success:       true,
		ChallengeTS:   time.Unix(claims.IssuedAt, 0).UTC().Format(time.RFC3339Nano),
		Hostname:      claims.Hostname,
		Action:        claims.Action,
		RiskScore:     claims.RiskScore,
		RiskBucket:    claims.RiskBucket,
		ChallengeKind: claims.ChallengeKind,
		ErrorCodes:    []string{},
	})
}

func (s *Server) parseSiteVerify(w http.ResponseWriter, r *http.Request) (model.SiteVerifyRequest, error) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	var out model.SiteVerifyRequest
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "application/json") {
		dec := json.NewDecoder(io.LimitReader(r.Body, s.cfg.MaxBodyBytes))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&out); err != nil {
			return out, err
		}
	} else {
		if err := r.ParseForm(); err != nil {
			return out, err
		}
		out.Secret = r.Form.Get("secret")
		out.Response = r.Form.Get("response")
		out.RemoteIP = r.Form.Get("remoteip")
		out.ExpectedAction = r.Form.Get("expected_action")
		out.ExpectedHostname = r.Form.Get("expected_hostname")
	}
	if out.Secret == "" || out.Response == "" {
		return out, errors.New("missing secret or response")
	}
	if len(out.Secret) > 512 || len(out.Response) > 8192 || len(out.ExpectedAction) > 64 || len(out.ExpectedHostname) > 253 || len(out.RemoteIP) > 64 {
		return out, errors.New("siteverify field too large")
	}
	return out, nil
}

func (s *Server) originAllowedForHostname(r *http.Request, site config.Site, expectedHostname string) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	originHost := config.NormalizeHostname(u.Hostname())
	expectedHost := config.NormalizeHostname(expectedHostname)
	return site.AllowsHostname(originHost) && originHost == expectedHost
}

func (s *Server) setCORS(w http.ResponseWriter, r *http.Request) {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}
}

func (s *Server) options(w http.ResponseWriter, r *http.Request) {
	// A preflight does not include the eventual custom request header value.
	// Reflecting Origin here only permits the browser to send the POST; the POST
	// itself still validates site_key + hostname + Origin before doing any work.
	s.setCORS(w, r)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-BerryShield-Site-Key")
	w.Header().Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid-json")
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "multiple-json-values")
		return errors.New("multiple json values")
	}
	return nil
}

func (s *Server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/metrics" && r.URL.Path != "/healthz" {
			// CORS is reflected only after site validation inside handlers.
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Printf("panic: %v", rec)
				writeError(w, http.StatusInternalServerError, "internal-error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) LogConfig() string {
	return fmt.Sprintf("env=%s addr=%s reputation=%t remote_risk=%t",
		s.cfg.Environment, s.cfg.Addr, s.cfg.ReputationURL != "", s.cfg.RiskEngineURL != "")
}
