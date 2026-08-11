package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/berryshield/berryshield/services/gateway/internal/config"
	"github.com/berryshield/berryshield/services/gateway/internal/model"
)

func testServer() *Server {
	site := config.Site{
		Key: "bs_test_public", Secret: "bs_test_secret_1234567890",
		Hostnames: []string{"example.test"}, TokenTTLSeconds: 120,
		ChallengeTTLSeconds: 180, RateLimitPerMinute: 60, BindIPPrefix: false,
		Thresholds: config.Thresholds{Pow: 30, Interactive: 62, Block: 92},
	}
	return New(config.Runtime{
		Environment: "test", SigningSecret: "01234567890123456789012345678901",
		SigningKeyID: "test-v1", Sites: config.NewRegistry([]config.Site{site}),
		MaxBodyBytes: 65536,
	}, log.New(io.Discard, "", 0))
}

func lowRiskChallengeBody() []byte {
	body := model.ChallengeRequest{
		SiteKey: "bs_test_public", Action: "login", Hostname: "example.test", SessionID: "bss_test",
		Telemetry: model.Telemetry{Client: model.ClientSignals{
			SDKVersion: "0.1.0", UserAgent: "Mozilla/5.0", Platform: "Win32",
			Languages: []string{"en-US"}, SecureContext: true, CookieEnabled: true,
			LocalStorageOK: true, SessionStorageOK: true, WASMAvailable: true,
			WASMMix: 123, WebCryptoAvailable: true, HardwareConcurrency: 8,
		}},
	}
	b, _ := json.Marshal(body)
	return b
}

func TestAllowThenSiteVerifyAndReplay(t *testing.T) {
	s := testServer()
	h := s.Handler()
	req := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(lowRiskChallengeBody()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://example.test")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://example.test" {
		t.Fatalf("cors=%q", got)
	}
	var ch model.ChallengeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	if ch.Decision != "allow" || ch.Token == "" {
		t.Fatalf("unexpected challenge: %+v", ch)
	}

	verify := func() model.SiteVerifyResponse {
		form := "secret=bs_test_secret_1234567890&response=" + ch.Token + "&expected_action=login&expected_hostname=example.test"
		r := httptest.NewRequest(http.MethodPost, "/v1/siteverify", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("verify status=%d body=%s", w.Code, w.Body.String())
		}
		var out model.SiteVerifyResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	first := verify()
	if !first.Success {
		t.Fatalf("first verify failed: %+v", first)
	}
	second := verify()
	if second.Success || len(second.ErrorCodes) == 0 || second.ErrorCodes[0] != "timeout-or-duplicate" {
		t.Fatalf("replay should fail: %+v", second)
	}
}

func TestPreflightReflectsOriginButPOSTEnforcesSite(t *testing.T) {
	h := testServer().Handler()
	pre := httptest.NewRequest(http.MethodOptions, "/v1/challenge", nil)
	pre.Header.Set("Origin", "https://evil.test")
	pre.Header.Set("Access-Control-Request-Method", "POST")
	pre.Header.Set("Access-Control-Request-Headers", "content-type,x-berryshield-site-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, pre)
	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight=%d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://evil.test" {
		t.Fatal("preflight should be syntactically allowed")
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(lowRiskChallengeBody()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.test")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("POST from wrong origin status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("forbidden POST must not get CORS allow origin")
	}
}

func TestChallengeVerifyRequiresMatchingSession(t *testing.T) {
	s := testServer()
	h := s.Handler()
	var body model.ChallengeRequest
	if err := json.Unmarshal(lowRiskChallengeBody(), &body); err != nil {
		t.Fatal(err)
	}
	body.Telemetry.Client.Webdriver = true
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://example.test")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("issue status=%d body=%s", w.Code, w.Body.String())
	}
	var ch model.ChallengeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	if ch.Decision != "pow" || ch.ChallengeID == "" {
		t.Fatalf("expected pow challenge: %+v", ch)
	}

	verifyBody := []byte(`{"session_id":"bss_wrong","proof":{"kind":"pow","nonce":0}}`)
	vr := httptest.NewRequest(http.MethodPost, "/v1/challenge/"+ch.ChallengeID+"/verify", bytes.NewReader(verifyBody))
	vr.Header.Set("Content-Type", "application/json")
	vr.Header.Set("Origin", "https://example.test")
	vw := httptest.NewRecorder()
	h.ServeHTTP(vw, vr)
	if vw.Code != http.StatusBadRequest || !strings.Contains(vw.Body.String(), "session-binding-mismatch") {
		t.Fatalf("session mismatch status=%d body=%s", vw.Code, vw.Body.String())
	}
}

func TestBoundTokenRequiresRemoteIPAndAcceptsCorrectPrefix(t *testing.T) {
	site := config.Site{
		Key: "bs_bound_public", Secret: "bs_bound_secret_1234567890",
		Hostnames: []string{"example.test"}, TokenTTLSeconds: 120,
		ChallengeTTLSeconds: 180, RateLimitPerMinute: 60, BindIPPrefix: true,
		Thresholds: config.Thresholds{Pow: 30, Interactive: 62, Block: 92},
	}
	s := New(config.Runtime{
		Environment: "test", SigningSecret: "01234567890123456789012345678901",
		SigningKeyID: "test-v1", Sites: config.NewRegistry([]config.Site{site}),
		MaxBodyBytes: 65536,
	}, log.New(io.Discard, "", 0))
	h := s.Handler()

	var body model.ChallengeRequest
	if err := json.Unmarshal(lowRiskChallengeBody(), &body); err != nil {
		t.Fatal(err)
	}
	body.SiteKey = site.Key
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(b))
	req.RemoteAddr = "203.0.113.42:12345"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://example.test")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("issue status=%d body=%s", w.Code, w.Body.String())
	}
	var ch model.ChallengeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	if ch.Token == "" {
		t.Fatalf("expected token: %+v", ch)
	}

	verify := func(remoteIP string) model.SiteVerifyResponse {
		form := "secret=" + site.Secret + "&response=" + ch.Token + "&expected_action=login&expected_hostname=EXAMPLE.TEST."
		if remoteIP != "" {
			form += "&remoteip=" + remoteIP
		}
		r := httptest.NewRequest(http.MethodPost, "/v1/siteverify", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		outW := httptest.NewRecorder()
		h.ServeHTTP(outW, r)
		var out model.SiteVerifyResponse
		if err := json.Unmarshal(outW.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	missing := verify("")
	if missing.Success || len(missing.ErrorCodes) == 0 || missing.ErrorCodes[0] != "missing-remoteip" {
		t.Fatalf("expected missing-remoteip: %+v", missing)
	}
	ok := verify("203.0.113.99") // same IPv4 /24 prefix as challenge issuance
	if !ok.Success {
		t.Fatalf("same-prefix verification should succeed: %+v", ok)
	}
}

func TestOriginMustMatchRequestedHostnameAcrossAllowedSiblings(t *testing.T) {
	site := config.Site{
		Key: "bs_multi_public", Secret: "bs_multi_secret_1234567890",
		Hostnames: []string{"a.example.test", "b.example.test"}, TokenTTLSeconds: 120,
		ChallengeTTLSeconds: 180, RateLimitPerMinute: 60, BindIPPrefix: false,
		Thresholds: config.Thresholds{Pow: 30, Interactive: 62, Block: 92},
	}
	s := New(config.Runtime{
		Environment: "test", SigningSecret: "01234567890123456789012345678901",
		SigningKeyID: "test-v1", Sites: config.NewRegistry([]config.Site{site}),
		MaxBodyBytes: 65536,
	}, log.New(io.Discard, "", 0))
	h := s.Handler()

	var body model.ChallengeRequest
	if err := json.Unmarshal(lowRiskChallengeBody(), &body); err != nil {
		t.Fatal(err)
	}
	body.SiteKey = site.Key
	body.Hostname = "b.example.test"
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://a.example.test")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "origin-not-allowed") {
		t.Fatalf("sibling origin confusion must fail: status=%d body=%s", w.Code, w.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(b))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Origin", "https://b.example.test")
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("matching allowed origin should succeed: status=%d body=%s", w2.Code, w2.Body.String())
	}
}

func TestSiteVerifyRequiresExpectedActionAndHostname(t *testing.T) {
	s := testServer()
	h := s.Handler()
	req := httptest.NewRequest(http.MethodPost, "/v1/challenge", bytes.NewReader(lowRiskChallengeBody()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://example.test")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var ch model.ChallengeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	if ch.Token == "" {
		t.Fatalf("expected passive token: %s", w.Body.String())
	}

	verify := func(form string) model.SiteVerifyResponse {
		r := httptest.NewRequest(http.MethodPost, "/v1/siteverify", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		outW := httptest.NewRecorder()
		h.ServeHTTP(outW, r)
		var out model.SiteVerifyResponse
		if err := json.Unmarshal(outW.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	base := "secret=bs_test_secret_1234567890&response=" + ch.Token
	missingAction := verify(base + "&expected_hostname=example.test")
	if missingAction.Success || len(missingAction.ErrorCodes) == 0 || missingAction.ErrorCodes[0] != "missing-expected-action" {
		t.Fatalf("unexpected missing action result: %+v", missingAction)
	}
	missingHost := verify(base + "&expected_action=login")
	if missingHost.Success || len(missingHost.ErrorCodes) == 0 || missingHost.ErrorCodes[0] != "missing-expected-hostname" {
		t.Fatalf("unexpected missing hostname result: %+v", missingHost)
	}
}
