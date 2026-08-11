package risk

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/berryshield/berryshield/services/gateway/internal/config"
	"github.com/berryshield/berryshield/services/gateway/internal/model"
)

type remoteSite struct {
	RateLimitPerMinute int               `json:"rate_limit_per_minute"`
	Thresholds         config.Thresholds `json:"thresholds"`
}

type Remote struct {
	URL      string
	Client   *http.Client
	Fallback Scorer
}

func NewRemote(url string, fallback Scorer) *Remote {
	return &Remote{
		URL:      url,
		Client:   &http.Client{Timeout: 800 * time.Millisecond},
		Fallback: fallback,
	}
}

func (r *Remote) Score(in model.RiskInput, site config.Site) model.RiskDecision {
	payload := struct {
		Input model.RiskInput `json:"input"`
		Site  remoteSite      `json:"site"`
	}{
		Input: in,
		Site: remoteSite{
			RateLimitPerMinute: site.RateLimitPerMinute,
			Thresholds:         site.Thresholds,
		},
	}
	b, _ := json.Marshal(payload)

	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL+"/v1/score", bytes.NewReader(b))
	if err != nil {
		return r.Fallback.Score(in, site)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.Client.Do(req)
	if err != nil {
		return r.Fallback.Score(in, site)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return r.Fallback.Score(in, site)
	}
	var out model.RiskDecision
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Decision == "" {
		return r.Fallback.Score(in, site)
	}
	return out
}
