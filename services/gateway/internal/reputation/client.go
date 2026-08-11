package reputation

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/berryshield/berryshield/services/gateway/internal/model"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTP: &http.Client{
			Timeout: 700 * time.Millisecond,
			Transport: &http.Transport{
				DialContext:         (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext,
				TLSHandshakeTimeout: 300 * time.Millisecond,
				MaxIdleConns:        32,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}
}

func (c *Client) Lookup(ctx context.Context, ip, ua, language string) model.Reputation {
	if c.BaseURL == "" || net.ParseIP(ip) == nil {
		return model.Reputation{}
	}
	if len(ua) > 512 {
		ua = ua[:512]
	}
	if len(language) > 128 {
		language = language[:128]
	}
	payload, err := json.Marshal(map[string]string{
		"ip": ip, "ua": ua, "lang": language,
	})
	if err != nil {
		return model.Reputation{Warnings: []string{"reputation-request-encode-failed"}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/ip", bytes.NewReader(payload))
	if err != nil {
		return model.Reputation{Warnings: []string{"reputation-request-build-failed"}}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return model.Reputation{Warnings: []string{"reputation-unavailable"}}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return model.Reputation{Warnings: []string{"reputation-non-200"}}
	}
	var out model.Reputation
	dec := json.NewDecoder(io.LimitReader(resp.Body, 64<<10))
	if err := dec.Decode(&out); err != nil {
		return model.Reputation{Warnings: []string{"reputation-invalid-json"}}
	}
	return out
}
