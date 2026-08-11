package risk

import (
	"testing"

	"github.com/berryshield/berryshield/services/gateway/internal/config"
	"github.com/berryshield/berryshield/services/gateway/internal/model"
)

func testSite() config.Site {
	return config.Site{
		RateLimitPerMinute: 60,
		Thresholds:         config.Thresholds{Pow: 30, Interactive: 62, Block: 92},
	}
}

func TestHeadlessEscalates(t *testing.T) {
	in := model.RiskInput{
		UserAgent: "HeadlessChrome",
		Telemetry: model.Telemetry{Client: model.ClientSignals{
			UserAgent: "HeadlessChrome", Webdriver: true, SecureContext: true,
			WebCryptoAvailable: true, WASMAvailable: true,
		}},
	}
	d := NewLocal().Score(in, testSite())
	if d.Decision == "allow" {
		t.Fatalf("expected escalation, got %+v", d)
	}
}

func TestLowRiskAllows(t *testing.T) {
	in := model.RiskInput{
		UserAgent: "Mozilla/5.0",
		Telemetry: model.Telemetry{Client: model.ClientSignals{
			UserAgent: "Mozilla/5.0", SecureContext: true, WebCryptoAvailable: true,
			WASMAvailable: true, Languages: []string{"pt-BR"}, Platform: "Win32",
		}},
	}
	d := NewLocal().Score(in, testSite())
	if d.Decision != "allow" {
		t.Fatalf("expected allow, got %+v", d)
	}
}
