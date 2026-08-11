package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
)

type Metrics struct {
	Requests      atomic.Uint64
	Challenges    atomic.Uint64
	Allowed       atomic.Uint64
	Pow           atomic.Uint64
	Interactive   atomic.Uint64
	Blocked       atomic.Uint64
	VerifySuccess atomic.Uint64
	VerifyFailure atomic.Uint64
	Replays       atomic.Uint64
	RateLimited   atomic.Uint64
}

func (m *Metrics) Handler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	lines := []string{
		fmt.Sprintf("berryshield_requests_total %d", m.Requests.Load()),
		fmt.Sprintf("berryshield_challenges_total %d", m.Challenges.Load()),
		fmt.Sprintf("berryshield_decision_allow_total %d", m.Allowed.Load()),
		fmt.Sprintf("berryshield_decision_pow_total %d", m.Pow.Load()),
		fmt.Sprintf("berryshield_decision_interactive_total %d", m.Interactive.Load()),
		fmt.Sprintf("berryshield_decision_block_total %d", m.Blocked.Load()),
		fmt.Sprintf("berryshield_siteverify_success_total %d", m.VerifySuccess.Load()),
		fmt.Sprintf("berryshield_siteverify_failure_total %d", m.VerifyFailure.Load()),
		fmt.Sprintf("berryshield_token_replay_total %d", m.Replays.Load()),
		fmt.Sprintf("berryshield_rate_limited_total %d", m.RateLimited.Load()),
	}
	_, _ = w.Write([]byte(strings.Join(lines, "\n") + "\n"))
}
