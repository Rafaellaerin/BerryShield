package challenge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/berryshield/berryshield/services/gateway/internal/model"
)

func NewID() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "bsc_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func NewSeed() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func New(kind, siteKey, action, hostname, sessionID, ipBind string, score int, tags []string, ttl time.Duration) (model.Challenge, error) {
	id, err := NewID()
	if err != nil {
		return model.Challenge{}, err
	}
	now := time.Now().UTC()
	c := model.Challenge{
		ID: id, SiteKey: siteKey, Action: action, Hostname: hostname,
		SessionID: sessionID, IPBind: ipBind, RiskScore: score,
		RiskTags: tags, Kind: kind, CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	switch kind {
	case "pow":
		seed, err := NewSeed()
		if err != nil {
			return model.Challenge{}, err
		}
		difficulty := 16
		if score >= 50 {
			difficulty = 17
		}
		c.Params = map[string]any{
			"seed":            seed,
			"difficulty_bits": difficulty,
			"algorithm":       "sha256",
			"max_nonce":       20000000,
		}
	case "interactive":
		seed, err := NewSeed()
		if err != nil {
			return model.Challenge{}, err
		}
		c.Params = map[string]any{
			"mode":          "press_hold",
			"min_hold_ms":   850,
			"max_hold_ms":   7000,
			"min_events":    2,
			"pow_seed":      seed,
			"pow_bits":      14,
			"pow_max_nonce": 10000000,
		}
	default:
		return model.Challenge{}, fmt.Errorf("unsupported challenge kind %q", kind)
	}
	return c, nil
}

func Verify(c model.Challenge, p model.Proof) error {
	if time.Now().After(c.ExpiresAt) {
		return errors.New("challenge expired")
	}
	if p.Kind != c.Kind {
		return errors.New("proof kind mismatch")
	}
	switch c.Kind {
	case "pow":
		seed, _ := c.Params["seed"].(string)
		difficulty := intFromAny(c.Params["difficulty_bits"])
		maxNonce := uint64(intFromAny(c.Params["max_nonce"]))
		if p.Nonce > maxNonce {
			return errors.New("nonce out of range")
		}
		msg := seed + ":" + strconv.FormatUint(p.Nonce, 10)
		sum := sha256.Sum256([]byte(msg))
		if leadingZeroBits(sum[:]) < difficulty {
			return errors.New("invalid proof of work")
		}
		return nil
	case "interactive":
		minHold := intFromAny(c.Params["min_hold_ms"])
		maxHold := intFromAny(c.Params["max_hold_ms"])
		minEvents := intFromAny(c.Params["min_events"])
		if p.HoldMS < minHold || p.HoldMS > maxHold {
			return errors.New("hold duration outside accepted range")
		}
		// Client-reported hold_ms is forgeable. Enforce a server-observed elapsed
		// floor as well (with a small network/scheduler tolerance).
		if time.Since(c.CreatedAt) < time.Duration(max(0, minHold-100))*time.Millisecond {
			return errors.New("interactive proof arrived too quickly")
		}
		if p.EventCount < minEvents {
			return errors.New("insufficient interaction events")
		}
		if p.PointerVariance < 0 || p.PointerVariance > 10 {
			return errors.New("invalid interaction summary")
		}
		seed, _ := c.Params["pow_seed"].(string)
		bits := intFromAny(c.Params["pow_bits"])
		maxNonce := uint64(intFromAny(c.Params["pow_max_nonce"]))
		if seed == "" || bits < 4 || p.Nonce > maxNonce {
			return errors.New("invalid interactive work proof")
		}
		msg := seed + ":" + strconv.FormatUint(p.Nonce, 10)
		sum := sha256.Sum256([]byte(msg))
		if leadingZeroBits(sum[:]) < bits {
			return errors.New("invalid interactive work proof")
		}
		return nil
	default:
		return errors.New("unsupported challenge")
	}
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if (x & (1 << uint(bit))) == 0 {
				n++
			} else {
				return n
			}
		}
	}
	return n
}

func intFromAny(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	default:
		return 0
	}
}
