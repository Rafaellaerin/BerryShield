package challenge

import (
	"crypto/sha256"
	"strconv"
	"testing"
	"time"

	"github.com/berryshield/berryshield/services/gateway/internal/model"
)

func TestLeadingZeroBits(t *testing.T) {
	if got := leadingZeroBits([]byte{0x00, 0x0f}); got != 12 {
		t.Fatalf("got %d want 12", got)
	}
}

func TestPOWVerification(t *testing.T) {
	c := model.Challenge{
		Kind:      "pow",
		ExpiresAt: time.Now().Add(time.Minute),
		Params: map[string]any{
			"seed": "test", "difficulty_bits": 8, "max_nonce": 100000,
		},
	}
	var nonce uint64
	for ; nonce < 100000; nonce++ {
		sum := sha256.Sum256([]byte("test:" + strconv.FormatUint(nonce, 10)))
		if leadingZeroBits(sum[:]) >= 8 {
			break
		}
	}
	if err := Verify(c, model.Proof{Kind: "pow", Nonce: nonce}); err != nil {
		t.Fatal(err)
	}
}

func TestInteractiveRejectsFabricatedInstantProof(t *testing.T) {
	c, err := New("interactive", "site", "login", "example.test", "s", "", 70, nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	p := model.Proof{Kind: "interactive", HoldMS: 900, EventCount: 3, PointerVariance: 0.2, Nonce: 0}
	if err := Verify(c, p); err == nil {
		t.Fatal("expected an immediately submitted interactive proof to fail")
	}
}

func TestInteractiveRequiresWorkProof(t *testing.T) {
	c, err := New("interactive", "site", "login", "example.test", "s", "", 70, nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c.CreatedAt = time.Now().Add(-2 * time.Second)
	seed := c.Params["pow_seed"].(string)
	bits := intFromAny(c.Params["pow_bits"])
	maxNonce := uint64(intFromAny(c.Params["pow_max_nonce"]))
	var nonce uint64
	for ; nonce <= maxNonce; nonce++ {
		sum := sha256.Sum256([]byte(seed + ":" + strconv.FormatUint(nonce, 10)))
		if leadingZeroBits(sum[:]) >= bits {
			break
		}
	}
	if nonce > maxNonce {
		t.Fatal("could not solve test work proof")
	}
	p := model.Proof{Kind: "interactive", HoldMS: 900, EventCount: 3, PointerVariance: 0.2, Nonce: nonce}
	if err := Verify(c, p); err != nil {
		t.Fatalf("valid interactive proof rejected: %v", err)
	}
}
