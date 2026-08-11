package token

import (
	"strings"
	"testing"
	"time"
)

func TestSignerAcceptsPreviousKeyByKID(t *testing.T) {
	oldSecret := strings.Repeat("o", 32)
	newSecret := strings.Repeat("n", 32)
	oldSigner := NewSigner(oldSecret, "old-v1")
	tok, _, err := Mint(oldSigner, "site", "login", "example.test", "", "passive", 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rotated := NewSignerWithKeys(newSecret, "new-v2", map[string]string{"old-v1": oldSecret})
	claims, err := rotated.Verify(tok, time.Now())
	if err != nil {
		t.Fatalf("rotated signer should verify previous-key token: %v", err)
	}
	if claims.SiteKey != "site" || claims.Action != "login" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestSignerRejectsUnknownKID(t *testing.T) {
	oldSigner := NewSigner(strings.Repeat("o", 32), "old-v1")
	tok, _, err := Mint(oldSigner, "site", "login", "example.test", "", "passive", 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rotated := NewSigner(strings.Repeat("n", 32), "new-v2")
	if _, err := rotated.Verify(tok, time.Now()); err == nil || !strings.Contains(err.Error(), "unknown signing key") {
		t.Fatalf("expected unknown key error, got %v", err)
	}
}
