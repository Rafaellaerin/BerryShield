package config

import "testing"

func TestNormalizeHostname(t *testing.T) {
	cases := map[string]string{
		"Example.COM.":      "example.com",
		"example.com:443":   "example.com",
		"[2001:db8::1]:443": "2001:db8::1",
		"[2001:db8::1]":     "2001:db8::1",
	}
	for in, want := range cases {
		if got := NormalizeHostname(in); got != want {
			t.Fatalf("NormalizeHostname(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAllowsHostnameWildcardDoesNotMatchApex(t *testing.T) {
	s := Site{Hostnames: []string{"*.example.com"}}
	if !s.AllowsHostname("api.EXAMPLE.com.") {
		t.Fatal("wildcard should match a subdomain")
	}
	if s.AllowsHostname("example.com") {
		t.Fatal("wildcard must not match apex")
	}
	if s.AllowsHostname("evil-example.com") {
		t.Fatal("wildcard must respect label boundary")
	}
}

func TestParsePreviousSigningKeys(t *testing.T) {
	keys, err := parsePreviousSigningKeys(`{"old-v1":"01234567890123456789012345678901"}`, "new-v2")
	if err != nil {
		t.Fatal(err)
	}
	if keys["old-v1"] == "" {
		t.Fatal("previous key missing")
	}
	if _, err := parsePreviousSigningKeys(`{"new-v2":"01234567890123456789012345678901"}`, "new-v2"); err == nil {
		t.Fatal("active kid must not also appear as previous")
	}
	if _, err := parsePreviousSigningKeys(`{"old-v1":"short"}`, "new-v2"); err == nil {
		t.Fatal("short previous key must fail")
	}
}

func TestIPBindingSecretFallsBackToSigningSecret(t *testing.T) {
	r := Runtime{SigningSecret: "signing", BindingSecret: "binding"}
	if got := r.IPBindingSecret(); got != "binding" {
		t.Fatalf("got %q", got)
	}
	r.BindingSecret = ""
	if got := r.IPBindingSecret(); got != "signing" {
		t.Fatalf("fallback got %q", got)
	}
}
