package reputation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLookupUsesPOSTAndBoundsHeaderDerivedFields(t *testing.T) {
	var method string
	var got map[string]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		if r.URL.RawQuery != "" {
			t.Fatalf("reputation context must not be placed in query string: %q", r.URL.RawQuery)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score":0}`))
	}))
	defer ts.Close()

	c := New(ts.URL)
	_ = c.Lookup(context.Background(), "8.8.8.8", strings.Repeat("u", 2000), strings.Repeat("l", 1000))
	if method != http.MethodPost {
		t.Fatalf("method=%q, want POST", method)
	}
	if len(got["ua"]) != 512 {
		t.Fatalf("ua len=%d, want 512", len(got["ua"]))
	}
	if len(got["lang"]) != 128 {
		t.Fatalf("lang len=%d, want 128", len(got["lang"]))
	}
	if got["ip"] != "8.8.8.8" {
		t.Fatalf("ip=%q", got["ip"])
	}
}
