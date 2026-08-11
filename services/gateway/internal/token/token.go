package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/berryshield/berryshield/services/gateway/internal/model"
)

var rawURL = base64.RawURLEncoding

type Signer struct {
	activeSecret []byte
	kid          string
	verifyKeys   map[string][]byte
}

func NewSigner(secret, kid string) *Signer {
	return NewSignerWithKeys(secret, kid, nil)
}

func NewSignerWithKeys(secret, kid string, previous map[string]string) *Signer {
	keys := make(map[string][]byte, len(previous)+1)
	keys[kid] = []byte(secret)
	for previousKID, previousSecret := range previous {
		if previousKID != "" && previousKID != kid {
			keys[previousKID] = []byte(previousSecret)
		}
	}
	return &Signer{activeSecret: []byte(secret), kid: kid, verifyKeys: keys}
}

func NewJTI() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return rawURL.EncodeToString(b), nil
}

func (s *Signer) Sign(claims model.TokenClaims) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "BST", "kid": s.kid}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := rawURL.EncodeToString(hb) + "." + rawURL.EncodeToString(pb)
	sig := macWithKey(s.activeSecret, unsigned)
	return unsigned + "." + rawURL.EncodeToString(sig), nil
}

func (s *Signer) Verify(tok string, now time.Time) (model.TokenClaims, error) {
	var claims model.TokenClaims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return claims, errors.New("malformed token")
	}
	headerBytes, err := rawURL.DecodeString(parts[0])
	if err != nil {
		return claims, errors.New("malformed header")
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg != "HS256" || header.Typ != "BST" || header.KID == "" {
		return claims, errors.New("invalid token header")
	}
	key, ok := s.verifyKeys[header.KID]
	if !ok {
		return claims, errors.New("unknown signing key")
	}
	unsigned := parts[0] + "." + parts[1]
	got, err := rawURL.DecodeString(parts[2])
	if err != nil {
		return claims, errors.New("malformed signature")
	}
	want := macWithKey(key, unsigned)
	if !hmac.Equal(got, want) {
		return claims, errors.New("invalid signature")
	}
	pb, err := rawURL.DecodeString(parts[1])
	if err != nil {
		return claims, errors.New("malformed payload")
	}
	if err := json.Unmarshal(pb, &claims); err != nil {
		return claims, errors.New("invalid payload")
	}
	if claims.Issuer != "berryshield" || claims.Audience != "siteverify" {
		return claims, errors.New("invalid token audience")
	}
	if claims.ExpiresAt <= now.Unix() {
		return claims, errors.New("expired token")
	}
	if claims.IssuedAt > now.Add(30*time.Second).Unix() {
		return claims, errors.New("token issued in future")
	}
	if claims.JTI == "" || claims.SiteKey == "" || claims.Hostname == "" || claims.Action == "" {
		return claims, errors.New("missing token claims")
	}
	return claims, nil
}

func macWithKey(key []byte, v string) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(v))
	return m.Sum(nil)
}

func RiskBucket(score int) string {
	switch {
	case score < 30:
		return "low"
	case score < 62:
		return "medium"
	case score < 92:
		return "high"
	default:
		return "critical"
	}
}

func Mint(s *Signer, siteKey, action, hostname, ipBind, challenge string, score int, ttl time.Duration) (string, model.TokenClaims, error) {
	jti, err := NewJTI()
	if err != nil {
		return "", model.TokenClaims{}, fmt.Errorf("jti: %w", err)
	}
	now := time.Now().UTC()
	claims := model.TokenClaims{
		Issuer:        "berryshield",
		Audience:      "siteverify",
		SiteKey:       siteKey,
		Action:        action,
		Hostname:      hostname,
		JTI:           jti,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(ttl).Unix(),
		RiskScore:     score,
		RiskBucket:    RiskBucket(score),
		ChallengeKind: challenge,
		IPBind:        ipBind,
	}
	tok, err := s.Sign(claims)
	return tok, claims, err
}
