package store

import (
	"sync"
	"time"

	"github.com/berryshield/berryshield/services/gateway/internal/model"
)

type rateWindow struct {
	Start time.Time
	Count int
}

type Memory struct {
	mu         sync.Mutex
	challenges map[string]model.Challenge
	spent      map[string]time.Time
	rates      map[string]rateWindow
}

func NewMemory() *Memory {
	return &Memory{
		challenges: make(map[string]model.Challenge),
		spent:      make(map[string]time.Time),
		rates:      make(map[string]rateWindow),
	}
}

func (m *Memory) PutChallenge(c model.Challenge) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gcLocked(time.Now())
	m.challenges[c.ID] = c
}

func (m *Memory) GetChallenge(id string) (model.Challenge, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gcLocked(time.Now())
	c, ok := m.challenges[id]
	return c, ok
}

func (m *Memory) FailChallenge(id string, maxAttempts int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.challenges[id]
	if !ok {
		return
	}
	c.Attempts++
	if c.Attempts >= maxAttempts {
		delete(m.challenges, id)
		return
	}
	m.challenges[id] = c
}

func (m *Memory) ConsumeChallenge(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.challenges[id]; !ok {
		return false
	}
	delete(m.challenges, id)
	return true
}

func (m *Memory) ConsumeJTI(jti string, expiresAt time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gcLocked(time.Now())
	if _, exists := m.spent[jti]; exists {
		return false
	}
	m.spent[jti] = expiresAt
	return true
}

func (m *Memory) AllowRate(key string, limit int, window time.Duration) (bool, int) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.rates[key]
	if r.Start.IsZero() || now.Sub(r.Start) >= window {
		r = rateWindow{Start: now, Count: 0}
	}
	r.Count++
	m.rates[key] = r
	return r.Count <= limit, r.Count
}

func (m *Memory) gcLocked(now time.Time) {
	for id, c := range m.challenges {
		if now.After(c.ExpiresAt) {
			delete(m.challenges, id)
		}
	}
	for jti, exp := range m.spent {
		if now.After(exp) {
			delete(m.spent, jti)
		}
	}
	for k, r := range m.rates {
		if now.Sub(r.Start) > 2*time.Minute {
			delete(m.rates, k)
		}
	}
}
