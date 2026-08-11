# BerryShield

BerryShield is an open-source, self-hosted anti-bot and adaptive CAPTCHA reference platform. It combines server-derived network context, privacy-reduced browser telemetry, IP reputation, configurable risk scoring, one-time proof tokens, proof-of-work, and an accessible interactive fallback.

> **Project status:** security-focused reference implementation / production-minded MVP. The default in-memory state store is intentionally single-instance. Before horizontal scaling, replace it with an atomic shared store (for challenge state, rate windows, and one-time token JTIs) and complete an independent security review.

## Why BerryShield exists

Most modern bot defenses are not "an image CAPTCHA." They are pipelines: browser execution, server-side verification, short-lived tokens, challenge state, telemetry, behavioral/network signals, and adaptive escalation. BerryShield implements that shape while keeping the components inspectable and replaceable.

### Implemented

- **Go gateway** — challenge orchestration, hostname/origin policy, trusted-proxy IP extraction, rate limiting, HMAC-signed proof tokens with key-ID rotation support, one-time server verification, metrics.
- **Rust risk engine** — optional isolated scorer with a Go fallback if it is unavailable.
- **Python reputation service** — concurrent aggregation of local heuristics plus optional AbuseIPDB, IPQualityScore, and MaxMind Insights.
- **TypeScript browser SDK** — privacy-reduced environment/behavior collection, adaptive execution, WebCrypto proof-of-work, accessible press-and-hold + low-cost work challenge.
- **WebAssembly probe** — tiny deterministic client-side execution probe plus a Rust/WASM source crate.
- **Red-team harness** — tests BerryShield itself for replay, origin mismatch, automation signals, malformed telemetry, and escalation behavior. It intentionally does **not** contain code for bypassing third-party CAPTCHA providers.
- **HAR research tooling** — structural, sanitized analysis of the supplied CAPTCHA traces; values such as cookies, opaque challenge tokens, secrets, and payloads are not emitted.

## Architecture

```text
Browser / App
    |
    | 1. POST /v1/challenge + telemetry
    v
+-------------------------+
| Go Gateway              |
| - site/origin policy    |
| - trusted client IP     |
| - per-IP/action rate    |
+-----------+-------------+
            |
       +----+-------------------+
       |                        |
       v                        v
+-------------+          +----------------+
| Python      |          | Rust scorer    |
| Reputation  |          | (optional)     |
+------+------+          +-------+--------+
       |                         |
       +------------+------------+
                    v
             allow / PoW /
          interactive / block
                    |
                    v
            one-time BST token
                    |
                    | 2. application backend
                    | POST /v1/siteverify
                    v
              protected action
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), and [`docs/RISK_ENGINE.md`](docs/RISK_ENGINE.md).

## Quick start

### Native development

Requirements for the components you want to run:

- Go 1.23+
- Python 3.11+
- Node.js 20+ / TypeScript 5+
- Rust stable for the optional isolated scorer and Rust/WASM rebuild

```bash
# 1) Reputation service (optional; local provider works without API keys)
cd services/reputation
PYTHONPATH=. python -m berry_reputation

# 2) Gateway
cd ../gateway
BERRYSHIELD_REPUTATION_URL=http://127.0.0.1:8081 \
BERRYSHIELD_SIGNING_SECRET='replace-this-with-at-least-32-random-bytes' \
go run .

# 3) SDK
cd ../../packages/browser-sdk
npm run build

# 4) Serve repository root and open apps/demo/
python -m http.server 3000 --directory ../..
```

The demo site key defaults to `bs_dev_public`; the development server secret is `bs_dev_secret_change_me`. Never use either development credential in production.

### Docker Compose

```bash
cp .env.example .env
# Replace secrets in .env first.
docker compose up --build
```

Demo: `http://localhost:3000`  
Gateway: `http://localhost:8080`  
Metrics: `http://localhost:8080/metrics`

## Browser integration

```html
<script type="module">
  import { BerryShield } from "/sdk/index.js";

  const shield = new BerryShield({
    siteKey: "bs_dev_public",
    endpoint: "http://localhost:8080",
    wasmProbeUrl: "/probe.wasm"
  });

  const token = await shield.execute("login");
  // Send `token` to your own backend with the protected request.
</script>
```

Your backend must verify the token server-to-server before accepting the protected action:

```bash
curl -sS http://localhost:8080/v1/siteverify \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'secret=YOUR_SERVER_SECRET' \
  --data-urlencode 'response=TOKEN_FROM_BROWSER' \
  --data-urlencode 'expected_action=login' \
  --data-urlencode 'expected_hostname=example.com'
```

A successful token is consumed. Reusing it returns `timeout-or-duplicate`.

## Decision ladder

Default policy:

| Risk | Decision | User impact |
|---:|---|---|
| 0–29 | `allow` | invisible/passive |
| 30–61 | `pow` | WebCrypto computation |
| 62–91 | `interactive` | accessible press-and-hold + low-cost PoW |
| 92–100 | `block` | deny |

Thresholds are per-site configuration and should be tuned with false-positive data, not intuition alone.

## Security invariants

1. A **site key is public**; a site secret is server-only.
2. Browser telemetry is untrusted input. It can raise/lower confidence only within policy; it never authenticates a user.
3. Challenges are session-bound; proof tokens are signed, short-lived, action/hostname-bound, optionally network-prefix-bound, and **single-use**.
4. When a browser sends `Origin`, its normalized hostname must exactly match the requested/challenge hostname and both must be allowed for the site; the application backend also verifies the expected action/hostname.
5. Forwarded IP headers are trusted only when the immediate peer is in configured trusted proxy CIDRs.
6. External reputation failures are isolated and fail open to local scoring; they do not take the protected site down.
7. No single fingerprinting signal should be treated as decisive. Accessibility-safe behavior signals have deliberately low weight.

## Research basis

The supplied HARs showed several recurring architectural patterns: separate challenge acquisition and verification, short-lived/opaque state, client telemetry, challenge-specific request fields, and server-side token verification. The sanitized observations live in [`docs/research/HAR_OBSERVATIONS.md`](docs/research/HAR_OBSERVATIONS.md) and the machine-generated structural summaries in `docs/research/`.

The defensive bypass analysis maps public stealth-browser, cookie/session replay, request mirroring, proxy rotation, and TLS-fingerprint imitation techniques into **BerryShield red-team test cases**, not third-party bypass tooling. See [`docs/research/BYPASS_RESILIENCE.md`](docs/research/BYPASS_RESILIENCE.md).

## Validate the repository

```bash
./scripts/verify.sh
```

The script tests Go, Python, TypeScript/Node, and the prebuilt minimal WASM probe. Rust tests run when Cargo is installed.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Integration guide](docs/INTEGRATION.md)
- [Configuration](docs/CONFIGURATION.md)
- [API](docs/API.md)
- [Risk engine](docs/RISK_ENGINE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Red-team / blue-team plan](docs/RED_TEAM.md)
- [Privacy](docs/PRIVACY.md)
- [Operations and hardening](docs/OPERATIONS.md)
- [Production checklist](docs/PRODUCTION_CHECKLIST.md)
- [Validation report](docs/TEST_REPORT.md)
- [HAR observations](docs/research/HAR_OBSERVATIONS.md)
- [Bypass resilience](docs/research/BYPASS_RESILIENCE.md)
- [Changelog](CHANGELOG.md)

## License and security reports

Licensed under the GNU General Public License v3.0 (GPL-3.0-only). See `SECURITY.md` for coordinated disclosure guidance.
