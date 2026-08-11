# Architecture

## Components

### Browser SDK — TypeScript/JavaScript

The SDK collects a deliberately bounded telemetry envelope: user-agent/platform consistency, language/timezone, coarse screen buckets, hardware hints, storage/WebCrypto/WASM availability, hashed WebGL vendor/renderer values, timing jitter, and aggregated interaction statistics. It does not collect typed text, pointer coordinates, browsing history, canvas images, fonts, or raw WebGL strings.

Telemetry is **evidence, not identity**. Every client field can be forged.

### Gateway — Go

The gateway is the policy and token authority. It owns site configuration, checks hostname and Origin, derives client IP from the network connection/trusted proxy chain, rate-limits by site + network prefix + action, calls reputation and risk services with short deadlines, creates/consumes challenge state, signs final tokens with an active HMAC key/key-ID, verifies a bounded previous-key ring for rotation, and consumes token JTIs at site verification.

### Reputation service — Python

The service queries enabled providers concurrently and applies a max-plus-consensus aggregate. Integrations are isolated: an unavailable provider adds a warning and the gateway can fall back to local risk rather than fail the site closed.

Supported adapters:

- local heuristic provider;
- AbuseIPDB;
- IPQualityScore (POST JSON with the API key in a header, avoiding reputation context in the request URL);
- MaxMind Insights.

### Risk engine — Rust

The Rust service mirrors the local Go scorer and lets scoring be isolated/deployed independently. If it times out or fails, the gateway uses its local Go scorer. Site secrets are never sent to the risk service.

### WebAssembly probe

`crates/probe-wasm/dist/probe.wasm` is a tiny, directly-instantiable module exporting `mix32`. It proves that the browser can fetch/instantiate/execute the configured WASM path and provides one low-value consistency signal. It is not a cryptographic attestation mechanism.

The Rust crate is a richer rebuildable source example.

## Request flow

1. SDK records aggregate behavior and environment signals.
2. Browser calls `POST /v1/challenge` with public site key, action, normalized hostname, random session ID, and telemetry.
3. Gateway validates site/action/hostname/Origin and enforces request limits. If `Origin` is present, its normalized hostname must equal the hostname being requested for the challenge, preventing confusion between sibling hostnames that share one site key.
4. Gateway derives the network prefix and requests reputation.
5. Risk engine returns a 0–100 score and decision tags.
6. `allow`: gateway returns a signed short-lived token immediately.
7. `pow`: gateway returns a random seed + SHA-256 leading-zero difficulty; browser solves it with WebCrypto and submits the nonce together with the original session ID.
8. `interactive`: gateway returns an accessible press-and-hold policy plus a low-cost PoW seed; the browser submits aggregate interaction values and work nonce. The server also enforces a minimum observed elapsed time, so a fabricated large `hold_ms` cannot be accepted immediately.
9. `block`: no proof token is issued.
10. Protected application sends the token and its server secret to `/v1/siteverify`.
11. Gateway verifies signature, issuer/audience, expiration, site, expected action/hostname, optional IP-prefix binding (requiring `remoteip` when enabled), then atomically consumes JTI.

## State model

Three state classes must be atomic:

- challenge IDs and attempt counters;
- rate-limit windows;
- consumed token JTIs.

The included `store.Memory` implementation provides correct semantics for one gateway process. A production multi-replica deployment needs a shared transactional/atomic store before scaling horizontally.

## Failures

- Reputation unavailable: add warning, continue with local information.
- Rust scorer unavailable: Go local scorer.
- WebAssembly unavailable: low-weight risk signal; never a standalone block.
- WebCrypto unavailable: policy may escalate away from PoW or the client will fail the computational challenge; deployments should monitor this and tune for supported browsers.
- Interactive challenge unavailable: application should offer a recovery/support path rather than an infinite loop.
