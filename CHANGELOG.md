# Changelog

All notable changes to BerryShield are documented here.

## 0.1.0 — 2026-08-11

Initial public reference release.

### Added

- Go anti-bot gateway with adaptive `allow` / `pow` / `interactive` / `block` decisions.
- HMAC-signed, action/hostname-bound, short-lived, one-time BST proof tokens.
- Signing `kid` keyring with previous-key verification for bounded rotation windows.
- Optional IPv4 /24 and IPv6 /56 network-prefix binding using a dedicated HMAC secret.
- Session-bound one-time challenge state, attempt limits, rate windows, and trusted-proxy-aware client-IP derivation.
- TypeScript browser SDK with bounded environment signals, aggregate behavior telemetry, WebCrypto PoW, and keyboard-operable press-and-hold fallback.
- Tiny prebuilt WebAssembly execution probe plus a Rust `wasm-bindgen` source crate.
- Optional Rust isolated risk scorer with Go fallback.
- Python IP-reputation service with local heuristics and optional AbuseIPDB, IPQualityScore, and MaxMind adapters.
- Low-volume authorized red-team regression harness for BerryShield replay/origin/automation scenarios.
- Sanitized structural HAR analyzer and research notes based on supplied traces.
- OpenAPI contract, Docker Compose stack, demo, CI, threat model, privacy/operations guidance, production checklist, and coordinated-disclosure policy.

### Security properties exercised

- token replay rejection;
- challenge replay rejection;
- action and hostname binding;
- exact browser Origin ↔ challenge hostname binding;
- network-prefix mismatch rejection;
- forwarded-header trust boundary;
- provider/scorer failure isolation;
- interactive server-observed elapsed floor;
- bounded parser/body handling.
