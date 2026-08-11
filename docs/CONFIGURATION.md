# Configuration Reference

BerryShield separates public site policy from process-level secrets. Environment variables are intended for deployment/runtime settings; multi-site policy can be loaded from JSON.

## Gateway environment

| Variable | Default | Purpose |
|---|---|---|
| `BERRYSHIELD_ENV` | `development` | Set to `production` to enable production configuration checks. |
| `BERRYSHIELD_ADDR` | `:8080` | Gateway listen address. |
| `BERRYSHIELD_SIGNING_SECRET` | development-only fallback | Active HMAC signing secret; required in production and at least 32 bytes. |
| `BERRYSHIELD_SIGNING_KID` | `dev-v1` | Active signing key identifier embedded in BST tokens. |
| `BERRYSHIELD_PREVIOUS_SIGNING_KEYS_JSON` | `{}` | JSON object mapping previous key IDs to 32+ byte secrets accepted only for verification during rotation. |
| `BERRYSHIELD_BINDING_SECRET` | active signing secret | HMAC secret for network-prefix binding. Use a separate stable 32+ byte value in production if binding is enabled. |
| `BERRYSHIELD_SITE_KEY` | `bs_dev_public` | Single-site public key when no sites file is configured. |
| `BERRYSHIELD_SITE_SECRET` | development secret | Single-site server secret when no sites file is configured. |
| `BERRYSHIELD_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated exact/wildcard allowed hostnames for the single-site mode. |
| `BERRYSHIELD_BIND_IP_PREFIX` | `true` natively | Bind proofs to IPv4 /24 or IPv6 /56 HMAC. Evaluate roaming/mobile false positives before enabling. |
| `BERRYSHIELD_SITES_FILE` | unset | Path to a JSON array of site definitions. Overrides single-site environment policy. |
| `BERRYSHIELD_TRUSTED_PROXY_CIDRS` | unset | Comma-separated CIDRs whose forwarded client-IP headers may be trusted. |
| `BERRYSHIELD_MAX_BODY_BYTES` | `65536` | Maximum browser/siteverify request body size. |
| `BERRYSHIELD_REPUTATION_URL` | unset | Internal Python reputation service base URL. |
| `BERRYSHIELD_RISK_ENGINE_URL` | unset | Optional Rust risk service base URL; local Go scorer is fallback. |

### Key rotation example

```env
BERRYSHIELD_SIGNING_KID=2026-08-v2
BERRYSHIELD_SIGNING_SECRET=<new 32+ byte secret>
BERRYSHIELD_PREVIOUS_SIGNING_KEYS_JSON={"2026-07-v1":"<old 32+ byte secret>"}
BERRYSHIELD_BINDING_SECRET=<stable independent 32+ byte secret>
```

Keep the previous signing key only until every token that could have been minted with it has expired, then remove it.

## Multi-site file

See [`../config/sites.example.json`](../config/sites.example.json). Each entry supports:

```json
{
  "site_key": "bs_example_public",
  "secret": "server-only-random-secret",
  "hostnames": ["example.com", "www.example.com"],
  "token_ttl_seconds": 120,
  "challenge_ttl_seconds": 180,
  "rate_limit_per_minute": 60,
  "bind_ip_prefix": false,
  "thresholds": {"pow": 30, "interactive": 62, "block": 92}
}
```

Validation requires `0 < pow < interactive < block <= 100`, token TTL 30–600 seconds, challenge TTL 30–900 seconds, unique site keys/secrets, and at least one hostname. Wildcards use `*.example.com` semantics and do not match the apex `example.com`.

## Reputation service

| Variable | Default | Purpose |
|---|---|---|
| `REPUTATION_HOST` | `0.0.0.0` | Listen host. Keep this service on an internal network. |
| `REPUTATION_PORT` | `8081` | Listen port. |
| `REPUTATION_CACHE_TTL` | `300` | Aggregate cache lifetime in seconds. |
| `BERRYSHIELD_HTTP_LOG` | unset | Set to `1` for minimal method/path logging; query strings are suppressed. |
| `ABUSEIPDB_API_KEY` | unset | Optional AbuseIPDB adapter. |
| `IPQS_API_KEY` | unset | Optional IPQualityScore adapter. |
| `MAXMIND_ACCOUNT_ID` | unset | Optional MaxMind account ID. |
| `MAXMIND_LICENSE_KEY` | unset | Optional MaxMind license key. |

Private, loopback, link-local, reserved, and otherwise non-global addresses are never sent to external reputation providers. External provider failures add warnings and do not crash the aggregate.

## Rust risk engine

| Variable | Default | Purpose |
|---|---|---|
| `RISK_ENGINE_ADDR` | `0.0.0.0:8082` | Internal score-service listen address. |
| `RUST_LOG` | library default | Rust tracing filter. |

The gateway sends only the risk input and non-secret site rate/threshold policy to this service. Site secrets are not included.

## Browser SDK

The SDK constructor takes a public `siteKey`, BerryShield gateway `endpoint`, and optional `wasmProbeUrl`. The application should instantiate the SDK on the protected origin, request a token immediately before a sensitive action, send the token to its own backend, and verify it server-to-server with both expected action and hostname.
