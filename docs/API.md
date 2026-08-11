# API

The canonical machine-readable contract is [`../schemas/openapi.yaml`](../schemas/openapi.yaml).

## `POST /v1/challenge`

Browser-facing. Requires a public `site_key`, an action, the page hostname, session ID, and telemetry. When `Origin` is present, its normalized hostname must be allowed for the site **and exactly match** the requested hostname.

Possible decisions:

- `allow` + `token`;
- `pow` + challenge parameters;
- `interactive` + challenge parameters;
- `block`.

## `POST /v1/challenge/{id}/verify`

Browser-facing. Submits the original `session_id` plus the proof for a one-time challenge. The session ID must match the one used when the challenge was issued. A valid proof consumes the challenge and returns a final token.

## `POST /v1/siteverify`

Server-facing. Accepts JSON or `application/x-www-form-urlencoded`.

Fields:

- `secret` — server-only per-site secret;
- `response` — token from the browser;
- `remoteip` — required when that site has `bind_ip_prefix=true`; otherwise optional;
- `expected_action` — required;
- `expected_hostname` — required.

A token is single-use. Verification failure uses stable error codes such as `invalid-input-secret`, `invalid-input-response`, `sitekey-secret-mismatch`, `missing-expected-action`, `missing-expected-hostname`, `action-mismatch`, `hostname-mismatch`, `missing-remoteip`, `remoteip-mismatch`, `session-binding-mismatch`, and `timeout-or-duplicate`.

## `GET /metrics`

Prometheus text exposition with counts for decisions, successful/failed verification, replays, and rate limiting.

## `GET /healthz`

Process liveness endpoint.
