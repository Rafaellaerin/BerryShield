# BerryShield Risk Engine (Rust)

Optional centralized scorer used by the Go gateway when `BERRYSHIELD_RISK_ENGINE_URL`
is configured. The gateway always has a local fail-safe scorer and falls back to it
on timeout, malformed responses, or non-200 responses.

The remote request intentionally contains only risk inputs, rate information and
thresholds. Site secrets and the BerryShield token signing key never leave the gateway.
