# Risk Engine

## Philosophy

The default scorer is intentionally explainable. It produces a numeric score plus tags, then maps the score to a decision. This makes false positives debuggable and allows the policy to be replaced later by calibrated statistical/ML models without changing the public API.

## Current signals

Network/server-derived evidence is favored over pure browser declarations. Examples include request rate, external reputation, Tor/hosting/proxy indicators, and the HTTP User-Agent. Browser-side consistency signals include exposed WebDriver, automation-oriented UA strings, platform/client-hint disagreement, malformed hardware/screen values, missing capabilities, and impossible aggregate pointer density.

Behavior is deliberately low weight. A user who never moves a mouse or who uses assistive technology must not be classified as a bot merely because of that.

## Default weights

Important current rules include:

- exposed WebDriver: +32;
- obvious automation UA: +30;
- missing server/client UA: +18;
- platform inconsistency: +12;
- network reputation: `provider_score × 0.48`;
- Tor: +22;
- hosting: +10;
- proxy/VPN: +7;
- high abuse score: +12;
- elevated request rate: +8.

Scores are clamped to 0–100. These numbers are starting points, not universal truth.

## Production tuning workflow

1. Log decision tags and coarse risk buckets, not raw sensitive telemetry.
2. Label outcomes using abuse-confirmed and legitimate traffic samples.
3. Measure false-positive rate separately for browser families, mobile networks, VPN users, assistive technology, and regions.
4. Tune `pow`, `interactive`, and `block` thresholds per protected action.
5. Prefer additional evidence over increasing one brittle rule.
6. Run shadow mode before a new block rule becomes enforcing.

## Reputation aggregation

The Python service normalizes provider scores and combines the strongest signal with a small consensus contribution from other successful providers. Boolean proxy/VPN/Tor/hosting flags are ORed; provider failures are warnings rather than fatal errors.

API keys are loaded only from environment variables and are never forwarded to the browser.
