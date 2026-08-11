# Red-Team / Blue-Team Program

This program is scoped to BerryShield instances you own or are authorized to test. It converts common anti-bot evasion ideas into defensive regression tests without shipping a third-party CAPTCHA bypass.

## Test matrix

### RT-01 — exposed automation

Send otherwise normal telemetry with `webdriver=true`. Expected: risk escalation with `webdriver-exposed`.

### RT-02 — obvious non-browser client

Use `curl/`, `python-requests`, or a headless UA in the controlled test request. Expected: `automation-user-agent` and escalation.

### RT-03 — stealth claim

Set `webdriver=false`, but create contradictions among server UA, client UA, platform, client hints, capabilities, and impossible behavior aggregates. Expected: cross-signal tags still accumulate; no single hidden field neutralizes the model.

### RT-04 — challenge replay

Solve a BerryShield challenge and submit the same challenge ID/proof again. Expected: second attempt fails because challenge state was consumed.

### RT-05 — token replay

Verify the same final token twice. Expected: first succeeds, second returns `timeout-or-duplicate`.

### RT-06 — action confusion

Acquire a token for one action and verify it as another. Expected: `action-mismatch`.

### RT-07 — hostname/origin confusion

Try a valid site key from a non-allowed Origin/hostname, then try `Origin=A` with requested hostname `B` where A and B are both individually allowed for the same site key. Expected: both cases are rejected before a proof is issued unless Origin and requested hostname match exactly.

### RT-08 — network binding mismatch

With prefix binding enabled, acquire and verify from a different prefix. Expected: mismatch. Also test mobile/roaming traffic to understand false positives before enabling this globally.

### RT-09 — proxy/reputation escalation

Inject a controlled/mock reputation result with Tor, hosting, proxy, or high abuse score. Expected: predictable tags and escalation according to policy.

### RT-10 — request mirroring

Replay a previously valid BerryShield HTTP body and token. Expected: copied telemetry alone does not produce a reusable server proof; copied final token is one-time.

### RT-11 — TLS/browser imitation

At your own edge, make automated clients imitate a normal TLS/HTTP fingerprint. Expected: BerryShield must not rely on that fingerprint alone; server rate/reputation, action binding, challenge state, and cross-signal consistency continue to apply.

### RT-12 — provider outage

Drop/timeout every reputation provider and the remote Rust scorer. Expected: gateway remains available and falls back to local scoring; monitoring indicates reduced evidence.

### RT-13 — malformed payload / parser abuse

Send oversized JSON, unknown fields, multiple JSON values, negative/NaN-like values where representable, and malformed IDs. Expected: bounded 4xx response, no panic.

### RT-14 — accessibility

Complete interactive verification using keyboard only and screen-reader navigation. Expected: no pointer movement requirement and successful completion.

## Blue-team acceptance criteria

- every exploit regression gets a deterministic automated test;
- detection logic has a legitimate-user countertest;
- no raw secrets or tokens are logged;
- new controls document spoofability and privacy/accessibility cost;
- policy changes can be shadowed/observed before blocking;
- multi-node deployments preserve atomic one-time semantics.

## Harness

`redteam/runner.py` contains low-volume tests specifically for BerryShield. By default it only accepts loopback targets; `--allow-remote` exists for explicitly authorized staging instances.
