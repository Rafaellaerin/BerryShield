# Production Readiness Checklist

This checklist is deliberately stricter than the development quick start. Treat it as a release gate for an internet-facing deployment.

## Secrets and identity

- [ ] `BERRYSHIELD_ENV=production`.
- [ ] Active signing secret is randomly generated, at least 32 bytes, and stored in a secret manager.
- [ ] `BERRYSHIELD_SIGNING_KID` is unique for the active key generation.
- [ ] Previous signing keys are present only during a bounded rotation window.
- [ ] A separate stable 32+ byte `BERRYSHIELD_BINDING_SECRET` is configured when IP-prefix binding is enabled.
- [ ] Every site has a unique server secret; no development/default secrets remain.
- [ ] Secrets are absent from browser bundles, logs, images, CI output, and repository history.

## Edge and network

- [ ] TLS is terminated at a hardened edge with modern protocol/cipher policy.
- [ ] Gateway, reputation service, and risk engine communicate on private/service networks.
- [ ] Reputation and risk ports are not directly published to the internet.
- [ ] Only real edge/proxy CIDRs are configured in `BERRYSHIELD_TRUSTED_PROXY_CIDRS`.
- [ ] The trusted edge overwrites client-supplied forwarding headers rather than appending untrusted values blindly.
- [ ] `/metrics` is private or authenticated at the edge.
- [ ] Edge request size, header size, connection, and timeout limits are compatible with—and no weaker than—the gateway limits.

## Site policy

- [ ] Hostname allowlists are minimal; wildcards are avoided unless operationally necessary.
- [ ] Browser `Origin` and requested hostname behavior is tested for every configured hostname.
- [ ] The backend always supplies `expected_action` and `expected_hostname` to `/v1/siteverify`.
- [ ] If IP-prefix binding is enabled, the backend supplies the original client `remoteip` from the same trusted edge chain.
- [ ] Token/challenge TTLs are no longer than the protected workflow requires.
- [ ] Rate limits and risk thresholds were tuned with legitimate-traffic shadow data and false-positive review.

## Horizontal scaling

- [ ] A shared atomic state backend has replaced `store.Memory` before running multiple gateway replicas.
- [ ] Challenge consume, JTI consume, attempt counting, and rate-window updates are atomic across replicas.
- [ ] Failure/partition behavior of the shared state backend has been tested.
- [ ] Sticky sessions are not treated as a substitute for shared anti-replay state.

## Privacy and accessibility

- [ ] Data inventory and retention are documented for client telemetry and external IP-reputation providers.
- [ ] Provider contracts/legal basis/region requirements were reviewed for the deployment jurisdiction.
- [ ] Raw tokens, secrets, typed text, form contents, pointer coordinates, and raw fingerprint strings are not logged.
- [ ] Keyboard-only and screen-reader completion of the interactive challenge is tested.
- [ ] A recovery/support path exists for users who cannot complete the challenge.

## Observability and incident response

- [ ] Dashboards cover decision distribution, verify failures, replays, rate limiting, and upstream dependency health.
- [ ] Alerts detect sudden changes in allow/PoW/interactive/block ratios and provider outage/fallback states.
- [ ] Logs are structured and redact credentials/tokens.
- [ ] Signing/site-secret rotation procedure is rehearsed.
- [ ] Emergency provider disable/fallback procedure is rehearsed.
- [ ] `SECURITY.md` disclosure channel is monitored.

## Security validation

- [ ] `./scripts/verify.sh` passes in CI.
- [ ] `go vet ./...` passes.
- [ ] Rust crates compile/test on the release toolchain.
- [ ] Container images build and are scanned by the operator's CI/security tooling.
- [ ] `redteam/runner.py` passes against an authorized staging deployment.
- [ ] RT-07 sibling-hostname confusion is tested when a site key has multiple allowed hostnames.
- [ ] Provider-outage and remote-risk-engine outage tests confirm graceful fallback.
- [ ] An independent security review/pentest is completed before high-value enforcement.
