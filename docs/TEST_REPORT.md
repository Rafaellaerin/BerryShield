# Validation Report — BerryShield 0.1.0

**Validation date:** 2026-08-11  
**Scope:** repository build/static checks plus low-volume localhost integration tests against BerryShield itself. No third-party CAPTCHA was bypassed and no live external reputation credentials were used.

## Environment

- Go 1.23.2 (`linux/amd64`)
- Python 3.13.5
- Node.js 22.16.0
- npm 10.9.2
- TypeScript compiler 5.8.3 available locally
- Cargo/Rust toolchain: not installed in this execution environment
- Docker CLI/daemon: not installed in this execution environment

## Results

| Check | Result | Notes |
|---|---|---|
| Go `go test ./...` | PASS | Gateway API, challenge, config, reputation client, risk scorer, and token/keyring tests pass. |
| Go `go vet ./...` | PASS | No findings. |
| Python unit suite | PASS | 6 tests: aggregation, provider parsing, current/legacy MaxMind shape, IPQS flags, and non-global-IP provider isolation. |
| Python compile check | PASS | Reputation service, CLI tools, HAR sanitizer, and red-team harness compile. |
| TypeScript build | PASS | Browser SDK compiles. |
| Node SDK tests | PASS | WebCrypto proof helper regression test passes. |
| Prebuilt WebAssembly instantiate | PASS | `probe.wasm` instantiates and exports callable `mix32`. |
| npm pack dry run | PASS | SDK package manifest produces a package containing the intended `dist` + README payload. |
| YAML parse | PASS | `docker-compose.yml`, OpenAPI schema, and GitHub Actions workflow parse as YAML. |
| Live gateway ↔ reputation integration | PASS | Both health endpoints responded and gateway called the Python service using JSON POST. |
| RT-01 WebDriver exposed | PASS | Escalated to PoW in the test policy. |
| RT-02 headless UA | PASS | Escalated to PoW in the test policy. |
| RT-03 platform contradiction | PASS | Request remained bounded and produced a valid policy decision. |
| RT-04 challenge replay | PASS | First proof accepted; replay rejected after challenge consumption. |
| RT-05 token replay | PASS | First siteverify succeeded; second returned `timeout-or-duplicate`. |
| RT-06 action mismatch | PASS | Wrong expected action rejected. |
| RT-07 disallowed Origin | PASS | Rejected before proof issuance. |
| RT-07b sibling-host confusion | PASS | Allowed `Origin=A` could not request a token for allowed sibling hostname `B`. |
| RT-08 network binding | PASS | Different IPv4 /24 rejected; same /24 accepted. |
| RT-13 malformed/impossible behavior scenario | PASS | Input produced a bounded policy decision and no crash. |
| Rust risk-engine tests | NOT RUN LOCALLY | CI installs Rust stable and runs `cargo test` for the risk-engine crate. |
| Rust WASM crate tests | NOT RUN LOCALLY | CI installs Rust stable and tests the source crate; the included prebuilt WASM was instantiated locally. |
| Docker image build | NOT RUN LOCALLY | Docker is absent here; Compose syntax was parsed, and image build remains a release-environment gate. |

## Security regression highlights

The final Go tests include exact Origin/hostname sibling isolation, mandatory expected action/hostname at server verification, single-use token consumption, session-bound challenges, normalized hostname handling, IPv4 prefix binding, reputation request field bounds, and real `kid`-based previous-key verification.

The authorized live red-team harness is intentionally constrained to BerryShield. It does not ship a reCAPTCHA/hCaptcha/Turnstile/GeeTest solver, Cloudflare clearance-cookie extractor, stealth browser configured for third-party bypass, or TLS impersonation client.

## Release gates still owned by the deployer

Before high-value production enforcement: compile/test Rust in release CI, build and scan containers, replace the single-process memory store before horizontal scaling, tune thresholds on representative legitimate traffic, complete accessibility/privacy review, and perform an independent application-security assessment.
