# Threat Model

## Assets

- protected application actions (login, signup, checkout, messaging, scraping-sensitive APIs);
- BerryShield site secrets and signing secret;
- proof-token integrity and single-use semantics;
- challenge state;
- risk/reputation integrity;
- user privacy and accessibility.

## Adversaries

BerryShield assumes adversaries may control normal browsers, automation frameworks, headless/stealth browsers, residential/datacenter proxies, replay captured client requests, modify all JavaScript-visible values, imitate common HTTP/TLS stacks, outsource interactive puzzles, and distribute traffic across IP addresses.

It does **not** assume client-side JavaScript or WebAssembly is secret. Anything shipped to the browser is observable and modifiable.

## Controls by attack class

| Attack | Primary controls | Residual risk |
|---|---|---|
| Token replay | signed token + short TTL + atomic JTI consumption | shared-store requirement across replicas |
| Challenge replay | random challenge ID + expiration + session binding + one-time consume + attempt cap | distributed race if store is not shared |
| Stolen public site key | hostname + Origin policy | public site keys are intentionally not secrets |
| Stolen server secret | operational secret rotation; never sent to browser/risk service | compromise allows verification calls until rotated |
| Forged browser telemetry | server-derived IP/rate + cross-signal rules + reputation + adaptive challenge | sophisticated automation can imitate many fields |
| `webdriver` hidden | webdriver is only one weighted signal | stealth browsers can reduce browser-only evidence |
| Cookie/session replay | BerryShield token is action/hostname/TTL/JTI bound; optional IP-prefix bind | IP binding can hurt roaming/mobile users |
| Proxy rotation | prefix rate limit + external reputation + hosting/Tor/proxy flags | residential proxy networks remain difficult |
| Solver farms | short challenge TTL, action binding, optional network binding, server-side risk; interactive mode adds low-cost work + server-observed elapsed floor | human solving cannot be perfectly distinguished |
| TLS/HTTP fingerprint imitation | deploy edge telemetry and correlate with JS/client hints; never trust fingerprint alone | high-quality impersonation is possible |
| Header spoofing | forwarded network headers accepted only from trusted peers | proxy must overwrite/sanitize incoming headers |
| Reputation-provider outage | tight timeout + isolation + local fallback | less evidence during outage |
| Provider false positive | consensus weighting + tunable thresholds + no single-vendor hard block | still requires production calibration |
| Accessibility exclusion | low behavior weights + keyboard-operable fallback | deployments must test assistive tech and recovery paths |

## Explicit non-goals

- perfect bot detection;
- identifying a real human with cryptographic certainty;
- replacing application authentication/authorization;
- hiding algorithms from a browser owner;
- DDoS absorption at L3/L4;
- bypassing third-party anti-bot services.

## Trust boundaries

Browser → Internet → trusted edge/reverse proxy → gateway → internal reputation/risk services → protected application.

Only the gateway signs tokens. Browser telemetry is always untrusted. Reputation/risk services receive no site secret. Forwarded client-IP headers are ignored unless the direct peer is configured as trusted.
