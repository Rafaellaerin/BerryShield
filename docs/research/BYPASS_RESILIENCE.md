# Bypass-resilience design notes

## Public bypass techniques considered

The public `sarperavci/CloudflareBypassForScraping` project describes two useful adversarial classes for defensive design: a stealth/patched Chromium flow that obtains a challenge clearance cookie plus the exact browser User-Agent, and a mirror mode that replays a request while attempting to resemble Chrome at the TLS/client layer. Other automation ecosystems similarly attempt to suppress obvious WebDriver indicators.

BerryShield treats these ideas as assumptions about the attacker rather than as features to reproduce against third parties.

## Defensive mapping

### Stealth browser / hidden WebDriver

Do not make `navigator.webdriver` a gate. BerryShield gives it weight, but continues to use server rate, IP reputation, UA/client-hint consistency, capability consistency, challenge history, and one-time server state.

### Captured cookie/token pair

A BerryShield final proof is short-lived, tied to site/action/hostname, optionally tied to a network prefix, and consumed at `/v1/siteverify`. A copied token therefore cannot be treated as a durable session credential.

### HTTP request mirroring

Replaying the same telemetry body is allowed to be observable—the client is untrusted—but it does not bypass server-side JTI/challenge consumption. Protected applications should obtain a fresh token per sensitive action.

### TLS/JA3/JA4 imitation

TLS fingerprints are useful edge evidence but not proof of humanity. A serious deployment can feed trusted edge fingerprints into a future/custom scorer and correlate them with browser/platform claims. BerryShield's core security does not depend on a TLS fingerprint being unique or unforgeable.

### Proxy rotation

Rate limits are only one layer. BerryShield can enrich network evidence with AbuseIPDB, IPQualityScore, and MaxMind and can treat Tor/hosting/proxy signals as risk rather than unconditional guilt. Residential proxy networks remain an unsolved adversarial area and require application-specific behavioral/business signals.

### CAPTCHA solvers / human farms

Any human-solvable challenge can be outsourced. BerryShield therefore emphasizes short TTLs, action binding, one-time verification, and risk reduction rather than assuming an interactive puzzle proves a unique human.

## What this repository intentionally does not include

No solver for reCAPTCHA/hCaptcha/Turnstile/GeeTest, no extraction of live clearance cookies, no stealth browser configured to defeat a third-party site, and no TLS impersonation client for bypassing external anti-bot systems. The red-team harness exercises equivalent failure modes against BerryShield itself.
