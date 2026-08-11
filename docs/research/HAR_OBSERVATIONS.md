# Structural observations from supplied HARs

The supplied browser HARs were treated as **protocol observations**, not as a source of reusable credentials. `tools/har_summarize.py` emits hosts, paths, methods, request field names, response JSON key shapes, and a few categorical challenge selectors. It intentionally does not emit cookies, authorization values, opaque query/body values, response bodies, or long opaque path segments.

## AWS WAF CAPTCHA / Challenge trace

Observed separate token and CAPTCHA hosts with repeated `/telemetry` and `/report` requests, scripts such as `challenge.js`/`captcha.js`, challenge acquisition through `/inputs`, computational verification through `/mp_verify`, and separate CAPTCHA `/problem` + `/verify` routes. The `/inputs` response exposed a structural challenge object plus `challenge_type` and `difficulty`; `/mp_verify` returned token/input state.

**BerryShield design implication:** keep telemetry, challenge acquisition, proof verification, and final proof-token issuance as distinct concepts. Computational work is represented by the PoW challenge; challenge state is server-owned.

## GeeTest traces

Observed `/load` followed by `/verify`, with challenge families selected through `risk_type`. Supplied traces contained `slide`, `match`, `icon`, `winlinze`, and `nine`. Verification requests included field names such as `captcha_id`, `lot_number`, `risk_type`, `payload`, `process_token`, `payload_protocol`, and `w`.

**BerryShield design implication:** challenge kind should be an adaptive server decision with an opaque challenge ID rather than a fixed widget behavior. The current reference implementation has passive, PoW, and accessible interactive modes; the challenge registry is designed to be extensible.

## hCaptcha trace

Observed `checksiteconfig`, repeated `getcaptcha/<id>` challenge acquisition, and `checkcaptcha/<id>/<opaque>` verification. Challenge JSON contained request configuration and task lists; verification requests carried answer, motion, site, client, and configuration fields. Successful response shape included `pass`, a generated pass identifier, and expiration.

**BerryShield design implication:** browser interaction summaries can be useful evidence, but the server must issue/verify a short-lived proof. BerryShield aggregates behavior instead of uploading raw pointer/key content.

## reCAPTCHA traces

Easy/moderate traces loaded API/anchor/webworker/frame resources, then used `/api2/reload`, `/api2/userverify`-style verification traffic and a separate server-side verification result in the test site. The supplied “hard” HAR was malformed/truncated; only lexical URL recovery was used for it, so no request/response-body claims are made from that file.

**BerryShield design implication:** final success belongs on the server, is action/hostname scoped, and should not be inferred merely because a browser widget returned something.

## Cloudflare Turnstile trace

Observed the Turnstile API loader, versioned script, challenge-platform routes including `new/normal` and retry traffic, and separate verification of the resulting token by the surrounding test site.

**BerryShield design implication:** minimize user-visible puzzles and use adaptive escalation. A passive allow path is first-class; server verification remains mandatory.

## Lemin trace

The supplied Lemin HAR contains only the demo page request and does not expose enough network protocol detail to support further architectural claims.

## Machine-readable/raw structural output

- `har-summary.json` — sanitized machine-readable structure.
- `har-summary.txt` — sanitized human-readable structure.

These files are regenerated with:

```bash
python tools/har_summarize.py --json /path/to/*.har
```
