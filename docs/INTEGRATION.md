# Integration Guide

## 1. Register a site

Copy `config/sites.example.json`, generate a unique public site key and a strong random server secret, then set `BERRYSHIELD_SITES_FILE` to the file path.

Treat the site key like a public identifier. Treat the site secret and global signing secret like credentials.

## 2. Add the browser SDK

Create one `BerryShield` instance per page/session and call `execute(action)` immediately before a sensitive action. Use a stable, semantic action name such as `login`, `signup`, `password_reset`, or `comment_create`.

Do not reuse a token for multiple requests.

## 3. Submit token to your backend

Send the returned BerryShield token alongside the protected request. Your application backend—not the browser—calls `/v1/siteverify`.

Always provide `expected_action` and `expected_hostname`. If you enable IP-prefix binding, provide the original user IP from the same trusted edge path.

## 4. Decide application policy

Only execute the protected action after `success: true`. A BerryShield success says that the configured anti-abuse proof was valid; it does not authenticate the user's identity.

## 5. CSP and hosting

Self-host the SDK and WASM when possible. Add the SDK origin to `script-src`, the gateway to `connect-src`, and WASM support to the CSP appropriate for your build. Avoid broad `*` rules solely for BerryShield.

## 6. Reverse proxy

Set `BERRYSHIELD_TRUSTED_PROXY_CIDRS` only to networks that actually proxy BerryShield. The proxy must overwrite/sanitize `X-Forwarded-For` and, if used, `CF-Connecting-IP`. Do not trust arbitrary internet clients to supply these headers.
