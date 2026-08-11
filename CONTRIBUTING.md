# Contributing

Keep changes small, testable, and threat-modelled. New browser signals must document: purpose, spoofability, privacy cost, accessibility impact, retention requirement, and what happens when the signal is unavailable.

New risk rules need tests for both escalation and a legitimate counterexample. Avoid rules based solely on `navigator.webdriver`, pointer movement, VPN usage, country, ASN, or a single vendor score.

Red-team contributions must target BerryShield or an explicitly authorized test fixture. Do not add reusable automation whose primary purpose is bypassing third-party CAPTCHA/anti-bot services.

Run `./scripts/verify.sh` before opening a pull request.
