# Security Policy

## Reporting

Please do not publish a working exploit before maintainers have had a reasonable opportunity to investigate and patch it. A useful report includes the affected version/commit, deployment assumptions, reproduction steps against a system you are authorized to test, impact, and a minimal proof of concept.

Do not include real user tokens, cookies, IP-address datasets, credentials, or HAR files containing live authentication material in a public issue.

## In scope

- token forgery, replay, or binding failures;
- origin/hostname/site isolation bypass;
- trusted-proxy/IP confusion;
- challenge state races;
- score manipulation that reliably crosses a policy boundary;
- SSRF or secret exposure in reputation integrations;
- denial-of-service issues reachable with modest traffic;
- privacy regressions in browser telemetry.

## Deployment assumptions

BerryShield is not a substitute for authentication, authorization, application rate limits, abuse monitoring, or DDoS protection at the network edge. The default memory store is single-instance; multi-node deployments need atomic shared state before they can preserve one-time-token and challenge semantics across replicas.
