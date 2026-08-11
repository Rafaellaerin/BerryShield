# Operations and Hardening

## Production checklist

- set `BERRYSHIELD_ENV=production`;
- generate a random signing secret of at least 32 bytes and store it in a secret manager;
- when IP-prefix binding is enabled, set a separate stable `BERRYSHIELD_BINDING_SECRET` (32+ bytes) so signing-key rotation does not invalidate network bindings;
- use unique per-site server secrets;
- restrict allowed hostnames; avoid wildcarding more than necessary;
- terminate TLS at a hardened trusted edge;
- configure only real reverse-proxy CIDRs as trusted;
- overwrite forwarded-IP headers at that edge;
- put `/metrics` on an internal/admin network or protect it at the proxy;
- set strict request/body/time limits at the edge and gateway;
- monitor reputation provider latency/errors;
- alert on replay, block, and rate-limit changes;
- run the red-team regression suite after policy changes;
- perform an accessibility review;
- perform an independent application-security review before high-value use.

## Horizontal scaling

The bundled memory store cannot coordinate challenges, rate windows, or consumed JTIs across replicas. Until a shared atomic backend is installed, run one gateway replica (you may still place a reverse proxy in front of it). Do not rely on sticky sessions as a complete anti-replay replacement.

## Key rotation

Tokens carry a `kid`. `BERRYSHIELD_SIGNING_SECRET` + `BERRYSHIELD_SIGNING_KID` define the active signing key, while `BERRYSHIELD_PREVIOUS_SIGNING_KEYS_JSON` is a JSON object of previous `kid -> secret` values accepted for verification during the short token migration window. New tokens are always minted with the active key. Remove previous keys after every token minted under them has expired.

If IP-prefix binding is enabled, keep `BERRYSHIELD_BINDING_SECRET` independent and stable across signing rotations. In development, omitting it falls back to the signing secret for convenience.

## Availability

Reputation and remote scoring are optional dependencies and have sub-second gateway timeouts. The system falls back to local scoring when they are unavailable. Monitor this state: a prolonged outage lowers available anti-abuse evidence even though the site stays up.

## Metrics

Scrape `/metrics` and graph:

- allow/PoW/interactive/block ratios;
- verification failure ratio;
- replay count;
- rate-limited requests;
- upstream reputation/risk service latency at your proxy/service layer.

Sudden decision distribution changes often indicate either an attack or a regression in telemetry/provider behavior.
