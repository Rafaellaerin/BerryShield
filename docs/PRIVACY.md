# Privacy and Data Minimization

Anti-bot telemetry can become fingerprinting data. BerryShield therefore makes several design choices to reduce collection while retaining useful inconsistency signals.

## Browser data collected by the reference SDK

- browser UA and platform declarations;
- languages and timezone;
- coarse screen width/height buckets and color depth;
- coarse hardware capability hints;
- cookie/storage/WebCrypto/WASM availability;
- short hashes of WebGL vendor/renderer strings rather than raw strings;
- coarse performance jitter;
- aggregate counts/statistics for pointer, keyboard, focus, and visibility activity.

## Not collected by the reference SDK

Typed text, key values, pointer coordinates, screenshots, canvas pixels, font lists, clipboard, microphone/camera/geolocation, browsing history, full WebGL strings, or persistent cross-site identifiers.

## Network data

The gateway necessarily sees source network information. It sends reputation context to the internal Python service in a JSON POST body rather than a query string. Non-global addresses (loopback, private, link-local, reserved, etc.) are kept local and are not sent to configured external intelligence providers. For globally routable addresses, the optional reputation service may send the IP address and limited UA/language context to enabled providers. The IPQualityScore adapter uses a JSON POST and API-key header rather than putting those fields in its request URL. Operators must evaluate their provider contracts, legal basis, retention policy, and regional requirements.

## Retention recommendation

Keep raw request telemetry only as long as needed for security investigation/tuning. Prefer aggregated metrics and decision tags for long-term monitoring. Hash/pseudonymize network identifiers in logs where full IPs are unnecessary.

## Logging defaults

The reputation service suppresses the standard HTTP request-line log by default. When its optional HTTP logging is enabled, it logs only client address, method, and path—not the query string. Gateway operators should apply the same principle at reverse proxies and observability layers.
