from __future__ import annotations

import ipaddress
import json
import os
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .cache import TTLCache
from .models import aggregate
from .providers import Provider, providers_from_env


class ReputationService:
    def __init__(self, providers: list[Provider], ttl_seconds: int = 300):
        self.providers = providers
        self.cache = TTLCache(ttl_seconds=ttl_seconds)
        self.pool = ThreadPoolExecutor(max_workers=max(4, len(providers) * 2), thread_name_prefix="reputation")

    def lookup(self, ip: str, ua: str = "", language: str = "") -> dict:
        ip_obj = ipaddress.ip_address(ip)
        ip = str(ip_obj)
        cache_key = f"{ip}|{ua[:96]}|{language[:32]}"
        if cached := self.cache.get(cache_key):
            return cached.to_dict()

        # Never send loopback/private/link-local/reserved addresses to external
        # intelligence providers. They have no useful public reputation and may
        # reveal internal addressing unnecessarily.
        selected = self.providers if ip_obj.is_global else [p for p in self.providers if getattr(p, "name", "") == "local"]
        futures = [self.pool.submit(p.lookup, ip, ua, language) for p in selected]
        results = []
        try:
            for f in as_completed(futures, timeout=2.0):
                try:
                    results.append(f.result())
                except Exception as exc:
                    # Provider isolation: one integration never breaks the aggregate.
                    from .models import ProviderResult
                    results.append(ProviderResult(provider="unknown", warning=type(exc).__name__))
        except FuturesTimeoutError:
            from .models import ProviderResult
            results.append(ProviderResult(provider="aggregate", warning="provider-timeout"))
            for f in futures:
                f.cancel()
        out = aggregate(results)
        self.cache.put(cache_key, out)
        return out.to_dict()


def make_handler(service: ReputationService):
    class Handler(BaseHTTPRequestHandler):
        server_version = "BerryShieldReputation/0.1"

        def log_message(self, fmt, *args):
            # Query strings may contain IP/UA context. Never emit them through
            # BaseHTTPRequestHandler's default request-line logger.
            if os.getenv("BERRYSHIELD_HTTP_LOG") == "1":
                parsed = urllib.parse.urlparse(self.path)
                print(f"{self.client_address[0]} {self.command} {parsed.path}", flush=True)

        def _lookup(self, ip: str, ua: str, language: str):
            try:
                result = service.lookup(ip, ua[:512], language[:128])
                return self._json(200, result)
            except ValueError:
                return self._json(400, {"error": "invalid-ip"})
            except Exception:
                return self._json(500, {"error": "internal-error"})

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/healthz":
                return self._json(200, {"ok": True, "service": "berryshield-reputation"})
            if parsed.path != "/v1/ip":
                return self._json(404, {"error": "not-found"})
            # GET remains as a local debugging compatibility path; POST is used
            # by the gateway so request context is not placed in URLs/logs.
            q = urllib.parse.parse_qs(parsed.query)
            return self._lookup((q.get("ip") or [""])[0], (q.get("ua") or [""])[0], (q.get("lang") or [""])[0])

        def do_POST(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/v1/ip":
                return self._json(404, {"error": "not-found"})
            if "application/json" not in (self.headers.get("Content-Type") or "").lower():
                return self._json(415, {"error": "content-type"})
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._json(400, {"error": "content-length"})
            if size <= 0 or size > 4096:
                return self._json(413, {"error": "body-size"})
            try:
                body = json.loads(self.rfile.read(size))
            except Exception:
                return self._json(400, {"error": "invalid-json"})
            if not isinstance(body, dict):
                return self._json(400, {"error": "invalid-json"})
            return self._lookup(str(body.get("ip", "")), str(body.get("ua", "")), str(body.get("lang", "")))

        def _json(self, status: int, value: dict):
            body = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main():
    host = os.getenv("REPUTATION_HOST", "0.0.0.0")
    port = int(os.getenv("REPUTATION_PORT", "8081"))
    ttl = int(os.getenv("REPUTATION_CACHE_TTL", "300"))
    service = ReputationService(providers_from_env(), ttl_seconds=ttl)
    httpd = ThreadingHTTPServer((host, port), make_handler(service))
    print(f"berryshield-reputation listening on {host}:{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
