from __future__ import annotations

import base64
import ipaddress
import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from .models import ProviderResult


class Provider(Protocol):
    name: str
    def lookup(self, ip: str, user_agent: str = "", language: str = "") -> ProviderResult: ...


def _json_request(url: str, headers: dict[str, str], timeout: float = 1.3) -> dict:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"http-{resp.status}")
        if int(resp.headers.get("Content-Length", "0") or "0") > 512_000:
            raise RuntimeError("response-too-large")
        raw = resp.read(512_001)
        if len(raw) > 512_000:
            raise RuntimeError("response-too-large")
        return json.loads(raw.decode("utf-8"))


def _json_post_request(url: str, headers: dict[str, str], payload: dict, timeout: float = 1.3) -> dict:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req_headers = {**headers, "Content-Type": "application/json"}
    req = urllib.request.Request(url, headers=req_headers, data=body, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"http-{resp.status}")
        if int(resp.headers.get("Content-Length", "0") or "0") > 512_000:
            raise RuntimeError("response-too-large")
        raw = resp.read(512_001)
        if len(raw) > 512_000:
            raise RuntimeError("response-too-large")
        return json.loads(raw.decode("utf-8"))


def _validate_public_ip(ip: str) -> ipaddress._BaseAddress:
    obj = ipaddress.ip_address(ip)
    return obj

def _maxmind_to_result(d: dict, provider: str = "maxmind") -> ProviderResult:
    traits = d.get("traits", {}) or {}
    anonymizer = d.get("anonymizer", {}) or {}
    def flag(name: str) -> bool:
        # MaxMind moved anonymizer fields out of traits; keep the legacy
        # fallback for compatibility with older service responses.
        return bool(anonymizer.get(name) or traits.get(name))
    anonymous = flag("is_anonymous")
    vpn = flag("is_anonymous_vpn")
    public_proxy = flag("is_public_proxy")
    residential = flag("is_residential_proxy")
    hosting = flag("is_hosting_provider")
    tor = flag("is_tor_exit_node")
    proxy = anonymous or vpn or public_proxy or residential
    score = 0
    score += 30 if anonymous else 0
    score += 20 if vpn else 0
    score += 18 if public_proxy else 0
    score += 18 if residential else 0
    score += 15 if hosting else 0
    score += 40 if tor else 0
    country = str((d.get("country") or {}).get("iso_code") or "")
    asn = str(traits.get("autonomous_system_number") or "")
    return ProviderResult(
        provider=provider, score=min(100, score), proxy=proxy, vpn=vpn, tor=tor,
        hosting=hosting, country=country, asn=asn,
    )


@dataclass(slots=True)
class LocalProvider:
    name: str = "local"

    def lookup(self, ip: str, user_agent: str = "", language: str = "") -> ProviderResult:
        obj = _validate_public_ip(ip)
        if obj.is_loopback or obj.is_private or obj.is_link_local:
            return ProviderResult(provider=self.name, score=0)
        score = 0
        ua = user_agent.lower()
        if any(x in ua for x in ("python-requests", "curl/", "wget/", "headlesschrome")):
            score += 30
        return ProviderResult(provider=self.name, score=score)


@dataclass(slots=True)
class AbuseIPDBProvider:
    api_key: str
    max_age_days: int = 30
    name: str = "abuseipdb"

    def lookup(self, ip: str, user_agent: str = "", language: str = "") -> ProviderResult:
        _validate_public_ip(ip)
        if not self.api_key:
            return ProviderResult(provider=self.name, warning="disabled")
        qs = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": self.max_age_days})
        url = "https://api.abuseipdb.com/api/v2/check?" + qs
        try:
            data = _json_request(url, {"Accept": "application/json", "Key": self.api_key})
            d = data.get("data", {})
            abuse = int(d.get("abuseConfidenceScore") or 0)
            usage = str(d.get("usageType") or "").lower()
            hosting = any(x in usage for x in ("data center", "web hosting", "hosting"))
            return ProviderResult(
                provider=self.name,
                score=min(100, round(abuse * 0.85 + (10 if hosting else 0))),
                abuse_score=abuse,
                hosting=hosting,
                country=str(d.get("countryCode") or ""),
                asn=str(d.get("asn") or ""),
            )
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError, RuntimeError, socket.timeout) as exc:
            return ProviderResult(provider=self.name, warning=type(exc).__name__)


@dataclass(slots=True)
class IPQSProvider:
    api_key: str
    name: str = "ipqs"

    def lookup(self, ip: str, user_agent: str = "", language: str = "") -> ProviderResult:
        _validate_public_ip(ip)
        if not self.api_key:
            return ProviderResult(provider=self.name, warning="disabled")
        payload = {
            "ip": ip,
            "strictness": 0,
            "allow_public_access_points": True,
            "lighter_penalties": True,
        }
        if user_agent:
            payload["user_agent"] = user_agent[:512]
        if language:
            payload["user_language"] = language[:128]
        url = "https://www.ipqualityscore.com/api/json/ip/"
        try:
            d = _json_post_request(url, {"Accept": "application/json", "IPQS-KEY": self.api_key}, payload)
            if d.get("success") is False:
                return ProviderResult(provider=self.name, warning="provider-error")
            fraud = int(d.get("fraud_score") or 0)
            vpn = bool(d.get("vpn") or d.get("active_vpn"))
            tor = bool(d.get("tor") or d.get("active_tor"))
            proxy = bool(d.get("proxy") or vpn or tor)
            connection_type = str(d.get("connection_type") or "").strip().lower()
            hosting = connection_type == "data center"
            return ProviderResult(
                provider=self.name,
                score=fraud,
                proxy=proxy,
                vpn=vpn,
                tor=tor,
                hosting=hosting,
                abuse_score=fraud,
                country=str(d.get("country_code") or ""),
                asn=str(d.get("ASN") or d.get("asn") or ""),
            )
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError, RuntimeError, socket.timeout) as exc:
            return ProviderResult(provider=self.name, warning=type(exc).__name__)


@dataclass(slots=True)
class MaxMindProvider:
    account_id: str
    license_key: str
    name: str = "maxmind"

    def lookup(self, ip: str, user_agent: str = "", language: str = "") -> ProviderResult:
        _validate_public_ip(ip)
        if not self.account_id or not self.license_key:
            return ProviderResult(provider=self.name, warning="disabled")
        auth = base64.b64encode(f"{self.account_id}:{self.license_key}".encode()).decode()
        url = "https://geoip.maxmind.com/geoip/v2.1/insights/" + urllib.parse.quote(ip, safe=":")
        try:
            d = _json_request(url, {
                "Accept": "application/vnd.maxmind.com-insights+json",
                "Authorization": "Basic " + auth,
            })
            return _maxmind_to_result(d, self.name)
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError, RuntimeError, socket.timeout) as exc:
            return ProviderResult(provider=self.name, warning=type(exc).__name__)


def providers_from_env() -> list[Provider]:
    return [
        LocalProvider(),
        AbuseIPDBProvider(os.getenv("ABUSEIPDB_API_KEY", "")),
        IPQSProvider(os.getenv("IPQS_API_KEY", "")),
        MaxMindProvider(os.getenv("MAXMIND_ACCOUNT_ID", ""), os.getenv("MAXMIND_LICENSE_KEY", "")),
    ]
