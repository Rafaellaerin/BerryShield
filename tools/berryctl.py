#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, secrets

def token(prefix: str, n: int = 24) -> str:
    return prefix + secrets.token_urlsafe(n)

def main():
    p=argparse.ArgumentParser(description="BerryShield configuration helper")
    sub=p.add_subparsers(dest="cmd", required=True)
    g=sub.add_parser("gen-site"); g.add_argument("--host", action="append", required=True)
    a=p.parse_args()
    if a.cmd == "gen-site":
        site={
            "site_key": token("bs_", 12),
            "secret": token("bss_", 32),
            "hostnames": a.host,
            "token_ttl_seconds": 120,
            "challenge_ttl_seconds": 180,
            "rate_limit_per_minute": 60,
            "bind_ip_prefix": False,
            "thresholds": {"pow":30,"interactive":62,"block":92},
        }
        print(json.dumps(site, indent=2))
if __name__ == "__main__": main()
