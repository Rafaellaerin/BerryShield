#!/usr/bin/env python3
"""Low-volume authorized regression harness for BerryShield itself.

The harness refuses non-loopback targets unless --allow-remote is supplied.
It exercises BerryShield's public contract and replay defenses; it does not
interact with or bypass third-party CAPTCHA providers.
"""
from __future__ import annotations
import argparse, copy, hashlib, json, socket, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path

BASE_CLIENT = {
  "sdk_version":"redteam-0.1","user_agent":"Mozilla/5.0","platform":"Win32",
  "languages":["en-US"],"timezone":"UTC","screen_width_bucket":1900,"screen_height_bucket":1100,
  "color_depth":24,"hardware_concurrency":8,"device_memory_gb":8,"max_touch_points":0,
  "webdriver":False,"secure_context":True,"cookie_enabled":True,"local_storage_ok":True,
  "session_storage_ok":True,"wasm_available":True,"wasm_mix":123,"webcrypto_available":True,
  "performance_jitter":0.01,"behavior":{"dwell_ms":2000,"pointer_events":20,"pointer_distance":300,
  "pointer_variance":0.3,"key_events":2,"key_interval_mean_ms":140,"key_interval_std_ms":20,
  "focus_transitions":0,"visibility_changes":0}
}

def is_loopback(url):
    host=urllib.parse.urlparse(url).hostname or ""
    if host in {"localhost","127.0.0.1","::1"}: return True
    try: return all(x.startswith("127.") or x == "::1" for x in {a[4][0] for a in socket.getaddrinfo(host,None)})
    except Exception: return False

def request(url, data=None, headers=None, method=None):
    req=urllib.request.Request(url,data=data,headers=headers or {},method=method)
    try:
        with urllib.request.urlopen(req,timeout=5) as r:
            raw=r.read(); return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw=e.read()
        try: payload=json.loads(raw) if raw else {}
        except Exception: payload={"error":f"http-{e.code}"}
        return e.code,payload

def post_json(url, body, headers):
    return request(url,json.dumps(body).encode(),{"Content-Type":"application/json",**headers},"POST")

def issue(target, site_key, hostname, action="redteam", client=None, ua=None, origin=None, extra_headers=None, session_suffix="base"):
    c=copy.deepcopy(client or BASE_CLIENT)
    body={"site_key":site_key,"action":action,"hostname":hostname,"session_id":"bss_redteam_"+session_suffix,"telemetry":{"client":c}}
    headers={"Origin":origin or f"http://{hostname}","User-Agent":ua or c["user_agent"],"X-BerryShield-Site-Key":site_key,**(extra_headers or {})}
    return post_json(target.rstrip("/")+"/v1/challenge",body,headers)

def siteverify(target, secret, token, action, hostname):
    body=urllib.parse.urlencode({"secret":secret,"response":token,"expected_action":action,"expected_hostname":hostname}).encode()
    return request(target.rstrip("/")+"/v1/siteverify",body,{"Content-Type":"application/x-www-form-urlencoded"},"POST")

def leading_zero_bits(digest: bytes) -> int:
    n=0
    for b in digest:
        if b == 0: n += 8; continue
        for bit in range(7,-1,-1):
            if b & (1<<bit): return n
            n += 1
    return n

def solve_own_pow(seed, bits, max_nonce):
    # This solves only BerryShield's documented test challenge.
    for nonce in range(max_nonce+1):
        if leading_zero_bits(hashlib.sha256(f"{seed}:{nonce}".encode()).digest()) >= bits:
            return nonce
    raise RuntimeError("BerryShield test PoW exhausted")

def check(label, ok, detail):
    print(f"{label}: {'PASS' if ok else 'FAIL'} — {detail}")
    return 0 if ok else 1

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--target",default="http://127.0.0.1:8080")
    ap.add_argument("--site-key",default="bs_dev_public"); ap.add_argument("--site-secret",default="")
    ap.add_argument("--hostname",default="localhost"); ap.add_argument("--sibling-hostname",default="")
    ap.add_argument("--allow-remote",action="store_true")
    ap.add_argument("--scenarios",default=str(Path(__file__).with_name("scenarios")/"default.json"))
    a=ap.parse_args()
    if not a.allow_remote and not is_loopback(a.target): raise SystemExit("Refusing non-loopback target; use --allow-remote only for an authorized staging instance.")
    failures=0

    scenarios=json.loads(Path(a.scenarios).read_text())
    for sc in scenarios:
        c=copy.deepcopy(BASE_CLIENT); c.update(sc.get("mutations",{})); c["behavior"].update(sc.get("behavior",{}))
        status,out=issue(a.target,a.site_key,a.hostname,client=c,ua=sc.get("server_user_agent"),extra_headers=sc.get("headers"),session_suffix=sc["id"])
        decision=out.get("decision")
        ok=status in (200,403) and decision is not None
        if "expect_not" in sc: ok=ok and decision != sc["expect_not"]
        if "expect_one_of" in sc: ok=ok and decision in sc["expect_one_of"]
        failures += check(f"{sc['id']} {sc['name']}",ok,f"status={status} decision={decision}")

    status,out=issue(a.target,a.site_key,a.hostname,origin="https://origin-not-allowed.invalid",session_suffix="origin")
    failures += check("RT-07 origin mismatch",status==403 and out.get("error")=="origin-not-allowed",f"status={status} body={out}")
    if a.sibling_hostname:
        status,out=issue(a.target,a.site_key,a.hostname,origin=f"http://{a.sibling_hostname}",session_suffix="sibling-origin")
        failures += check("RT-07b sibling-host confusion",status==403 and out.get("error")=="origin-not-allowed",f"status={status} error={out.get('error')}")
    else:
        print("RT-07b sibling-host confusion: SKIP — pass --sibling-hostname for another hostname allowed by the same site key")

    # Force BerryShield's own PoW, solve it normally, then replay the challenge proof.
    c=copy.deepcopy(BASE_CLIENT); c["webdriver"]=True
    status,out=issue(a.target,a.site_key,a.hostname,client=c,session_suffix="challenge-replay")
    if status==200 and out.get("decision")=="pow":
        p=out.get("params") or {}; nonce=solve_own_pow(str(p.get("seed","")),int(p.get("difficulty_bits",16)),int(p.get("max_nonce",20_000_000)))
        path=f"/v1/challenge/{urllib.parse.quote(out['challenge_id'])}/verify"
        headers={"Origin":f"http://{a.hostname}","User-Agent":"Mozilla/5.0","X-BerryShield-Site-Key":a.site_key}
        verify_body={"session_id":"bss_redteam_challenge-replay","proof":{"kind":"pow","nonce":nonce}}
        first=post_json(a.target.rstrip("/")+path,verify_body,headers)
        second=post_json(a.target.rstrip("/")+path,verify_body,headers)
        failures += check("RT-04 challenge replay",first[0]==200 and first[1].get("success") is True and second[0]==400,f"first_status={first[0]} second_status={second[0]} second_error={second[1].get('error')}")
    else:
        failures += check("RT-04 challenge replay",False,f"could not obtain PoW: status={status} body={out}")

    if a.site_secret:
        status,out=issue(a.target,a.site_key,a.hostname,action="redteam-token",session_suffix="token")
        token=out.get("token") if status==200 else None
        if token:
            first=siteverify(a.target,a.site_secret,token,"redteam-token",a.hostname)
            second=siteverify(a.target,a.site_secret,token,"redteam-token",a.hostname)
            failures += check("RT-05 token replay",first[1].get("success") is True and second[1].get("success") is False and "timeout-or-duplicate" in second[1].get("error-codes",[]),f"first={first[1].get('success')} second={second[1].get('error-codes')}")
        else:
            failures += check("RT-05 token replay",False,f"baseline did not return allow token: {out}")

        status,out=issue(a.target,a.site_key,a.hostname,action="redteam-action-a",session_suffix="action")
        token=out.get("token") if status==200 else None
        if token:
            wrong=siteverify(a.target,a.site_secret,token,"redteam-action-b",a.hostname)
            failures += check("RT-06 action mismatch",wrong[1].get("success") is False and "action-mismatch" in wrong[1].get("error-codes",[]),f"errors={wrong[1].get('error-codes')}")
        else:
            failures += check("RT-06 action mismatch",False,f"baseline did not return allow token: {out}")
    else:
        print("RT-05/RT-06: SKIP — pass --site-secret to test server-side token invariants")

    raise SystemExit(1 if failures else 0)
if __name__=="__main__": main()
