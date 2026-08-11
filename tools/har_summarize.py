#!/usr/bin/env python3
"""Sanitized HAR summarizer for defensive protocol research.

Never emits cookie values, authorization headers, response bodies, or full query values.
It extracts structure only: hosts, paths, methods, field names, response JSON key shapes,
and a few non-secret categorical values such as GeeTest risk_type.
"""
from __future__ import annotations
import argparse, collections, json, re, urllib.parse
from pathlib import Path

SENSITIVE = re.compile(r"(?i)(token|cookie|secret|authorization|pass|hmac|key|response|solution|payload|session|clearance)")

def sanitize_path(path: str) -> str:
    parts=[]
    for seg in path.split("/"):
        if not seg:
            parts.append(seg); continue
        core=seg.rsplit(".",1)[0]
        looks_opaque = (len(seg) > 48 or re.fullmatch(r"[0-9a-fA-F]{17,}", core or "") or re.fullmatch(r"[A-Za-z0-9_-]{24,}", core or ""))
        if looks_opaque:
            ext = "." + seg.rsplit(".",1)[1] if "." in seg and len(seg.rsplit(".",1)[1]) <= 6 else ""
            parts.append("<opaque>" + ext)
        else:
            parts.append(seg)
    return "/".join(parts) or "/"

def json_shape(value, prefix="", depth=0, out=None):
    out = out if out is not None else set()
    if depth > 3: return out
    if isinstance(value, dict):
        for k, v in value.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            out.add(p)
            json_shape(v, p, depth+1, out)
    elif isinstance(value, list) and value:
        json_shape(value[0], prefix+"[]", depth+1, out)
    return out

def body_field_names(post):
    out=[]
    for p in post.get("params") or []:
        n=p.get("name")
        if n: out.append(n)
    text=post.get("text") or ""
    mime=(post.get("mimeType") or "").lower()
    if text and "json" in mime:
        try:
            obj=json.loads(text)
            if isinstance(obj, dict): out += list(obj.keys())
        except Exception: pass
    elif text and "x-www-form-urlencoded" in mime:
        try: out += [k for k,_ in urllib.parse.parse_qsl(text, keep_blank_values=True)]
        except Exception: pass
    return sorted(set(out))

def summarize(path: Path):
    raw=path.read_text(errors="replace")
    base={"file":path.name, "entries":0, "parse":"json", "hosts":[], "routes":[], "categorical":{}, "notes":[]}
    try:
        data=json.loads(raw)
        entries=data.get("log",{}).get("entries",[])
    except Exception as exc:
        # Recovery for a truncated HAR: only URL structure, no values.
        urls=re.findall(r'"url"\s*:\s*"(https?://[^"\\]+)', raw)
        hc=collections.Counter(); pc=collections.Counter()
        for u in urls:
            try:
                p=urllib.parse.urlparse(u); hc[p.hostname or ""]+=1; pc[("?",p.hostname or "",sanitize_path(p.path))]+=1
            except Exception: pass
        base.update({"parse":"lexical-recovery","entries":len(urls),"hosts":hc.most_common(12),
                     "routes":[{"method":m,"host":h,"path":p,"count":c} for (m,h,p),c in pc.most_common(30)]})
        base["notes"].append(f"HAR JSON was malformed/truncated; lexical URL recovery only ({type(exc).__name__}).")
        return base

    hc=collections.Counter(); routes={}; categorical=collections.defaultdict(set)
    for e in entries:
        req=e.get("request",{}); method=req.get("method","?")
        try: u=urllib.parse.urlparse(req.get("url", ""))
        except Exception: continue
        host=u.hostname or ""; path_only=sanitize_path(u.path or "/")
        hc[host]+=1
        key=(method,host,path_only)
        r=routes.setdefault(key,{"method":method,"host":host,"path":path_only,"count":0,"query_fields":set(),"post_fields":set(),"response_shape":set()})
        r["count"]+=1
        for q in req.get("queryString") or []:
            name=q.get("name")
            if name: r["query_fields"].add(name)
            # Retain only categorical protocol selectors, never opaque values.
            if name in {"risk_type","client_type","type","theme","size"}:
                val=str(q.get("value",""))[:64]
                if val and not SENSITIVE.search(name): categorical[name].add(val)
        r["post_fields"].update(body_field_names(req.get("postData") or {}))
        content=(e.get("response",{}).get("content") or {})
        txt=content.get("text") or ""; mime=(content.get("mimeType") or "").lower()
        if txt and ("json" in mime or txt.lstrip().startswith(("{","["))):
            # JSONP is intentionally not decoded here.
            try: r["response_shape"].update(json_shape(json.loads(txt)))
            except Exception: pass
    out=[]
    for _,r in sorted(routes.items(), key=lambda kv:(-kv[1]["count"],kv[1]["host"],kv[1]["path"])):
        r={**r,"query_fields":sorted(r["query_fields"]),"post_fields":sorted(r["post_fields"]),"response_shape":sorted(r["response_shape"])}
        out.append(r)
    base.update({"entries":len(entries),"hosts":hc.most_common(12),"routes":out[:40],"categorical":{k:sorted(v) for k,v in categorical.items()}})
    return base

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("paths",nargs="+"); ap.add_argument("--json",action="store_true")
    a=ap.parse_args(); results=[summarize(Path(p)) for p in a.paths]
    if a.json: print(json.dumps(results,indent=2,ensure_ascii=False))
    else:
        for r in results:
            print(f"\n## {r['file']} ({r['entries']} entries, {r['parse']})")
            print("hosts:", ", ".join(f"{h} ({n})" for h,n in r['hosts']))
            if r['categorical']: print("categorical:", r['categorical'])
            for x in r['routes'][:15]:
                fields=sorted(set(x.get('query_fields',[])+x.get('post_fields',[])))
                print(f"- {x['method']} {x['host']}{x['path']} x{x['count']} fields={fields} shape={x.get('response_shape',[])[:12]}")
            for n in r['notes']: print("note:",n)
if __name__=='__main__': main()
