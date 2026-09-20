# 📡 Traffic Analysis, Sniffing & PCAP Bible — CTF A/D

> **Panduan Menangkap Traffic Lawan Real-Time, Menemukan Exploit Mereka, dan Membaca Flag di Jaringan.**

---

## 1. ⚡ QUICK ONE-LINER SNIFFING (Copy-Paste Langsung di Terminal)

```bash
# 1. Tangkap SEMUA request HTTP GET/POST di Port 80 secara langsung di terminal:
tcpdump -i any -A -s 0 -nn 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12:2]&0xf0)>>2)) != 0)'

# 2. Tangkap string FLAG yang lewat di jaringan secara live (ngrep):
ngrep -q -d any -W byline -i "flag|jcsc|ctf|cyber" port 80

# 3. Tangkap payload POST (sering berisi exploit / webshell / SQLi):
tcpdump -i any -s 0 -A -l -n "tcp port 80 and (tcp[((tcp[12:2] & 0xf0) >> 2):4] = 0x504f5354)"

# 4. Tangkap payload GET:
tcpdump -i any -s 0 -A -l -n "tcp port 80 and (tcp[((tcp[12:2] & 0xf0) >> 2):4] = 0x47455420)"

# 5. Rekam seluruh traffic lomba ke file PCAP di background (untuk analisis nanti):
tcpdump -i any -s 0 -w /tmp/traffic_$(date +%s).pcap -C 50 -W 5 &
```

---

## 2. 🕵️ CARA MENGANALISIS FILE PCAP DENGAN TSHARK / TCPDUMP

Jika kamu sudah merekam file PCAP (`/tmp/traffic.pcap`), gunakan perintah ini untuk mengekstrak informasi:

```bash
# 1. Ekstrak semua string FLAG dari file PCAP:
tshark -r /tmp/traffic.pcap -Y "http contains \"FLAG\" or http contains \"JCSC\"" -T fields -e http.file_data | grep -oP '(FLAG|JCSC|CTF|CYBER)\{[^}]+\}' | sort -u

# 2. Ekstrak semua URL yang diakses attacker (melihat endpoint apa yang dieksploitasi):
tshark -r /tmp/traffic.pcap -Y "http.request.method == \"GET\" or http.request.method == \"POST\"" -T fields -e ip.src -e http.request.method -e http.request.uri | sort | uniq -c | sort -nr

# 3. Ekstrak data POST (melihat payload RCE / SQLi yang dikirim lawan):
tshark -r /tmp/traffic.pcap -Y "http.request.method == \"POST\"" -T fields -e ip.src -e http.request.uri -e urlencoded-form.value -e http.file_data

# 4. Cari tahu siapa IP lawan yang paling aktif menyerang kita:
tshark -r /tmp/traffic.pcap -Y "http.request" -T fields -e ip.src | sort | uniq -c | sort -nr | head -10
```

---

## 3. 🦈 FILTER WIRESHARK TERBAIK (Saat Buka PCAP di Laptop)

Buka file PCAP di Wireshark dan gunakan display filter berikut:

| Kebutuhan Analisis | Display Filter Wireshark |
|---|---|
| **Cari Flag** | `frame contains "FLAG{"` atau `http contains "FLAG"` |
| **Hanya HTTP Requests** | `http.request` |
| **Cari Payload SQLi** | `http.request.uri matches "union|select|sleep|order%20by"` |
| **Cari Serangan LFI** | `http.request.uri matches "\.\./|php://|base64"` |
| **Cari Reverse Shell** | `tcp.port in {4444, 1337, 9001, 1234} and tcp.flags.syn==1` |
| **Follow Stream** | Klik kanan pada paket -> *Follow* -> *TCP Stream* / *HTTP Stream* |

---

## 4. 🔄 STRATEGI: CURI EXPLOIT LAWAN & TEMBAKKAN BALIK

Saat bertanding di CTF Attack-Defense:
1. Jalankan sniffer WAF bawaan tools kita:
   ```bash
   python3 adctf.py autopilot --targets 10.60.1-20.1 --submit-url http://10.0.0.1/api/submit --token TOKEN
   ```
2. Atau jika menganalisis manual via log:
   ```bash
   tail -f /var/log/nginx/access.log | grep -E "union|eval|system|php://|\.\./"
   ```
3. Saat kamu melihat payload attacker lain yang berhasil, segera salin dan tembakkan ke tim-tim lain yang belum menambal bug tersebut menggunakan probe:
   ```bash
   python3 adctf.py probe -t 10.60.1-20.1 -e /endpoint.php -p param --payload "PAYLOAD_DARI_LOG"
   ```
