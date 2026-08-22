# UFW SLA Allowlist — Langkah Aman

Fitur ini hanya menambahkan rule allow untuk IP/subnet SLA checker dari `ip.txt`. Script tidak membuka port, tidak mengubah default policy, dan tidak mengaktifkan UFW.

## 1. Buat `ip.txt`

Satu IP atau subnet per baris. Komentar diawali `#`.

```text
# IP SLA checker panitia
10.10.0.254

# Jika panitia memberi subnet resmi
10.10.0.0/24
```

Jangan memasukkan:

```text
0.0.0.0/0
::/0
```

## 2. Preview dulu

Jalankan dari folder project:

```bash
python3 scripts/adctf.py firewall-allowlist --ip-file ip.txt
```

Preview harus menunjukkan:

```text
Action: UFW allow from <entry> to any
Ports: tidak diubah
Enable: tidak dijalankan
Default policy: tidak diubah
```

## 3. Terapkan allowlist saja

Setelah IP diverifikasi dari technical meeting:

```bash
sudo python3 scripts/adctf.py firewall-allowlist \
  --ip-file ip.txt \
  --apply
```

Script akan menjalankan konsep rule berikut untuk setiap baris valid:

```bash
sudo ufw insert 1 allow from 10.10.0.254 to any
```

Script tidak menjalankan `ufw enable`, tidak menjalankan `ufw reset`, dan tidak mengatur port aplikasi.

## 4. Verifikasi manual

```bash
sudo ufw status numbered
sudo ufw status verbose
```

Pastikan allowlist SLA berada di atas rule deny yang sudah ada.

## 5. Atur port dan aktifkan firewall secara manual

Sesuaikan dengan hasil `ss -lntup` dan aturan panitia:

```bash
# SSH — sesuaikan source IP jika sudah pasti
sudo ufw allow 22/tcp

# Port aplikasi — hanya port yang benar-benar digunakan
sudo ufw allow 80/tcp
sudo ufw allow 8080/tcp
```

Sebelum enable, periksa ulang:

```bash
sudo ufw status numbered
```

Baru jika semua port dan IP SLA sudah benar:

```bash
sudo ufw enable
```

## 6. Tes SLA setelah firewall aktif

```bash
python3 scripts/adctf.py check --url http://127.0.0.1/
tail -f /var/log/ufw.log
tail -f /var/log/nginx/access.log
```

Jika SLA checker gagal, jangan menambahkan rule acak. Periksa IP sumber yang terlihat di access log dan cocokkan dengan daftar resmi panitia.

## Batasan penting

- Allowlist tidak membuktikan bahwa IP tersebut benar-benar milik SLA checker; verifikasi dari panitia.
- `ufw insert 1` memprioritaskan allow rule di UFW, tetapi rule yang sudah dikelola tool lain tetap harus diperiksa.
- Jangan memakai auto-ban berdasarkan jumlah request karena health checker bisa terlihat seperti traffic berulang.
- Jangan menjalankan `ufw reset` di tengah lomba.
