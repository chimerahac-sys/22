# HTTP Verification — curl dan Burp Repeater

Dipakai untuk verifikasi manual terhadap service CTF yang berada dalam scope.

## curl satu request

```bash
curl -i --max-time 5 http://10.10.10.5/
curl -i --max-time 5 "http://10.10.10.5/search.php?q=VALUE"
curl -i --max-time 5 -X POST "http://10.10.10.5/login.php" -d "username=VALUE&password=VALUE"
```

Jangan mengubah contoh ini menjadi loop tanpa rate limit. Untuk traffic yang dikirim otomatis, gunakan `adctf.py verify` karena ia mewajibkan jeda minimal 2 detik.

## Burp Repeater

1. Intercept satu request dari target CTF.
2. Kirim ke Repeater.
3. Ubah satu parameter saja.
4. Bandingkan status, panjang body, dan waktu respons.
5. Simpan bukti request/response dan hentikan jika SLA berubah.

Hindari Intruder mass mode, crawler agresif, dan request burst jika aturan lomba melarangnya.
