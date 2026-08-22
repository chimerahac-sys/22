# Targeted Probe — CTF Internal

Tool ini hanya untuk target private/internal yang sudah ditentukan panitia. Ia bukan mass scanner.

## Jalankan

```bash
python3 scripts/exploit/targeted_probe.py
```

Saat diminta:

```text
Masukkan file IP [enemy.txt]: enemy.txt
Pilihan: 1
Endpoint, contoh /search.php: /search.php
Nama parameter, contoh id atau q: id
Payload yang ingin diuji: PAYLOAD_UJI
Timeout detik [5]: 5
Ketik CONFIRM untuk mulai: CONFIRM
```

## Format `enemy.txt`

```text
# satu IP per baris
10.10.10.5
10.10.10.6
```

IP publik, wildcard, CIDR, dan duplikat ditolak. Target dibatasi 256 alamat agar tidak berubah menjadi discovery massal.

## Interpretasi hasil

| Hasil | Arti |
|---|---|
| `VULNERABLE-INDICATOR` | Ada indikator respons yang relevan; validasi manual sebelum tindakan lanjutan |
| `NO-EVIDENCE` | Tidak ada indikator dari satu request ini; bukan bukti pasti aman |
| `INCONCLUSIVE` | Respons error/status tidak cukup untuk kesimpulan |
| `UNREACHABLE` | Target tidak menjawab atau timeout |

Tool hanya mengirim satu request per IP, berurutan, tanpa retry dan jeda 2 detik antar-target. Payload dimasukkan operator; tool tidak menghasilkan payload destruktif.
