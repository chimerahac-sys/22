# Nmap — Single-Host CTF Reference

Nmap hanya digunakan bila aturan lomba mengizinkannya. Pilih satu host dan port yang sudah berada dalam scope; jangan memakai CIDR besar atau mode aggressive.

```bash
# Satu host, port yang diketahui
nmap -Pn -T2 -p 80,443,8080 10.10.10.5

# Deteksi versi terbatas pada port yang sudah diketahui
nmap -Pn -T2 -sV --version-light -p 80 10.10.10.5
```

Jangan gunakan `-A`, `-T5`, `-p-`, `-iL` besar, NSE intrusive, atau discovery massal tanpa izin tertulis panitia.
