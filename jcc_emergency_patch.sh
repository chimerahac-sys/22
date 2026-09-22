#!/bin/bash
# JCC 2026 EMERGENCY PATCH KIT (BASH VERSION)
# Gunakan ini jika tidak bisa menjalankan script Python di server target
# Cara pakai: ssh user@target_ip 'bash -s' < jcc_emergency_patch.sh

echo "[*] JCC 2026 Emergency Patch Kit Started"
echo "[*] Target: $(hostname)"

# KONFIGURASI
FLAG_PATH="/flag"
SERVICE_PORT="80" # Sesuaikan dengan port service (80, 8080, 5000, dll)
SERVICE_NAME="httpd" # Atau apache2, nginx, python3, dll

# 1. AMANKAN FLAG (PENTING!)
# Pindahkan flag ke lokasi tersembunyi dan batasi permission
if [ -f "$FLAG_PATH" ]; then
    echo "[+] Flag found at $FLAG_PATH"
    cp "$FLAG_PATH" /tmp/.hidden_flag_$(date +%s)
    chmod 000 "$FLAG_PATH" # Hilangkan permission baca agar attacker tidak bisa cat /flag
    chown root:root "$FLAG_PATH"
    echo "[+] Flag secured and permissions revoked."
else
    echo "[-] Warning: Flag file not found at $FLAG_PATH"
fi

# 2. SIMPLE WAF (FILTER REQUEST BERBAHAYA)
# Menggunakan iptables untuk memblokir IP yang melakukan scanning berlebihan
# Catatan: Butuh root access. Jika tidak root, gunakan pendekatan aplikasi (misal mod_security config)

echo "[*] Setting up basic firewall rules..."
# Blokir port selain yang diperlukan (Opsional, hati-hati jangan sampai mematikan checker)
# iptables -A INPUT -p tcp --dport $SERVICE_PORT -j ACCEPT
# iptables -A INPUT -p tcp --dport 22 -j ACCEPT # Jangan blokir SSH!
# iptables -A INPUT -j DROP 

# 3. PATCH OTOMATIS UNTUK KERENTANAN UMUM (CONTOH WEB)
# Jika service berupa PHP/Python sederhana, kita bisa inject sanitization
# Contoh: Mematikan fungsi dangerous di php.ini jika ada akses write
if [ -f "/etc/php/7.4/apache2/php.ini" ]; then
    echo "[*] Patching PHP configuration..."
    sed -i 's/disable_functions = /disable_functions = system,exec,passthru,shell_exec,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source/' /etc/php/7.4/apache2/php.ini
    systemctl restart apache2
fi

# 4. MONITORING SERANGAN SEDERHANA
# Log aktivitas mencurigakan ke file khusus untuk analisis manual nanti
echo "[*] Starting basic attack monitor..."
tail -f /var/log/apache2/access.log | grep --line-buffered -E "union|select|script|../|etc/passwd" >> /tmp/attack_log.txt &
MONITOR_PID=$!
echo "[+] Monitor running with PID $MONITOR_PID"

# 5. RESTART SERVICE UNTUK MEMASTIKAN PERUBAHAN BERLAKU
echo "[*] Restarting service $SERVICE_NAME..."
if command -v systemctl &> /dev/null; then
    systemctl restart $SERVICE_NAME
elif command -v service &> /dev/null; then
    service $SERVICE_NAME restart
else
    # Fallback untuk service custom (misal python app)
    pkill -f "python.*app.py"
    nohup python3 app.py > /dev/null 2>&1 &
fi

echo "[+] Patching completed. Service restarted."
echo "[!] Jangan lupa submit flag lawan dan pantau SLA!"
