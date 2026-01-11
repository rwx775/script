#!/bin/bash

# ================================================== 
#                INFO PENGETAHUAN (KB)
# ================================================== 
# T1548.001 | SUID AND Known-Binary AND Executable
# T1548.003 | Sudo-Listable AND NOPASSWD-Found
# T1053.003 | Cron-Exists AND Writable-by-User
# T1037.004 | RC-Local-Exists AND Writable-by-User
# ================================================== 

# Pengaturan Warna
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NOCOLOR='\033[0m'

echo -e "${YELLOW}=== Privilege Escalation Diagnosis (AND Logic) ===${NOCOLOR}"
echo "-----------------------------------------------------"

# --- 1. WORKING MEMORY (Fakta-fakta) ---
F1_SUID_PATH=""
F1_CAN_EXECUTE=false

F2_SUDO_L=false
F2_NOPASSWD=false

F3_CRON_EXISTS=false
F3_CRON_WRITABLE=""

F4_RC_EXISTS=false
F4_RC_WRITABLE=false

# --- 2. TAHAP PENGUMPULAN FAKTA ---
echo -e "[*] Tahap 1: Pengumpulan Fakta Terperinci"

# A. Fakta untuk T1548.001 (SUID)
# Mencari apakah ada binary GTFOBins yang memiliki bit SUID
F1_SUID_PATH=$(find /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null | grep -E "/(nmap|vim|perl|python|bash|find|more|less|nano|cp|mv)$" | head -n 1)
if [ -x "$F1_SUID_PATH" ]; then F1_CAN_EXECUTE=true; fi

# B. Fakta untuk T1548.003 (Sudo)
if sudo -l -n &>/dev/null; then F2_SUDO_L=true; fi
if sudo -l -n 2>/dev/null | grep -q "NOPASSWD"; then F2_NOPASSWD=true; fi

# C. Fakta untuk T1053.003 (Cron)
if [ -f /etc/crontab ]; then 
    F3_CRON_EXISTS=true
    # Cek apakah ada script yang dipanggil cron dan bisa ditulis user
    CRON_PATHS=$(grep -v "^#" /etc/crontab | awk '{print $6}' | grep "/")
    for path in $CRON_PATHS; do
        if [ -w "$path" ]; then F3_CRON_WRITABLE="$path"; break; fi
    done
fi

# D. Fakta untuk T1037.004 (RC Script)
if [ -f /etc/rc.local ]; then F4_RC_EXISTS=true; fi
if [ -w /etc/rc.local ]; then F4_RC_WRITABLE=true; fi

echo -e "${GREEN}[V] Selesai Mengumpulkan Fakta.${NOCOLOR}\n"

# --- 3. INFERENCE ENGINE (Forward Chaining with AND Logic) ---
echo -e "[*] Tahap 2: Menjalankan Mesin Inferensi (Composite Rules)..."

DIAGNOSA_HASIL=()

# RULE 1: IF (Fakta SUID Ada) AND (User Bisa Eksekusi)
if [ ! -z "$F1_SUID_PATH" ] && [ "$F1_CAN_EXECUTE" = true ]; then
    echo -e "  [>] R1 Terpicu: Kombinasi SUID + Izin Eksekusi pada $F1_SUID_PATH"
    DIAGNOSA_HASIL+=("T1548.001: Abuse Elevation Control Mechanism (Setuid/Setgid)")
fi

# RULE 2: IF (Sudo Bisa di-List) AND (Ada String NOPASSWD)
if [ "$F2_SUDO_L" = true ] && [ "$F2_NOPASSWD" = true ]; then
    echo -e "  [>] R2 Terpicu: Kombinasi Akses Sudo + NOPASSWD ditemukan."
    DIAGNOSA_HASIL+=("T1548.003: Abuse Elevation Control Mechanism (Sudo/Sudo Caching)")
fi

# RULE 3: IF (Cron File Ada) AND (Ada Script yang Writable)
if [ "$F3_CRON_EXISTS" = true ] && [ ! -z "$F3_CRON_WRITABLE" ]; then
    echo -e "  [>] R3 Terpicu: Kombinasi File Cron + Script Writable ($F3_CRON_WRITABLE)"
    DIAGNOSA_HASIL+=("T1053.003: Scheduled Task/Job (Cron)")
fi

# RULE 4: IF (RC Script Ada) AND (File Writable oleh User)
if [ "$F4_RC_EXISTS" = true ] && [ "$F4_RC_WRITABLE" = true ]; then
    echo -e "  [>] R4 Terpicu: Kombinasi rc.local Ada + Izin Tulis (Writable)."
    DIAGNOSA_HASIL+=("T1037.004: Boot and Logon RC Script")
fi

# --- 4. OUTPUT / KESIMPULAN (Goal) ---
echo -e "\n-----------------------------------------------------"
echo -e "${YELLOW}=== HASIL DIAGNOSA AKHIR ===${NOCOLOR}"

if [ ${#DIAGNOSA_HASIL[@]} -eq 0 ]; then
    echo -e "${GREEN}Sistem Aman. Tidak ada aturan (Rules) yang terpenuhi secara utuh.${NOCOLOR}"
else
    echo -e "${RED}DITEMUKAN CELAH PRIVILEGE ESCALATION:${NOCOLOR}"
    for hasil in "${DIAGNOSA_HASIL[@]}"; do
        echo -e "  - $hasil"
    done
fi
echo "-----------------------------------------------------"
