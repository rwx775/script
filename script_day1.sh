#!/bin/bash

# ================================================== 
#                INFO PENGETAHUAN
# ================================================== 
# Abuse Elevation Control Mechanism | T1548
# T1548.001 | T1548.003
# ================================================== 
# Abuse Elevation Control Mechanism | T1053
# T1053.003
# ================================================== 
# Boot or Logon Initialization Scripts | T1037
# T1053.004
# ================================================== 

# Pengaturan Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # Tanpa warna

echo -e "${YELLOW}=== Privilege Escalation Diagnosis ===${NC}"
echo "-----------------------------------------------------"

# --- 1. MEMORY (Penyimpanan Fakta) ---
# Tergantung device, setelah di scan fakta ditemukan akan disimpan ke sini.
FAKTA_SUID_BIN=""
FAKTA_SUDO_NOPASSWD=""
FAKTA_WRITABLE_CRON=""
FAKTA_WRITABLE_RC=""

# --- 2. Pengumpulan Fakta secara Otomatis ---
echo -e "[*] Tahap 1: Pengumpulan Fakta "

# A. Cek SUID Binaries (T1548.001)
# Test Exploit dari GTFoBin
FAKTA_SUID_BIN=$(find /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null | grep -E "/(nmap|vim|perl|python|bash|find|more|less|nano|cp|mv)$")

# B. Cek Sudo NOPASSWD (T1548.003)
# Hanya bisa dicek jika user saat ini punya akses sudo -l
FAKTA_SUDO_NOPASSWD=$(sudo -l -n 2>/dev/null | grep "NOPASSWD")

# C. Cek Writable Cron Job (T1053.003)
# Mencari file script di crontab yang bisa ditulis oleh user saat ini
if [ -f /etc/crontab ]; then
    CRON_PATHS=$(grep -v "^#" /etc/crontab | awk '{print $6}' | grep "/")
    for path in $CRON_PATHS; do
        if [ -w "$path" ]; then FAKTA_WRITABLE_CRON="$path"; break; fi
    done
fi

# D. Cek Writable RC Scripts (T1037.004)
# Mencari rc.local atau init.d yang dapat dimodifikasi.
if [ -w /etc/rc.local ]; then
    FAKTA_WRITABLE_RC="/etc/rc.local"
fi

echo -e "${GREEN}[V] Selesai Mengumpulkan Fakta.${NC}\n"

# --- 3. INFERENCE ENGINE ---
# R = Rule
# OUTPUT DARI R1,R2,R3,R4
echo -e "[*] Tahap 2: Menjalankan Mesin Inferensi (Rule)..."

DIAGNOSA_HASIL=()

# RULE 1: IF (SUID_Binaries_Found) THEN (T1548.001)
if [ ! -z "$FAKTA_SUID_BIN" ]; then
    echo -e "  [>] Rule 1, Fakta SUID ditemukan pada: $FAKTA_SUID_BIN"
    DIAGNOSA_HASIL+=("T1548.001: Abuse Elevation Control Mechanism (Setuid/Setgid)")
fi

# RULE 2: IF (Sudo_NoPasswd_Found) THEN (T1548.003)
if [ ! -z "$FAKTA_SUDO_NOPASSWD" ]; then
    echo -e "  [>] Rule 2, Fakta Sudo NOPASSWD ditemukan."
    DIAGNOSA_HASIL+=("T1548.003: Abuse Elevation Control Mechanism (Sudo/Sudo Caching)")
fi

# RULE 3: IF (Writable_Cron_Script_Found) THEN (T1053.003)
if [ ! -z "$FAKTA_WRITABLE_CRON" ]; then
    echo -e "  [>] Rule 3, Fakta Script Cron Writable ditemukan di: $FAKTA_WRITABLE_CRON"
    DIAGNOSA_HASIL+=("T1053.003: Scheduled Task/Job (Cron)")
fi

# RULE 4: IF (Writable_RC_Script_Found) THEN (T1037.004)
if [ ! -z "$FAKTA_WRITABLE_RC" ]; then
    echo -e "  [>] Rule 4, Fakta RC Script Writable ditemukan di: $FAKTA_WRITABLE_RC"
    DIAGNOSA_HASIL+=("T1037.004: Boot and Logon RC Script")
fi

# --- 4. OUTPUT / KESIMPULAN (Goal) ---
echo -e "\n-----------------------------------------------------"
echo -e "${YELLOW}=== HASIL DIAGNOSA AKHIR ===${NC}"

if [ ${#DIAGNOSA_HASIL[@]} -eq 0 ]; then
    echo -e "${GREEN}Sistem Aman. Tidak ditemukan miskonfigurasi berdasarkan batasan masalah.${NC}"
else
    echo -e "${RED}DITEMUKAN CELAH PRIVILEGE ESCALATION:${NC}"
    for hasil in "${DIAGNOSA_HASIL[@]}"; do
        echo -e "  - $hasil"
    done
    echo -e "\n${YELLOW}Rekomendasi:${NC} Periksa izin file (chmod) dan batasi akses sudoers."
fi
echo "-----------------------------------------------------"
