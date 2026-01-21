#!/bin/bash

# ================================================== 
#         SISTEM PAKAR DIAGNOSA PRIVILEGE ESCALATION
#              (VERSI MULTI-DETECTION SUID)
# ================================================== 

# Pengaturan Warna
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== Privilege Escalation Expert System ===${NC}"
echo "-----------------------------------------------------"

# --- 1. WORKING MEMORY ---
F01_SUID_AKTIF=false
F02_OWNER_ROOT=false
F03_SUDO_NOPASSWD=false
F04_CRON_WRITABLE=false
F05_RC_WRITABLE=false

# Array untuk menampung banyak temuan
LIST_SUID_TEMUAN=()
PATH_CRON=""

# --- 2. TAHAP PENGUMPULAN DATA (Fakta) ---
echo -e "[*] Tahap 1: Pengumpulan Fakta Sistem..."

# A. Identifikasi F01 & F02 (SUID & Root Owner)
# Mencari semua biner yang sesuai kriteria
ALL_SUID=$(find /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null | grep -E "/(nano|vim|nmap|bash|perl|python|find)$")

if [ ! -z "$ALL_SUID" ]; then
    F01_SUID_AKTIF=true
    while IFS= read -r line; do
        echo -e "  [Fakta F01] Biner SUID Ditemukan: $line"
        
        OWNER=$(stat -c '%U' "$line")
        if [ "$OWNER" == "root" ]; then
            F02_OWNER_ROOT=true
            echo -e "  [Fakta F02] Pemilik file $line adalah root"
            # Memasukkan temuan ke dalam array
            LIST_SUID_TEMUAN+=("$line")
        fi
    done <<< "$ALL_SUID"
fi

# B. Identifikasi F03 (Sudo NOPASSWD)
SUDO_CHECK=$(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null)
if [ ! -z "$SUDO_CHECK" ]; then
    F03_SUDO_NOPASSWD=true
    echo -e "  [Fakta F03] Ditemukan entri NOPASSWD: $SUDO_CHECK"
fi

# C. Identifikasi F04 (Cron Writable)
if [ -f /etc/crontab ]; then
    CRON_PATHS=$(grep -v "^#" /etc/crontab | awk '{print $7}' | grep "/")
    for p in $CRON_PATHS; do
        if [ -f "$p" ] && [ -w "$p" ]; then
            F04_CRON_WRITABLE=true
            PATH_CRON="$p"
            echo -e "  [Fakta F04] Skrip Cron Writable: $p"
            break
        fi
    done
fi

# D. Identifikasi F05 (RC Local Writable)
if [ -f /etc/rc.local ] && [ -w /etc/rc.local ]; then
    F05_RC_WRITABLE=true
    echo -e "  [Fakta F05] Berkas /etc/rc.local dapat dimodifikasi"
fi

echo -e "${GREEN}[V] Selesai Mengumpulkan Fakta.${NC}\n"

# --- 3. INFERENCE ENGINE ---
echo -e "[*] Tahap 2: Menjalankan Mesin Inferensi..."
DIAGNOSA_HASIL=()

if [ "$F01_SUID_AKTIF" = true ] && [ "$F02_OWNER_ROOT" = true ]; then
    echo -e "  [>] Aturan R1 Terpicu: Terdeteksi ${#LIST_SUID_TEMUAN[@]} biner SUID milik Root"
    DIAGNOSA_HASIL+=("D01")
fi

if [ "$F03_SUDO_NOPASSWD" = true ]; then
    echo -e "  [>] Aturan R2 Terpicu: Temuan NOPASSWD pada Sudoers"
    DIAGNOSA_HASIL+=("D02")
fi

if [ "$F04_CRON_WRITABLE" = true ]; then
    echo -e "  [>] Aturan R3 Terpicu: Cron memanggil skrip writable ($PATH_CRON)"
    DIAGNOSA_HASIL+=("D03")
fi

if [ "$F05_RC_WRITABLE" = true ]; then
    echo -e "  [>] Aturan R4 Terpicu: Berkas /etc/rc.local bersifat world-writable"
    DIAGNOSA_HASIL+=("D04")
fi

# --- 4. OUTPUT HASIL & MITIGASI ---
echo -e "\n-----------------------------------------------------"
echo -e "${YELLOW}=== KESIMPULAN DIAGNOSA & MITIGASI ===${NC}"

if [ ${#DIAGNOSA_HASIL[@]} -eq 0 ]; then
    echo -e "${GREEN}Sistem Aman. Tidak ditemukan celah konfigurasi spesifik.${NC}"
else
    echo -e "${RED}DITEMUKAN CELAH KEAMANAN:${NC}"
    for d_id in "${DIAGNOSA_HASIL[@]}"; do
        case $d_id in
            "D01")
                echo -e "\n[!] Diagnosa: T1548.001 - Abuse Elevation Control: Setuid"
                echo -e "${YELLOW}Daftar Biner Berbahaya:${NC}"
                for biner in "${LIST_SUID_TEMUAN[@]}"; do
                    echo -e "    -> $biner"
                done
                echo -e "${YELLOW}Langkah Mitigasi (R01):${NC}"
                echo -e "    - Hapus bit SUID: chmod u-s [path-biner]"
                echo -e "    - Gunakan 'setcap' sebagai alternatif."
                ;;
            "D02")
                echo -e "\n[!] Diagnosa: T1548.003 - Abuse Elevation Control: Sudo"
                echo -e "${YELLOW}Langkah Mitigasi (R02):${NC}"
                echo -e "    - Gunakan 'sudo visudo' untuk perbaikan."
                ;;
            "D03")
                echo -e "\n[!] Diagnosa: T1053.003 - Schedule Task/Job: Cron"
                echo -e "${YELLOW}Langkah Mitigasi (R03):${NC}"
                echo -e "    - Set izin 755 dan owner root pada skrip cron."
                ;;
            "D04")
                echo -e "\n[!] Diagnosa: T1037.004 - Boot Logon Script: RC Script"
                echo -e "${YELLOW}Langkah Mitigasi (R04):${NC}"
                echo -e "    - Jalankan: chmod 644 /etc/rc.local"
                ;;
        esac
    done
fi
echo -e "\n-----------------------------------------------------"
