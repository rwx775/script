#!/bin/bash

# ================================================== 
#        SISTEM PAKAR DIAGNOSA PRIVILEGE ESCALATION
#             (BERDASARKAN TABEL 4.1 - 4.4)
# ================================================== 

# Pengaturan Warna untuk Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Privilege Escalation Expert System ===${NC}"
echo "-----------------------------------------------------"

# --- 1. WORKING MEMORY (Fakta-fakta sesuai Tabel 4.1) ---
# Menggunakan penamaan F01-F05 agar sinkron dengan Bab 4
F01_SUID_AKTIF=false
F02_OWNER_ROOT=false
F03_SUDO_NOPASSWD=false
F04_CRON_WRITABLE=false
F05_RC_WRITABLE=false

# Variabel Pembantu Teknis untuk Menyimpan Path Temuan
PATH_SUID=""
PATH_CRON=""

# --- 2. TAHAP PENGUMPULAN DATA (Fakta) ---
echo -e "[*] Tahap 1: Pengumpulan Fakta Sistem..."

# A. Identifikasi F01 & F02 (SUID & Root Owner)
# Mencari biner GTFOBins umum yang memiliki bit SUID
PATH_SUID=$(find /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null | grep -E "/(vim|nmap|bash|perl|python|find)$" | head -n 1)
if [ ! -z "$PATH_SUID" ]; then
    F01_SUID_AKTIF=true
    # Cek apakah pemiliknya adalah root (F02)
    OWNER=$(stat -c '%U' "$PATH_SUID")
    if [ "$OWNER" == "root" ]; then
        F02_OWNER_ROOT=true
    fi
fi

# B. Identifikasi F03 (Sudo NOPASSWD)
if sudo -l -n 2>/dev/null | grep -q "NOPASSWD"; then
    F03_SUDO_NOPASSWD=true
fi

# C. Identifikasi F04 (Cron Writable)
if [ -f /etc/crontab ]; then
    # Mencari path script yang dipanggil di crontab (kolom ke-7)
    CRON_PATHS=$(grep -v "^#" /etc/crontab | awk '{print $7}' | grep "/")
    for p in $CRON_PATHS; do
        if [ -f "$p" ] && [ -w "$p" ]; then
            F04_CRON_WRITABLE=true
            PATH_CRON="$p"
            break
        fi
    done
fi

# D. Identifikasi F05 (RC Local Writable)
if [ -f /etc/rc.local ] && [ -w /etc/rc.local ]; then
    F05_RC_WRITABLE=true
fi

echo -e "${GREEN}[V] Selesai Mengumpulkan Fakta.${NC}\n"

# --- 3. INFERENCE ENGINE (Match-Execute sesuai Tabel 4.4) ---
echo -e "[*] Tahap 2: Menjalankan Mesin Inferensi..."

DIAGNOSA_HASIL=()

# R1: IF F01 AND F02 THEN D01
if [ "$F01_SUID_AKTIF" = true ] && [ "$F02_OWNER_ROOT" = true ]; then
    echo -e "  [>] Aturan R1 Terpicu: Kombinasi SUID + Root Owner pada $PATH_SUID"
    DIAGNOSA_HASIL+=("D01")
fi

# R2: IF F03 THEN D02
if [ "$F03_SUDO_NOPASSWD" = true ]; then
    echo -e "  [>] Aturan R2 Terpicu: Temuan NOPASSWD pada Sudoers"
    DIAGNOSA_HASIL+=("D02")
fi

# R3: IF F04 THEN D03
if [ "$F04_CRON_WRITABLE" = true ]; then
    echo -e "  [>] Aturan R3 Terpicu: Cron memanggil skrip writable ($PATH_CRON)"
    DIAGNOSA_HASIL+=("D03")
fi

# R4: IF F05 THEN D04
if [ "$F05_RC_WRITABLE" = true ]; then
    echo -e "  [>] Aturan R4 Terpicu: Berkas /etc/rc.local bersifat world-writable"
    DIAGNOSA_HASIL+=("D04")
fi

# --- 4. OUTPUT HASIL & MITIGASI (Sesuai Tabel 4.2 & 4.3) ---
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
                echo -e "${YELLOW}Langkah Mitigasi (R01):${NC}"
                echo -e "    - Identifikasi apakah biner memerlukan SUID untuk fungsi dasar."
                echo -e "    - Hapus bit SUID dengan perintah: chmod u-s $PATH_SUID"
                echo -e "    - Gunakan 'setcap' sebagai alternatif pengganti SUID." ;;
            "D02")
                echo -e "\n[!] Diagnosa: T1548.003 - Abuse Elevation Control: Sudo"
                echo -e "${YELLOW}Langkah Mitigasi (R02):${NC}"
                echo -e "    - Edit konfigurasi menggunakan perintah: sudo visudo."
                echo -e "    - Ganti NOPASSWD dengan perintah spesifik daripada akses ALL."
                echo -e "    - Set 'timestamp_timeout' yang rendah pada /etc/sudoers." ;;
            "D03")
                echo -e "\n[!] Diagnosa: T1053.003 - Schedule Task/Job: Cron"
                echo -e "${YELLOW}Langkah Mitigasi (R03):${NC}"
                echo -e "    - Perbarui kepemilikan skrip adalah root dan set izin 755."
                echo -e "    - Jangan menaruh skrip di /var/tmp atau di /tmp." ;;
            "D04")
                echo -e "\n[!] Diagnosa: T1037.004 - Boot Logon Script: RC Script"
                echo -e "${YELLOW}Langkah Mitigasi (R04):${NC}"
                echo -e "    - Update izin akses file menjadi 644: chmod 644 /etc/rc.local"
                echo -e "    - Pertimbangkan bermigrasi ke systemd untuk kontrol lebih baik." ;;
        esac
    done
fi
echo "-----------------------------------------------------"
