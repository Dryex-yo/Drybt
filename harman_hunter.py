#!/usr/bin/env python3
"""
Harman International Bug Bounty Hunter - DRYBT Integration
User-Agent: BugBounty-Harman
Cookie session siap pakai
Module: param_discovery, open_redirect, sqli, lfi, race_condition, ssrf, xss, csrf, cors, dir_traversal
"""

import subprocess
import sys
import os
import time
import json
from datetime import datetime

# ===== KONFIGURASI =====
USER_AGENT = "BugBounty-Harman"

# ===== MASUKKAN COOKIE SESSION KAMU DI SINI =====
# Copy dari DevTools → Application → Cookies → session
SESSION_COOKIE = "eyJfcGVybWFuZW50Ijp0cnVlfQ.HO450Q.PZK__GQhNHYDW3QO98HlqO6EWl8"
# GANTI dengan value session asli kamu!

# Cookie lain (opsional, dari gambar DevTools kamu)
UUID_COOKIE = "abo0JspXOtjuvFduY35OXB1Yfl"  # Ganti dengan uuid kamu jika perlu
MIUD_COOKIE = "1833A9B1288A62DF330BBEAE29B563AD"  # Ganti dengan MIUD kamu jika perlu

# Gabungkan semua cookie
COOKIE_STRING = f"session={SESSION_COOKIE}; uuid={UUID_COOKIE}; MIUD={MIUD_COOKIE}"

DRYBT_MAIN = "main.py"
RATE_DELAY = 0.2  # 5 request/detik
TIMEOUT = 1800    # 30 menit per module

# 10 Module
MODULES = [
    "param_discovery",
    "open_redirect",
    "sqli",
    "lfi",
    "race_condition",
    "ssrf",
    "xss",
    "csrf",
    "cors",
    "dir_traversal"
]

# Target Harman (scope critical & high)
TARGETS = [
    "https://www.jbl.com",
    "https://www.bowerswilkins.com",
    "https://www.denon.com",
    "https://www.harmanaudio.com",
    "https://www.harmankardon.com"
]

def add_headers_to_config():
    """Tambahkan user-agent dan cookie ke config.yaml"""
    config_path = "config.yaml"
    
    # Konten config yang akan ditulis
    config_content = f"""
# DRYBT Configuration for Harman Bug Bounty
user_agent: "{USER_AGENT}"
headers:
  Cookie: "{COOKIE_STRING}"
  User-Agent: "{USER_AGENT}"
rate_limit: 5
timeout: 30
"""
    
    with open(config_path, 'w') as f:
        f.write(config_content)
    print(f"[✓] Config ditulis ke {config_path}")
    print(f"    User-Agent: {USER_AGENT}")
    print(f"    Cookie: {COOKIE_STRING[:50]}...")

def scan_target(target, module):
    """Jalankan scan satu module ke satu target"""
    cmd = [sys.executable, DRYBT_MAIN, "-t", target, "-m", module]
    
    # Environment untuk header custom
    env = os.environ.copy()
    env["HTTP_USER_AGENT"] = USER_AGENT
    env["HTTP_COOKIE"] = COOKIE_STRING
    
    print(f"\n[→] Target : {target}")
    print(f"    Module : {module}")
    print(f"    Timeout: {TIMEOUT} detik ({TIMEOUT/60:.0f} menit)")
    
    start = time.time()
    
    try:
        result = subprocess.run(
            cmd, 
            env=env, 
            capture_output=True, 
            text=True, 
            timeout=TIMEOUT
        )
        duration = time.time() - start
        print(f"    ✓ Selesai dalam {duration:.2f} detik ({duration/60:.2f} menit)")
        
        # Simpan hasil
        report_dir = "reports/harman"
        os.makedirs(report_dir, exist_ok=True)
        
        target_safe = target.replace('https://', '').replace('/', '_').replace('.', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{report_dir}/{target_safe}_{module}_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write(f"Target: {target}\n")
            f.write(f"Module: {module}\n")
            f.write(f"User-Agent: {USER_AGENT}\n")
            f.write(f"Cookie: {COOKIE_STRING}\n")
            f.write(f"Timeout: {TIMEOUT} detik\n")
            f.write(f"Duration: {duration:.2f} detik\n")
            f.write(f"Timestamp: {datetime.now()}\n")
            f.write("\n" + "="*60 + "\n")
            f.write("STDOUT:\n")
            f.write("="*60 + "\n")
            f.write(result.stdout)
            f.write("\n" + "="*60 + "\n")
            f.write("STDERR:\n")
            f.write("="*60 + "\n")
            f.write(result.stderr)
        
        print(f"    📁 Laporan: {report_file}")
        
        time.sleep(RATE_DELAY)
        return True
        
    except subprocess.TimeoutExpired:
        print(f"    ⏱️ TIMEOUT setelah {TIMEOUT} detik")
        
        # Tetap simpan laporan timeout
        report_dir = "reports/harman"
        os.makedirs(report_dir, exist_ok=True)
        target_safe = target.replace('https://', '').replace('/', '_').replace('.', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{report_dir}/{target_safe}_{module}_{timestamp}_TIMEOUT.txt"
        
        with open(report_file, 'w') as f:
            f.write(f"Target: {target}\n")
            f.write(f"Module: {module}\n")
            f.write(f"Status: TIMEOUT\n")
            f.write(f"User-Agent: {USER_AGENT}\n")
            f.write(f"Cookie: {COOKIE_STRING}\n")
            f.write(f"Timestamp: {datetime.now()}\n")
        
        print(f"    📁 Laporan timeout: {report_file}")
        return False
        
    except Exception as e:
        print(f"    ✗ ERROR: {e}")
        return False

def main():
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║              HARMAN INTERNATIONAL BUG BOUNTY HUNTER                  ║
║                        by Colin for Khan                             ║
║                                                                      ║
║  User-Agent : BugBounty-Harman                                       ║
║  Cookie     : session + uuid + MIUD (dari login)                     ║
║  Module     : 10 module                                              ║
║  Timeout    : 1800 detik (30 menit) per module                       ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Cek DRYBT
    if not os.path.exists(DRYBT_MAIN):
        print(f"[✗] ERROR: {DRYBT_MAIN} tidak ditemukan!")
        print("    Pastikan script ini dijalankan dari folder DRYBT")
        sys.exit(1)
    
    # Tambahkan konfigurasi
    add_headers_to_config()
    
    # Info scan
    print(f"\n{'='*60}")
    print(f"[*] User-Agent    : {USER_AGENT}")
    print(f"[*] Cookie loaded : Yes ({len(COOKIE_STRING)} karakter)")
    print(f"[*] Total target  : {len(TARGETS)}")
    print(f"[*] Total module  : {len(MODULES)}")
    print(f"[*] Total scan    : {len(TARGETS) * len(MODULES)}")
    print(f"{'='*60}")
    
    print("\n[!] PASTIKAN:")
    print("    1. Cookie session sudah diisi dengan benar")
    print("    2. Akun test sudah login dan session masih aktif")
    print("    3. Kamu sudah registrasi di program Harman YesWeHack")
    print("\n[?] Tekan Enter untuk memulai scan, atau Ctrl+C batal...")
    input()
    
    print("\n[*] Memulai scanning...\n")
    
    total_success = 0
    total_timeout = 0
    
    for target in TARGETS:
        for module in MODULES:
            success = scan_target(target, module)
            if success:
                total_success += 1
            else:
                total_timeout += 1
    
    # Ringkasan akhir
    print("\n" + "="*60)
    print("[✓] SCAN SELESAI")
    print(f"    Sukses : {total_success}")
    print(f"    Timeout: {total_timeout}")
    print(f"    Total  : {len(TARGETS) * len(MODULES)}")
    print(f"    Laporan di folder: reports/harman/")
    print("="*60)

if __name__ == "__main__":
    main()