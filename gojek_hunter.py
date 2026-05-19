#!/usr/bin/env python3
"""
Gojek Bug Bounty Hunter - DRYBT Integration
Username: Dryex
Module: param_discovery, open_redirect, sqli, lfi, race_condition, ssrf, xss, csrf, cors, dir_traversal
Timeout: 1800 detik (30 menit) per module
"""

import subprocess
import sys
import os
import time
import json
from datetime import datetime

# ===== KONFIGURASI =====
YWH_USERNAME = "Dryex"
USER_AGENT_HEADER = f"X-YesWeHack-Research: {YWH_USERNAME}"
DRYBT_MAIN = "main.py"
RATE_DELAY = 0.2  # 5 request/detik
TIMEOUT = 1800     # 30 menit per module (maksimal)

# 10 Module sesuai permintaan
MODULES = [
    "param_discovery",   # Parameter Discovery
    "open_redirect",     # Open Redirect
    "sqli",              # SQL Injection
    "lfi",               # Local File Inclusion
    "race_condition",    # Race Condition
    "ssrf",              # Server-Side Request Forgery
    "xss",               # Cross-Site Scripting
    "csrf",              # CSRF
    "cors",              # CORS
    "dir_traversal"      # Directory Traversal
]

# Target Gojek (scope critical & high)
TARGETS = [
    "https://api.gojek.co.id",
    "https://gofood.co.id",
    "https://api.gobiz.co.id",
    "https://portal.gofoodmerchant.co.id",
    "https://www.gojek.com"
]

def add_user_agent_to_config():
    """Tambahkan header ke config.yaml"""
    config_path = "config.yaml"
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = f.read()
        if USER_AGENT_HEADER not in config:
            with open(config_path, 'a') as f:
                f.write(f"\ncustom_header: '{USER_AGENT_HEADER}'\n")
            print(f"[✓] Header '{USER_AGENT_HEADER}' ditambahkan ke config.yaml")
        else:
            print(f"[✓] Header sudah ada")
    else:
        print("[!] config.yaml tidak ditemukan, buat manual nanti")

def scan_target(target, module):
    """Jalankan scan satu module ke satu target"""
    cmd = [sys.executable, DRYBT_MAIN, "-t", target, "-m", module]
    
    # Environment untuk header custom
    env = os.environ.copy()
    env["HTTP_X_YESWEHACK_RESEARCH"] = YWH_USERNAME
    
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
        report_dir = "reports/gojek"
        os.makedirs(report_dir, exist_ok=True)
        
        target_safe = target.replace('https://', '').replace('/', '_').replace('.', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{report_dir}/{target_safe}_{module}_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write(f"Target: {target}\n")
            f.write(f"Module: {module}\n")
            f.write(f"Username: {YWH_USERNAME}\n")
            f.write(f"Header: {USER_AGENT_HEADER}\n")
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
        
        # Rate limiting
        time.sleep(RATE_DELAY)
        return True
        
    except subprocess.TimeoutExpired:
        duration = TIMEOUT
        print(f"    ⏱️ TIMEOUT setelah {TIMEOUT} detik ({TIMEOUT/60:.0f} menit)")
        print(f"    (Ini normal untuk module berat seperti SSRF, SQLi, XSS)")
        
        # Tetap simpan partial output jika ada
        report_dir = "reports/gojek"
        os.makedirs(report_dir, exist_ok=True)
        target_safe = target.replace('https://', '').replace('/', '_').replace('.', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{report_dir}/{target_safe}_{module}_{timestamp}_TIMEOUT.txt"
        
        with open(report_file, 'w') as f:
            f.write(f"Target: {target}\n")
            f.write(f"Module: {module}\n")
            f.write(f"Status: TIMEOUT setelah {TIMEOUT} detik\n")
            f.write(f"Username: {YWH_USERNAME}\n")
            f.write(f"Timestamp: {datetime.now()}\n")
        
        print(f"    📁 Laporan timeout: {report_file}")
        return False
        
    except Exception as e:
        print(f"    ✗ ERROR: {e}")
        return False

def main():
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                    GOJEK BUG BOUNTY HUNTER                           ║
║                        by Colin for Khan                             ║
║                                                                      ║
║  Username  : Dryex                                                   ║
║  Header    : X-YesWeHack-Research: Dryex                            ║
║  Module    : 10 module (param, open_redirect, sqli, lfi, race,       ║
║              ssrf, xss, csrf, cors, dir_traversal)                   ║
║  Timeout   : 1800 detik (30 menit) per module                        ║
║  Rate Limit: 5 request/detik                                         ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Cek DRYBT
    if not os.path.exists(DRYBT_MAIN):
        print(f"[✗] ERROR: {DRYBT_MAIN} tidak ditemukan!")
        print("    Pastikan script ini dijalankan dari folder DRYBT")
        sys.exit(1)
    
    # Tambahkan header ke config
    add_user_agent_to_config()
    
    # Info scan
    print(f"\n{'='*60}")
    print(f"[*] Username YesWeHack : {YWH_USERNAME}")
    print(f"[*] Total target        : {len(TARGETS)}")
    print(f"[*] Total module        : {len(MODULES)}")
    print(f"[*] Total scan          : {len(TARGETS) * len(MODULES)}")
    print(f"[*] Timeout per module  : {TIMEOUT} detik ({TIMEOUT/60:.0f} menit)")
    print(f"{'='*60}")
    
    print("\n[!] PERINGATAN:")
    print("    - Pastikan kamu sudah registrasi di program Gojek YesWeHack")
    print("    - Pastikan kamu punya akun Gojek aktif (nomor HP Indonesia/Singapura/Vietnam/Thailand)")
    print("    - Jangan melakukan fake booking berlebihan")
    print("    - Scan ini akan berlangsung lama (bisa 5-10 jam)")
    print("\n[?] Tekan Enter untuk memulai, atau Ctrl+C untuk batal...")
    input()
    
    print("\n[*] Memulai scanning...\n")
    
    hasil = {}
    total_success = 0
    total_timeout = 0
    total_error = 0
    
    for target in TARGETS:
        for module in MODULES:
            success = scan_target(target, module)
            if success:
                total_success += 1
                hasil[f"{target}_{module}"] = "success"
            else:
                total_timeout += 1
                hasil[f"{target}_{module}"] = "timeout_or_error"
    
    # Ringkasan akhir
    print("\n" + "="*60)
    print("[✓] SCAN SELESAI")
    print(f"    Sukses : {total_success}")
    print(f"    Timeout: {total_timeout}")
    print(f"    Total  : {len(TARGETS) * len(MODULES)}")
    print(f"    Laporan di folder: reports/gojek/")
    print("="*60)
    
    # Simpan ringkasan
    summary_file = f"reports/gojek/summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(summary_file, 'w') as f:
        json.dump({
            "username": YWH_USERNAME,
            "targets": TARGETS,
            "modules": MODULES,
            "timeout": TIMEOUT,
            "results": hasil,
            "timestamp": datetime.now().isoformat()
        }, f, indent=2)
    print(f"\n📋 Ringkasan: {summary_file}")

if __name__ == "__main__":
    main()