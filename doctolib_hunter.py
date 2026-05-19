#!/usr/bin/env python3
"""
Doctolib Bug Bounty Hunter - MODE 2 (Single Target)
Scan 1 target dengan semua module DRYBT
User-Agent otomatis: BugBounty/42 (YWH)
"""

import subprocess
import sys
import os
import time
import json
from datetime import datetime

# ===== KONFIGURASI =====
TARGET = "https://www.doctolib.fr"   # <-- Ganti jika mau target lain
USER_AGENT = "BugBounty/42 (YWH)"
DRYBT_MAIN = "main.py"
RATE_DELAY = 0.1  # 10 request per detik

# 12 Module DRYBT
MODULES = [
    "param_discovery",
    "jwt",
    "graphql",
    "sqli",
    "xss",
    "lfi",
    "ssrf",
    "open_redirect",
    "cors",
    "csrf",
    "race_condition",
    "dir_traversal"
]

# ===== FUNGSI =====
def add_user_agent():
    """Tambahkan user-agent ke config.yaml"""
    config_path = "config.yaml"
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = f.read()
        if USER_AGENT not in config:
            with open(config_path, 'a') as f:
                f.write(f"\nuser_agent: '{USER_AGENT}'\n")
            print(f"[✓] User-agent ditambahkan ke config.yaml")
        else:
            print(f"[✓] User-agent sudah ada")
    else:
        print("[!] config.yaml tidak ditemukan, lanjutkan...")

def scan_module(module):
    """Jalankan satu module"""
    cmd = [sys.executable, DRYBT_MAIN, "-t", TARGET, "-m", module]
    env = os.environ.copy()
    env["HTTP_USER_AGENT"] = USER_AGENT
    
    print(f"\n[→] Module: {module}")
    start = time.time()
    
    try:
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600)
        duration = time.time() - start
        print(f"    ✓ Selesai dalam {duration:.2f} detik")
        
        # Simpan hasil
        os.makedirs("reports/doctolib_mode2", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"reports/doctolib_mode2/{module}_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write(f"Target: {TARGET}\n")
            f.write(f"Module: {module}\n")
            f.write(f"User-Agent: {USER_AGENT}\n")
            f.write(f"Duration: {duration:.2f}s\n\n")
            f.write("--- STDOUT ---\n")
            f.write(result.stdout)
            f.write("\n--- STDERR ---\n")
            f.write(result.stderr)
        
        print(f"    ✓ Laporan: {report_file}")
        time.sleep(RATE_DELAY)
        return True
        
    except subprocess.TimeoutExpired:
        print(f"    ✗ Timeout setelah 600 detik")
        return False
    except Exception as e:
        print(f"    ✗ Error: {e}")
        return False

# ===== MAIN =====
def main():
    print("""
╔══════════════════════════════════════════════════════════╗
║   DRYBT - Doctolib MODE 2 (Single Target)               ║
║   Target: https://www.doctolib.fr                       ║
║   Module : 12 module                                     ║
║   User-Agent: BugBounty/42 (YWH)                        ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    if not os.path.exists(DRYBT_MAIN):
        print(f"[✗] Error: {DRYBT_MAIN} tidak ditemukan!")
        print("    Jalankan script ini dari folder DRYBT")
        sys.exit(1)
    
    add_user_agent()
    
    print(f"\n[*] Target: {TARGET}")
    print(f"[*] Total module: {len(MODULES)}")
    print("[*] Mulai scan...\n")
    
    results = {}
    for module in MODULES:
        results[module] = "success" if scan_module(module) else "failed"
    
    # Ringkasan
    print("\n" + "="*60)
    print("[✓] SCAN SELESAI")
    print(f"    Target: {TARGET}")
    print(f"    Berhasil: {sum(1 for v in results.values() if v == 'success')}/{len(MODULES)} module")
    print("    Laporan di folder: reports/doctolib_mode2/")
    print("="*60)

if __name__ == "__main__":
    main()