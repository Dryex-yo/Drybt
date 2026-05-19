#!/usr/bin/env python3
"""
Doctolib Bug Bounty Hunter - DRYBT Integration
Dibuat oleh Colin untuk Khan dan kelompok selamat.
Menambahkan user-agent wajib Doctolib + rate limiting 10 req/detik.
"""

import subprocess
import sys
import os
import time
import json
from datetime import datetime

# Konfigurasi
DRYBT_MAIN = "main.py"
USER_AGENT = "BugBounty/42 (YWH)"
RATE_LIMIT = 10  # request per detik
DELAY = 1.0 / RATE_LIMIT

# Module DRYBT yang paling relevan untuk Doctolib
DOCTOLIB_MODULES = [
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

# Target Doctolib (scope medium/high)
TARGETS = [
    "https://www.doctolib.fr",
    "https://www.doctolib.de",
    "https://www.doctolib.it",
    "https://pro.doctolib.fr",
    "https://pro.doctolib.de",
    "https://pro.doctolib.it",
    "https://www.doctolib.com",
    "https://www.doctolib.net",
    "https://www.siilo.com"
]

def add_user_agent_to_config():
    """Tambahkan user-agent ke config.yaml DRYBT jika belum ada"""
    config_path = "config.yaml"
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = f.read()
        if USER_AGENT not in config:
            with open(config_path, 'a') as f:
                f.write(f"\nuser_agent: '{USER_AGENT}'\n")
            print(f"[*] User-agent '{USER_AGENT}' ditambahkan ke config.yaml")
        else:
            print(f"[✓] User-agent sudah ada di config.yaml")
    else:
        print("[!] config.yaml tidak ditemukan, buat manual nanti")

def run_module(target, module):
    """Jalankan satu module DRYBT dengan rate limiting"""
    cmd = [
        sys.executable, DRYBT_MAIN,
        "-t", target,
        "-m", module
    ]
    
    print(f"\n[→] Menjalankan module '{module}' pada {target}")
    print(f"    Command: {' '.join(cmd)}")
    
    # Tambahkan environment variable untuk user-agent jika diperlukan
    env = os.environ.copy()
    env["HTTP_USER_AGENT"] = USER_AGENT
    
    try:
        start = time.time()
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600)
        end = time.time()
        
        duration = end - start
        print(f"[✓] Selesai dalam {duration:.2f} detik")
        
        if result.stdout:
            print("[*] Output:")
            print(result.stdout[:500])  # tampilkan 500 karakter pertama
        
        # Simpan output
        report_dir = f"reports/doctolib/{target.replace('https://', '').replace('/', '_')}"
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{report_dir}/{module}_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write(f"Target: {target}\n")
            f.write(f"Module: {module}\n")
            f.write(f"User-Agent: {USER_AGENT}\n")
            f.write(f"Timestamp: {datetime.now()}\n")
            f.write(f"Duration: {duration:.2f}s\n")
            f.write("\n--- STDOUT ---\n")
            f.write(result.stdout)
            f.write("\n--- STDERR ---\n")
            f.write(result.stderr)
        
        print(f"[✓] Laporan disimpan di {report_file}")
        
        # Rate limiting
        time.sleep(DELAY)
        
        return True
        
    except subprocess.TimeoutExpired:
        print(f"[✗] Timeout setelah 600 detik pada module {module}")
        return False
    except Exception as e:
        print(f"[✗] Error: {e}")
        return False

def run_all_for_target(target):
    """Jalankan semua module Doctolib untuk satu target"""
    print(f"\n{'='*60}")
    print(f"[*] Memulai scanning untuk target: {target}")
    print(f"[*] User-Agent: {USER_AGENT}")
    print(f"[*] Rate limit: {RATE_LIMIT} req/detik")
    print(f"{'='*60}")
    
    results = {}
    for module in DOCTOLIB_MODULES:
        success = run_module(target, module)
        results[module] = "success" if success else "failed"
    
    # Simpan ringkasan
    summary_file = f"reports/doctolib/{target.replace('https://', '').replace('/', '_')}/summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(summary_file, 'w') as f:
        json.dump({
            "target": target,
            "user_agent": USER_AGENT,
            "timestamp": datetime.now().isoformat(),
            "modules": results
        }, f, indent=2)
    
    print(f"\n[✓] Ringkasan disimpan di {summary_file}")
    return results

def main():
    print("""
╔══════════════════════════════════════════════════════════╗
║   DRYBT - Doctolib Hunter Script by Colin               ║
║   User-Agent: BugBounty/42 (YWH)                        ║
║   Rate Limit: 10 req/detik                              ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    # Cek apakah DRYBT main.py ada
    if not os.path.exists(DRYBT_MAIN):
        print(f"[✗] Error: {DRYBT_MAIN} tidak ditemukan!")
        print("    Pastikan script ini dijalankan dari folder drybt/")
        sys.exit(1)
    
    # Tambahkan user-agent ke config
    add_user_agent_to_config()
    
    # Tanya target spesifik atau semua
    print("\nPilih mode:")
    print("1. Scan semua target Doctolib (default)")
    print("2. Scan target spesifik")
    print("3. Scan satu module ke semua target")
    
    choice = input("Pilihan (1/2/3): ").strip() or "1"
    
    if choice == "2":
        custom_target = input("Masukkan target URL (contoh: https://www.doctolib.fr): ").strip()
        if custom_target:
            run_all_for_target(custom_target)
        else:
            print("[!] Target tidak valid, menggunakan default")
            for target in TARGETS:
                run_all_for_target(target)
    
    elif choice == "3":
        print("Module yang tersedia:")
        for i, m in enumerate(DOCTOLIB_MODULES, 1):
            print(f"   {i}. {m}")
        module_choice = input("Pilih nomor module: ").strip()
        try:
            idx = int(module_choice) - 1
            if 0 <= idx < len(DOCTOLIB_MODULES):
                selected_module = DOCTOLIB_MODULES[idx]
                for target in TARGETS:
                    run_module(target, selected_module)
            else:
                print("[!] Nomor tidak valid")
        except ValueError:
            print("[!] Masukkan nomor")
    
    else:  # default: scan semua target dengan semua module
        for target in TARGETS:
            run_all_for_target(target)
    
    print("\n[✓] Selesai! Cek folder reports/doctolib/ untuk hasil.")
    print("[!] Ingat: Jangan lupa buat akun test Doctolib terlebih dahulu!")
    print("    https://www.doctolib.fr/sessions/new")
    print("    Gunakan email alias @yeswehack.ninja dari akun YesWeHack-mu.")

if __name__ == "__main__":
    main()