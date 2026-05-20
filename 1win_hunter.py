#!/usr/bin/env python3
"""
1win Bug Bounty Hunter - DRYBT Integration
Target: 1win.com
Cookie session disertakan
Module: 8 module
Rate limit: 5 request/detik
Timeout: 2 jam per module
Dilengkapi timer berjalan (live counter) per module
"""

import subprocess
import sys
import os
import time
import threading
import json
from datetime import datetime

# ===== KONFIGURASI =====
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
DRYBT_MAIN = "main.py"
RATE_DELAY = 0.2  # 5 request/detik
TIMEOUT = 7200     # 2 jam per module

# ===== COOKIE SESSION DARI BROWSER =====
COOKIE_STRING = "cda_session=fe8bd4c3-621f-47ce-9fc4-d08258a70747; session-id=26a27ccf-5454-516c-aeca-e32163b2a3f3; session-lax=1"

# Header opsional untuk identifikasi
HEADER_RESEARCHER = "X-HackerOne-Researcher: Dryex"

# Module prioritas untuk 1win (8 module)
MODULES = [
    "param_discovery",
    "sqli",
    "lfi",
    "ssrf",
    "xss",
    "csrf",
    "cors",
    "race_condition"
]

# Target 1win
TARGETS = [
    "https://1win.com",
    "https://1win.com/api",
    "https://1win.com/en",
    "https://1win.com/br"
]

# Flag untuk timer
stop_timer = False

def timer_display(module, target):
    """Menampilkan timer berjalan untuk module yang sedang di-scan"""
    start_time = time.time()
    while not stop_timer:
        elapsed = int(time.time() - start_time)
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        sys.stdout.write(f"\r    ⏱️  Timer: {hours:02d}:{minutes:02d}:{seconds:02d} (HH:MM:SS)  ")
        sys.stdout.flush()
        time.sleep(1)

def add_headers_to_config():
    """Tambahkan cookie dan header ke config.yaml"""
    config_path = "config.yaml"
    config_content = f"""
# DRYBT Configuration for 1win Bug Bounty
user_agent: "{USER_AGENT}"
headers:
  Cookie: "{COOKIE_STRING}"
  User-Agent: "{USER_AGENT}"
  X-HackerOne-Researcher: "Dryex"
rate_limit: 5
timeout: 120
"""
    with open(config_path, 'w') as f:
        f.write(config_content)
    print(f"[✓] Config ditulis ke {config_path}")

def scan_target(target, module):
    """Jalankan scan satu module ke satu target dengan timer"""
    global stop_timer
    cmd = [sys.executable, DRYBT_MAIN, "-t", target, "-m", module]
    
    env = os.environ.copy()
    env["HTTP_USER_AGENT"] = USER_AGENT
    env["HTTP_COOKIE"] = COOKIE_STRING
    env["HTTP_X_HACKERONE_RESEARCHER"] = "Dryex"
    
    print(f"\n[→] Target : {target}")
    print(f"    Module : {module}")
    print(f"    Timeout: {TIMEOUT} detik ({TIMEOUT/60:.0f} menit = {TIMEOUT/3600:.1f} jam)")
    print(f"    ⏱️  Timer mulai...")
    
    start = time.time()
    
    # Reset timer flag
    stop_timer = False
    
    # Jalankan timer di thread terpisah
    timer_thread = threading.Thread(target=timer_display, args=(module, target))
    timer_thread.daemon = True
    timer_thread.start()
    
    try:
        result = subprocess.run(
            cmd, 
            env=env, 
            capture_output=True, 
            text=True, 
            timeout=TIMEOUT
        )
        
        # Hentikan timer
        stop_timer = True
        timer_thread.join(timeout=1)
        
        duration = time.time() - start
        print(f"\n    ✓ Selesai dalam {duration:.2f} detik ({duration/60:.2f} menit)")
        
        # Simpan hasil
        report_dir = "reports/1win1"
        os.makedirs(report_dir, exist_ok=True)
        
        target_safe = target.replace('https://', '').replace('/', '_').replace('.', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{report_dir}/{target_safe}_{module}_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write(f"Target: {target}\n")
            f.write(f"Module: {module}\n")
            f.write(f"Cookie: {COOKIE_STRING}\n")
            f.write(f"Header: {HEADER_RESEARCHER}\n")
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
        # Hentikan timer
        stop_timer = True
        timer_thread.join(timeout=1)
        
        print(f"\n    ⏱️ TIMEOUT setelah {TIMEOUT} detik ({TIMEOUT/60:.0f} menit)")
        
        # Tetap simpan laporan timeout
        report_dir = "reports/1win1"
        os.makedirs(report_dir, exist_ok=True)
        target_safe = target.replace('https://', '').replace('/', '_').replace('.', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{report_dir}/{target_safe}_{module}_{timestamp}_TIMEOUT.txt"
        
        with open(report_file, 'w') as f:
            f.write(f"Target: {target}\n")
            f.write(f"Module: {module}\n")
            f.write(f"Status: TIMEOUT setelah {TIMEOUT} detik\n")
            f.write(f"Cookie: {COOKIE_STRING}\n")
            f.write(f"Timestamp: {datetime.now()}\n")
        
        print(f"    📁 Laporan timeout: {report_file}")
        return False
        
    except Exception as e:
        stop_timer = True
        timer_thread.join(timeout=1)
        print(f"\n    ✗ ERROR: {e}")
        return False

def main():
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                    1WIN BUG BOUNTY HUNTER                            ║
║                        by Colin for Khan                             ║
║                                                                      ║
║  Target    : 1win.com                                                ║
║  Cookie    : cda_session, session-id, session-lax                    ║
║  Header    : X-HackerOne-Researcher: Dryex                           ║
║  Rate Limit: 5 request/detik (WAJIB!)                                ║
║  Timeout   : 2 jam (7200 detik) per module                           ║
║  Timer     : Live counter (HH:MM:SS) per module                      ║
║  Module    : 8 module                                                ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    if not os.path.exists(DRYBT_MAIN):
        print(f"[✗] ERROR: {DRYBT_MAIN} tidak ditemukan!")
        print("    Pastikan script ini dijalankan dari folder DRYBT")
        sys.exit(1)
    
    add_headers_to_config()
    
    print(f"\n{'='*60}")
    print(f"[*] Cookie loaded : Yes")
    print(f"[*] Total target  : {len(TARGETS)}")
    print(f"[*] Total module  : {len(MODULES)}")
    print(f"[*] Total scan    : {len(TARGETS) * len(MODULES)}")
    print(f"[*] Rate limit    : 5 req/detik")
    print(f"[*] Timeout       : {TIMEOUT} detik ({TIMEOUT/3600:.1f} jam)")
    print(f"[*] Timer aktif   : Ya (detik berjalan)")
    print(f"{'='*60}")
    
    print("\n[!] PERINGATAN:")
    print("    - Patuhi rate limit 5 request/detik!")
    print("    - Jangan akses data user lain!")
    print("    - Timer akan berjalan di samping output DRYBT")
    print(f"    - Scan ini akan berlangsung ~8-10 jam")
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
    
    print("\n" + "="*60)
    print("[✓] SCAN SELESAI")
    print(f"    Sukses : {total_success}")
    print(f"    Timeout: {total_timeout}")
    print(f"    Total  : {len(TARGETS) * len(MODULES)}")
    print(f"    Laporan di folder: reports/1win/")
    print("="*60)

if __name__ == "__main__":
    main()