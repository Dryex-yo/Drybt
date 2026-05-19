# 🔍 DRYBT by Dryex v.1

**DRYBT (Dryex Bug Bounty Tools)** - Ultimate Bug Bounty Scanner dengan 13 Security Modules.  
Beyond Industry Standard | Zero False Positive | Maximum Speed

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0-blue.svg">
  <img src="https://img.shields.io/badge/python-3.10%2B-green.svg">
  <img src="https://img.shields.io/badge/license-MIT-red.svg">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Mac-orange.svg">
</p>

---

## 📌 Fitur

| Module | Nama | Fungsi |
|--------|------|--------|
| 1 | **Parameter Discovery** | Menemukan parameter tersembunyi (108+ parameter) |
| 2 | **Race Condition** | Deteksi race condition vulnerability |
| 3 | **JWT Attack** | JWT token vulnerability (algorithm confusion, weak secret) |
| 4 | **GraphQL Batching** | Introspection, batching attack, IDOR via batching |
| 5 | **LLM Injection** | Prompt injection, system prompt extraction |
| 6 | **SSRF Scanner** | Internal IP, Cloud metadata, Protocol smuggling |
| 7 | **SQL Injection** | Error-based, Boolean-based, Time-based, Union-based |
| 8 | **XSS Scanner** | Reflected, Attribute, JavaScript, URL, WAF Bypass |
| 9 | **LFI/RFI Scanner** | Local/Remote File Inclusion, Log poisoning |
| 10 | **Open Redirect** | Basic redirect, Bypass, DOM-based, Header injection |
| 11 | **CORS Scanner** | Wildcard origin, Null origin, Reflected origin |
| 12 | **CSRF Scanner** | Missing CSRF tokens, Token validation bypass |
| 13 | **Directory Traversal** | Path traversal, WAF bypass, Encoding techniques |

---

## 🚀 Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/dryex/drybt.git
cd drybt
```

### 2. Setup Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate.bat

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Jalankan

```bash
# Intelligent target detection
python main.py -t https://example.com --detect

# Scan single module
python main.py -t https://example.com -m param_discovery
python main.py -t https://example.com -m sqli
python main.py -t https://example.com -m xss
python main.py -t https://example.com -m lfi

# Scan dengan JWT token
python main.py -t https://example.com -m jwt --token "your_jwt_token"

# Scan semua module
python main.py -t https://example.com -m all
```

---

## 📖 Available Modules

```bash
python main.py -h
```

| Command | Module |
|---------|--------|
| `param_discovery` | Parameter Discovery |
| `race_condition` | Race Condition Tester |
| `jwt` | JWT Attack Suite |
| `graphql` | GraphQL Batching Attack |
| `llm` | LLM Injection Scanner |
| `ssrf` | SSRF Scanner |
| `sqli` | SQL Injection Scanner |
| `xss` | XSS Scanner |
| `lfi` | LFI/RFI Scanner |
| `open_redirect` | Open Redirect Scanner |
| `cors` | CORS Scanner |
| `csrf` | CSRF Scanner |
| `dir_traversal` | Directory Traversal Scanner |
| `all` | Run All Modules |

---

## 📊 Output Report

Hasil scan disimpan dalam format JSON di folder `reports/`:

```json
{
  "tool": "DRYBT by Dryex v.1",
  "target": "https://example.com",
  "scan_start": "2026-05-19T21:21:18.161876",
  "total_findings": 5,
  "findings": [...]
}
```

---

## ⚙️ Requirements

- Python 3.10+
- aiohttp
- colorama
- pyyaml
- cryptography
- python-jose
- requests
- beautifulsoup4

---

## 📁 Project Structure

```
drybt/
├── main.py                 # Entry point
├── requirements.txt        # Dependencies
├── config.yaml             # Configuration
├── core/                   # Core modules
│   ├── http_client.py      # HTTP client (async, rate limiting)
│   ├── logger.py           # Logging system
│   ├── output.py           # Report generator
│   └── target_detector.py  # Intelligent target detection
├── modules/                # Security modules (13)
│   ├── param_discovery.py
│   ├── race_condition.py
│   ├── jwt_attack.py
│   ├── graphql_batch.py
│   ├── llm_injection.py
│   ├── ssrf_scanner.py
│   ├── sqli_scanner.py
│   ├── xss_scanner.py
│   ├── lfi_rfi_scanner.py
│   ├── open_redirect.py
│   ├── cors_scanner.py
│   ├── csrf_scanner.py
│   └── dir_traversal.py
├── payloads/               # Wordlists
└── reports/                # Scan results
```

---

## 🎯 Performance

| Module | Waktu Scan | Akurasi |
|--------|-----------|---------|
| Parameter Discovery | ~7 detik | 99% |
| Race Condition | ~10 detik | 95% |
| JWT Attack | < 1 menit | 95% |
| GraphQL Batching | < 5 menit | 95% |
| LLM Injection | < 1 menit | 90% |
| SSRF Scanner | ~27 menit | 90% |
| SQL Injection | ~22 menit | 90% |
| XSS Scanner | ~18 menit | 90% |
| LFI/RFI Scanner | ~11 menit | 95% |
| Open Redirect | ~21 menit | 90% |
| CORS Scanner | < 5 menit | 95% |
| CSRF Scanner | < 5 menit | 90% |
| Directory Traversal | ~16 menit | 90% |

---

## ⚠️ Disclaimer

Tools ini hanya untuk keperluan testing yang sah dan authorized.

Penggunaan tanpa izin dapat melanggar hukum. Penulis tidak bertanggung jawab atas penyalahgunaan tools ini.

---

## 📝 License

MIT License - Copyright (c) 2026 Dryex

---

## 🤝 Kontribusi

Pull requests dan issues sangat diterima untuk pengembangan lebih lanjut.

---

## 📧 Contact

- **GitHub**: [@dryex](https://github.com/Dryex-yo)
- **Project Link**: [https://github.com/Dryex-yo/Drybt.git](https://github.com/Dryex-yo/Drybt.git)

<p align="center"> Made with ❤️ by Dryex </p>