#!/usr/bin/env python3
"""
CLEAR Bug Bounty Scanner - Fixed (No Emoji)
Target: https://www.clearme.com
Header: X-Bug-Bounty: HackerOne-dryex
"""

import asyncio
import aiohttp
import time
import re
import json
import hashlib
from urllib.parse import urljoin, quote
from datetime import datetime

# ============ KONFIGURASI ============
TARGET = "https://www.clearme.com"
HACKERONE_USERNAME = "dryex"

# TIMEOUT SETTINGS
CONNECT_TIMEOUT = 15
TOTAL_TIMEOUT = 45
REQUEST_DELAY = 0.8

HEADERS = {
    "X-Bug-Bounty": f"HackerOne-{HACKERONE_USERNAME}",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json, text/html, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive"
}

# Warna output (tanpa emoji)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

class CLEARBountyScanner:
    def __init__(self):
        self.target = TARGET
        self.username = HACKERONE_USERNAME
        self.findings = []
        self.session = None
        self.start_time = None
        
        self.endpoints = [
            "/", "/api", "/v1", "/v2", "/api/v1", "/api/v2",
            "/graphql", "/gql", "/query",
            "/auth", "/login", "/register",
            "/user", "/me", "/profile", "/account",
            "/admin", "/debug", "/health", "/status",
            "/robots.txt", "/sitemap.xml", "/.env", "/config",
            "/swagger", "/docs", "/api-docs", "/openapi.json",
            "/.well-known/security.txt", "/security.txt"
        ]
        
        self.params = ['id', 'debug', 'redirect', 'url', 'file']
        self.test_marker = f"DRYBT_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(
            connect=CONNECT_TIMEOUT,
            sock_read=TOTAL_TIMEOUT,
            total=TOTAL_TIMEOUT
        )
        
        connector = aiohttp.TCPConnector(
            limit=10,
            limit_per_host=5,
            ttl_dns_cache=300,
            enable_cleanup_closed=True
        )
        
        self.session = aiohttp.ClientSession(
            headers=HEADERS,
            timeout=timeout,
            connector=connector,
            cookie_jar=aiohttp.DummyCookieJar()
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def request(self, method: str, path: str, **kwargs):
        url = urljoin(self.target, path)
        
        for attempt in range(2):
            try:
                return await self.session.request(method, url, **kwargs)
            except asyncio.TimeoutError:
                if attempt == 0:
                    print(f"   {YELLOW}[!] Timeout on {path}, retrying...{RESET}")
                    await asyncio.sleep(2)
                else:
                    print(f"   {RED}[X] Timeout on {path} after 2 attempts{RESET}")
                    return None
            except Exception:
                if attempt == 0:
                    await asyncio.sleep(1)
                else:
                    return None
        return None
    
    async def test_clickjacking(self):
        print(f"\n{BLUE}[1] TESTING CLICKJACKING (X-Frame-Options){RESET}")
        
        resp = await self.request("GET", "/")
        if resp:
            xfo = resp.headers.get("X-Frame-Options", "")
            csp = resp.headers.get("Content-Security-Policy", "")
            
            if not xfo and "frame-ancestors" not in csp:
                self.findings.append({
                    "type": "CLICKJACKING",
                    "severity": "medium",
                    "endpoint": "/",
                    "details": "X-Frame-Options header missing"
                })
                print(f"   {RED}[VULNERABLE] No X-Frame-Options{RESET}")
                
                poc = self.generate_clickjack_poc()
                with open("clickjacking_poc.html", "w", encoding="utf-8") as f:
                    f.write(poc)
                print(f"   {YELLOW}   -> POC saved: clickjacking_poc.html{RESET}")
            elif xfo:
                print(f"   {GREEN}[PROTECTED] X-Frame-Options: {xfo}{RESET}")
            else:
                print(f"   {GREEN}[PROTECTED] by CSP{RESET}")
        else:
            print(f"   {YELLOW}[?] Could not test (timeout/error){RESET}")
        
        await asyncio.sleep(REQUEST_DELAY)
    
    def generate_clickjack_poc(self):
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - CLEAR</title>
    <style>
        body {{ font-family: monospace; padding: 20px; background: #1e1e1e; color: #d4d4d4; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .alert {{ background: #2d2d2d; border-left: 4px solid #f48771; padding: 15px; margin: 20px 0; }}
        iframe {{ width: 100%; height: 600px; border: 2px solid #f48771; opacity: 0.5; }}
        .info {{ background: #0d7377; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .warning {{ color: #f48771; font-weight: bold; }}
        code {{ background: #2d2d2d; padding: 2px 5px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="info">
            <h2>CLEAR Clickjacking Proof of Concept</h2>
            <p>Target: https://www.clearme.com</p>
            <p>Status: <span class="warning">VULNERABLE</span> - No X-Frame-Options header</p>
            <p>Reported by: dryex (HackerOne)</p>
            <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        <div class="alert">
            <p><strong>↓ CLEAR website loaded inside iframe ↓</strong></p>
            <iframe src="https://www.clearme.com"></iframe>
        </div>
        <div class="info">
            <h3>Impact:</h3>
            <p>Attacker can embed CLEAR website in malicious page and trick users into clicking invisible elements, leading to:</p>
            <ul>
                <li>Account takeover</li>
                <li>Unauthorized actions</li>
                <li>Credential theft</li>
            </ul>
            <h3>Fix:</h3>
            <p>Add <code>X-Frame-Options: DENY</code> or <code>Content-Security-Policy: frame-ancestors 'none'</code></p>
        </div>
    </div>
</body>
</html>'''
    
    async def scan_cors(self):
        print(f"\n{BLUE}[2] SCANNING CORS...{RESET}")
        
        test_endpoints = ["/", "/api", "/v1", "/graphql"]
        test_origins = ["https://evil.com", "null"]
        
        cors_findings = []
        
        for endpoint in test_endpoints:
            for origin in test_origins:
                try:
                    async with self.session.get(endpoint, headers={"Origin": origin}) as resp:
                        acao = resp.headers.get("access-control-allow-origin", "")
                        acac = resp.headers.get("access-control-allow-credentials", "")
                        
                        if acao == "*" and acac == "true":
                            cors_findings.append({
                                "type": "CORS_WILDCARD_WITH_CREDENTIALS",
                                "severity": "critical",
                                "endpoint": endpoint
                            })
                            print(f"   {RED}[CRITICAL] {endpoint} | ACAO: * | ACAC: true{RESET}")
                        elif acao == origin:
                            cors_findings.append({
                                "type": "CORS_REFLECTED_ORIGIN",
                                "severity": "high",
                                "endpoint": endpoint
                            })
                            print(f"   {RED}[HIGH] {endpoint} reflects origin{RESET}")
                        elif acao == "null":
                            cors_findings.append({
                                "type": "CORS_NULL_ORIGIN",
                                "severity": "medium",
                                "endpoint": endpoint
                            })
                            print(f"   {YELLOW}[MEDIUM] {endpoint} accepts null origin{RESET}")
                except Exception:
                    pass
                await asyncio.sleep(0.5)
        
        self.findings.extend(cors_findings)
        print(f"   {GREEN}[DONE] CORS scan complete.{RESET}")
    
    async def discover_endpoints(self):
        print(f"\n{BLUE}[3] ENDPOINT DISCOVERY...{RESET}")
        
        discovered = []
        total = len(self.endpoints)
        
        for i, endpoint in enumerate(self.endpoints):
            resp = await self.request("GET", endpoint)
            if resp and resp.status in [200, 201, 401, 403]:
                discovered.append({
                    "endpoint": endpoint,
                    "status": resp.status
                })
                if resp.status == 200:
                    print(f"   {GREEN}[FOUND] {endpoint} -> {resp.status}{RESET}")
                else:
                    print(f"   {YELLOW}[AUTH] {endpoint} -> {resp.status} (auth required){RESET}")
            elif resp and resp.status == 404:
                pass
            else:
                print(f"   {BLUE}[SKIP] {endpoint} -> timeout/error{RESET}")
            
            if (i + 1) % 10 == 0:
                print(f"   Progress: {i+1}/{total}")
            
            await asyncio.sleep(REQUEST_DELAY)
        
        self.findings.append({
            "type": "ENDPOINTS_DISCOVERED",
            "severity": "info",
            "endpoints": discovered
        })
        
        print(f"   {GREEN}[DONE] Discovered {len(discovered)} endpoints{RESET}")
        return discovered
    
    async def check_info_disclosure(self):
        print(f"\n{BLUE}[4] INFO DISCLOSURE...{RESET}")
        
        sensitive_paths = [
            "/robots.txt", "/sitemap.xml", "/.env", "/config.json",
            "/swagger.json", "/openapi.json", "/.git/HEAD", "/security.txt"
        ]
        
        for path in sensitive_paths:
            resp = await self.request("GET", path)
            if resp and resp.status == 200:
                body = await resp.text()
                print(f"   {YELLOW}[FOUND] {path} ({len(body)} bytes){RESET}")
                self.findings.append({
                    "type": "INFO_DISCLOSURE",
                    "severity": "info",
                    "path": path,
                    "status": resp.status,
                    "size": len(body)
                })
            await asyncio.sleep(REQUEST_DELAY)
        
        print(f"   {GREEN}[DONE] Info disclosure check complete.{RESET}")
    
    async def run(self):
        self.start_time = time.time()
        
        print(f"""
{CYAN}╔══════════════════════════════════════════════════════════════════╗
║                    CLEAR BUG BOUNTY SCANNER                        ║
║                         by dryex                                   ║
╠══════════════════════════════════════════════════════════════════╣
║  Target: {self.target}
║  Header: X-Bug-Bounty: HackerOne-{self.username}
║  Timeout: Connect={CONNECT_TIMEOUT}s, Total={TOTAL_TIMEOUT}s
║  Delay: {REQUEST_DELAY}s antar request
╚══════════════════════════════════════════════════════════════════╝{RESET}
        """)
        
        await self.test_clickjacking()
        await self.scan_cors()
        await self.discover_endpoints()
        await self.check_info_disclosure()
        
        elapsed = time.time() - self.start_time
        
        print(f"\n{CYAN}{'='*60}")
        print(f"SCAN SUMMARY")
        print(f"{'='*60}{RESET}")
        print(f"Time: {elapsed:.2f} seconds")
        
        critical = [f for f in self.findings if f.get("severity") == "critical"]
        high = [f for f in self.findings if f.get("severity") == "high"]
        medium = [f for f in self.findings if f.get("severity") == "medium"]
        
        print(f"\nCritical: {len(critical)}")
        print(f"High: {len(high)}")
        print(f"Medium: {len(medium)}")
        print(f"Info: {len(self.findings) - len(critical) - len(high) - len(medium)}")
        
        report = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "scan_duration_seconds": round(elapsed, 2),
            "timeout_settings": {
                "connect_timeout": CONNECT_TIMEOUT,
                "total_timeout": TOTAL_TIMEOUT,
                "request_delay": REQUEST_DELAY
            },
            "findings": self.findings
        }
        
        with open("clear_bounty_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{GREEN}[SAVED] Report: clear_bounty_report.json{RESET}")
        
        if any(f["type"] == "CLICKJACKING" for f in self.findings):
            print(f"{GREEN}[SAVED] Clickjacking POC: clickjacking_poc.html{RESET}")
        
        print(f"{CYAN}{'='*60}{RESET}\n")


async def main():
    async with CLEARBountyScanner() as scanner:
        await scanner.run()

if __name__ == "__main__":
    asyncio.run(main())