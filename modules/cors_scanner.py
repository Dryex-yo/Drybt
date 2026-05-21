#!/usr/bin/env python3
"""
Module 11: CORS Scanner
6 Layer CORS misconfiguration detection dengan zero false positive
Mendeteksi: Wildcard origin, Null origin, Credentials leakage, Reflected origin

MODIFIED: Added external HTTPClient support for X-Bug-Bounty header
"""

import asyncio
from typing import List, Dict, Optional
from core.http_client import HTTPClient
from core.logger import Logger

logger = Logger()

class CORSScanner:
    def __init__(self, target: str, threads: int = 40, client: HTTPClient = None):
        self.target = target.rstrip('/')
        self.threads = threads
        self.client = client  # External client with X-Bug-Bounty header
        self.findings: List[Dict] = []
        self.stats = {
            'endpoints_tested': 0,
            'origins_tested': 0,
            'vulnerabilities_found': 0
        }
        
        # ============ TEST ORIGINS ============
        self.test_origins = [
            'https://evil.com',
            'http://evil.com',
            'https://attacker.com',
            'http://attacker.com',
            'https://evil.attacker.com',
            'http://evil.attacker.com',
            'null',
            f'https://evil.{self.target.replace("https://", "").replace("http://", "")}',
            f'http://evil.{self.target.replace("https://", "").replace("http://", "")}',
            self.target,
            self.target.replace('https://', 'http://'),
            '*',
            f'{self.target}/evil',
            f'{self.target}:8080',
            'https://127.0.0.1',
            'http://127.0.0.1',
            'https://0.0.0.0',
            'https://еvil.com',
            'https://evil。com',
            'https://evil.com https://attacker.com',
            'https://evil.com,https://attacker.com',
            'file:///etc/passwd',
            'data:text/html,<script>alert(1)</script>',
            'javascript:alert(1)',
        ]
        
        # ============ TEST ENDPOINTS ============
        self.test_endpoints = [
            "/", "/api", "/api/v1", "/v1", "/api/users", "/users",
            "/auth", "/login", "/logout", "/register", "/signup",
            "/profile", "/me", "/account", "/settings",
            "/data", "/config", "/info", "/status",
            "/graphql", "/gql", "/query", "/api/graphql",
            "/.well-known", "/cors", "/cors-test"
        ]
        
        # ============ RESPONSE INDICATORS ============
        self.aca_headers = [
            'access-control-allow-origin',
            'access-control-allow-credentials',
            'access-control-allow-methods',
            'access-control-allow-headers',
            'access-control-expose-headers',
            'access-control-max-age'
        ]
    
    async def _get_client(self):
        """Get HTTP client - use external if available, otherwise create new"""
        if self.client:
            return self.client
        else:
            return HTTPClient(self.target, timeout=5, retries=1)
    
    async def test_cors(self, endpoint: str, origin: str) -> Optional[Dict]:
        """Test CORS configuration with specific origin"""
        client = await self._get_client()
        headers = {"Origin": origin}
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                response = await ctx_client.get(endpoint, headers=headers)
                if response:
                    acao = response.headers.get('access-control-allow-origin', '')
                    acac = response.headers.get('access-control-allow-credentials', '')
                    
                    # Layer 1: Wildcard with credentials
                    if acao == '*' and acac == 'true':
                        self.stats['vulnerabilities_found'] += 1
                        return {
                            "vulnerable": True,
                            "type": "WILDCARD_WITH_CREDENTIALS",
                            "severity": "critical",
                            "confidence": 100,
                            "endpoint": endpoint,
                            "origin_sent": origin,
                            "acao": acao,
                            "acac": acac,
                            "details": "ACAO: * with ACAC: true - Credentials can be stolen by any origin"
                        }
                    
                    # Layer 2: Null origin
                    if acao == 'null' and origin == 'null':
                        self.stats['vulnerabilities_found'] += 1
                        return {
                            "vulnerable": True,
                            "type": "NULL_ORIGIN_ACCEPTED",
                            "severity": "high",
                            "confidence": 95,
                            "endpoint": endpoint,
                            "origin_sent": origin,
                            "acao": acao,
                            "acac": acac,
                            "details": "Null origin accepted - Can be exploited from sandboxed iframes"
                        }
                    
                    # Layer 3: Reflected origin
                    if acao == origin and origin not in [self.target, self.target.replace('https://', 'http://')]:
                        severity = "critical" if acac == 'true' else "high"
                        self.stats['vulnerabilities_found'] += 1
                        return {
                            "vulnerable": True,
                            "type": "REFLECTED_ORIGIN",
                            "severity": severity,
                            "confidence": 100,
                            "endpoint": endpoint,
                            "origin_sent": origin,
                            "acao": acao,
                            "acac": acac,
                            "details": f"Reflected origin: {acao}"
                        }
                    
                    # Layer 4: Wildcard origin
                    if acao == '*':
                        self.stats['vulnerabilities_found'] += 1
                        return {
                            "vulnerable": True,
                            "type": "WILDCARD_ORIGIN",
                            "severity": "medium",
                            "confidence": 80,
                            "endpoint": endpoint,
                            "origin_sent": origin,
                            "acao": acao,
                            "acac": acac,
                            "details": "Wildcard origin allowed (without credentials)"
                        }
                    
                    # Layer 5: Subdomain wildcard
                    domain = self.target.replace("https://", "").replace("http://", "")
                    if acao and acao.endswith(f'.{domain}'):
                        self.stats['vulnerabilities_found'] += 1
                        return {
                            "vulnerable": True,
                            "type": "SUBDOMAIN_WILDCARD",
                            "severity": "medium",
                            "confidence": 85,
                            "endpoint": endpoint,
                            "origin_sent": origin,
                            "acao": acao,
                            "acac": acac,
                            "details": f"Subdomain wildcard accepted: {acao}"
                        }
                    
                    # Layer 6: Overly permissive methods
                    acam = response.headers.get('access-control-allow-methods', '')
                    if 'GET' in acam and 'POST' in acam and 'PUT' in acam and 'DELETE' in acam:
                        if acao == origin:
                            self.stats['vulnerabilities_found'] += 1
                            return {
                                "vulnerable": True,
                                "type": "OVERLY_PERMISSIVE_METHODS",
                                "severity": "low",
                                "confidence": 70,
                                "endpoint": endpoint,
                                "origin_sent": origin,
                                "acao": acao,
                                "acam": acam,
                                "details": f"Overly permissive methods: {acam}"
                            }
        else:
            response = await client.get(endpoint, headers=headers)
            if response:
                acao = response.headers.get('access-control-allow-origin', '')
                acac = response.headers.get('access-control-allow-credentials', '')
                
                # Layer 1: Wildcard with credentials
                if acao == '*' and acac == 'true':
                    self.stats['vulnerabilities_found'] += 1
                    return {
                        "vulnerable": True,
                        "type": "WILDCARD_WITH_CREDENTIALS",
                        "severity": "critical",
                        "confidence": 100,
                        "endpoint": endpoint,
                        "origin_sent": origin,
                        "acao": acao,
                        "acac": acac,
                        "details": "ACAO: * with ACAC: true - Credentials can be stolen by any origin"
                    }
                
                # Layer 2: Null origin
                if acao == 'null' and origin == 'null':
                    self.stats['vulnerabilities_found'] += 1
                    return {
                        "vulnerable": True,
                        "type": "NULL_ORIGIN_ACCEPTED",
                        "severity": "high",
                        "confidence": 95,
                        "endpoint": endpoint,
                        "origin_sent": origin,
                        "acao": acao,
                        "acac": acac,
                        "details": "Null origin accepted - Can be exploited from sandboxed iframes"
                    }
                
                # Layer 3: Reflected origin
                if acao == origin and origin not in [self.target, self.target.replace('https://', 'http://')]:
                    severity = "critical" if acac == 'true' else "high"
                    self.stats['vulnerabilities_found'] += 1
                    return {
                        "vulnerable": True,
                        "type": "REFLECTED_ORIGIN",
                        "severity": severity,
                        "confidence": 100,
                        "endpoint": endpoint,
                        "origin_sent": origin,
                        "acao": acao,
                        "acac": acac,
                        "details": f"Reflected origin: {acao}"
                    }
                
                # Layer 4: Wildcard origin
                if acao == '*':
                    self.stats['vulnerabilities_found'] += 1
                    return {
                        "vulnerable": True,
                        "type": "WILDCARD_ORIGIN",
                        "severity": "medium",
                        "confidence": 80,
                        "endpoint": endpoint,
                        "origin_sent": origin,
                        "acao": acao,
                        "acac": acac,
                        "details": "Wildcard origin allowed (without credentials)"
                    }
                
                # Layer 5: Subdomain wildcard
                domain = self.target.replace("https://", "").replace("http://", "")
                if acao and acao.endswith(f'.{domain}'):
                    self.stats['vulnerabilities_found'] += 1
                    return {
                        "vulnerable": True,
                        "type": "SUBDOMAIN_WILDCARD",
                        "severity": "medium",
                        "confidence": 85,
                        "endpoint": endpoint,
                        "origin_sent": origin,
                        "acao": acao,
                        "acac": acac,
                        "details": f"Subdomain wildcard accepted: {acao}"
                    }
                
                # Layer 6: Overly permissive methods
                acam = response.headers.get('access-control-allow-methods', '')
                if 'GET' in acam and 'POST' in acam and 'PUT' in acam and 'DELETE' in acam:
                    if acao == origin:
                        self.stats['vulnerabilities_found'] += 1
                        return {
                            "vulnerable": True,
                            "type": "OVERLY_PERMISSIVE_METHODS",
                            "severity": "low",
                            "confidence": 70,
                            "endpoint": endpoint,
                            "origin_sent": origin,
                            "acao": acao,
                            "acam": acam,
                            "details": f"Overly permissive methods: {acam}"
                        }
        
        return None
    
    async def scan_endpoint(self, endpoint: str) -> List[Dict]:
        """Scan single endpoint for CORS misconfigurations"""
        
        findings = []
        semaphore = asyncio.Semaphore(self.threads)
        
        async def test_origin(origin: str):
            async with semaphore:
                self.stats['origins_tested'] += 1
                result = await self.test_cors(endpoint, origin)
                if result:
                    findings.append(result)
                    icon = "💎" if result.get('severity') == 'critical' else "🔴" if result.get('severity') == 'high' else "🟠"
                    logger.info(f"{icon} CORS on {endpoint}: {origin[:60]} | ACAO: {result.get('acao')}")
        
        tasks = [test_origin(origin) for origin in self.test_origins]
        await asyncio.gather(*tasks)
        
        return findings
    
    async def scan(self, custom_endpoints: List[str] = None) -> Dict:
        """Full CORS scanner"""
        
        if custom_endpoints:
            endpoints = custom_endpoints
        else:
            endpoints = self.test_endpoints
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🚀 DRYBT - CORS SCANNER")
        logger.info(f"{'='*60}")
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"📡 Endpoints: {len(endpoints)}")
        logger.info(f"📊 Origins to test: {len(self.test_origins)}")
        logger.info(f"🔧 Threads: {self.threads}")
        logger.info(f"{'='*60}\n")
        
        start_time = asyncio.get_event_loop().time()
        
        for endpoint in endpoints:
            logger.info(f"\n📡 Testing endpoint: {endpoint}")
            findings = await self.scan_endpoint(endpoint)
            self.findings.extend(findings)
            self.stats['endpoints_tested'] += 1
        
        elapsed = asyncio.get_event_loop().time() - start_time
        
        critical_findings = [f for f in self.findings if f.get('severity') == 'critical']
        high_findings = [f for f in self.findings if f.get('severity') == 'high']
        medium_findings = [f for f in self.findings if f.get('severity') == 'medium']
        
        print(f"\n{'='*60}")
        print(f"📊 CORS SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"⏱️  Time: {elapsed:.2f} seconds")
        print(f"📡 Endpoints tested: {self.stats['endpoints_tested']}")
        print(f"📊 Origins tested: {self.stats['origins_tested']}")
        print(f"🎯 Vulnerabilities found: {len(self.findings)}")
        
        if critical_findings:
            print(f"\n💎 CRITICAL VULNERABILITIES:")
            for f in critical_findings:
                print(f"   🔥 {f['type']} | {f.get('endpoint')} | Confidence: {f.get('confidence', 0)}%")
        
        if high_findings:
            print(f"\n🔴 HIGH VULNERABILITIES:")
            for f in high_findings:
                print(f"   ⚡ {f['type']} | {f.get('endpoint')} | Confidence: {f.get('confidence', 0)}%")
        
        if medium_findings:
            print(f"\n🟠 MEDIUM VULNERABILITIES:")
            for f in medium_findings:
                print(f"   📌 {f['type']} | {f.get('endpoint')} | Confidence: {f.get('confidence', 0)}%")
        
        print(f"\n{'='*60}")
        
        rating = "💎 CRITICAL - Credentials at risk!" if critical_findings else \
                 "🔴 HIGH - Origin reflection detected" if high_findings else \
                 "🟠 MEDIUM - Weak CORS configuration" if medium_findings else \
                 "✅ SECURE - No CORS misconfigurations detected"
        
        print(f"📈 Result: {rating}")
        print(f"{'='*60}\n")
        
        return {
            "module": "cors_scanner",
            "target": self.target,
            "scan_time_seconds": round(elapsed, 2),
            "endpoints_tested": self.stats['endpoints_tested'],
            "origins_tested": self.stats['origins_tested'],
            "vulnerabilities_found": len(self.findings),
            "critical_vulnerabilities": len(critical_findings),
            "high_vulnerabilities": len(high_findings),
            "medium_vulnerabilities": len(medium_findings),
            "security_rating": rating,
            "findings": self.findings
        }


# ================================================================
# MAIN RUN FUNCTION - MODIFIED FOR EXTERNAL CLIENT
# ================================================================
async def run(target: str, custom_endpoints: List[str] = None, client: HTTPClient = None) -> Dict:
    """
    Run CORS scanner - DRYBT CORS SCANNER
    
    Args:
        target: Target URL
        custom_endpoints: Custom endpoints to test (optional)
        client: Optional external HTTPClient (for X-Bug-Bounty header)
    """
    scanner = CORSScanner(target, client=client)
    return await scanner.scan(custom_endpoints)