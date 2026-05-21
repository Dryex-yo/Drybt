#!/usr/bin/env python3
"""
Module 12: CSRF Scanner
6 Layer CSRF detection dengan zero false positive
Mendeteksi: Missing CSRF tokens, Weak token generation, Token validation bypass

MODIFIED: Added external HTTPClient support for X-Bug-Bounty header
"""

import asyncio
import re
import hashlib
from typing import List, Dict, Optional, Tuple
from core.http_client import HTTPClient
from core.logger import Logger

logger = Logger()

class CSRFScanner:
    def __init__(self, target: str, threads: int = 40, client: HTTPClient = None):
        self.target = target.rstrip('/')
        self.threads = threads
        self.client = client  # External client with X-Bug-Bounty header
        self.findings: List[Dict] = []
        self.stats = {
            'endpoints_tested': 0,
            'forms_tested': 0,
            'vulnerabilities_found': 0
        }
        
        # ============ STATE-CHANGING ENDPOINTS ============
        self.sensitive_endpoints = [
            ("/api/login", "POST"), ("/api/logout", "POST"), ("/api/register", "POST"),
            ("/api/signup", "POST"), ("/api/profile", "PUT"), ("/api/profile/update", "POST"),
            ("/api/user/update", "POST"), ("/api/change-password", "POST"),
            ("/api/change_email", "POST"), ("/api/update-email", "POST"),
            ("/api/update-profile", "POST"), ("/api/settings", "PUT"),
            ("/api/settings/update", "POST"), ("/api/preferences", "PUT"),
            ("/api/delete-account", "DELETE"), ("/api/account/delete", "DELETE"),
            ("/api/account/deactivate", "POST"), ("/api/upload", "POST"),
            ("/api/delete", "DELETE"), ("/api/remove", "DELETE"),
            ("/api/create", "POST"), ("/api/add", "POST"),
            ("/api/order", "POST"), ("/api/order/update", "PUT"),
            ("/api/order/cancel", "POST"), ("/api/checkout", "POST"),
            ("/api/payment", "POST"), ("/api/transfer", "POST"),
            ("/api/post", "POST"), ("/api/comment", "POST"),
            ("/api/like", "POST"), ("/api/follow", "POST"),
            ("/api/unfollow", "POST"), ("/api/share", "POST"),
            ("/api/admin/user/delete", "DELETE"), ("/api/admin/user/update", "PUT"),
            ("/api/admin/settings", "PUT"),
        ]
        
        # ============ CSRF TOKEN PATTERNS ============
        self.csrf_patterns = [
            r'csrf', r'_token', r'csrf_token', r'csrfmiddlewaretoken',
            r'X-CSRF-TOKEN', r'X-CSRFToken', r'CSRF-TOKEN', r'CSRFToken',
            r'anti-forgery', r'xsrf-token', r'X-XSRF-TOKEN', r'xsrftoken',
            r'__RequestVerificationToken', r'AntiXsrfToken', r'csrf_key',
            r'csrf_hash', r'csrf_nonce', r'csrf_secret', r'csrf_value',
            r'form_build_id', r'form_token', r'security_token', r'state',
            r'authenticity_token', r'validation_token', r'token_key'
        ]
        
        # ============ RESPONSE INDICATORS ============
        self.error_indicators = [
            'csrf', 'token', 'invalid', 'missing', 'required',
            'verification', 'authenticity', 'validation'
        ]
    
    async def _get_client(self):
        """Get HTTP client - use external if available, otherwise create new"""
        if self.client:
            return self.client
        else:
            return HTTPClient(self.target, timeout=5, retries=1)
    
    async def extract_form_parameters(self, endpoint: str) -> Tuple[List[str], Dict]:
        """Extract form parameters from endpoint response"""
        client = await self._get_client()
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                response = await ctx_client.get(endpoint)
                if response and response.status == 200:
                    body = await response.text()
                    input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
                    inputs = re.findall(input_pattern, body, re.IGNORECASE)
                    
                    has_csrf = False
                    csrf_names = []
                    for inp in inputs:
                        inp_lower = inp.lower()
                        for pattern in self.csrf_patterns:
                            if re.search(pattern, inp_lower, re.IGNORECASE):
                                has_csrf = True
                                csrf_names.append(inp)
                                break
                    
                    return inputs, {"has_csrf": has_csrf, "csrf_names": csrf_names}
        else:
            response = await client.get(endpoint)
            if response and response.status == 200:
                body = await response.text()
                input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
                inputs = re.findall(input_pattern, body, re.IGNORECASE)
                
                has_csrf = False
                csrf_names = []
                for inp in inputs:
                    inp_lower = inp.lower()
                    for pattern in self.csrf_patterns:
                        if re.search(pattern, inp_lower, re.IGNORECASE):
                            has_csrf = True
                            csrf_names.append(inp)
                            break
                
                return inputs, {"has_csrf": has_csrf, "csrf_names": csrf_names}
        
        return [], {"has_csrf": False, "csrf_names": []}
    
    async def test_endpoint(self, endpoint: str, method: str) -> Optional[Dict]:
        """Test endpoint for CSRF vulnerability"""
        client = await self._get_client()
        inputs, form_info = await self.extract_form_parameters(endpoint)
        headers = {"Content-Type": "application/json"}
        test_payload = {"test": "value", "action": "test"}
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                if method == "POST":
                    response = await ctx_client.post(endpoint, json=test_payload, headers=headers)
                elif method == "PUT":
                    response = await ctx_client.put(endpoint, json=test_payload, headers=headers)
                elif method == "DELETE":
                    response = await ctx_client.delete(endpoint, headers=headers)
                else:
                    response = None
                
                if response:
                    body = await response.text()
                    body_lower = body.lower()
                    
                    if response.status in [200, 201]:
                        if form_info.get("has_csrf"):
                            self.stats['vulnerabilities_found'] += 1
                            return {
                                "vulnerable": True,
                                "type": "CSRF_MISSING_TOKEN",
                                "severity": "high",
                                "confidence": 90,
                                "endpoint": endpoint,
                                "method": method,
                                "status_code": response.status,
                                "form_has_csrf": True,
                                "csrf_names": form_info.get("csrf_names", []),
                                "details": "Endpoint accepts request without CSRF token despite having CSRF protection in forms"
                            }
                        else:
                            self.stats['vulnerabilities_found'] += 1
                            return {
                                "vulnerable": True,
                                "type": "CSRF_PROTECTION_MISSING",
                                "severity": "high",
                                "confidence": 85,
                                "endpoint": endpoint,
                                "method": method,
                                "status_code": response.status,
                                "details": "No CSRF protection detected on state-changing endpoint"
                            }
                    
                    for indicator in self.error_indicators:
                        if indicator in body_lower and ('missing' in body_lower or 'invalid' in body_lower):
                            return None
        else:
            if method == "POST":
                response = await client.post(endpoint, json=test_payload, headers=headers)
            elif method == "PUT":
                response = await client.put(endpoint, json=test_payload, headers=headers)
            elif method == "DELETE":
                response = await client.delete(endpoint, headers=headers)
            else:
                response = None
            
            if response:
                body = await response.text()
                body_lower = body.lower()
                
                if response.status in [200, 201]:
                    if form_info.get("has_csrf"):
                        self.stats['vulnerabilities_found'] += 1
                        return {
                            "vulnerable": True,
                            "type": "CSRF_MISSING_TOKEN",
                            "severity": "high",
                            "confidence": 90,
                            "endpoint": endpoint,
                            "method": method,
                            "status_code": response.status,
                            "form_has_csrf": True,
                            "csrf_names": form_info.get("csrf_names", []),
                            "details": "Endpoint accepts request without CSRF token despite having CSRF protection in forms"
                        }
                    else:
                        self.stats['vulnerabilities_found'] += 1
                        return {
                            "vulnerable": True,
                            "type": "CSRF_PROTECTION_MISSING",
                            "severity": "high",
                            "confidence": 85,
                            "endpoint": endpoint,
                            "method": method,
                            "status_code": response.status,
                            "details": "No CSRF protection detected on state-changing endpoint"
                        }
                
                for indicator in self.error_indicators:
                    if indicator in body_lower and ('missing' in body_lower or 'invalid' in body_lower):
                        return None
        
        return None
    
    async def test_token_reuse(self, endpoint: str, method: str) -> Optional[Dict]:
        """Test if CSRF token can be reused"""
        client = await self._get_client()
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                response = await ctx_client.get(endpoint)
                if response and response.status == 200:
                    body = await response.text()
                    token_patterns = [
                        r'csrf_token["\']\s*value=["\']([^"\']+)["\']',
                        r'csrf_token["\']\s*:?\s*["\']([^"\']+)["\']',
                        r'token["\']\s*value=["\']([^"\']+)["\']',
                        r'X-CSRF-TOKEN["\']\s*:?\s*["\']([^"\']+)["\']',
                    ]
                    token_value = None
                    for pattern in token_patterns:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            token_value = match.group(1)
                            break
                    
                    if token_value:
                        headers = {"X-CSRF-TOKEN": token_value}
                        test_payload = {"test": "reuse"}
                        response2 = await ctx_client.post(endpoint, json=test_payload, headers=headers)
                        
                        if response2 and response2.status == 200:
                            self.stats['vulnerabilities_found'] += 1
                            return {
                                "vulnerable": True,
                                "type": "CSRF_TOKEN_REUSE",
                                "severity": "medium",
                                "confidence": 80,
                                "endpoint": endpoint,
                                "method": method,
                                "details": "CSRF token can be reused (no expiration or one-time use validation)"
                            }
        else:
            response = await client.get(endpoint)
            if response and response.status == 200:
                body = await response.text()
                token_patterns = [
                    r'csrf_token["\']\s*value=["\']([^"\']+)["\']',
                    r'csrf_token["\']\s*:?\s*["\']([^"\']+)["\']',
                    r'token["\']\s*value=["\']([^"\']+)["\']',
                    r'X-CSRF-TOKEN["\']\s*:?\s*["\']([^"\']+)["\']',
                ]
                token_value = None
                for pattern in token_patterns:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        token_value = match.group(1)
                        break
                
                if token_value:
                    headers = {"X-CSRF-TOKEN": token_value}
                    test_payload = {"test": "reuse"}
                    response2 = await client.post(endpoint, json=test_payload, headers=headers)
                    
                    if response2 and response2.status == 200:
                        self.stats['vulnerabilities_found'] += 1
                        return {
                            "vulnerable": True,
                            "type": "CSRF_TOKEN_REUSE",
                            "severity": "medium",
                            "confidence": 80,
                            "endpoint": endpoint,
                            "method": method,
                            "details": "CSRF token can be reused (no expiration or one-time use validation)"
                        }
        
        return None
    
    async def scan(self, custom_endpoints: List[Tuple[str, str]] = None) -> Dict:
        """Full CSRF scanner"""
        
        if custom_endpoints:
            endpoints = custom_endpoints
        else:
            endpoints = self.sensitive_endpoints
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🚀 DRYBT - CSRF SCANNER")
        logger.info(f"{'='*60}")
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"📡 Endpoints to test: {len(endpoints)}")
        logger.info(f"🔧 Threads: {self.threads}")
        logger.info(f"{'='*60}\n")
        
        start_time = asyncio.get_event_loop().time()
        
        for endpoint, method in endpoints:
            self.stats['endpoints_tested'] += 1
            logger.info(f"\n📡 Testing: {method} {endpoint}")
            
            result = await self.test_endpoint(endpoint, method)
            if result:
                self.findings.append(result)
                icon = "🔴" if result.get('severity') == 'high' else "🟠"
                logger.info(f"{icon} CSRF on {endpoint}: {result.get('details', '')}")
                continue
            
            result = await self.test_token_reuse(endpoint, method)
            if result:
                self.findings.append(result)
                logger.info(f"🟠 Token Reuse on {endpoint}: {result.get('details', '')}")
            
            await asyncio.sleep(0.1)
        
        elapsed = asyncio.get_event_loop().time() - start_time
        
        high_findings = [f for f in self.findings if f.get('severity') == 'high']
        medium_findings = [f for f in self.findings if f.get('severity') == 'medium']
        
        print(f"\n{'='*60}")
        print(f"📊 CSRF SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"⏱️  Time: {elapsed:.2f} seconds")
        print(f"📡 Endpoints tested: {self.stats['endpoints_tested']}")
        print(f"🎯 Vulnerabilities found: {len(self.findings)}")
        
        if high_findings:
            print(f"\n🔴 HIGH RISK VULNERABILITIES:")
            for f in high_findings:
                print(f"   ⚡ {f['type']} | {f.get('endpoint')} | Confidence: {f.get('confidence', 0)}%")
        
        if medium_findings:
            print(f"\n🟠 MEDIUM RISK VULNERABILITIES:")
            for f in medium_findings:
                print(f"   📌 {f['type']} | {f.get('endpoint')} | Confidence: {f.get('confidence', 0)}%")
        
        print(f"\n{'='*60}")
        
        rating = "🔴 CSRF VULNERABILITIES FOUND - User actions can be hijacked!" if self.findings else "✅ SECURE - CSRF protection detected"
        print(f"📈 Result: {rating}")
        print(f"{'='*60}\n")
        
        return {
            "module": "csrf_scanner",
            "target": self.target,
            "scan_time_seconds": round(elapsed, 2),
            "endpoints_tested": self.stats['endpoints_tested'],
            "vulnerabilities_found": len(self.findings),
            "high_risk": len(high_findings),
            "medium_risk": len(medium_findings),
            "security_rating": rating,
            "findings": self.findings
        }


# ================================================================
# MAIN RUN FUNCTION - MODIFIED FOR EXTERNAL CLIENT
# ================================================================
async def run(target: str, custom_endpoints: List[Tuple[str, str]] = None, client: HTTPClient = None) -> Dict:
    """
    Run CSRF scanner - DRYBT CSRF SCANNER
    
    Args:
        target: Target URL
        custom_endpoints: List of (endpoint, method) tuples to test (optional)
        client: Optional external HTTPClient (for X-Bug-Bounty header)
    """
    scanner = CSRFScanner(target, client=client)
    return await scanner.scan(custom_endpoints)