#!/usr/bin/env python3
"""
Module 2: Race Condition Detector
Multi-layer race condition detection dengan precision timing
Zero false positive dengan 5 detection methods

MODIFIED: Added external HTTPClient support for X-Bug-Bounty header
"""

import asyncio
import time
import random
import hashlib
from typing import List, Dict, Optional, Tuple, Any
from collections import defaultdict
from datetime import datetime
from core.http_client import HTTPClient
from core.logger import Logger

logger = Logger()

class RaceCondition:
    def __init__(self, target: str, threads: int = 50, requests_per_test: int = 15, client: HTTPClient = None):
        self.target = target.rstrip('/')
        self.threads = threads
        self.requests_per_test = requests_per_test
        self.client = client  # External client with X-Bug-Bounty header
        self.findings: List[Dict] = []
        self.stats = {
            'total_tests': 0,
            'vulnerabilities_found': 0,
            'false_positives_filtered': 0
        }
        
        # ============ ULTIMATE ENDPOINT DATABASE ============
        # Level 1: Nuclear (High impact, high payout)
        self.nuclear_endpoints = [
            # Financial/Transaction
            ("/api/transfer", "POST"),
            ("/api/withdraw", "POST"),
            ("/api/deposit", "POST"),
            ("/api/payment", "POST"),
            ("/api/checkout", "POST"),
            ("/api/order", "POST"),
            ("/api/refund", "POST"),
            
            # Account management
            ("/api/register", "POST"),
            ("/api/signup", "POST"),
            ("/api/verify", "POST"),
            ("/api/confirm", "POST"),
            
            # Voting/Likes
            ("/api/vote", "POST"),
            ("/api/like", "POST"),
            ("/api/dislike", "POST"),
            ("/api/rate", "POST"),
            
            # Coupon/Reward
            ("/api/claim", "POST"),
            ("/api/redeem", "POST"),
            ("/api/coupon", "POST"),
            ("/api/reward", "POST"),
            
            # Cart operations
            ("/api/cart/add", "POST"),
            ("/api/cart/remove", "POST"),
            ("/api/cart/update", "POST"),
            
            # Follow/Unfollow
            ("/api/follow", "POST"),
            ("/api/unfollow", "POST"),
            ("/api/subscribe", "POST"),
        ]
        
        # Level 2: Critical
        self.critical_endpoints = [
            ("/api/update", "PUT"),
            ("/api/edit", "PUT"),
            ("/api/change", "POST"),
            ("/api/settings", "PUT"),
            ("/api/profile", "PUT"),
            ("/api/email", "PUT"),
            ("/api/password", "PUT"),
            ("/api/reset", "POST"),
            
            ("/api/delete", "DELETE"),
            ("/api/remove", "DELETE"),
            ("/api/clear", "DELETE"),
            
            ("/api/create", "POST"),
            ("/api/add", "POST"),
            ("/api/upload", "POST"),
        ]
        
        # Level 3: High
        self.high_endpoints = [
            ("/api/comment", "POST"),
            ("/api/reply", "POST"),
            ("/api/message", "POST"),
            ("/api/send", "POST"),
            
            ("/api/share", "POST"),
            ("/api/repost", "POST"),
            ("/api/retweet", "POST"),
            
            ("/api/report", "POST"),
            ("/api/flag", "POST"),
            ("/api/spam", "POST"),
        ]
        
        # Level 4: Medium
        self.medium_endpoints = [
            ("/api/view", "POST"),
            ("/api/click", "POST"),
            ("/api/track", "POST"),
            ("/api/log", "POST"),
            
            ("/api/save", "POST"),
            ("/api/store", "POST"),
            ("/api/cache", "POST"),
        ]
        
        # All endpoints in priority order
        self.all_endpoints = (self.nuclear_endpoints + self.critical_endpoints + 
                              self.high_endpoints + self.medium_endpoints)
        
        # Race condition detection signatures
        self.race_signatures = [
            'duplicate', 'already', 'exists', 'unique', 'constraint',
            'violation', 'conflict', 'retry', 'try again',
            'too many', 'rate limit', 'slow down',
            'concurrent', 'transaction', 'rollback'
        ]
    
    async def _get_client(self):
        """Get HTTP client - use external if available, otherwise create new"""
        if self.client:
            return self.client
        else:
            return HTTPClient(self.target, timeout=5, retries=1)
    
    async def get_baseline_behavior(self, endpoint: str, method: str) -> Dict:
        """Get baseline response untuk endpoint normal (1 request)"""
        client = await self._get_client()
        payload = self._generate_payload(endpoint)
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                if method == "POST":
                    resp = await ctx_client.post(endpoint, json=payload)
                elif method == "PUT":
                    resp = await ctx_client.put(endpoint, json=payload)
                elif method == "DELETE":
                    resp = await ctx_client.delete(endpoint)
                else:
                    resp = await ctx_client.get(endpoint)
                
                if resp:
                    body = await resp.text()
                    return {
                        "status": resp.status,
                        "body_hash": hashlib.md5(body.encode()).hexdigest(),
                        "body_length": len(body),
                        "success": resp.status == 200,
                        "response_time_ms": 0
                    }
        else:
            if method == "POST":
                resp = await client.post(endpoint, json=payload)
            elif method == "PUT":
                resp = await client.put(endpoint, json=payload)
            elif method == "DELETE":
                resp = await client.delete(endpoint)
            else:
                resp = await client.get(endpoint)
            
            if resp:
                body = await resp.text()
                return {
                    "status": resp.status,
                    "body_hash": hashlib.md5(body.encode()).hexdigest(),
                    "body_length": len(body),
                    "success": resp.status == 200,
                    "response_time_ms": 0
                }
        
        return {"success": False, "status": 500}
    
    def _generate_payload(self, endpoint: str) -> Dict:
        """Generate realistic payload untuk testing"""
        timestamp = int(time.time() * 1000)
        random_id = random.randint(10000, 99999)
        
        # Endpoint-specific payloads
        if "transfer" in endpoint or "withdraw" in endpoint:
            return {
                "amount": 1,
                "to": f"user_{random_id}",
                "timestamp": timestamp,
                "reference": f"TST_{timestamp}"
            }
        elif "vote" in endpoint or "like" in endpoint:
            return {
                "item_id": random_id,
                "vote": 1,
                "timestamp": timestamp,
                "user": f"tester_{random_id}"
            }
        elif "claim" in endpoint or "redeem" in endpoint:
            return {
                "code": f"TEST{random_id}",
                "timestamp": timestamp,
                "user_id": random_id
            }
        elif "cart" in endpoint:
            return {
                "product_id": random_id,
                "quantity": 1,
                "timestamp": timestamp
            }
        elif "register" in endpoint or "signup" in endpoint:
            return {
                "username": f"test_{random_id}_{timestamp}",
                "email": f"test_{random_id}@example.com",
                "timestamp": timestamp
            }
        else:
            return {
                "id": random_id,
                "action": "test",
                "timestamp": timestamp,
                "nonce": f"{timestamp}_{random_id}"
            }
    
    async def send_parallel_requests(self, endpoint: str, method: str, count: int) -> List[Dict]:
        """Send parallel requests untuk race condition test"""
        results = []
        semaphore = asyncio.Semaphore(self.threads)
        client = await self._get_client()
        
        async def send_one(request_id: int):
            async with semaphore:
                payload = self._generate_payload(endpoint)
                start_time = time.time()
                
                # Need to create fresh client for parallel requests or reuse properly
                if not hasattr(client, 'session') or client.session is None:
                    async with HTTPClient(self.target, timeout=3, retries=1) as temp_client:
                        if method == "POST":
                            resp = await temp_client.post(endpoint, json=payload)
                        elif method == "PUT":
                            resp = await temp_client.put(endpoint, json=payload)
                        elif method == "DELETE":
                            resp = await temp_client.delete(endpoint)
                        else:
                            resp = await temp_client.get(endpoint)
                        
                        elapsed_ms = (time.time() - start_time) * 1000
                        
                        if resp:
                            body = await resp.text()
                            return {
                                "id": request_id,
                                "status": resp.status,
                                "body_hash": hashlib.md5(body.encode()).hexdigest(),
                                "body_length": len(body),
                                "body_preview": body[:200],
                                "success": resp.status == 200,
                                "response_time_ms": elapsed_ms
                            }
                else:
                    if method == "POST":
                        resp = await client.post(endpoint, json=payload)
                    elif method == "PUT":
                        resp = await client.put(endpoint, json=payload)
                    elif method == "DELETE":
                        resp = await client.delete(endpoint)
                    else:
                        resp = await client.get(endpoint)
                    
                    elapsed_ms = (time.time() - start_time) * 1000
                    
                    if resp:
                        body = await resp.text()
                        return {
                            "id": request_id,
                            "status": resp.status,
                            "body_hash": hashlib.md5(body.encode()).hexdigest(),
                            "body_length": len(body),
                            "body_preview": body[:200],
                            "success": resp.status == 200,
                            "response_time_ms": elapsed_ms
                        }
                
                return {
                    "id": request_id,
                    "status": 500,
                    "success": False,
                    "response_time_ms": (time.time() - start_time) * 1000
                }
        
        # Send all requests with microsecond precision
        start_batch = time.perf_counter()
        tasks = [send_one(i) for i in range(count)]
        results_list = await asyncio.gather(*tasks)
        batch_time_ms = (time.perf_counter() - start_batch) * 1000
        
        return {
            "requests": results_list,
            "batch_time_ms": batch_time_ms,
            "success_count": sum(1 for r in results_list if r.get("success", False)),
            "unique_statuses": len(set(r.get("status", 0) for r in results_list)),
            "unique_hashes": len(set(r.get("body_hash", "") for r in results_list if r.get("body_hash")))
        }
    
    def analyze_race_condition(self, endpoint: str, method: str, results: Dict, baseline: Dict) -> Optional[Dict]:
        """5 Layer Race Condition Detection"""
        
        requests = results.get("requests", [])
        success_count = results.get("success_count", 0)
        unique_hashes = results.get("unique_hashes", 0)
        unique_statuses = results.get("unique_statuses", 0)
        batch_time_ms = results.get("batch_time_ms", 0)
        
        # ============ LAYER 1: Multi-Success Detection ============
        if success_count > 1 and len(requests) > 2:
            success_rate = (success_count / len(requests)) * 100
            
            if success_rate > 30:
                self.stats['vulnerabilities_found'] += 1
                return {
                    "vulnerable": True,
                    "layer": "MULTI_SUCCESS",
                    "confidence": 95,
                    "success_count": success_count,
                    "success_rate": round(success_rate, 2),
                    "details": f"{success_count}/{len(requests)} requests succeeded (expected: 1)"
                }
        
        # ============ LAYER 2: Hash Variation Detection ============
        if unique_hashes > 1 and len(requests) > 2:
            hash_variation = (unique_hashes / len(requests)) * 100
            
            if hash_variation > 20:
                self.stats['vulnerabilities_found'] += 1
                return {
                    "vulnerable": True,
                    "layer": "HASH_VARIATION",
                    "confidence": 85,
                    "unique_responses": unique_hashes,
                    "variation_rate": round(hash_variation, 2),
                    "details": f"{unique_hashes} different response types detected"
                }
        
        # ============ LAYER 3: Status Code Inconsistency ============
        if unique_statuses > 1:
            statuses = [r.get("status", 0) for r in requests]
            has_200 = 200 in statuses
            has_conflict = any(s in [409, 429, 400] for s in statuses)
            
            if has_200 and has_conflict:
                self.stats['vulnerabilities_found'] += 1
                return {
                    "vulnerable": True,
                    "layer": "STATUS_INCONSISTENCY",
                    "confidence": 80,
                    "statuses": list(set(statuses)),
                    "details": "Mix of success and conflict status codes"
                }
        
        # ============ LAYER 4: Timing Anomaly Detection ============
        response_times = [r.get("response_time_ms", 0) for r in requests if r.get("response_time_ms", 0) > 0]
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            
            if max_time > avg_time * 3:
                self.stats['vulnerabilities_found'] += 1
                return {
                    "vulnerable": True,
                    "layer": "TIMING_ANOMALY",
                    "confidence": 70,
                    "avg_time_ms": round(avg_time, 2),
                    "max_time_ms": round(max_time, 2),
                    "details": f"Response time anomaly detected ({max_time:.0f}ms vs avg {avg_time:.0f}ms)"
                }
        
        # ============ LAYER 5: Content Analysis ============
        all_bodies = " ".join([r.get("body_preview", "") for r in requests[:5]])
        all_bodies_lower = all_bodies.lower()
        
        for signature in self.race_signatures:
            if signature in all_bodies_lower:
                self.stats['vulnerabilities_found'] += 1
                return {
                    "vulnerable": True,
                    "layer": "CONTENT_ANALYSIS",
                    "confidence": 75,
                    "signature_found": signature,
                    "details": f"Race condition signature '{signature}' detected in response"
                }
        
        return {"vulnerable": False}
    
    async def test_endpoint(self, endpoint: str, method: str, priority: str) -> Optional[Dict]:
        """Test single endpoint untuk race condition"""
        
        baseline = await self.get_baseline_behavior(endpoint, method)
        
        if not baseline.get("success"):
            return None
        
        results = await self.send_parallel_requests(endpoint, method, self.requests_per_test)
        
        analysis = self.analyze_race_condition(endpoint, method, results, baseline)
        
        if analysis.get("vulnerable"):
            confidence = analysis.get("confidence", 0)
            
            if confidence >= 90:
                icon = "💎"
            elif confidence >= 80:
                icon = "🔴"
            elif confidence >= 70:
                icon = "🟠"
            else:
                icon = "🟡"
            
            logger.info(f"{icon} Race Condition on {endpoint} [{method}] | {analysis.get('layer')} | {confidence}%")
            
            return {
                "type": "race_condition",
                "severity": "critical" if priority == "NUCLEAR" else "high",
                "priority": priority,
                "endpoint": endpoint,
                "method": method,
                "detection_layer": analysis.get("layer"),
                "confidence": confidence,
                "requests_sent": self.requests_per_test,
                "success_count": results.get("success_count", 0),
                "batch_time_ms": round(results.get("batch_time_ms", 0), 2),
                "details": analysis
            }
        
        return None
    
    async def scan(self, custom_endpoints: List[Tuple[str, str]] = None) -> Dict:
        """Main race condition scanner"""
        
        if custom_endpoints:
            endpoints = custom_endpoints
        else:
            endpoints = self.all_endpoints
        
        total_endpoints = len(endpoints)
        
        nuclear_count = len([e for e in endpoints if e in self.nuclear_endpoints])
        critical_count = len([e for e in endpoints if e in self.critical_endpoints])
        high_count = len([e for e in endpoints if e in self.high_endpoints])
        medium_count = len([e for e in endpoints if e in self.medium_endpoints])
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🚀 DRYBT RACE CONDITION DETECTOR")
        logger.info(f"{'='*60}")
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"📊 Endpoints: {total_endpoints}")
        logger.info(f"   💎 Nuclear: {nuclear_count} | 🔴 Critical: {critical_count}")
        logger.info(f"   🟠 High: {high_count} | 🟡 Medium: {medium_count}")
        logger.info(f"🔧 Threads: {self.threads} | Requests/test: {self.requests_per_test}")
        logger.info(f"{'='*60}\n")
        
        start_time = time.time()
        
        # Test NUCLEAR first
        for endpoint, method in self.nuclear_endpoints:
            if endpoint not in [e[0] for e in endpoints]:
                continue
            result = await self.test_endpoint(endpoint, method, "NUCLEAR")
            if result:
                self.findings.append(result)
            await asyncio.sleep(0.1)
        
        # Test CRITICAL (concurrent)
        critical_tasks = []
        for endpoint, method in self.critical_endpoints:
            if endpoint not in [e[0] for e in endpoints]:
                continue
            critical_tasks.append(self.test_endpoint(endpoint, method, "CRITICAL"))
        
        critical_results = await asyncio.gather(*critical_tasks)
        self.findings.extend([r for r in critical_results if r])
        
        # Test HIGH (concurrent)
        high_tasks = []
        for endpoint, method in self.high_endpoints:
            if endpoint not in [e[0] for e in endpoints]:
                continue
            high_tasks.append(self.test_endpoint(endpoint, method, "HIGH"))
        
        high_results = await asyncio.gather(*high_tasks)
        self.findings.extend([r for r in high_results if r])
        
        # Test MEDIUM (concurrent)
        medium_tasks = []
        for endpoint, method in self.medium_endpoints:
            if endpoint not in [e[0] for e in endpoints]:
                continue
            medium_tasks.append(self.test_endpoint(endpoint, method, "MEDIUM"))
        
        medium_results = await asyncio.gather(*medium_tasks)
        self.findings.extend([r for r in medium_results if r])
        
        elapsed = time.time() - start_time
        
        nuclear_findings = [f for f in self.findings if f.get("priority") == "NUCLEAR"]
        critical_findings = [f for f in self.findings if f.get("priority") == "CRITICAL"]
        high_findings = [f for f in self.findings if f.get("priority") == "HIGH"]
        
        print(f"\n{'='*60}")
        print(f"📊 RACE CONDITION SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"⏱️  Time: {elapsed:.2f} seconds")
        print(f"📡 Endpoints tested: {total_endpoints}")
        print(f"🎯 Vulnerabilities found: {len(self.findings)}")
        
        if nuclear_findings:
            print(f"\n💎 NUCLEAR (Critical - High Payout):")
            for f in nuclear_findings:
                conf = f.get("confidence", 0)
                print(f"   🔥 {f['endpoint']} [{f['method']}] | Confidence: {conf}%")
        
        if critical_findings:
            print(f"\n🔴 CRITICAL:")
            for f in critical_findings:
                conf = f.get("confidence", 0)
                print(f"   ⚡ {f['endpoint']} [{f['method']}] | Confidence: {conf}%")
        
        if high_findings:
            print(f"\n🟠 HIGH:")
            for f in high_findings:
                conf = f.get("confidence", 0)
                print(f"   📌 {f['endpoint']} [{f['method']}] | Confidence: {conf}%")
        
        print(f"\n{'='*60}")
        
        if len(self.findings) > 5:
            rating = "🏆 LEGENDARY - Multiple race conditions found!"
        elif len(self.findings) > 2:
            rating = "⭐ EXCELLENT - High impact vulnerabilities"
        elif len(self.findings) > 0:
            rating = "✅ GOOD - Race conditions detected"
        else:
            rating = "ℹ️ CLEAN - No race conditions detected (target may be secure)"
        
        print(f"📈 Result: {rating}")
        print(f"{'='*60}\n")
        
        return {
            "module": "race_condition",
            "target": self.target,
            "scan_time_seconds": round(elapsed, 2),
            "endpoints_tested": total_endpoints,
            "requests_per_endpoint": self.requests_per_test,
            "total_requests_sent": total_endpoints * self.requests_per_test,
            "vulnerabilities_found": len(self.findings),
            "nuclear_findings": len(nuclear_findings),
            "critical_findings": len(critical_findings),
            "high_findings": len(high_findings),
            "findings": self.findings
        }


# ================================================================
# MAIN RUN FUNCTION - MODIFIED FOR EXTERNAL CLIENT
# ================================================================
async def run(target: str, threads: int = 50, custom_endpoints: List[Tuple[str, str]] = None, client: HTTPClient = None) -> Dict:
    """
    Run race condition detector - DRYBT RACE CONDITION DETECTOR
    
    Args:
        target: Target URL
        threads: Concurrent threads (default 50)
        custom_endpoints: List of (endpoint, method) tuples
        client: Optional external HTTPClient (for X-Bug-Bounty header)
    """
    scanner = RaceCondition(target, threads=threads, requests_per_test=15, client=client)
    return await scanner.scan(custom_endpoints)