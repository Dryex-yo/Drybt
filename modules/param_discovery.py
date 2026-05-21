#!/usr/bin/env python3
"""
Module 1: Parameter Discovery 
Zero miss detection dengan 7 layer validation
Speed: <5 detik untuk 100+ parameter

MODIFIED: Added external HTTPClient support for X-Bug-Bounty header
"""

import asyncio
import random
import time
import json
import hashlib
import re
from typing import List, Dict, Set, Optional, Tuple, Any
from collections import defaultdict
from core.http_client import HTTPClient
from core.logger import Logger

logger = Logger()

class ParameterDiscovery:
    def __init__(self, target: str, threads: int = 100, timeout: int = 2, client: HTTPClient = None):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.client = client  # External client with X-Bug-Bounty header
        self.found_parameters: Set[str] = set()
        self.findings: List[Dict] = []
        
        # ============ ULTIMATE PARAMETER DATABASE ============
        # Level 1: Nuclear Priority (Langsung payout kalo ketemu)
        self.nuclear_params = [
            'id', 'user_id', 'account_id', 'uid', 'uuid', 'guid',
            'admin', 'is_admin', 'role', 'permission', 'access_level',
            'debug', 'test', 'dev_mode', 'bypass', 'override',
            'token', 'api_key', 'apikey', 'secret', 'private_key'
        ]
        
        # Level 2: Critical (Sering jadi IDOR/SQLi)
        self.critical_params = [
            'q', 'query', 'search', 'keyword', 'filter',
            'redirect', 'redirect_uri', 'return_to', 'next', 'callback', 'callback_url',
            'url', 'link', 'href', 'dest', 'destination', 'goto',
            'file', 'path', 'dir', 'folder', 'filename', 'download',
            'page', 'offset', 'limit', 'per_page', 'cursor', 'page_id',
            'email', 'username', 'name', 'fullname', 'phone'
        ]
        
        # Level 3: High Impact
        self.high_params = [
            'action', 'method', 'mode', 'type', 'format', 'output',
            'sort', 'order', 'sort_by', 'sort_dir', 'order_by',
            'include', 'exclude', 'expand', 'embed', 'fields',
            'lang', 'locale', 'timezone', 'currency',
            'from', 'to', 'start', 'end', 'start_date', 'end_date',
            'before', 'after', 'since', 'until'
        ]
        
        # Level 4: Medium
        self.medium_params = [
            'view', 'template', 'theme', 'layout', 'style',
            'color', 'size', 'width', 'height', 'limit',
            'offset', 'skip', 'take', 'top', 'first', 'last'
        ]
        
        # Level 5: Low but still important
        self.low_params = [
            'X-Requested-With', 'X-Forwarded-For', 'X-Real-IP',
            'callback', 'jsonp', 'cors', 'origin'
        ]
        
        # All parameters in priority order
        self.all_params = (self.nuclear_params + self.critical_params + 
                          self.high_params + self.medium_params + self.low_params)
        
        # Cache systems
        self.baseline_cache: Dict[str, Dict] = {}
        self.signature_cache: Dict[str, str] = {}
        
        # Detection statistics
        self.stats = {
            'total_requests': 0,
            'successful_detections': 0,
            'false_positives_blocked': 0
        }
    
    async def _get_client(self):
        """Get HTTP client - use external if available, otherwise create new"""
        if self.client:
            return self.client
        else:
            return HTTPClient(self.target, timeout=self.timeout, retries=1)
    
    async def get_baseline_signature(self, path: str) -> Dict:
        """Get baseline signature dengan 7 layer analysis"""
        if path in self.baseline_cache:
            return self.baseline_cache[path]
        
        client = await self._get_client()
        
        if not hasattr(client, 'session') or client.session is None:
            # Need to create context manager
            async with client as ctx_client:
                resp = await ctx_client.get(path)
                if not resp:
                    return {'exists': False}
                body = await resp.text()
                headers = dict(resp.headers)
        else:
            resp = await client.get(path)
            if not resp:
                return {'exists': False}
            body = await resp.text()
            headers = dict(resp.headers)
        
        # Layer 1: Content signature (hash)
        content_hash = hashlib.md5(body.encode()).hexdigest()
        
        # Layer 2: Structure signature (for JSON/HTML)
        structure_hash = self._get_structure_hash(body)
        
        # Layer 3: Length signature
        length = len(body)
        
        # Layer 4: Header signature
        header_signature = hashlib.md5(str(sorted(headers.items())).encode()).hexdigest()
        
        signature = {
            'exists': True,
            'content_hash': content_hash,
            'structure_hash': structure_hash,
            'length': length,
            'header_signature': header_signature,
            'status_code': resp.status,
            'content_type': headers.get('content-type', ''),
            'body_preview': body[:500]
        }
        
        self.baseline_cache[path] = signature
        return signature
    
    def _get_structure_hash(self, content: str) -> str:
        """Get structure hash untuk JSON/HTML content"""
        # Remove dynamic values, keep only structure
        if content.strip().startswith('{'):
            try:
                data = json.loads(content)
                structure = self._get_json_structure(data)
                return hashlib.md5(str(structure).encode()).hexdigest()
            except:
                pass
        
        # For HTML, remove numbers and dynamic IDs
        html_structure = re.sub(r'[0-9]+', 'N', content)
        html_structure = re.sub(r'"[^"]*"', '""', html_structure)
        return hashlib.md5(html_structure.encode()).hexdigest()
    
    def _get_json_structure(self, obj: Any, depth: int = 0) -> Any:
        """Get JSON structure (keys only, no values)"""
        if depth > 10:
            return '...'
        if isinstance(obj, dict):
            return {k: self._get_json_structure(v, depth+1) for k, v in obj.items()}
        elif isinstance(obj, list):
            if obj:
                return [self._get_json_structure(obj[0], depth+1)]
            return []
        else:
            return type(obj).__name__
    
    def _search_json_deep(self, obj: Any, target: str, max_depth: int = 20) -> bool:
        """Deep search dalam nested JSON"""
        if max_depth <= 0:
            return False
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                if self._search_json_deep(value, target, max_depth-1):
                    return True
                # Also check keys
                if target in str(key):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if self._search_json_deep(item, target, max_depth-1):
                    return True
        elif isinstance(obj, str):
            if target in obj:
                return True
        elif isinstance(obj, (int, float, bool)):
            if str(obj) == target:
                return True
        return False
    
    async def test_parameter_advanced(self, path: str, param: str, test_value: str) -> Optional[Dict]:
        """7 Layer Detection System - Zero Miss"""
        client = await self._get_client()
        
        url = f"{path}?{param}={test_value}"
        start_time = time.time()
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                resp = await ctx_client.get(url)
                if not resp or resp.status >= 500:
                    return None
                body = await resp.text()
        else:
            resp = await client.get(url)
            if not resp or resp.status >= 500:
                return None
            body = await resp.text()
        
        response_time = (time.time() - start_time) * 1000
        self.stats['total_requests'] += 1
        
        # ============ LAYER 1: Direct String Match ============
        if test_value in body:
            self.stats['successful_detections'] += 1
            return {
                "param": param,
                "method": "DIRECT_REFLECTION",
                "confidence": 100,
                "response_time_ms": round(response_time, 2)
            }
        
        # ============ LAYER 2: JSON Deep Search ============
        if body.strip().startswith('{') or body.strip().startswith('['):
            try:
                data = json.loads(body)
                if self._search_json_deep(data, test_value):
                    self.stats['successful_detections'] += 1
                    return {
                        "param": param,
                        "method": "JSON_DEEP_REFLECTION",
                        "confidence": 100,
                        "response_time_ms": round(response_time, 2)
                    }
            except:
                pass
        
        # ============ LAYER 3: URL Encoded Detection ============
        import urllib.parse
        encoded_value = urllib.parse.quote(test_value)
        if encoded_value in body:
            self.stats['successful_detections'] += 1
            return {
                "param": param,
                "method": "URL_ENCODED_REFLECTION",
                "confidence": 95,
                "response_time_ms": round(response_time, 2)
            }
        
        # ============ LAYER 4: Unicode/Normalized Detection ============
        normalized = test_value.encode().decode('unicode_escape')
        if normalized != test_value and normalized in body:
            self.stats['successful_detections'] += 1
            return {
                "param": param,
                "method": "NORMALIZED_REFLECTION",
                "confidence": 90,
                "response_time_ms": round(response_time, 2)
            }
        
        # ============ LAYER 5: Content Hash Change Detection ============
        baseline = await self.get_baseline_signature(path)
        if baseline.get('exists'):
            current_hash = hashlib.md5(body.encode()).hexdigest()
            if current_hash != baseline.get('content_hash'):
                self.stats['successful_detections'] += 1
                return {
                    "param": param,
                    "method": "CONTENT_HASH_CHANGE",
                    "confidence": 85,
                    "response_time_ms": round(response_time, 2),
                    "hash_diff": True
                }
        
        # ============ LAYER 6: Structure Change Detection ============
        current_structure = self._get_structure_hash(body)
        if current_structure != baseline.get('structure_hash', ''):
            self.stats['successful_detections'] += 1
            return {
                "param": param,
                "method": "STRUCTURE_CHANGE",
                "confidence": 80,
                "response_time_ms": round(response_time, 2)
            }
        
        # ============ LAYER 7: Length Delta Detection ============
        length_delta = abs(len(body) - baseline.get('length', 0))
        if length_delta > 20:
            self.stats['successful_detections'] += 1
            return {
                "param": param,
                "method": "LENGTH_DELTA",
                "confidence": 70,
                "response_time_ms": round(response_time, 2),
                "length_delta": length_delta
            }
        
        return None
    
    async def scan_path(self, path: str) -> List[str]:
        """Scan single path dengan priority-based concurrent execution"""
        logger.info(f"🔍 Scanning: {path}")
        
        found = []
        test_value = f"DRYBT_{random.randint(100000, 999999)}_{int(time.time())}"
        
        semaphore = asyncio.Semaphore(self.threads)
        
        async def test_with_priority(param: str, priority: str, order: int):
            async with semaphore:
                result = await self.test_parameter_advanced(path, param, test_value)
                if result:
                    found.append(param)
                    self.found_parameters.add(param)
                    
                    method = result.get("method", "UNKNOWN")
                    confidence = result.get("confidence", 0)
                    time_ms = result.get("response_time_ms", 0)
                    
                    if confidence >= 95:
                        icon = "💎"
                    elif confidence >= 80:
                        icon = "🔴"
                    elif confidence >= 70:
                        icon = "🟠"
                    else:
                        icon = "🟡"
                    
                    logger.success(f"{icon} [{priority.upper()}] {param} | {method} | {confidence}% | {time_ms}ms")
                    
                    self.findings.append({
                        "type": "parameter_discovery",
                        "param": param,
                        "priority": priority,
                        "priority_level": order,
                        "path": path,
                        "detection_method": method,
                        "confidence": confidence,
                        "response_time_ms": time_ms,
                        "status_code": result.get("status_code", 200)
                    })
        
        for idx, param in enumerate(self.nuclear_params):
            await test_with_priority(param, "NUCLEAR", 1)
        
        tasks = [test_with_priority(param, "CRITICAL", 2) for param in self.critical_params]
        await asyncio.gather(*tasks)
        
        tasks = [test_with_priority(param, "HIGH", 3) for param in self.high_params]
        await asyncio.gather(*tasks)
        
        tasks = [test_with_priority(param, "MEDIUM", 4) for param in self.medium_params]
        await asyncio.gather(*tasks)
        
        tasks = [test_with_priority(param, "LOW", 5) for param in self.low_params]
        await asyncio.gather(*tasks)
        
        return found
    
    async def intelligent_endpoint_discovery(self) -> List[str]:
        """Auto-detect live endpoints dengan smart probing"""
        test_paths = [
            "/", "/api", "/v1", "/v2", "/api/v1", "/api/v2",
            "/rest", "/rest/v1", "/graphql", "/gql", "/query",
            "/search", "/search?q=test", "/api/search",
            "/user", "/users", "/profile", "/me",
            "/auth", "/login", "/api/auth",
            "/data", "/api/data", "/content",
            "/public", "/api/public", "/open",
            "/test", "/debug", "/admin", "/dev"
        ]
        
        async def probe(path: str) -> Optional[str]:
            client = await self._get_client()
            
            if not hasattr(client, 'session') or client.session is None:
                async with client as ctx_client:
                    resp = await ctx_client.get(path)
                    if resp and resp.status < 400:
                        return path
            else:
                resp = await client.get(path)
                if resp and resp.status < 400:
                    return path
            return None
        
        logger.info(f"🎯 Intelligent endpoint discovery on {self.target}")
        
        results = await asyncio.gather(*[probe(p) for p in test_paths])
        found_endpoints = [p for p in results if p]
        
        if found_endpoints:
            logger.success(f"Found {len(found_endpoints)} live endpoints")
            for ep in found_endpoints[:10]:
                logger.info(f"  📍 {ep}")
        else:
            logger.warning("No custom endpoints found, using root")
            found_endpoints = ["/"]
        
        return found_endpoints
    
    async def scan_endpoints(self, paths: List[str] = None) -> Dict:
        """Main scan dengan intelligent routing"""
        
        if paths is None:
            paths = await self.intelligent_endpoint_discovery()
        
        total_params = len(self.all_params)
        logger.info(f"\n{'='*60}")
        logger.info(f"🚀 DRYBT PARAMETER DISCOVERY")
        logger.info(f"{'='*60}")
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"📊 Parameters: {total_params} (5 priority levels)")
        logger.info(f"🔧 Threads: {self.threads} | Timeout: {self.timeout}s")
        logger.info(f"📁 Endpoints: {len(paths)}")
        logger.info(f"{'='*60}\n")
        
        start_time = time.time()
        
        for path in paths:
            await self.scan_path(path)
        
        elapsed = time.time() - start_time
        
        nuclear_found = [p for p in self.found_parameters if p in self.nuclear_params]
        critical_found = [p for p in self.found_parameters if p in self.critical_params]
        high_found = [p for p in self.found_parameters if p in self.high_params]
        medium_found = [p for p in self.found_parameters if p in self.medium_params]
        low_found = [p for p in self.found_parameters if p in self.low_params]
        
        print(f"\n{'='*60}")
        print(f"📊 SCAN SUMMARY - DRYBT PARAMETER DISCOVERY")
        print(f"{'='*60}")
        print(f"⏱️  Time: {elapsed:.2f} seconds")
        print(f"📡 Requests sent: {self.stats['total_requests']}")
        print(f"✅ Detections: {self.stats['successful_detections']}")
        print(f"🎯 Parameters found: {len(self.found_parameters)}/{total_params}")
        
        if nuclear_found:
            print(f"\n💎 NUCLEAR (Payout guaranteed):")
            for p in nuclear_found:
                print(f"   🔥 {p}")
        
        if critical_found:
            print(f"\n🔴 CRITICAL:")
            for p in critical_found:
                print(f"   ⚡ {p}")
        
        if high_found:
            print(f"\n🟠 HIGH:")
            for p in high_found:
                print(f"   📌 {p}")
        
        if medium_found:
            print(f"\n🟡 MEDIUM:")
            for p in medium_found:
                print(f"   📍 {p}")
        
        if low_found:
            print(f"\n🔵 LOW:")
            for p in low_found:
                print(f"   📎 {p}")
        
        print(f"\n{'='*60}")
        
        detection_rate = (self.stats['successful_detections'] / max(self.stats['total_requests'], 1)) * 100
        if detection_rate > 10:
            rating = "🏆 LEGENDARY"
        elif detection_rate > 5:
            rating = "⭐ EXCELLENT"
        elif detection_rate > 1:
            rating = "✅ GOOD"
        else:
            rating = "ℹ️ NORMAL (target may not reflect parameters)"
        
        print(f"📈 Detection rate: {detection_rate:.2f}% - {rating}")
        print(f"{'='*60}\n")
        
        return {
            "module": "param_discovery",
            "target": self.target,
            "scan_time_seconds": round(elapsed, 2),
            "total_requests": self.stats['total_requests'],
            "endpoints_scanned": paths,
            "total_parameters_tested": total_params,
            "total_parameters_found": len(self.found_parameters),
            "nuclear_params": list(nuclear_found),
            "critical_params": list(critical_found),
            "high_params": list(high_found),
            "medium_params": list(medium_found),
            "low_params": list(low_found),
            "detection_rate_percent": round(detection_rate, 2),
            "performance_rating": rating,
            "findings": self.findings
        }


# ================================================================
# MAIN RUN FUNCTION - MODIFIED FOR EXTERNAL CLIENT
# ================================================================
async def run(target: str, threads: int = 100, use_ai: bool = False, client: HTTPClient = None) -> Dict:
    """
    Run parameter discovery - DRYBT PARAMETER DISCOVERY
    
    Args:
        target: Target URL (e.g., https://example.com)
        threads: Concurrent threads (default 100 for maximum speed)
        use_ai: Not used, kept for compatibility
        client: Optional external HTTPClient (for X-Bug-Bounty header)
    """
    scanner = ParameterDiscovery(target, threads=threads, timeout=2, client=client)
    return await scanner.scan_endpoints()