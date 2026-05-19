#!/usr/bin/env python3
"""
DRYBT by Dryex v.1 - Intelligent Target Detector
Mendeteksi teknologi, framework, endpoint, dan merekomendasikan module yang tepat
"""

import re
import asyncio
from typing import Dict, List, Optional, Set, Tuple
from core.http_client import HTTPClient
from core.logger import Logger

logger = Logger()

class TargetDetector:
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.results = {
            "tool": "DRYBT by Dryex v.1",
            "version": "v.1",
            "target": target,
            "technologies": [],
            "frameworks": [],
            "servers": [],
            "endpoints": [],
            "suggested_modules": [],
            "headers": {},
            "cookies": [],
            "forms": [],
            "api_endpoints": [],
            "graphql_endpoints": [],
            "has_login_form": False,
            "has_search_form": False,
            "estimated_risk": "unknown"
        }
        
        # Technology signatures with confidence levels
        self.tech_signatures = {
            "WordPress": {
                "patterns": [r'wp-content', r'wp-includes', r'wordpress', r'wp-json', r'wp-admin', r'wp-login'],
                "confidence": 90
            },
            "Laravel": {
                "patterns": [r'laravel', r'csrf-token', r'_token', r'laravel_session', r'x-csrf-token'],
                "confidence": 85
            },
            "Django": {
                "patterns": [r'csrfmiddlewaretoken', r'django', r'csrftoken', r'__admin_media_prefix__'],
                "confidence": 85
            },
            "Ruby on Rails": {
                "patterns": [r'rails', r'authenticity_token', r'_rails', r'rack.session', r'csrf-param'],
                "confidence": 85
            },
            "Node.js/Express": {
                "patterns": [r'express', r'x-powered-by:\s*express', r'connect.sid', r'nodejs'],
                "confidence": 80
            },
            "Spring Boot": {
                "patterns": [r'spring-boot', r'x-application-context', r'jsessionid'],
                "confidence": 80
            },
            "ASP.NET": {
                "patterns": [r'asp\.net', r'__viewstate', r'__eventvalidation', r'aspxauth', r'\.aspx'],
                "confidence": 85
            },
            "GraphQL": {
                "patterns": [r'__typename', r'schema', r'graphql', r'mutation', r'query\s*\{', r'__schema'],
                "confidence": 95
            },
            "REST API": {
                "patterns": [r'application/json', r'api/', r'/v\d+/', r'/api/v\d+'],
                "confidence": 70
            },
            "JWT Authentication": {
                "patterns": [r'bearer', r'jwt', r'eyJhbGci', r'authorization:\s*bearer', r'access_token'],
                "confidence": 90
            },
            "Drupal": {
                "patterns": [r'drupal', r'sites/default', r'drupal.js', r'jquery.once'],
                "confidence": 85
            },
            "Joomla": {
                "patterns": [r'joomla', r'media/system/js', r'com_content', r'option=com'],
                "confidence": 85
            },
            "Magento": {
                "patterns": [r'magento', r'skin/frontend', r'Mage\.', r'checkout/cart'],
                "confidence": 85
            },
            "Shopify": {
                "patterns": [r'shopify', r'myshopify\.com', r'cdn\.shopify', r'cart\.js'],
                "confidence": 85
            }
        }
        
        # Framework signatures
        self.framework_signatures = {
            "Bootstrap": {
                "patterns": [r'bootstrap', r'bs-', r'col-md-', r'container-fluid', r'navbar'],
                "confidence": 90
            },
            "jQuery": {
                "patterns": [r'jquery', r'\$\(', r'\$\.', r'jQuery'],
                "confidence": 95
            },
            "React": {
                "patterns": [r'react', r'react-dom', r'__react', r'ReactDOM', r'useState', r'useEffect'],
                "confidence": 90
            },
            "Vue.js": {
                "patterns": [r'vue', r'v-', r'vuejs', r'__vue__', r'v-model', r'v-bind'],
                "confidence": 90
            },
            "Angular": {
                "patterns": [r'angular', r'ng-', r'ng-app', r'_ng', r'ng-model', r'ng-click'],
                "confidence": 90
            },
            "Tailwind CSS": {
                "patterns": [r'tailwind', r'tw-', r'class="[\w\s-]*?flex[\w\s-]*?"', r'bg-'],
                "confidence": 85
            },
            "Alpine.js": {
                "patterns": [r'alpine', r'x-data', r'x-show', r'x-bind', r'x-model'],
                "confidence": 85
            }
        }
        
        # Server signatures
        self.server_signatures = {
            "Apache": {"patterns": [r'apache', r'httpd'], "confidence": 95},
            "Nginx": {"patterns": [r'nginx'], "confidence": 95},
            "IIS": {"patterns": [r'iis', r'microsoft-iis'], "confidence": 95},
            "CloudFlare": {"patterns": [r'cloudflare', r'cf-ray', r'__cfduid'], "confidence": 95},
            "AWS (CloudFront)": {"patterns": [r'cloudfront', r'x-amz-cf'], "confidence": 90},
            "Google Cloud": {"patterns": [r'google', r'gcp', r'x-cloud-trace'], "confidence": 85},
            "AWS (ELB)": {"patterns": [r'aws', r'elb', r'x-amzn-requestid'], "confidence": 85}
        }
    
    async def detect_headers(self):
        """Analyze HTTP headers for technology detection"""
        async with HTTPClient(self.target, timeout=5) as client:
            response = await client.get("/")
            if response:
                for key, value in response.headers.items():
                    self.results["headers"][key] = value
                    
                    # Detect server
                    if key.lower() == 'server':
                        self.results["servers"].append(value)
                    
                    # Detect technology from headers
                    if key.lower() == 'x-powered-by':
                        for tech in self.tech_signatures:
                            if any(p in value.lower() for p in self.tech_signatures[tech]["patterns"]):
                                if tech not in self.results["technologies"]:
                                    self.results["technologies"].append(tech)
                    
                    # Detect cookies
                    if key.lower() == 'set-cookie':
                        self.results["cookies"].append(value)
                        
                        # Detect session patterns
                        if any(s in value for s in ['session', 'sess', 'token', 'jwt']):
                            if "Session Cookie" not in self.results["technologies"]:
                                self.results["technologies"].append("Session Cookie")
    
    async def detect_from_html(self, body: str):
        """Detect technologies and frameworks from HTML body"""
        body_lower = body.lower()
        
        # Detect technologies
        for tech, info in self.tech_signatures.items():
            for pattern in info["patterns"]:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    if tech not in self.results["technologies"]:
                        self.results["technologies"].append(tech)
                        logger.debug(f"Detected {tech} (confidence: {info['confidence']}%)")
                    break
        
        # Detect frameworks
        for framework, info in self.framework_signatures.items():
            for pattern in info["patterns"]:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    if framework not in self.results["frameworks"]:
                        self.results["frameworks"].append(framework)
                        logger.debug(f"Detected {framework} (confidence: {info['confidence']}%)")
                    break
        
        # Detect endpoints
        endpoint_patterns = [
            (r'["\'](/api/[^"\']+)["\']', "api"),
            (r'["\'](/v\d+/[^"\']+)["\']', "api"),
            (r'["\'](/graphql[^"\']*)["\']', "graphql"),
            (r'["\'](/rest/[^"\']+)["\']', "api"),
            (r'["\'](/[^"\']+\.json)["\']', "json"),
            (r'fetch\(["\']([^"\']+)["\']', "fetch"),
            (r'url:\s*["\']([^"\']+)["\']', "url"),
            (r'endpoint:\s*["\']([^"\']+)["\']', "endpoint"),
        ]
        
        endpoints = set()
        for pattern, etype in endpoint_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                if match not in endpoints:
                    endpoints.add(match)
                    self.results["endpoints"].append(match)
                    if etype == "graphql":
                        self.results["graphql_endpoints"].append(match)
                    elif etype == "api":
                        self.results["api_endpoints"].append(match)
        
        # Detect forms
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
        
        for match in re.finditer(form_pattern, body, re.IGNORECASE | re.DOTALL):
            action = match.group(1)
            form_html = match.group(2)
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
            
            self.results["forms"].append({
                "action": action,
                "inputs": inputs,
                "has_csrf": any('csrf' in inp.lower() or 'token' in inp.lower() for inp in inputs),
                "has_password": any('password' in inp.lower() or 'pass' in inp.lower() for inp in inputs),
                "has_email": any('email' in inp.lower() for inp in inputs)
            })
            
            if any('password' in inp.lower() for inp in inputs):
                self.results["has_login_form"] = True
            
            if any('search' in inp.lower() or 'q' in inp.lower() for inp in inputs):
                self.results["has_search_form"] = True
    
    async def probe_endpoints(self):
        """Probe discovered endpoints to check if they exist"""
        async with HTTPClient(self.target, timeout=3) as client:
            for endpoint in list(self.results["endpoints"][:20]):  # Limit to 20
                response = await client.get(endpoint)
                if response and response.status == 200:
                    logger.success(f"Confirmed endpoint: {endpoint}")
                elif response and response.status == 404:
                    self.results["endpoints"].remove(endpoint)
    
    async def suggest_modules(self):
        """Suggest appropriate modules based on detected technologies"""
        tech_str = ' '.join(self.results["technologies"]).lower()
        tech_list = [t.lower() for t in self.results["technologies"]]
        
        # GraphQL detection
        if 'graphql' in tech_str or self.results["graphql_endpoints"]:
            self.results["suggested_modules"].append("graphql")
        
        # JWT detection
        if 'jwt' in tech_str or 'bearer' in tech_str:
            self.results["suggested_modules"].append("jwt")
        
        # API detection
        if self.results["api_endpoints"] or 'rest api' in tech_str:
            self.results["suggested_modules"].append("param_discovery")
        
        # Login form detection
        if self.results["has_login_form"]:
            self.results["suggested_modules"].extend(["sqli", "csrf"])
        
        # Search form detection
        if self.results["has_search_form"]:
            self.results["suggested_modules"].extend(["xss", "param_discovery"])
        
        # Always recommended modules (core security testing)
        core_modules = [
            "param_discovery", "race_condition", "open_redirect", 
            "cors", "csrf", "dir_traversal", "ssrf", "sqli", "xss", "lfi"
        ]
        
        for module in core_modules:
            if module not in self.results["suggested_modules"]:
                self.results["suggested_modules"].append(module)
        
        # Estimate risk level
        high_risk_modules = ["sqli", "xss", "lfi", "ssrf", "jwt", "graphql"]
        if any(module in high_risk_modules for module in self.results["suggested_modules"]):
            self.results["estimated_risk"] = "HIGH"
        elif len(self.results["suggested_modules"]) > 5:
            self.results["estimated_risk"] = "MEDIUM"
        else:
            self.results["estimated_risk"] = "LOW"
    
    async def scan(self) -> Dict:
        """Full target detection scan"""
        logger.info(f"🔍 DRYBT - Intelligent target detection on {self.target}")
        
        # Detect from headers
        await self.detect_headers()
        
        # Detect from HTML
        async with HTTPClient(self.target, timeout=5) as client:
            response = await client.get("/")
            if response and response.status == 200:
                body = await response.text()
                await self.detect_from_html(body)
        
        # Suggest modules based on findings
        await self.suggest_modules()
        
        # Remove duplicates
        self.results["technologies"] = list(set(self.results["technologies"]))
        self.results["frameworks"] = list(set(self.results["frameworks"]))
        self.results["servers"] = list(set(self.results["servers"]))
        self.results["endpoints"] = list(set(self.results["endpoints"]))[:20]
        self.results["suggested_modules"] = list(set(self.results["suggested_modules"]))
        
        # Print beautiful summary
        print(f"\n{'='*70}")
        print(f"📊 DRYBT by Dryex v.1 - TARGET DETECTION RESULTS")
        print(f"{'='*70}")
        print(f"🎯 Target: {self.target}")
        print(f"📈 Risk Assessment: {self.results['estimated_risk']}")
        
        if self.results["servers"]:
            print(f"\n🖥️  Web Server: {', '.join(self.results['servers'])}")
        
        if self.results["technologies"]:
            print(f"\n🔧 Technologies Detected:")
            for tech in self.results["technologies"]:
                print(f"   📌 {tech}")
        
        if self.results["frameworks"]:
            print(f"\n📚 Frontend Frameworks:")
            for framework in self.results["frameworks"]:
                print(f"   🎨 {framework}")
        
        if self.results["api_endpoints"]:
            print(f"\n🔌 API Endpoints Found: {len(self.results['api_endpoints'])}")
            for ep in self.results["api_endpoints"][:5]:
                print(f"   📍 {ep}")
        
        if self.results["graphql_endpoints"]:
            print(f"\n📡 GraphQL Endpoints Found: {len(self.results['graphql_endpoints'])}")
            for ep in self.results["graphql_endpoints"]:
                print(f"   🔮 {ep}")
        
        if self.results["has_login_form"]:
            print(f"\n🔐 Login Form Detected → Check SQLi, CSRF, Auth Bypass")
        
        if self.results["has_search_form"]:
            print(f"\n🔎 Search Form Detected → Check XSS, SQLi")
        
        print(f"\n💡 Recommended Modules to Run:")
        for i, module in enumerate(self.results["suggested_modules"][:10], 1):
            print(f"   {i}. {module}")
        
        if len(self.results["suggested_modules"]) > 10:
            print(f"   ... and {len(self.results['suggested_modules']) - 10} more")
        
        print(f"\n{'='*70}")
        print(f"💡 Quick Command:")
        print(f"   python main.py -t {self.target} -m all")
        print(f"{'='*70}\n")
        
        return self.results
    
    @staticmethod
    async def run(target: str) -> Dict:
        """Run target detection"""
        detector = TargetDetector(target)
        return await detector.scan()
