#!/usr/bin/env python3
"""
Target Detector Module - Intelligent Detection
Detects: Technology stack, frameworks, APIs, authentication methods
MODIFIED: Added X-Bug-Bounty header for CLEAR program
"""

import re
import json
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

class TargetDetector:
    def __init__(self, base_url: str, http_client):
        self.base_url = base_url.rstrip('/')
        self.client = http_client
        self.results = {
            'technologies': [],
            'forms': [],
            'api_endpoints': [],
            'headers': {},
            'auth_methods': [],
            'cookies': [],
            'parameters': []
        }
    
    async def detect_all(self) -> Dict:
        """Run all detection methods"""
        
        # Basic info detection
        await self._detect_headers()
        await self._detect_robots()
        await self._detect_sitemap()
        
        # Technology detection
        await self._detect_server()
        await self._detect_framework()
        await self._detect_js_libraries()
        
        # Endpoint discovery
        await self._find_forms()
        await self._find_api_endpoints()
        await self._find_common_paths()
        
        # Parameter discovery (light)
        await self._discover_parameters()
        
        return self.results
    
    async def _detect_headers(self):
        """Detect security and technology headers"""
        try:
            resp = await self.client.get("/")
            if resp and resp.headers:
                headers = dict(resp.headers)
                self.results['headers'] = headers
                
                # Detect security headers
                security_headers = ['X-Frame-Options', 'X-XSS-Protection', 
                                   'X-Content-Type-Options', 'Content-Security-Policy',
                                   'Strict-Transport-Security']
                for h in security_headers:
                    if h in headers:
                        self.results['technologies'].append(f'Security: {h}')
                
                # Detect server
                if 'Server' in headers:
                    self.results['technologies'].append(f'Server: {headers["Server"]}')
                
                # Detect framework
                if 'X-Powered-By' in headers:
                    self.results['technologies'].append(f'Framework: {headers["X-Powered-By"]}')
        except:
            pass
    
    async def _detect_server(self):
        """Detect web server type"""
        # Already captured in headers, but try additional methods
        common_paths = ['/server-status', '/server-info']
        for path in common_paths:
            try:
                resp = await self.client.get(path)
                if resp and resp.status == 200:
                    self.results['technologies'].append(f'Server info exposed: {path}')
            except:
                pass
    
    async def _detect_framework(self):
        """Detect JavaScript frameworks and CSS frameworks"""
        try:
            resp = await self.client.get("/")
            if resp:
                text = await resp.text()
                
                # JavaScript frameworks
                frameworks = {
                    'react': ['react', 'ReactDOM', 'react-', '__REACT_'],
                    'vue': ['vue', 'Vue.js', 'vue-', '__VUE_'],
                    'angular': ['angular', 'ng-', 'ngVersion', 'AngularJS'],
                    'jquery': ['jQuery', '$', 'jquery'],
                    'bootstrap': ['bootstrap', 'data-bs-', 'col-md-'],
                    'tailwind': ['tailwind', 'tw-', 'class="tw-'],
                }
                
                for framework, patterns in frameworks.items():
                    for pattern in patterns:
                        if pattern.lower() in text.lower():
                            self.results['technologies'].append(f'Frontend: {framework}')
                            break
        except:
            pass
    
    async def _detect_js_libraries(self):
        """Detect JavaScript libraries from script tags"""
        try:
            resp = await self.client.get("/")
            if resp:
                text = await resp.text()
                
                # Extract script src
                script_pattern = r'<script[^>]*src=["\']([^"\']+\.js)["\'][^>]*>'
                scripts = re.findall(script_pattern, text, re.IGNORECASE)
                
                for script in scripts[:20]:  # Limit to 20
                    if 'googleapis' in script:
                        self.results['technologies'].append('Google APIs')
                    elif 'cloudflare' in script:
                        self.results['technologies'].append('Cloudflare')
                    elif 'facebook' in script:
                        self.results['technologies'].append('Facebook SDK')
        except:
            pass
    
    async def _detect_robots(self):
        """Check robots.txt for disallowed paths"""
        try:
            resp = await self.client.get("/robots.txt")
            if resp and resp.status == 200:
                text = await resp.text()
                disallowed = re.findall(r'Disallow:\s*(.+)', text, re.IGNORECASE)
                if disallowed:
                    self.results['technologies'].append(f'Robots.txt: {len(disallowed)} disallowed paths')
        except:
            pass
    
    async def _detect_sitemap(self):
        """Check for sitemap.xml"""
        try:
            resp = await self.client.get("/sitemap.xml")
            if resp and resp.status == 200:
                self.results['technologies'].append('Sitemap.xml found')
        except:
            pass
    
    async def _find_forms(self):
        """Find HTML forms for CSRF/SSRF testing"""
        try:
            resp = await self.client.get("/")
            if resp:
                text = await resp.text()
                
                # Find all forms
                form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>'
                forms = re.findall(form_pattern, text, re.IGNORECASE)
                
                for form_action in forms:
                    self.results['forms'].append({
                        'action': form_action,
                        'url': urljoin(self.base_url, form_action)
                    })
                
                # Check for CSRF tokens
                csrf_patterns = ['csrf', 'CSRF', 'token', 'authenticity', '_token']
                for pattern in csrf_patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        self.results['technologies'].append(f'CSRF protection: {pattern}')
        except:
            pass
    
    async def _find_api_endpoints(self):
        """Discover API endpoints from HTML and common patterns"""
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](/graphql)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](/swagger[^"\']*)["\']',
            r'["\'](/openapi[^"\']*)["\']',
        ]
        
        try:
            resp = await self.client.get("/")
            if resp:
                text = await resp.text()
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    for match in matches:
                        if match not in self.results['api_endpoints']:
                            self.results['api_endpoints'].append(match)
        except:
            pass
        
        # Try common API paths
        common_apis = ['/api', '/api/v1', '/v1', '/graphql', '/rest', '/swagger']
        for api_path in common_apis:
            try:
                resp = await self.client.get(api_path)
                if resp and resp.status in [200, 401, 403]:
                    self.results['api_endpoints'].append(api_path)
            except:
                pass
    
    async def _find_common_paths(self):
        """Check common admin and sensitive paths"""
        common_paths = [
            '/admin', '/login', '/dashboard', '/user', '/profile',
            '/config', '/backup', '/.git', '/.env', '/wp-admin',
            '/phpmyadmin', '/cpanel', '/webmail', '/api/docs'
        ]
        
        for path in common_paths:
            try:
                resp = await self.client.get(path)
                if resp and resp.status in [200, 401, 403]:
                    self.results['technologies'].append(f'Exposed path: {path}')
            except:
                pass
    
    async def _discover_parameters(self):
        """Discover parameters from links and forms (light version)"""
        params = set()
        
        try:
            resp = await self.client.get("/")
            if resp:
                text = await resp.text()
                
                # Extract parameters from links
                param_pattern = r'\?([^"\'\s>]+)=[^"\'\s>&]+'
                matches = re.findall(param_pattern, text)
                for match in matches:
                    param_name = match.split('=')[0] if '=' in match else match
                    params.add(param_name)
                
                # Extract from form inputs
                input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
                inputs = re.findall(input_pattern, text, re.IGNORECASE)
                for inp in inputs:
                    params.add(inp)
        
        except:
            pass
        
        self.results['parameters'] = list(params)[:50]  # Limit to 50 parameters
    
    async def detect_auth(self) -> Dict:
        """Detect authentication methods"""
        auth_methods = []
        
        # Check for login page
        login_paths = ['/login', '/signin', '/auth', '/oauth', '/authorize']
        for path in login_paths:
            try:
                resp = await self.client.get(path)
                if resp and resp.status == 200:
                    auth_methods.append(f'Login page: {path}')
                    
                    # Check for OAuth
                    text = await resp.text()
                    if 'oauth' in text.lower():
                        auth_methods.append('OAuth detected')
                    if 'jwt' in text.lower() or 'bearer' in text.lower():
                        auth_methods.append('JWT/Bearer token detected')
            except:
                pass
        
        # Check authentication headers
        try:
            resp = await self.client.get("/")
            if resp:
                headers = resp.headers
                if 'WWW-Authenticate' in headers:
                    auth_methods.append(f'HTTP Auth: {headers["WWW-Authenticate"]}')
                if 'Authorization' in headers:
                    auth_methods.append('Authorization header required')
        except:
            pass
        
        self.results['auth_methods'] = auth_methods
        return self.results
    
    def get_summary(self) -> str:
        """Get human-readable summary"""
        summary = f"""
=== Target Detection Summary ===
Target: {self.base_url}

Technologies Found:
{chr(10).join(['  - ' + t for t in self.results['technologies'][:15]])}

API Endpoints:
{chr(10).join(['  - ' + e for e in self.results['api_endpoints'][:10]])}

Forms Found: {len(self.results['forms'])}
Parameters Found: {len(self.results['parameters'])}
Auth Methods: {len(self.results['auth_methods'])}

Security Headers:
{chr(10).join(['  - ' + k + ': ' + v[:50] for k, v in self.results['headers'].items() if k.startswith('X-') or k == 'Content-Security-Policy'][:10])}
"""
        return summary