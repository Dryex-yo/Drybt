#!/usr/bin/env python3
"""
DRYBT by Dryex v.1 - Ultimate Bug Bounty Tools
Beyond Industry Standard - Zero False Positive - Maximum Speed
13 Security Modules Integrated

MODIFIED: Added X-Bug-Bounty header support for CLEAR bug bounty program
Username: dryex
"""

import asyncio
import argparse
import sys
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
╔════════════════════════════════════════════════════════════════════════════════╗
║                                                                                ║
║     ██████╗ ██████╗ ██╗   ██╗██████╗ ████████╗    ██████╗ ██╗   ██╗            ║
║     ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝    ██╔══██╗╚██╗ ██╔╝            ║
║     ██║  ██║██████╔╝ ╚████╔╝ ██████╔╝   ██║       ██████╔╝ ╚████╔╝             ║
║     ██║  ██║██╔══██╗  ╚██╔╝  ██╔══██╗   ██║       ██╔══██╗  ╚██╔╝              ║
║     ██████╔╝██║  ██║   ██║   ██████╔╝   ██║       ██████╔╝   ██║               ║
║     ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═════╝    ╚═╝       ╚═════╝    ╚═╝               ║
║                                                                                ║
║     DRYBT by Dryex v.1                                                         ║
║     13 Security Modules | Zero False Positive | Maximum Speed                  ║
║     Beyond Industry Standard                                                   ║
║                                                                                ║
║     Modules:                                                                   ║
║     1. Parameter Discovery   8. XSS Scanner                                    ║
║     2. Race Condition        9. LFI/RFI Scanner                                ║
║     3. JWT Attack           10. Open Redirect                                  ║
║     4. GraphQL Batching     11. CORS Scanner                                   ║
║     5. LLM Injection        12. CSRF Scanner                                   ║
║     6. SSRF Scanner         13. Directory Traversal                            ║
║     7. SQL Injection                                                           ║
║                                                                                ║
║  [CLEAR Mode] X-Bug-Bounty: HackerOne-dryex                                    ║
║                                                                                ║
╚════════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""

# Core imports
from core.logger import Logger
from core.output import ReportGenerator
from core.target_detector import TargetDetector
from core.http_client import HTTPClient

# Module 1-5 imports
from modules.param_discovery import ParameterDiscovery
from modules.race_condition import RaceCondition
from modules.jwt_attack import JWTAttack
from modules.graphql_batch import GraphQLBatch
from modules.llm_injection import LLMInjection

# Module 6-9 imports (Advanced scanners)
from modules.ssrf_scanner import SSRFScanner
from modules.sqli_scanner import SQLiScanner
from modules.xss_scanner import XSSScanner
from modules.lfi_rfi_scanner import LFI_RFI_Scanner

# Module 10-13 imports (Additional scanners)
from modules.open_redirect import OpenRedirectScanner
from modules.cors_scanner import CORSScanner
from modules.csrf_scanner import CSRFScanner
from modules.dir_traversal import DirTraversalScanner

logger = Logger()

class DRYBT:
    def __init__(self, target: str, output: str = "reports/scan_report.json", jwt_token: str = None):
        self.target = target.rstrip('/')
        self.output = output
        self.jwt_token = jwt_token
        self.results = []
        self.report_gen = ReportGenerator(target)
    
    async def _get_client(self):
        """Get HTTP client with CLEAR headers"""
        return HTTPClient(self.target, hackerone_username="dryex")
    
    # ================================================================
    # MODULE 1: Parameter Discovery
    # ================================================================
    async def run_param_discovery(self) -> dict:
        """Module 1: Parameter Discovery - 7 Layer detection"""
        logger.info("Running Module 1: Parameter Discovery")
        async with await self._get_client() as client:
            return await ParameterDiscovery.run(self.target, client=client)
    
    # ================================================================
    # MODULE 2: Race Condition
    # ================================================================
    async def run_race_condition(self) -> dict:
        """Module 2: Race Condition Tester - 5 Layer detection"""
        logger.info("Running Module 2: Race Condition Tester")
        async with await self._get_client() as client:
            return await RaceCondition.run(self.target, client=client)
    
    # ================================================================
    # MODULE 3: JWT Attack
    # ================================================================
    async def run_jwt_attack(self) -> dict:
        """Module 3: JWT Attack Suite - 7 Layer detection"""
        logger.info("Running Module 3: JWT Attack Suite")
        if not self.jwt_token:
            logger.warning("No JWT token provided! Use --token parameter")
            return {"module": "jwt_attack", "status": "missing_token", "findings": []}
        async with await self._get_client() as client:
            return await JWTAttack.run(self.target, self.jwt_token, client=client)
    
    # ================================================================
    # MODULE 4: GraphQL Batching
    # ================================================================
    async def run_graphql_batch(self) -> dict:
        """Module 4: GraphQL Batching Attack - 7 Layer detection"""
        logger.info("Running Module 4: GraphQL Batching Attack")
        async with await self._get_client() as client:
            return await GraphQLBatch.run(self.target, client=client)
    
    # ================================================================
    # MODULE 5: LLM Injection
    # ================================================================
    async def run_llm_injection(self) -> dict:
        """Module 5: LLM Injection Scanner - 8 Layer detection"""
        logger.info("Running Module 5: LLM Injection Scanner")
        async with await self._get_client() as client:
            return await LLMInjection.run(self.target, client=client)
    
    # ================================================================
    # MODULE 6: SSRF Scanner
    # ================================================================
    async def run_ssrf(self) -> dict:
        """Module 6: SSRF Scanner - 8 Layer detection"""
        logger.info("Running Module 6: SSRF Scanner")
        async with await self._get_client() as client:
            return await SSRFScanner.run(self.target, client=client)
    
    # ================================================================
    # MODULE 7: SQL Injection Scanner
    # ================================================================
    async def run_sqli(self) -> dict:
        """Module 7: SQL Injection Scanner - 9 Layer detection"""
        logger.info("Running Module 7: SQL Injection Scanner")
        async with await self._get_client() as client:
            return await SQLiScanner.run(self.target, client=client)
    
    # ================================================================
    # MODULE 8: XSS Scanner
    # ================================================================
    async def run_xss(self) -> dict:
        """Module 8: XSS Scanner - 9 Layer detection, Context-aware"""
        logger.info("Running Module 8: XSS Scanner")
        async with await self._get_client() as client:
            return await XSSScanner.run(self.target, client=client)
    
    # ================================================================
    # MODULE 9: LFI/RFI Scanner
    # ================================================================
    async def run_lfi_rfi(self) -> dict:
        """Module 9: LFI/RFI Scanner - 9 Layer detection"""
        logger.info("Running Module 9: LFI/RFI Scanner")
        async with await self._get_client() as client:
            return await LFI_RFI_Scanner.run(self.target, client=client)
    
    # ================================================================
    # MODULE 10: Open Redirect Scanner
    # ================================================================
    async def run_open_redirect(self) -> dict:
        """Module 10: Open Redirect Scanner"""
        logger.info("Running Module 10: Open Redirect Scanner")
        async with await self._get_client() as client:
            return await OpenRedirectScanner.run(self.target, client=client)
    
    # ================================================================
    # MODULE 11: CORS Scanner
    # ================================================================
    async def run_cors(self) -> dict:
        """Module 11: CORS Misconfiguration Scanner"""
        logger.info("Running Module 11: CORS Scanner")
        async with await self._get_client() as client:
            return await CORSScanner.run(self.target, client=client)
    
    # ================================================================
    # MODULE 12: CSRF Scanner
    # ================================================================
    async def run_csrf(self) -> dict:
        """Module 12: CSRF Scanner"""
        logger.info("Running Module 12: CSRF Scanner")
        async with await self._get_client() as client:
            return await CSRFScanner.run(self.target, client=client)
    
    # ================================================================
    # MODULE 13: Directory Traversal Scanner
    # ================================================================
    async def run_dir_traversal(self) -> dict:
        """Module 13: Directory Traversal Scanner"""
        logger.info("Running Module 13: Directory Traversal Scanner")
        async with await self._get_client() as client:
            return await DirTraversalScanner.run(self.target, client=client)
    
    # ================================================================
    # MODULE DISPATCHER
    # ================================================================
    async def run_module(self, module_name: str) -> dict:
        """Run a single module by name"""
        modules = {
            "param_discovery": self.run_param_discovery,
            "race_condition": self.run_race_condition,
            "jwt": self.run_jwt_attack,
            "graphql": self.run_graphql_batch,
            "llm": self.run_llm_injection,
            "ssrf": self.run_ssrf,
            "sqli": self.run_sqli,
            "xss": self.run_xss,
            "lfi": self.run_lfi_rfi,
            "open_redirect": self.run_open_redirect,
            "cors": self.run_cors,
            "csrf": self.run_csrf,
            "dir_traversal": self.run_dir_traversal,
        }
        
        if module_name not in modules:
            logger.error(f"Unknown module: {module_name}")
            return None
        
        return await modules[module_name]()
    
    # ================================================================
    # RUN ALL MODULES
    # ================================================================
    async def run_all(self) -> list:
        """Run all 13 modules sequentially"""
        logger.info("Running ALL 13 modules...")
        modules = [
            ("param_discovery", self.run_param_discovery),
            ("race_condition", self.run_race_condition),
            ("jwt", self.run_jwt_attack),
            ("graphql", self.run_graphql_batch),
            ("llm", self.run_llm_injection),
            ("ssrf", self.run_ssrf),
            ("sqli", self.run_sqli),
            ("xss", self.run_xss),
            ("lfi", self.run_lfi_rfi),
            ("open_redirect", self.run_open_redirect),
            ("cors", self.run_cors),
            ("csrf", self.run_csrf),
            ("dir_traversal", self.run_dir_traversal),
        ]
        
        results = []
        for name, func in modules:
            logger.info(f"\n{'='*60}")
            logger.info(f"Starting module: {name}")
            logger.info(f"{'='*60}")
            result = await func()
            results.append(result)
            await asyncio.sleep(2)  # Delay between modules
        
        return results
    
    # ================================================================
    # SAVE RESULTS
    # ================================================================
    def save_results(self):
        """Save all findings to report"""
        for result in self.results:
            if result and 'findings' in result:
                for finding in result['findings']:
                    self.report_gen.add_finding(
                        module=result.get('module', 'unknown'),
                        title=finding.get('type', 'finding'),
                        severity=finding.get('severity', 'info'),
                        details=finding
                    )
        
        self.report_gen.to_json(self.output)
        logger.success(f"Report saved to {self.output}")

# ================================================================
# MAIN FUNCTION
# ================================================================
async def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="DRYBT by Dryex v.1 - Ultimate Bug Bounty Tools (13 Modules)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔════════════════════════════════════════════════════════════════════════════════╗
║ EXAMPLES                                                                       ║
╠════════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║  Basic Usage:                                                                  ║
║    python main.py -t https://example.com -m param_discovery                    ║
║    python main.py -t https://example.com -m all                                ║
║                                                                                ║
║  With JWT Token:                                                               ║
║    python main.py -t https://example.com -m jwt --token "your_jwt_token"       ║
║                                                                                ║
║  With Target Detection:                                                        ║
║    python main.py -t https://www.clearme.com --detect                          ║
║                                                                                ║
║  Available Modules:                                                            ║
║    param_discovery, race_condition, jwt, graphql, llm,                         ║
║    ssrf, sqli, xss, lfi, open_redirect, cors, csrf, dir_traversal, all         ║
║                                                                                ║
╚════════════════════════════════════════════════════════════════════════════════╝
        """
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-m", "--module", choices=[
        "param_discovery", "race_condition", "jwt", "graphql", "llm",
        "ssrf", "sqli", "xss", "lfi", "open_redirect", "cors", "csrf", "dir_traversal", "all"
    ], default="param_discovery", help="Module to run")
    parser.add_argument("--token", help="JWT token for JWT attack module")
    parser.add_argument("-o", "--output", default="reports/scan_report.json", help="Output file")
    parser.add_argument("--detect", action="store_true", help="Run intelligent target detection first")
    
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}[✓] CLEAR Mode Active: X-Bug-Bounty: HackerOne-dryex{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target: {args.target}")
    print(f"[*] Module: {args.module}")
    print(f"[*] Output: {args.output}{Style.RESET_ALL}")
    if args.token:
        print(f"{Fore.CYAN}[*] JWT Token: {args.token[:50]}...{Style.RESET_ALL}")
    print()
    
    # Intelligent target detection (FIXED)
    if args.detect:
        print(f"{Fore.YELLOW}[*] Running intelligent target detection...{Style.RESET_ALL}")
        try:
            async with HTTPClient(args.target, hackerone_username="dryex") as client:
                detector = TargetDetector(args.target, client)
                detection_results = await detector.detect_all()
                
                # Print summary
                print(detector.get_summary())
                
                # Show suggested modules based on detection
                suggested = []
                if detection_results.get('api_endpoints'):
                    suggested.append("param_discovery")
                    if any('/graphql' in str(e) for e in detection_results['api_endpoints']):
                        suggested.append("graphql")
                if detection_results.get('parameters'):
                    suggested.extend(["xss", "sqli", "lfi"])
                if detection_results.get('forms'):
                    suggested.append("csrf")
                
                suggested = list(set(suggested))[:5]
                
                if suggested:
                    print(f"\n{Fore.CYAN}Suggested modules: {', '.join(suggested)}{Style.RESET_ALL}")
                    response = input("Run suggested modules? (y/N): ")
                    if response.lower() == 'y':
                        args.module = "all"
        except Exception as e:
            print(f"{Fore.RED}[!] Detection failed: {e}{Style.RESET_ALL}")
    
    scanner = DRYBT(args.target, args.output, args.token)
    
    if args.module == "all":
        scanner.results = await scanner.run_all()
    else:
        result = await scanner.run_module(args.module)
        if result:
            scanner.results = [result]
    
    scanner.save_results()
    
    # Print summary
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"DRYBT by Dryex v.1 - SCAN COMPLETE")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    total_findings = 0
    for result in scanner.results:
        if result:
            module = result.get('module', 'unknown')
            status = result.get('status', 'completed')
            if status == 'missing_token':
                print(f"{Fore.YELLOW}[!] {module}: {result.get('message', 'Token required')}{Style.RESET_ALL}")
            else:
                findings_count = len(result.get('findings', []))
                total_findings += findings_count
                if findings_count > 0:
                    print(f"{Fore.RED}[+] {module}: {findings_count} findings{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] {module}: {findings_count} findings{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"Total findings: {total_findings}")
    print(f"Report saved to: {args.output}")
    print(f"{'='*60}{Style.RESET_ALL}")

if __name__ == "__main__":
    asyncio.run(main())