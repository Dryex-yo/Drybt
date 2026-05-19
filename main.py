#!/usr/bin/env python3
"""
DRYBT by Dryex v.1 - Ultimate Bug Bounty Tools
Beyond Industry Standard - Zero False Positive - Maximum Speed
13 Security Modules Integrated

Module 1: Parameter Discovery - 7 Layer detection
Module 2: Race Condition - 5 Layer detection
Module 3: JWT Attack - 7 Layer detection
Module 4: GraphQL Batching - 7 Layer detection
Module 5: LLM Injection - 8 Layer detection
Module 6: SSRF Scanner - 8 Layer detection (Internal IP, Cloud metadata, Port scanning, Protocol smuggling)
Module 7: SQL Injection - 9 Layer detection (Error, Boolean, Time, Union, Stacked, OOB, Fingerprinting)
Module 8: XSS Scanner - 9 Layer detection (Reflected, Stored, DOM, Mutated, Blind - Context aware)
Module 9: LFI/RFI Scanner - 9 Layer detection (LFI, RFI, Null byte, WAF bypass, Log poisoning)
Module 10: Open Redirect Scanner
Module 11: CORS Scanner
Module 12: CSRF Scanner
Module 13: Directory Traversal Scanner
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
╚════════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""

# Core imports
from core.logger import Logger
from core.output import ReportGenerator
from core.target_detector import TargetDetector

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
    
    # ================================================================
    # MODULE 1: Parameter Discovery
    # ================================================================
    async def run_param_discovery(self) -> dict:
        """Module 1: Parameter Discovery - 7 Layer detection"""
        logger.info("Running Module 1: Parameter Discovery")
        return await ParameterDiscovery.run(self.target, threads=50, use_ai=False)
    
    # ================================================================
    # MODULE 2: Race Condition
    # ================================================================
    async def run_race_condition(self) -> dict:
        """Module 2: Race Condition Tester - 5 Layer detection"""
        logger.info("Running Module 2: Race Condition Tester")
        return await RaceCondition.run(self.target, threads=50)
    
    # ================================================================
    # MODULE 3: JWT Attack
    # ================================================================
    async def run_jwt_attack(self) -> dict:
        """Module 3: JWT Attack Suite - 7 Layer detection"""
        logger.info("Running Module 3: JWT Attack Suite")
        if not self.jwt_token:
            logger.warning("No JWT token provided! Use --token parameter")
            return {"module": "jwt_attack", "status": "missing_token", "findings": []}
        return await JWTAttack.run(self.target, self.jwt_token)
    
    # ================================================================
    # MODULE 4: GraphQL Batching
    # ================================================================
    async def run_graphql_batch(self) -> dict:
        """Module 4: GraphQL Batching Attack - 7 Layer detection"""
        logger.info("Running Module 4: GraphQL Batching Attack")
        return await GraphQLBatch.run(self.target)
    
    # ================================================================
    # MODULE 5: LLM Injection
    # ================================================================
    async def run_llm_injection(self) -> dict:
        """Module 5: LLM Injection Scanner - 8 Layer detection"""
        logger.info("Running Module 5: LLM Injection Scanner")
        return await LLMInjection.run(self.target)
    
    # ================================================================
    # MODULE 6: SSRF Scanner (Internal IP, Cloud metadata, Port scanning)
    # ================================================================
    async def run_ssrf(self) -> dict:
        """Module 6: SSRF Scanner - 8 Layer detection"""
        logger.info("Running Module 6: SSRF Scanner")
        return await SSRFScanner.run(self.target)
    
    # ================================================================
    # MODULE 7: SQL Injection Scanner
    # ================================================================
    async def run_sqli(self) -> dict:
        """Module 7: SQL Injection Scanner - 9 Layer detection"""
        logger.info("Running Module 7: SQL Injection Scanner")
        return await SQLiScanner.run(self.target)
    
    # ================================================================
    # MODULE 8: XSS Scanner (Context-aware: HTML, Attribute, JS, CSS, URL)
    # ================================================================
    async def run_xss(self) -> dict:
        """Module 8: XSS Scanner - 9 Layer detection, Context-aware"""
        logger.info("Running Module 8: XSS Scanner")
        return await XSSScanner.run(self.target)
    
    # ================================================================
    # MODULE 9: LFI/RFI Scanner (Local/Remote File Inclusion)
    # ================================================================
    async def run_lfi_rfi(self) -> dict:
        """Module 9: LFI/RFI Scanner - 9 Layer detection"""
        logger.info("Running Module 9: LFI/RFI Scanner")
        return await LFI_RFI_Scanner.run(self.target)
    
    # ================================================================
    # MODULE 10: Open Redirect Scanner
    # ================================================================
    async def run_open_redirect(self) -> dict:
        """Module 10: Open Redirect Scanner"""
        logger.info("Running Module 10: Open Redirect Scanner")
        return await OpenRedirectScanner.run(self.target)
    
    # ================================================================
    # MODULE 11: CORS Scanner
    # ================================================================
    async def run_cors(self) -> dict:
        """Module 11: CORS Misconfiguration Scanner"""
        logger.info("Running Module 11: CORS Scanner")
        return await CORSScanner.run(self.target)
    
    # ================================================================
    # MODULE 12: CSRF Scanner
    # ================================================================
    async def run_csrf(self) -> dict:
        """Module 12: CSRF Scanner"""
        logger.info("Running Module 12: CSRF Scanner")
        return await CSRFScanner.run(self.target)
    
    # ================================================================
    # MODULE 13: Directory Traversal Scanner
    # ================================================================
    async def run_dir_traversal(self) -> dict:
        """Module 13: Directory Traversal Scanner"""
        logger.info("Running Module 13: Directory Traversal Scanner")
        return await DirTraversalScanner.run(self.target)
    
    # ================================================================
    # MODULE DISPATCHER
    # ================================================================
    async def run_module(self, module_name: str) -> dict:
        """Run a single module by name"""
        modules = {
            # Core modules (1-5)
            "param_discovery": self.run_param_discovery,
            "race_condition": self.run_race_condition,
            "jwt": self.run_jwt_attack,
            "graphql": self.run_graphql_batch,
            "llm": self.run_llm_injection,
            # Advanced modules (6-9)
            "ssrf": self.run_ssrf,
            "sqli": self.run_sqli,
            "xss": self.run_xss,
            "lfi": self.run_lfi_rfi,
            # Additional modules (10-13)
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
            # Core modules (1-5)
            ("param_discovery", self.run_param_discovery),
            ("race_condition", self.run_race_condition),
            ("jwt", self.run_jwt_attack),
            ("graphql", self.run_graphql_batch),
            ("llm", self.run_llm_injection),
            # Advanced modules (6-9)
            ("ssrf", self.run_ssrf),
            ("sqli", self.run_sqli),
            ("xss", self.run_xss),
            ("lfi", self.run_lfi_rfi),
            # Additional modules (10-13)
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
            await asyncio.sleep(1)  # Delay between modules
        
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
║    python main.py -t https://example.com --detect                              ║
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
    
    # Intelligent target detection
    if args.detect:
        detector = TargetDetector(args.target)
        detection_results = await detector.scan()
        
        if detection_results["suggested_modules"]:
            print(f"{Fore.CYAN}Suggested to run: {', '.join(detection_results['suggested_modules'])}{Style.RESET_ALL}\n")
            
            response = input("Run suggested modules? (y/N): ")
            if response.lower() == 'y':
                args.module = "all"
    
    print(f"{Fore.CYAN}[*] Target: {args.target}")
    print(f"[*] Module: {args.module}")
    print(f"[*] Output: {args.output}{Style.RESET_ALL}")
    if args.token:
        print(f"{Fore.CYAN}[*] JWT Token: {args.token[:50]}...{Style.RESET_ALL}")
    print()
    
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