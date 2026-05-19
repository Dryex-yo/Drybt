#!/usr/bin/env python3
"""
DRYBT Logger Module - Professional Logging System
"""

from colorama import Fore, Style, init
from datetime import datetime
import sys

init(autoreset=True)

class Logger:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.verbose = False
        self.log_file = None
        self.tool_name = "DRYBT by Dryex v.1"
    
    def set_verbose(self, verbose: bool):
        self.verbose = verbose
    
    def set_log_file(self, log_file: str):
        self.log_file = log_file
    
    def _write(self, message: str, color: str = Fore.WHITE):
        timestamp = datetime.now().strftime("%H:%M:%S")
        colored_msg = f"{color}[{timestamp}] {message}{Style.RESET_ALL}"
        print(colored_msg)
        
        if self.log_file:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {message}\n")
    
    def info(self, message: str):
        self._write(f"[*] {message}", Fore.CYAN)
    
    def success(self, message: str):
        self._write(f"[+] {message}", Fore.GREEN)
    
    def warning(self, message: str):
        self._write(f"[!] {message}", Fore.YELLOW)
    
    def error(self, message: str):
        self._write(f"[x] {message}", Fore.RED)
    
    def debug(self, message: str):
        if self.verbose:
            self._write(f"[D] {message}", Fore.MAGENTA)
    
    def finding(self, title: str, details: str = ""):
        self._write(f"\n[🔍] {title}", Fore.GREEN)
        if details:
            self._write(f"     {details}", Fore.WHITE)
    
    def banner(self):
        self._write(f"\n{'='*60}", Fore.CYAN)
        self._write(f"{self.tool_name}", Fore.CYAN)
        self._write(f"{'='*60}\n", Fore.CYAN)