#!/usr/bin/env python3
"""
HTTP Client Module - Professional Grade
Optimized: Concurrent, Rate Limiting, Retry Logic, Session Management
MODIFIED: Mandatory X-Bug-Bounty header for CLEAR - Username: dryex
"""

import asyncio
import aiohttp
import random
import time
import os
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urljoin

class HTTPClient:
    def __init__(self, base_url: str, timeout: int = 10, retries: int = 2,
                 rate_limit: float = 0.3, max_concurrent: int = 50,
                 hackerone_username: str = None):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.retries = retries
        self.rate_limit = rate_limit
        self.max_concurrent = max_concurrent
        self._request_times: List[float] = []
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.session = None
        self._closed = False
        
        # CLEAR Bug Bounty header - Username: dryex
        self.hackerone_username = hackerone_username or os.environ.get('HACKERONE_USERNAME', 'dryex')
        self.bug_bounty_header = f"HackerOne-{self.hackerone_username}"
        
        # Professional user agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.0',
        ]
        
        # Default headers dengan X-Bug-Bounty untuk dryex
        self.default_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'X-Bug-Bounty': self.bug_bounty_header,  # MANDATORY: HackerOne-dryex
        }
        
        print(f"[✓] HTTPClient initialized with X-Bug-Bounty: {self.bug_bounty_header}")
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=self.max_concurrent,
            ssl=False,
            ttl_dns_cache=300,
            force_close=True,
            enable_cleanup_closed=True
        )
        
        # Rotate User-Agent tapi tetap pertahankan X-Bug-Bounty
        headers = self.default_headers.copy()
        headers['User-Agent'] = random.choice(self.user_agents)
        
        self.session = aiohttp.ClientSession(
            headers=headers,
            connector=connector,
            timeout=aiohttp.ClientTimeout(
                total=self.timeout,
                connect=5,
                sock_read=self.timeout,
                sock_connect=5
            ),
            cookie_jar=aiohttp.DummyCookieJar()
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session and not self._closed:
            await self.session.close()
            self._closed = True
    
    async def _rate_limit(self):
        """Adaptive rate limiting untuk menghindari block"""
        now = time.time()
        self._request_times = [t for t in self._request_times if now - t < 1]
        
        if len(self._request_times) > 30:
            wait_time = 0.05
        elif len(self._request_times) > 50:
            wait_time = 0.1
        else:
            wait_time = 1.0 / (self.rate_limit * max(len(self._request_times), 1)) if self._request_times else 0
        
        if wait_time > 0:
            await asyncio.sleep(min(wait_time, 0.5))
        
        self._request_times.append(now)
    
    def _merge_headers(self, custom_headers: Optional[Dict] = None) -> Dict:
        """Merge custom headers dengan default headers, pastikan X-Bug-Bounty tetap ada"""
        merged_headers = self.default_headers.copy()
        
        if custom_headers:
            merged_headers.update(custom_headers)
        
        # PASTIKAN X-Bug-Bounty selalu ada
        merged_headers['X-Bug-Bounty'] = self.bug_bounty_header
        
        return merged_headers
    
    async def _request(self, method: str, path: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Professional request handler dengan retry dan exponential backoff"""
        url = urljoin(self.base_url, path)
        
        # Pastikan headers selalu mengandung X-Bug-Bounty
        if 'headers' in kwargs:
            kwargs['headers'] = self._merge_headers(kwargs['headers'])
        else:
            kwargs['headers'] = self.default_headers.copy()
        
        await self._rate_limit()
        
        async with self._semaphore:
            for attempt in range(self.retries + 1):
                try:
                    if attempt > 0:
                        backoff = (2 ** attempt) + random.uniform(0, 1)
                        await asyncio.sleep(backoff)
                    
                    async with self.session.request(method, url, **kwargs) as response:
                        await response.read()
                        return response
                        
                except asyncio.TimeoutError:
                    if attempt == self.retries:
                        return None
                except aiohttp.ClientConnectionError:
                    if attempt == self.retries:
                        return None
                except aiohttp.ClientResponseError as e:
                    if e.status >= 500 and attempt < self.retries:
                        continue
                    return None
                except Exception:
                    if attempt == self.retries:
                        return None
            
            return None
    
    async def get(self, path: str, params: Optional[Dict] = None,
                  headers: Optional[Dict] = None) -> Optional[aiohttp.ClientResponse]:
        kwargs = {'params': params or {}}
        if headers:
            kwargs['headers'] = headers
        return await self._request('GET', path, **kwargs)
    
    async def post(self, path: str, data: Optional[Any] = None,
                   json: Optional[Dict] = None,
                   headers: Optional[Dict] = None) -> Optional[aiohttp.ClientResponse]:
        kwargs = {}
        if data:
            kwargs['data'] = data
        if json:
            kwargs['json'] = json
        if headers:
            kwargs['headers'] = headers
        return await self._request('POST', path, **kwargs)
    
    async def put(self, path: str, json: Optional[Dict] = None,
                  headers: Optional[Dict] = None) -> Optional[aiohttp.ClientResponse]:
        kwargs = {}
        if json:
            kwargs['json'] = json
        if headers:
            kwargs['headers'] = headers
        return await self._request('PUT', path, **kwargs)
    
    async def delete(self, path: str, headers: Optional[Dict] = None) -> Optional[aiohttp.ClientResponse]:
        kwargs = {}
        if headers:
            kwargs['headers'] = headers
        return await self._request('DELETE', path, **kwargs)
    
    async def get_text(self, path: str, **kwargs) -> Optional[str]:
        response = await self.get(path, **kwargs)
        if response and response.status == 200:
            try:
                return await response.text()
            except:
                return None
        return None
    
    async def get_json(self, path: str, **kwargs) -> Optional[Dict]:
        response = await self.get(path, **kwargs)
        if response and response.status == 200:
            try:
                return await response.json()
            except:
                return None
        return None
    
    async def head(self, path: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        return await self._request('HEAD', path, **kwargs)
    
    async def options(self, path: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        return await self._request('OPTIONS', path, **kwargs)