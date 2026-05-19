#!/usr/bin/env python3
"""
HTTP Client Module - Professional Grade
Optimized: Concurrent, Rate Limiting, Retry Logic, Session Management
"""

import asyncio
import aiohttp
import random
import time
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urljoin

class HTTPClient:
    def __init__(self, base_url: str, timeout: int = 10, retries: int = 2,
                 rate_limit: float = 0.3, max_concurrent: int = 50):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.retries = retries
        self.rate_limit = rate_limit
        self.max_concurrent = max_concurrent
        self._request_times: List[float] = []
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.session = None
        self._closed = False
        
        # Professional user agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.0',
        ]
        
        # Default headers
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
        }
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=self.max_concurrent,
            ssl=False,
            ttl_dns_cache=300,
            force_close=True,
            enable_cleanup_closed=True
        )
        
        # Rotate User-Agent
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
            cookie_jar=aiohttp.DummyCookieJar()  # Disable cookies for speed
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
        
        # Dynamic rate limiting based on request frequency
        if len(self._request_times) > 30:  # More than 30 requests per second
            wait_time = 0.05
        elif len(self._request_times) > 50:
            wait_time = 0.1
        else:
            wait_time = 1.0 / (self.rate_limit * max(len(self._request_times), 1)) if self._request_times else 0
        
        if wait_time > 0:
            await asyncio.sleep(min(wait_time, 0.5))
        
        self._request_times.append(now)
    
    async def _request(self, method: str, path: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Professional request handler dengan retry dan exponential backoff"""
        url = urljoin(self.base_url, path)
        
        await self._rate_limit()
        
        async with self._semaphore:
            for attempt in range(self.retries + 1):
                try:
                    # Exponential backoff with jitter
                    if attempt > 0:
                        backoff = (2 ** attempt) + random.uniform(0, 1)
                        await asyncio.sleep(backoff)
                    
                    async with self.session.request(method, url, **kwargs) as response:
                        # Read response body to ensure it's fully received
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
        """HTTP GET request"""
        kwargs = {'params': params or {}}
        if headers:
            kwargs['headers'] = headers
        return await self._request('GET', path, **kwargs)
    
    async def post(self, path: str, data: Optional[Any] = None,
                   json: Optional[Dict] = None,
                   headers: Optional[Dict] = None) -> Optional[aiohttp.ClientResponse]:
        """HTTP POST request"""
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
        """HTTP PUT request"""
        kwargs = {}
        if json:
            kwargs['json'] = json
        if headers:
            kwargs['headers'] = headers
        return await self._request('PUT', path, **kwargs)
    
    async def delete(self, path: str, headers: Optional[Dict] = None) -> Optional[aiohttp.ClientResponse]:
        """HTTP DELETE request"""
        kwargs = {}
        if headers:
            kwargs['headers'] = headers
        return await self._request('DELETE', path, **kwargs)
    
    async def get_text(self, path: str, **kwargs) -> Optional[str]:
        """GET request dan return response text"""
        response = await self.get(path, **kwargs)
        if response and response.status == 200:
            try:
                return await response.text()
            except:
                return None
        return None
    
    async def get_json(self, path: str, **kwargs) -> Optional[Dict]:
        """GET request dan return JSON response"""
        response = await self.get(path, **kwargs)
        if response and response.status == 200:
            try:
                return await response.json()
            except:
                return None
        return None
    
    async def head(self, path: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """HTTP HEAD request"""
        return await self._request('HEAD', path, **kwargs)
    
    async def options(self, path: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """HTTP OPTIONS request"""
        return await self._request('OPTIONS', path, **kwargs)