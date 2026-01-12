"""
Utility HTTP client with safety features.
"""

import time
from typing import Dict, Optional, List
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class SafeHTTPClient:
    """
    HTTP client wrapper with rate limiting, retries, and safety features.
    """
    
    DEFAULT_HEADERS = {
        'User-Agent': 'SOC-Scanner/1.0 (Security Testing Tool)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }
    
    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 3,
        rate_limit: float = 0.5,  # seconds between requests
        verify_ssl: bool = False
    ):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.verify_ssl = verify_ssl
        self.last_request_time = 0
        
        # Create session with retry strategy
        self.session = requests.Session()
        self.session.headers.update(self.DEFAULT_HEADERS)
        
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
    
    def _rate_limit_wait(self):
        """Enforce rate limiting."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self.last_request_time = time.time()
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """Make GET request."""
        self._rate_limit_wait()
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', self.verify_ssl)
        return self.session.get(url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """Make POST request."""
        self._rate_limit_wait()
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', self.verify_ssl)
        return self.session.post(url, **kwargs)
    
    def set_cookies(self, cookies: Dict[str, str]):
        """Set session cookies."""
        self.session.cookies.update(cookies)
    
    def set_headers(self, headers: Dict[str, str]):
        """Set additional headers."""
        self.session.headers.update(headers)
