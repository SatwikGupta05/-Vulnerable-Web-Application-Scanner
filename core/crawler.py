"""
Website crawler for discovering attack surfaces.
Finds forms, input fields, URL parameters, and links.
"""

import re
from typing import List, Set, Optional, Callable
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import requests
from requests.exceptions import RequestException

from core.models import ScanTarget, Form, FormField, URLParameter


class WebCrawler:
    """
    Crawls target websites to discover attack surfaces.
    Finds forms, input fields, URL parameters, and links.
    """
    
    # Default headers to mimic a real browser
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    
    def __init__(
        self,
        max_depth: int = 2,
        max_pages: int = 50,
        timeout: int = 10,
        follow_redirects: bool = True,
        respect_robots: bool = True,
        callback: Optional[Callable] = None
    ):
        """
        Initialize the crawler.
        
        Args:
            max_depth: Maximum crawling depth
            max_pages: Maximum pages to crawl
            timeout: Request timeout in seconds
            follow_redirects: Follow HTTP redirects
            respect_robots: Respect robots.txt (not implemented yet)
            callback: Progress callback function
        """
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.respect_robots = respect_robots
        self.callback = callback
        
        self.session = requests.Session()
        self.session.headers.update(self.DEFAULT_HEADERS)
        
        self.visited_urls: Set[str] = set()
        self.discovered_forms: List[Form] = []
        self.discovered_params: List[URLParameter] = []
        self.discovered_urls: List[str] = []
        self.base_domain: str = ""
    
    def _log(self, message: str):
        """Log message via callback if available"""
        if self.callback:
            self.callback(message)
    
    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """Normalize and validate URL"""
        try:
            # Join with base URL if relative
            full_url = urljoin(base_url, url)
            parsed = urlparse(full_url)
            
            # Only allow http/https
            if parsed.scheme not in ('http', 'https'):
                return None
            
            # Stay within same domain
            if self.base_domain and parsed.netloc != self.base_domain:
                return None
            
            # Remove fragments
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            
            return normalized
        except Exception:
            return None
    
    def _extract_forms(self, html: str, page_url: str) -> List[Form]:
        """Extract forms from HTML content"""
        forms = []
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            for form_tag in soup.find_all('form'):
                action = form_tag.get('action', '')
                method = form_tag.get('method', 'GET').upper()
                
                # Normalize action URL
                if action:
                    action = urljoin(page_url, action)
                else:
                    action = page_url
                
                # Extract input fields
                fields = []
                
                # Input elements
                for input_tag in form_tag.find_all('input'):
                    name = input_tag.get('name', '')
                    if name:
                        fields.append(FormField(
                            name=name,
                            field_type=input_tag.get('type', 'text'),
                            value=input_tag.get('value', ''),
                            required=input_tag.has_attr('required')
                        ))
                
                # Textarea elements
                for textarea in form_tag.find_all('textarea'):
                    name = textarea.get('name', '')
                    if name:
                        fields.append(FormField(
                            name=name,
                            field_type='textarea',
                            value=textarea.string or '',
                            required=textarea.has_attr('required')
                        ))
                
                # Select elements
                for select in form_tag.find_all('select'):
                    name = select.get('name', '')
                    if name:
                        # Get first option value
                        first_option = select.find('option')
                        value = first_option.get('value', '') if first_option else ''
                        fields.append(FormField(
                            name=name,
                            field_type='select',
                            value=value,
                            required=select.has_attr('required')
                        ))
                
                if fields:  # Only add forms with fields
                    forms.append(Form(
                        action=action,
                        method=method,
                        fields=fields,
                        page_url=page_url
                    ))
        
        except Exception as e:
            self._log(f"Error extracting forms: {str(e)}")
        
        return forms
    
    def _extract_links(self, html: str, page_url: str) -> List[str]:
        """Extract links from HTML content"""
        links = []
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                normalized = self._normalize_url(href, page_url)
                if normalized and normalized not in self.visited_urls:
                    links.append(normalized)
        
        except Exception as e:
            self._log(f"Error extracting links: {str(e)}")
        
        return links
    
    def _extract_url_params(self, url: str) -> List[URLParameter]:
        """Extract URL parameters from a URL"""
        params = []
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            for name, values in query_params.items():
                for value in values:
                    params.append(URLParameter(
                        name=name,
                        value=value,
                        url=url
                    ))
        
        except Exception as e:
            self._log(f"Error extracting URL params: {str(e)}")
        
        return params
    
    def _fetch_page(self, url: str) -> Optional[str]:
        """Fetch page content"""
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=False  # Allow self-signed certs for testing
            )
            
            # Only process HTML content
            content_type = response.headers.get('content-type', '')
            if 'text/html' in content_type:
                return response.text
            
        except RequestException as e:
            self._log(f"Error fetching {url}: {str(e)}")
        
        return None
    
    def crawl(self, target_url: str) -> ScanTarget:
        """
        Crawl the target website and discover attack surfaces.
        
        Args:
            target_url: The starting URL to crawl
        
        Returns:
            ScanTarget with discovered forms, params, and URLs
        """
        self._log(f"Starting crawl of {target_url}")
        
        # Reset state
        self.visited_urls.clear()
        self.discovered_forms.clear()
        self.discovered_params.clear()
        self.discovered_urls.clear()
        
        # Set base domain
        parsed = urlparse(target_url)
        self.base_domain = parsed.netloc
        
        # Queue for BFS crawling
        queue = [(target_url, 0)]  # (url, depth)
        
        while queue and len(self.visited_urls) < self.max_pages:
            url, depth = queue.pop(0)
            
            if url in self.visited_urls:
                continue
            
            if depth > self.max_depth:
                continue
            
            self.visited_urls.add(url)
            self.discovered_urls.append(url)
            self._log(f"Crawling: {url} (depth {depth})")
            
            # Extract URL parameters
            url_params = self._extract_url_params(url)
            self.discovered_params.extend(url_params)
            
            # Fetch and parse page
            html = self._fetch_page(url)
            if not html:
                continue
            
            # Extract forms
            forms = self._extract_forms(html, url)
            self.discovered_forms.extend(forms)
            self._log(f"Found {len(forms)} forms on {url}")
            
            # Extract links for further crawling
            if depth < self.max_depth:
                links = self._extract_links(html, url)
                for link in links:
                    if link not in self.visited_urls:
                        queue.append((link, depth + 1))
        
        self._log(f"Crawl complete. Found {len(self.discovered_forms)} forms, "
                  f"{len(self.discovered_params)} URL params, "
                  f"{len(self.discovered_urls)} URLs")
        
        return ScanTarget(
            base_url=target_url,
            forms=self.discovered_forms,
            url_parameters=self.discovered_params,
            discovered_urls=self.discovered_urls,
            cookies=dict(self.session.cookies),
            headers=dict(self.session.headers)
        )
    
    def get_session(self) -> requests.Session:
        """Get the requests session (for reuse by scanners)"""
        return self.session
