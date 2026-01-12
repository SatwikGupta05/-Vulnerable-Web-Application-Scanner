"""
SSRF (Server-Side Request Forgery) scanner plugin.
OWASP A10:2021 - Server-Side Request Forgery
"""

from typing import List, Any
from urllib.parse import urlparse

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class SSRFScanner(BasePlugin):
    """SSRF vulnerability scanner."""
    
    name = "SSRF Scanner"
    description = "Detects Server-Side Request Forgery vulnerabilities"
    version = "1.0.0"
    owasp_category = OWASPCategory.A10_SSRF
    
    # SSRF test payloads targeting internal resources
    PAYLOADS = [
        ("http://localhost/", "localhost"),
        ("http://127.0.0.1/", "loopback"),
        ("http://[::1]/", "ipv6_loopback"),
        ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
        ("http://metadata.google.internal/", "gcp_metadata"),
        ("http://169.254.169.254/metadata/v1/", "digital_ocean"),
        ("http://192.168.1.1/", "internal_network"),
        ("http://10.0.0.1/", "internal_network_10"),
        ("file:///etc/passwd", "file_protocol"),
    ]
    
    # Parameter names that might accept URLs
    URL_PARAM_PATTERNS = ['url', 'uri', 'path', 'src', 'source', 'link', 
                          'redirect', 'next', 'file', 'load', 'fetch', 'page']
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def _looks_like_url_param(self, name: str) -> bool:
        """Check if parameter name suggests URL input."""
        return any(p in name.lower() for p in self.URL_PARAM_PATTERNS)
    
    def _test_ssrf(self, url: str, param_name: str, method: str = 'GET') -> List[Finding]:
        """Test for SSRF vulnerabilities."""
        findings = []
        
        for payload, payload_type in self.PAYLOADS:
            if self.is_cancelled:
                break
            
            try:
                if method.upper() == 'POST':
                    response = self.session.post(url, data={param_name: payload}, 
                                                  timeout=self.timeout, verify=False)
                else:
                    response = self.session.get(url, params={param_name: payload}, 
                                                 timeout=self.timeout, verify=False)
                
                # Check for signs of SSRF
                ssrf_indicators = [
                    'root:', '/bin/', 'localhost', 'ami-id', 'instance-id',
                    'meta-data', '169.254', 'internal', 'private'
                ]
                
                if any(ind in response.text.lower() for ind in ssrf_indicators):
                    severity = Severity.CRITICAL if 'metadata' in payload_type else Severity.HIGH
                    
                    finding = Finding(
                        title=f"SSRF in parameter '{param_name}'",
                        description=(
                            f"Server-Side Request Forgery detected. The server made a request "
                            f"to internal resource: {payload_type}. This could expose internal "
                            f"services, cloud metadata, or sensitive files."
                        ),
                        severity=severity,
                        owasp_category=self.owasp_category,
                        affected_url=url,
                        evidence=f"Internal resource accessed via {payload_type}",
                        payload_used=payload,
                        impact=9.0, exploitability=8.0, exposure=10.0, confidence=0.85,
                        references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery/"]
                    )
                    findings.append(finding)
                    break
            except Exception:
                pass
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run SSRF scan."""
        self.findings = []
        self.session = session or __import__('requests').Session()
        
        self.report_progress("Starting SSRF scan", 0)
        
        # Find URL-like parameters
        url_params = [p for p in target.url_parameters if self._looks_like_url_param(p.name)]
        total = len(url_params)
        
        for i, param in enumerate(url_params):
            if self.is_cancelled:
                break
            self.report_progress(f"Testing {param.name}", ((i+1)/max(total,1))*100)
            for f in self._test_ssrf(param.url.split('?')[0], param.name):
                self.add_finding(f)
        
        # Also check forms
        for form in target.forms:
            for field in form.fields:
                if self._looks_like_url_param(field.name):
                    for f in self._test_ssrf(form.action, field.name, form.method):
                        self.add_finding(f)
        
        self.report_progress("SSRF scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        return """
## Remediation for SSRF

1. **Validate and sanitize URLs** - Only allow expected protocols (http/https)
2. **Use allowlists** - Only permit requests to known-safe domains
3. **Block internal IPs** - Deny requests to localhost, 169.254.x.x, 10.x.x.x, 192.168.x.x, etc.
4. **Disable unnecessary protocols** - Block file://, gopher://, dict://, etc.
5. **Use cloud metadata protection** - Enable IMDSv2 on AWS, use metadata concealment on GCP

```python
from urllib.parse import urlparse
import ipaddress

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        return not ip.is_private and not ip.is_loopback
    except ValueError:
        # Domain name, check against allowlist
        return parsed.hostname in ALLOWED_DOMAINS
```
"""
