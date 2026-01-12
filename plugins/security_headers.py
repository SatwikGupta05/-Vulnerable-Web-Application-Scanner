"""
Security Headers analysis scanner plugin.
Checks for the presence and configuration of security-related HTTP headers.
OWASP A05:2021 - Security Misconfiguration
"""

from typing import List, Any, Dict, Optional
from urllib.parse import urlparse

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class SecurityHeadersScanner(BasePlugin):
    """
    Security Headers analysis scanner.
    
    Checks for the presence and correct configuration of:
    - Content-Security-Policy
    - X-Frame-Options
    - Strict-Transport-Security
    - X-Content-Type-Options
    - X-XSS-Protection
    - Referrer-Policy
    - Permissions-Policy
    """
    
    name = "Security Headers Scanner"
    description = "Analyzes HTTP security headers configuration"
    version = "1.0.0"
    owasp_category = OWASPCategory.A05_SECURITY_MISCONFIGURATION
    
    # Security headers to check
    SECURITY_HEADERS = {
        'Content-Security-Policy': {
            'severity': Severity.HIGH,
            'description': 'Content Security Policy helps prevent XSS and data injection attacks',
            'cwe': 'CWE-1021',
            'impact': 7.0,
        },
        'Strict-Transport-Security': {
            'severity': Severity.HIGH,
            'description': 'HTTP Strict Transport Security ensures HTTPS-only access',
            'cwe': 'CWE-319',
            'impact': 6.0,
        },
        'X-Frame-Options': {
            'severity': Severity.MEDIUM,
            'description': 'X-Frame-Options prevents clickjacking attacks',
            'cwe': 'CWE-1021',
            'impact': 5.0,
        },
        'X-Content-Type-Options': {
            'severity': Severity.MEDIUM,
            'description': 'X-Content-Type-Options prevents MIME type sniffing',
            'cwe': 'CWE-16',
            'impact': 4.0,
        },
        'X-XSS-Protection': {
            'severity': Severity.LOW,
            'description': 'X-XSS-Protection enables browser XSS filtering (deprecated but still useful for legacy browsers)',
            'cwe': 'CWE-79',
            'impact': 3.0,
        },
        'Referrer-Policy': {
            'severity': Severity.LOW,
            'description': 'Referrer-Policy controls how much referrer information is included with requests',
            'cwe': 'CWE-200',
            'impact': 3.0,
        },
        'Permissions-Policy': {
            'severity': Severity.LOW,
            'description': 'Permissions-Policy controls browser feature access (camera, mic, geolocation)',
            'cwe': 'CWE-16',
            'impact': 3.0,
        },
        'Cross-Origin-Opener-Policy': {
            'severity': Severity.LOW,
            'description': 'COOP prevents cross-origin attacks like Spectre',
            'cwe': 'CWE-346',
            'impact': 3.0,
        },
        'Cross-Origin-Resource-Policy': {
            'severity': Severity.LOW,
            'description': 'CORP prevents cross-origin resource loading',
            'cwe': 'CWE-346',
            'impact': 3.0,
        },
    }
    
    # CSP directive checks
    CSP_UNSAFE_PATTERNS = [
        ("'unsafe-inline'", "Allows inline scripts, bypassing CSP protection"),
        ("'unsafe-eval'", "Allows eval(), which is dangerous"),
        ("data:", "Allows data: URIs which can be used for XSS"),
        ("*", "Overly permissive wildcard source"),
    ]
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def _fetch_headers(self, url: str) -> Optional[Dict[str, str]]:
        """Fetch HTTP headers from URL"""
        try:
            import requests
            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
            return dict(response.headers)
        except Exception as e:
            self.report_progress(f"Error fetching headers: {str(e)}")
            return None
    
    def _check_missing_headers(self, headers: Dict[str, str], url: str) -> List[Finding]:
        """Check for missing security headers"""
        findings = []
        
        # Normalize header names (case-insensitive)
        header_names = {k.lower(): v for k, v in headers.items()}
        
        for header, config in self.SECURITY_HEADERS.items():
            header_lower = header.lower()
            
            if header_lower not in header_names:
                finding = Finding(
                    title=f"Missing Security Header: {header}",
                    description=(
                        f"The security header '{header}' is not present. "
                        f"{config['description']}."
                    ),
                    severity=config['severity'],
                    owasp_category=self.owasp_category,
                    affected_url=url,
                    evidence=f"Header '{header}' not found in response",
                    impact=config['impact'],
                    exploitability=5.0,
                    exposure=8.0,
                    confidence=1.0,
                    references=[
                        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
                    ]
                )
                findings.append(finding)
        
        return findings
    
    def _check_csp_configuration(self, csp_value: str, url: str) -> List[Finding]:
        """Check CSP for weak configurations"""
        findings = []
        
        if not csp_value:
            return findings
        
        for pattern, issue in self.CSP_UNSAFE_PATTERNS:
            if pattern in csp_value:
                finding = Finding(
                    title=f"Weak CSP Configuration: {pattern}",
                    description=(
                        f"The Content-Security-Policy contains '{pattern}'. {issue}. "
                        "This weakens the protection against XSS attacks."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_category=self.owasp_category,
                    affected_url=url,
                    evidence=f"CSP contains: {pattern}",
                    payload_used="",
                    impact=5.0,
                    exploitability=6.0,
                    exposure=7.0,
                    confidence=0.95,
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
                    ]
                )
                findings.append(finding)
        
        return findings
    
    def _check_hsts_configuration(self, hsts_value: str, url: str) -> List[Finding]:
        """Check HSTS for proper configuration"""
        findings = []
        
        if not hsts_value:
            return findings
        
        # Check max-age
        if 'max-age=' in hsts_value.lower():
            try:
                # Extract max-age value
                import re
                match = re.search(r'max-age=(\d+)', hsts_value.lower())
                if match:
                    max_age = int(match.group(1))
                    
                    # Recommended: at least 1 year (31536000 seconds)
                    if max_age < 31536000:
                        finding = Finding(
                            title="HSTS max-age Too Short",
                            description=(
                                f"HSTS max-age is {max_age} seconds ({max_age // 86400} days). "
                                "Recommended minimum is 1 year (31536000 seconds)."
                            ),
                            severity=Severity.LOW,
                            owasp_category=self.owasp_category,
                            affected_url=url,
                            evidence=f"max-age={max_age}",
                            impact=3.0,
                            exploitability=2.0,
                            exposure=5.0,
                            confidence=1.0
                        )
                        findings.append(finding)
            except:
                pass
        
        # Check for includeSubDomains
        if 'includesubdomains' not in hsts_value.lower():
            finding = Finding(
                title="HSTS Missing includeSubDomains",
                description=(
                    "HSTS header does not include 'includeSubDomains' directive. "
                    "Subdomains may be accessible over insecure HTTP."
                ),
                severity=Severity.LOW,
                owasp_category=self.owasp_category,
                affected_url=url,
                evidence=f"HSTS: {hsts_value}",
                impact=3.0,
                exploitability=3.0,
                exposure=5.0,
                confidence=1.0
            )
            findings.append(finding)
        
        return findings
    
    def _check_x_frame_options(self, xfo_value: str, url: str) -> List[Finding]:
        """Check X-Frame-Options configuration"""
        findings = []
        
        if not xfo_value:
            return findings
        
        # Check for ALLOWALL (insecure)
        xfo_upper = xfo_value.upper()
        
        if xfo_upper not in ('DENY', 'SAMEORIGIN') and 'ALLOW-FROM' not in xfo_upper:
            finding = Finding(
                title="Invalid X-Frame-Options Value",
                description=(
                    f"X-Frame-Options is set to '{xfo_value}' which is not a valid value. "
                    "Valid values are DENY, SAMEORIGIN, or ALLOW-FROM uri."
                ),
                severity=Severity.MEDIUM,
                owasp_category=self.owasp_category,
                affected_url=url,
                evidence=f"X-Frame-Options: {xfo_value}",
                impact=4.0,
                exploitability=4.0,
                exposure=6.0,
                confidence=0.9
            )
            findings.append(finding)
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run security headers scan on target"""
        self.findings = []
        self.session = session
        
        self.report_progress("Starting Security Headers scan", 0)
        
        # Fetch headers from target
        self.report_progress(f"Fetching headers from {target.base_url}", 20)
        headers = self._fetch_headers(target.base_url)
        
        if not headers:
            finding = Finding(
                title="Unable to Fetch HTTP Headers",
                description="Could not retrieve HTTP headers from the target.",
                severity=Severity.INFO,
                owasp_category=self.owasp_category,
                affected_url=target.base_url,
                evidence="HTTP request failed",
                impact=2.0,
                exploitability=1.0,
                exposure=4.0,
                confidence=1.0
            )
            self.add_finding(finding)
            return self.findings
        
        # Check for missing headers
        self.report_progress("Checking for missing security headers", 40)
        missing_findings = self._check_missing_headers(headers, target.base_url)
        for finding in missing_findings:
            self.add_finding(finding)
        
        # Normalize header names
        header_names = {k.lower(): v for k, v in headers.items()}
        
        # Check CSP configuration if present
        if 'content-security-policy' in header_names:
            self.report_progress("Analyzing Content-Security-Policy", 60)
            csp_findings = self._check_csp_configuration(
                header_names['content-security-policy'],
                target.base_url
            )
            for finding in csp_findings:
                self.add_finding(finding)
        
        # Check HSTS configuration if present
        if 'strict-transport-security' in header_names:
            self.report_progress("Analyzing Strict-Transport-Security", 70)
            hsts_findings = self._check_hsts_configuration(
                header_names['strict-transport-security'],
                target.base_url
            )
            for finding in hsts_findings:
                self.add_finding(finding)
        
        # Check X-Frame-Options if present
        if 'x-frame-options' in header_names:
            self.report_progress("Analyzing X-Frame-Options", 80)
            xfo_findings = self._check_x_frame_options(
                header_names['x-frame-options'],
                target.base_url
            )
            for finding in xfo_findings:
                self.add_finding(finding)
        
        # Also check discovered pages
        for url in target.discovered_urls[:5]:  # Check first 5 pages
            if url != target.base_url:
                self.report_progress(f"Checking headers on {url}", 90)
                page_headers = self._fetch_headers(url)
                if page_headers:
                    page_missing = self._check_missing_headers(page_headers, url)
                    # Only add if different from base findings (avoid duplicates)
                    for finding in page_missing:
                        if not any(f.affected_url == finding.affected_url and 
                                   f.title == finding.title for f in self.findings):
                            self.add_finding(finding)
        
        self.report_progress("Security Headers scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        """Get remediation guidance for security header issues"""
        header_remediation = {
            'Content-Security-Policy': """
## Remediation for Content-Security-Policy

Add a Content-Security-Policy header:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';
```

**Nginx:**
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;
```

**Apache:**
```apache
Header always set Content-Security-Policy "default-src 'self'"
```

Start restrictive and loosen as needed. Use CSP Evaluator: https://csp-evaluator.withgoogle.com/
""",
            'Strict-Transport-Security': """
## Remediation for Strict-Transport-Security

Add HSTS header with at least 1 year max-age:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Nginx:**
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

**Apache:**
```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```
""",
            'X-Frame-Options': """
## Remediation for X-Frame-Options

Add X-Frame-Options header:

```
X-Frame-Options: DENY
```
or
```
X-Frame-Options: SAMEORIGIN
```

**Nginx:**
```nginx
add_header X-Frame-Options "DENY" always;
```

**Apache:**
```apache
Header always set X-Frame-Options "DENY"
```

Note: For modern browsers, use CSP frame-ancestors instead.
""",
            'X-Content-Type-Options': """
## Remediation for X-Content-Type-Options

Add X-Content-Type-Options header:

```
X-Content-Type-Options: nosniff
```

**Nginx:**
```nginx
add_header X-Content-Type-Options "nosniff" always;
```

**Apache:**
```apache
Header always set X-Content-Type-Options "nosniff"
```
""",
        }
        
        # Find matching remediation
        for header, remediation in header_remediation.items():
            if header.lower() in finding.title.lower():
                return remediation
        
        return """
## General Security Headers Remediation

Add the following headers to your server configuration:

```
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

Reference: https://owasp.org/www-project-secure-headers/
"""
