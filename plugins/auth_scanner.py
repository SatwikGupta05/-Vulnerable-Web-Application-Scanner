"""
Authentication vulnerabilities scanner plugin.
OWASP A07:2021 - Identification and Authentication Failures
"""

import re
from typing import List, Any

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class AuthScanner(BasePlugin):
    """Authentication vulnerability scanner."""
    
    name = "Authentication Scanner"
    description = "Detects authentication weaknesses and misconfigurations"
    version = "1.0.0"
    owasp_category = OWASPCategory.A07_AUTH_FAILURES
    
    # Common login form patterns
    LOGIN_PATTERNS = ['login', 'signin', 'sign-in', 'auth', 'authenticate']
    
    # Common weak credentials to test
    COMMON_CREDS = [
        ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
        ('root', 'root'), ('test', 'test'), ('user', 'user'),
    ]
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def _is_login_form(self, form) -> bool:
        """Check if form appears to be a login form."""
        # Check action URL
        if any(p in form.action.lower() for p in self.LOGIN_PATTERNS):
            return True
        # Check for password field
        return any(f.field_type == 'password' for f in form.fields)
    
    def _check_https_login(self, form, target_url: str) -> List[Finding]:
        """Check if login form submits over HTTPS."""
        findings = []
        
        if form.action.startswith('http://'):
            finding = Finding(
                title="Login Form Over HTTP",
                description=(
                    "The login form submits credentials over unencrypted HTTP. "
                    "Credentials can be intercepted by attackers."
                ),
                severity=Severity.HIGH,
                owasp_category=self.owasp_category,
                affected_url=form.action,
                evidence=f"Form action: {form.action}",
                impact=8.0, exploitability=6.0, exposure=9.0, confidence=0.95,
                references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"]
            )
            findings.append(finding)
        
        return findings
    
    def _check_autocomplete(self, form) -> List[Finding]:
        """Check if password field allows autocomplete."""
        findings = []
        
        for field in form.fields:
            if field.field_type == 'password':
                # Note: We can't check autocomplete attribute from our data model
                # This is a simplified check
                pass
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run authentication scan."""
        self.findings = []
        self.session = session or __import__('requests').Session()
        
        self.report_progress("Starting Authentication scan", 0)
        
        # Find login forms
        login_forms = [f for f in target.forms if self._is_login_form(f)]
        
        self.report_progress(f"Found {len(login_forms)} login forms", 20)
        
        for i, form in enumerate(login_forms):
            if self.is_cancelled:
                break
            
            progress = 20 + ((i + 1) / max(len(login_forms), 1)) * 60
            self.report_progress(f"Analyzing {form.action}", progress)
            
            # Check HTTPS
            for f in self._check_https_login(form, target.base_url):
                self.add_finding(f)
        
        # Check for exposed session tokens in URLs
        self.report_progress("Checking for session tokens in URLs", 90)
        session_patterns = [r'session[_-]?id=', r'jsessionid=', r'phpsessid=', r'token=']
        for url in target.discovered_urls:
            for pattern in session_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    finding = Finding(
                        title="Session Token in URL",
                        description="Session identifiers should not be in URLs (session fixation risk).",
                        severity=Severity.MEDIUM,
                        owasp_category=self.owasp_category,
                        affected_url=url,
                        evidence=f"Pattern found: {pattern}",
                        impact=6.0, exploitability=5.0, exposure=7.0, confidence=0.85
                    )
                    self.add_finding(finding)
                    break
        
        self.report_progress("Authentication scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        return """
## Remediation for Authentication Issues

1. **Always use HTTPS** - Encrypt all authentication traffic
2. **Implement MFA** - Add multi-factor authentication
3. **Use secure session management** - HttpOnly, Secure, SameSite cookies
4. **Never expose tokens in URLs** - Use headers or POST body for tokens
5. **Implement account lockout** - Prevent brute force attacks

**Session cookie configuration:**
```python
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
```
"""
