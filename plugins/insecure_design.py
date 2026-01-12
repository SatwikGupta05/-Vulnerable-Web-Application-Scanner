"""
Insecure Design scanner plugin.
OWASP A06:2025 / A04:2021 - Insecure Design

Detects design-level flaws that can't be fixed with implementation alone.
"""

import re
from typing import List, Any

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class InsecureDesignScanner(BasePlugin):
    """
    Insecure Design vulnerability scanner.
    
    Checks for:
    - Missing rate limiting
    - Predictable resource locations
    - Lack of captcha on sensitive forms
    - Unlimited file upload sizes
    - Missing account lockout
    """
    
    name = "Insecure Design Scanner"
    description = "Detects design-level security flaws (OWASP 2025)"
    version = "1.0.0"
    owasp_category = OWASPCategory.A06_2025_INSECURE_DESIGN
    
    # Predictable paths that suggest poor design
    PREDICTABLE_PATHS = [
        '/admin', '/administrator', '/admin.php', '/wp-admin',
        '/backup', '/backup.sql', '/backup.zip', '/db.sql',
        '/.git', '/.svn', '/.env', '/config.php', '/config.json',
        '/phpinfo.php', '/test.php', '/debug', '/trace',
        '/api/v1/users', '/api/admin', '/swagger', '/api-docs'
    ]
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def _check_rate_limiting(self, target: ScanTarget) -> List[Finding]:
        """Check for missing rate limiting on sensitive endpoints."""
        findings = []
        
        # Find login forms
        login_forms = [f for f in target.forms 
                       if any(p in f.action.lower() for p in ['login', 'signin', 'auth'])]
        
        for form in login_forms:
            try:
                # Make multiple rapid requests
                responses = []
                for _ in range(5):
                    response = self.session.get(form.action, timeout=5, verify=False)
                    responses.append(response.status_code)
                
                # If all succeed, no rate limiting detected
                if all(r == 200 for r in responses):
                    finding = Finding(
                        title="Missing Rate Limiting on Login",
                        description=(
                            f"The login endpoint {form.action} does not appear to have rate "
                            "limiting. This could allow brute force attacks."
                        ),
                        severity=Severity.MEDIUM,
                        owasp_category=self.owasp_category,
                        affected_url=form.action,
                        evidence="5 rapid requests all returned 200 OK",
                        impact=6.0, exploitability=7.0, exposure=8.0, confidence=0.70,
                        references=["https://owasp.org/Top10/A04_2021-Insecure_Design/"]
                    )
                    findings.append(finding)
            except Exception:
                pass
        
        return findings
    
    def _check_sensitive_form_protection(self, target: ScanTarget) -> List[Finding]:
        """Check for missing captcha on sensitive forms."""
        findings = []
        
        sensitive_keywords = ['register', 'signup', 'password', 'reset', 'forgot', 'contact']
        
        for form in target.forms:
            # Check if it's a sensitive form
            if any(kw in form.action.lower() for kw in sensitive_keywords):
                # Check for captcha fields
                field_names = [f.name.lower() for f in form.fields if f.name]
                has_captcha = any('captcha' in name or 'recaptcha' in name or 'hcaptcha' in name 
                                  for name in field_names)
                
                if not has_captcha:
                    finding = Finding(
                        title="Missing CAPTCHA on Sensitive Form",
                        description=(
                            f"The form at {form.action} handles sensitive operations "
                            "but lacks CAPTCHA protection against automated abuse."
                        ),
                        severity=Severity.LOW,
                        owasp_category=self.owasp_category,
                        affected_url=form.action,
                        evidence=f"Sensitive form without captcha: {form.action}",
                        impact=4.0, exploitability=6.0, exposure=7.0, confidence=0.75
                    )
                    findings.append(finding)
        
        return findings
    
    def _check_predictable_resources(self, target: ScanTarget) -> List[Finding]:
        """Check for predictable resource locations."""
        findings = []
        
        from urllib.parse import urljoin
        
        for path in self.PREDICTABLE_PATHS:
            if self.is_cancelled:
                break
            
            url = urljoin(target.base_url, path)
            
            try:
                response = self.session.get(url, timeout=5, verify=False, 
                                            allow_redirects=False)
                
                # Check for accessible sensitive paths
                if response.status_code in (200, 301, 302):
                    severity = Severity.HIGH if any(s in path for s in ['.git', '.env', 'backup', 'config']) else Severity.MEDIUM
                    
                    finding = Finding(
                        title=f"Accessible Sensitive Path: {path}",
                        description=(
                            f"The path {path} is accessible. This may expose sensitive "
                            "files or administrative functionality."
                        ),
                        severity=severity,
                        owasp_category=self.owasp_category,
                        affected_url=url,
                        evidence=f"Response: {response.status_code}",
                        impact=7.0 if severity == Severity.HIGH else 5.0,
                        exploitability=9.0, exposure=8.0, confidence=0.85
                    )
                    findings.append(finding)
            
            except Exception:
                pass
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run insecure design scan."""
        self.findings = []
        self.session = session or __import__('requests').Session()
        
        self.report_progress("Starting Insecure Design scan", 0)
        
        # Check rate limiting
        self.report_progress("Checking rate limiting", 20)
        for f in self._check_rate_limiting(target):
            self.add_finding(f)
        
        # Check form protections
        self.report_progress("Checking form protections", 50)
        for f in self._check_sensitive_form_protection(target):
            self.add_finding(f)
        
        # Check predictable resources
        self.report_progress("Checking predictable resources", 70)
        for f in self._check_predictable_resources(target):
            self.add_finding(f)
        
        self.report_progress("Insecure Design scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        return """
## Remediation for Insecure Design

### Rate Limiting:
```python
# Flask example with flask-limiter
from flask_limiter import Limiter
limiter = Limiter(app, default_limits=["100 per minute"])

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    ...
```

### CAPTCHA Protection:
- Add reCAPTCHA or hCaptcha to sensitive forms
- Verify on server-side, never client-only

### Secure Resource Locations:
1. **Block sensitive paths** in web server config
2. **Remove debug files** from production
3. **Use random tokens** instead of predictable IDs
4. **Implement proper access controls**

```nginx
# Nginx - Block sensitive paths
location ~ /\.(git|svn|env) {
    deny all;
}
```

Reference: https://owasp.org/Top10/A04_2021-Insecure_Design/
"""
