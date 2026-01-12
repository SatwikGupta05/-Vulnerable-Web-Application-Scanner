"""
Error Disclosure scanner plugin.
Detects exposed stack traces, debug info, and sensitive error messages.
OWASP A09:2021 - Security Logging and Monitoring Failures
"""

import re
from typing import List, Any

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class ErrorDisclosureScanner(BasePlugin):
    """Error and information disclosure scanner."""
    
    name = "Error Disclosure Scanner"
    description = "Detects exposed error messages and debug information"
    version = "1.0.0"
    owasp_category = OWASPCategory.A09_LOGGING_FAILURES
    
    # Patterns indicating error disclosure
    ERROR_PATTERNS = [
        (r'Traceback \(most recent call last\)', 'Python traceback', Severity.HIGH),
        (r'Exception in thread', 'Java exception', Severity.HIGH),
        (r'at [a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\([a-zA-Z0-9_]+\.java:\d+\)', 'Java stack trace', Severity.HIGH),
        (r'Fatal error:.*\.php on line \d+', 'PHP fatal error', Severity.HIGH),
        (r'Warning:.*\.php on line \d+', 'PHP warning', Severity.MEDIUM),
        (r'Stack trace:', 'Generic stack trace', Severity.HIGH),
        (r'System\.NullReferenceException', '.NET exception', Severity.HIGH),
        (r'Microsoft OLE DB Provider', 'Database connection error', Severity.HIGH),
        (r'SQLSTATE\[', 'SQL error state', Severity.HIGH),
        (r'DEBUG\s*=\s*True', 'Debug mode enabled', Severity.MEDIUM),
        (r'development mode', 'Development mode', Severity.MEDIUM),
        (r'(?:api[_-]?key|secret[_-]?key|password)\s*[:=]', 'Exposed credentials', Severity.CRITICAL),
        (r'/home/[a-zA-Z0-9_]+/', 'Server path disclosure', Severity.LOW),
        (r'C:\\\\[a-zA-Z0-9_\\\\]+', 'Windows path disclosure', Severity.LOW),
    ]
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def _check_response(self, url: str, response_text: str) -> List[Finding]:
        """Check response for error disclosure patterns."""
        findings = []
        
        for pattern, desc, severity in self.ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                match = re.search(pattern, response_text, re.IGNORECASE)
                evidence = match.group(0)[:100] if match else desc
                
                finding = Finding(
                    title=f"Information Disclosure: {desc}",
                    description=(
                        f"The application exposes sensitive error information: {desc}. "
                        f"This can help attackers understand the application structure."
                    ),
                    severity=severity,
                    owasp_category=self.owasp_category,
                    affected_url=url,
                    evidence=evidence,
                    impact=4.0 if severity == Severity.LOW else 6.0,
                    exploitability=2.0, exposure=7.0, confidence=0.90,
                    references=["https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"]
                )
                findings.append(finding)
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run error disclosure scan."""
        self.findings = []
        self.session = session or __import__('requests').Session()
        
        self.report_progress("Starting Error Disclosure scan", 0)
        
        # Check main pages
        urls_to_check = [target.base_url] + target.discovered_urls[:10]
        
        for i, url in enumerate(urls_to_check):
            if self.is_cancelled:
                break
            
            self.report_progress(f"Checking {url}", ((i+1)/len(urls_to_check))*100)
            
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                for f in self._check_response(url, response.text):
                    if not any(existing.title == f.title and existing.affected_url == f.affected_url 
                               for existing in self.findings):
                        self.add_finding(f)
                
                # Also trigger errors with bad input
                error_triggers = ['?id=\'', '?file=../../../', '?debug=true']
                for trigger in error_triggers:
                    try:
                        err_resp = self.session.get(url + trigger, timeout=self.timeout, verify=False)
                        for f in self._check_response(url + trigger, err_resp.text):
                            if not any(existing.title == f.title for existing in self.findings):
                                self.add_finding(f)
                    except:
                        pass
            except Exception:
                pass
        
        self.report_progress("Error Disclosure scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        return """
## Remediation for Error/Information Disclosure

1. **Disable debug mode in production** - Set DEBUG=False
2. **Use generic error pages** - Don't expose internal errors to users
3. **Log errors securely** - Log details server-side, show generic message to users
4. **Remove stack traces** - Configure frameworks to hide stack traces in production

**Example (Django):**
```python
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com']
```

**Example (Express.js):**
```javascript
app.use((err, req, res, next) => {
    console.error(err.stack);  // Log internally
    res.status(500).send('Something went wrong');  // Generic message
});
```
"""
