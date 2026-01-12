"""
Exceptional Conditions Handling scanner plugin.
OWASP A10:2025 - Mishandling of Exceptional Conditions

Detects improper error handling, fail-open scenarios, and logic flaws.
"""

import re
from typing import List, Any

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class ExceptionalConditionsScanner(BasePlugin):
    """
    Exceptional Conditions vulnerability scanner.
    
    Checks for:
    - Fail-open authentication scenarios
    - Improper error handling that exposes functionality
    - Logic flaws under stress conditions
    - Race condition indicators
    """
    
    name = "Exceptional Conditions Scanner"
    description = "Detects mishandling of exceptional conditions (OWASP 2025)"
    version = "1.0.0"
    owasp_category = OWASPCategory.A10_2025_EXCEPTIONAL_CONDITIONS
    
    # Patterns indicating poor exception handling
    ERROR_HANDLING_PATTERNS = [
        (r'catch\s*\(\s*\)\s*\{?\s*\}', 'Empty catch block', Severity.MEDIUM),
        (r'except:\s*pass', 'Python bare except with pass', Severity.MEDIUM),
        (r'on\s*error\s*resume\s*next', 'VB error suppression', Severity.HIGH),
        (r'rescue\s*=>\s*nil', 'Ruby silent rescue', Severity.MEDIUM),
    ]
    
    # Headers indicating poor error config
    DEBUG_HEADERS = [
        'X-Debug-Token', 'X-Debug-Token-Link', 'X-Debug',
        'X-Powered-By-Plesk', 'X-AspNetMvc-Version'
    ]
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def _test_fail_open(self, url: str) -> List[Finding]:
        """Test for fail-open scenarios in authentication."""
        findings = []
        
        # Test with malformed authentication headers
        test_cases = [
            ({'Authorization': ''}, 'Empty Authorization'),
            ({'Authorization': 'Bearer '}, 'Empty Bearer token'),
            ({'Authorization': 'Basic '}, 'Empty Basic auth'),
            ({'Cookie': ''}, 'Empty cookies'),
            ({'X-Forwarded-For': '127.0.0.1'}, 'Localhost spoofing'),
        ]
        
        try:
            # Get baseline
            baseline = self.session.get(url, timeout=self.timeout, verify=False)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
            
            for headers, desc in test_cases:
                response = self.session.get(url, headers=headers, 
                                            timeout=self.timeout, verify=False)
                
                # Check for unexpected access
                if response.status_code == 200 and baseline_status in (401, 403):
                    finding = Finding(
                        title=f"Potential Fail-Open: {desc}",
                        description=(
                            f"Sending {desc} bypassed expected authentication. "
                            "The application may fail-open under exceptional conditions."
                        ),
                        severity=Severity.HIGH,
                        owasp_category=self.owasp_category,
                        affected_url=url,
                        evidence=f"Got 200 with {desc}, expected {baseline_status}",
                        impact=8.0, exploitability=7.0, exposure=9.0, confidence=0.80,
                        references=["https://owasp.org/Top10/A10_2025-Exceptional_Conditions/"]
                    )
                    findings.append(finding)
        
        except Exception:
            pass
        
        return findings
    
    def _test_error_responses(self, target: ScanTarget) -> List[Finding]:
        """Test application error handling behavior."""
        findings = []
        
        error_triggers = [
            (target.base_url + '/' + 'a' * 5000, 'Long URL'),
            (target.base_url + '/%00', 'Null byte'),
            (target.base_url + '/.%00.', 'Null in path'),
            (target.base_url + '?=' + 'a' * 10000, 'Large parameter'),
        ]
        
        for test_url, desc in error_triggers:
            if self.is_cancelled:
                break
            
            try:
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                # Check for unhandled errors
                error_indicators = [
                    r'exception', r'error', r'stack\s*trace', r'traceback',
                    r'fatal', r'unhandled', r'null\s*reference'
                ]
                
                for indicator in error_indicators:
                    if re.search(indicator, response.text, re.IGNORECASE):
                        finding = Finding(
                            title=f"Poor Exception Handling: {desc}",
                            description=(
                                f"Application exposed error details when tested with {desc}. "
                                "Improper exception handling can lead to information disclosure."
                            ),
                            severity=Severity.MEDIUM,
                            owasp_category=self.owasp_category,
                            affected_url=test_url[:100],
                            evidence=f"Triggered with: {desc}",
                            impact=4.0, exploitability=3.0, exposure=6.0, confidence=0.75
                        )
                        findings.append(finding)
                        break
            
            except Exception:
                pass
        
        return findings
    
    def _check_debug_headers(self, url: str) -> List[Finding]:
        """Check for debug headers that indicate poor production config."""
        findings = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            for header in self.DEBUG_HEADERS:
                if header in response.headers:
                    finding = Finding(
                        title=f"Debug Header Exposed: {header}",
                        description=(
                            f"The response includes debug header '{header}'. "
                            "Debug features should be disabled in production."
                        ),
                        severity=Severity.LOW,
                        owasp_category=self.owasp_category,
                        affected_url=url,
                        evidence=f"{header}: {response.headers[header][:50]}",
                        impact=3.0, exploitability=2.0, exposure=5.0, confidence=0.95
                    )
                    findings.append(finding)
        
        except Exception:
            pass
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run exceptional conditions scan."""
        self.findings = []
        self.session = session or __import__('requests').Session()
        
        self.report_progress("Starting Exceptional Conditions scan", 0)
        
        # Test fail-open scenarios
        self.report_progress("Testing fail-open scenarios", 20)
        for f in self._test_fail_open(target.base_url):
            self.add_finding(f)
        
        # Test error handling
        self.report_progress("Testing error handling", 50)
        for f in self._test_error_responses(target):
            self.add_finding(f)
        
        # Check debug headers
        self.report_progress("Checking debug configuration", 80)
        for f in self._check_debug_headers(target.base_url):
            self.add_finding(f)
        
        self.report_progress("Exceptional Conditions scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        return """
## Remediation for Exceptional Conditions Handling

### Fail-Secure Design:
1. **Default to deny** - When errors occur, deny access by default
2. **Validate all paths** - Ensure authentication checks can't be bypassed

```python
def authenticate(request):
    try:
        token = request.headers.get('Authorization')
        if not token:
            raise AuthError("No token")
        return validate_token(token)
    except Exception:
        # FAIL-SECURE: Deny on any error
        raise AuthError("Authentication failed")
```

### Proper Error Handling:
1. **Catch specific exceptions** - Don't use bare except
2. **Log errors internally** - Don't expose to users
3. **Return generic messages** - Hide implementation details

### Production Configuration:
1. **Disable debug mode** - Set DEBUG=False
2. **Remove debug headers** - Configure web server properly
3. **Use structured logging** - Log errors for monitoring, not users

Reference: https://owasp.org/Top10/A10_2025-Exceptional_Conditions/
"""
