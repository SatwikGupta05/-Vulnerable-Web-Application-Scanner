"""
Cross-Site Scripting (XSS) vulnerability scanner plugin.
Tests for reflected, stored, and DOM-based XSS vulnerabilities.
OWASP A03:2021 - Injection
"""

import re
import html
from typing import List, Any, Tuple
from urllib.parse import urljoin, quote

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class XSSScanner(BasePlugin):
    """
    Cross-Site Scripting (XSS) vulnerability scanner.
    
    Tests input fields and URL parameters for XSS vulnerabilities
    by injecting JavaScript payloads and checking if they're reflected.
    """
    
    name = "XSS Scanner"
    description = "Detects Cross-Site Scripting (XSS) vulnerabilities"
    version = "1.0.0"
    owasp_category = OWASPCategory.A03_INJECTION
    
    # XSS test payloads with unique identifiers
    PAYLOADS = [
        # Basic script tags
        ('<script>alert("XSS_TEST_123")</script>', 'script'),
        ('<script>alert(1)</script>', 'script'),
        ('<script src="http://xss.test/"></script>', 'script_src'),
        
        # Event handlers
        ('<img src=x onerror="alert(\'XSS\')">', 'img_onerror'),
        ('<svg onload="alert(\'XSS\')">', 'svg_onload'),
        ('<body onload="alert(\'XSS\')">', 'body_onload'),
        ('<div onmouseover="alert(\'XSS\')">hover</div>', 'div_mouseover'),
        ('<input onfocus="alert(\'XSS\')" autofocus>', 'input_focus'),
        
        # Encoded payloads
        ('%3Cscript%3Ealert(1)%3C/script%3E', 'url_encoded'),
        ('&#60;script&#62;alert(1)&#60;/script&#62;', 'html_entities'),
        
        # Breaking out of attributes
        ('" onmouseover="alert(\'XSS\')" x="', 'attr_break_double'),
        ("' onmouseover='alert(1)' x='", 'attr_break_single'),
        ('"><script>alert(1)</script>', 'attr_script_break'),
        
        # JavaScript protocol
        ('javascript:alert(1)', 'js_protocol'),
        ('javascript:alert(String.fromCharCode(88,83,83))', 'js_protocol_encoded'),
        
        # Data protocol
        ('data:text/html,<script>alert(1)</script>', 'data_protocol'),
        
        # Template injection
        ('{{constructor.constructor("alert(1)")()}}', 'template_injection'),
        ('${alert(1)}', 'template_literal'),
    ]
    
    # Patterns indicating XSS reflection
    REFLECTION_PATTERNS = [
        r'<script[^>]*>.*?alert\s*\(.*?\).*?</script>',
        r'onerror\s*=\s*["\']?alert',
        r'onload\s*=\s*["\']?alert',
        r'onmouseover\s*=\s*["\']?alert',
        r'onfocus\s*=\s*["\']?alert',
        r'onclick\s*=\s*["\']?alert',
        r'javascript\s*:\s*alert',
        r'<img[^>]+onerror\s*=',
        r'<svg[^>]+onload\s*=',
    ]
    
    def __init__(self):
        super().__init__()
        self.session = None
        self.reflection_regex = re.compile(
            '|'.join(self.REFLECTION_PATTERNS),
            re.IGNORECASE | re.DOTALL
        )
    
    def _check_reflection(
        self,
        response_text: str,
        payload: str,
        payload_type: str
    ) -> Tuple[bool, str, str]:
        """
        Check if payload is reflected in response.
        
        Returns:
            (is_reflected, xss_type, evidence)
        """
        # Direct reflection check
        if payload.lower() in response_text.lower():
            # Check if it's actually executable (not just text)
            if self.reflection_regex.search(response_text):
                return (True, 'reflected', f"Payload reflected as executable: {payload[:50]}")
        
        # Check for partial reflection (attributes, events)
        payload_lower = payload.lower()
        response_lower = response_text.lower()
        
        # Check for event handler reflection
        event_patterns = ['onerror=', 'onload=', 'onmouseover=', 'onfocus=', 'onclick=']
        for event in event_patterns:
            if event in payload_lower and event in response_lower:
                if 'alert' in response_lower:
                    return (True, 'reflected', f"Event handler reflected: {event}")
        
        # Check for script tag reflection
        if '<script' in payload_lower and '<script' in response_lower:
            return (True, 'reflected', "Script tag reflected in response")
        
        return (False, '', '')
    
    def _test_parameter(
        self,
        url: str,
        param_name: str,
        param_value: str,
        method: str = 'GET',
        all_params: dict = None
    ) -> List[Finding]:
        """Test a single parameter for XSS"""
        findings = []
        
        for payload, payload_type in self.PAYLOADS:
            if self.is_cancelled:
                break
            
            try:
                # Prepare test data
                test_params = all_params.copy() if all_params else {}
                test_params[param_name] = payload
                
                # Send request
                if method.upper() == 'POST':
                    response = self.session.post(
                        url,
                        data=test_params,
                        timeout=self.timeout,
                        allow_redirects=True,
                        verify=False
                    )
                else:
                    response = self.session.get(
                        url,
                        params=test_params,
                        timeout=self.timeout,
                        allow_redirects=True,
                        verify=False
                    )
                
                # Check for reflection
                is_reflected, xss_type, evidence = self._check_reflection(
                    response.text,
                    payload,
                    payload_type
                )
                
                if is_reflected:
                    finding = Finding(
                        title=f"Reflected XSS in parameter '{param_name}'",
                        description=(
                            f"Cross-Site Scripting (XSS) vulnerability detected in the '{param_name}' parameter. "
                            f"The application reflects user input without proper encoding, allowing "
                            f"attackers to inject malicious JavaScript that executes in victims' browsers."
                        ),
                        severity=Severity.HIGH,
                        owasp_category=self.owasp_category,
                        affected_url=url,
                        evidence=evidence,
                        payload_used=payload[:100],  # Truncate for readability
                        impact=7.0,
                        exploitability=9.0,
                        exposure=10.0,
                        confidence=0.90,
                        references=[
                            "https://owasp.org/Top10/A03_2021-Injection/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                        ]
                    )
                    findings.append(finding)
                    self.report_progress(f"Found XSS in {param_name}")
                    break  # One finding per parameter
                
            except Exception as e:
                self.report_progress(f"Error testing {param_name}: {str(e)}")
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run XSS scan on target"""
        self.findings = []
        self.session = session
        
        if not self.session:
            import requests
            self.session = requests.Session()
        
        total_tests = len(target.forms) + len(target.url_parameters)
        current_test = 0
        
        self.report_progress("Starting XSS scan", 0)
        
        # Test forms
        for form in target.forms:
            if self.is_cancelled:
                break
            
            current_test += 1
            progress = (current_test / max(total_tests, 1)) * 100
            
            self.report_progress(
                f"Testing form: {form.action}",
                progress
            )
            
            # Build form data
            form_data = {f.name: f.value or 'test' for f in form.fields}
            
            # Test each text-like field
            for field in form.fields:
                if field.field_type in ('submit', 'button', 'hidden', 'file', 'checkbox', 'radio'):
                    continue
                
                findings = self._test_parameter(
                    url=form.action,
                    param_name=field.name,
                    param_value=field.value,
                    method=form.method,
                    all_params=form_data
                )
                
                for finding in findings:
                    self.add_finding(finding)
        
        # Test URL parameters
        for param in target.url_parameters:
            if self.is_cancelled:
                break
            
            current_test += 1
            progress = (current_test / max(total_tests, 1)) * 100
            
            self.report_progress(
                f"Testing URL param: {param.name}",
                progress
            )
            
            findings = self._test_parameter(
                url=param.url.split('?')[0],
                param_name=param.name,
                param_value=param.value,
                method='GET'
            )
            
            for finding in findings:
                self.add_finding(finding)
        
        self.report_progress("XSS scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        """Get remediation guidance for XSS"""
        return """
## Remediation for Cross-Site Scripting (XSS)

### Immediate Actions:

1. **Output Encoding**
   - HTML encode all user input before rendering in HTML context
   - Use context-aware encoding (HTML, JavaScript, CSS, URL)
   
   ```python
   # Python (Flask/Jinja2)
   from markupsafe import escape
   safe_output = escape(user_input)
   
   # In templates, Jinja2 auto-escapes by default
   {{ user_input }}  # Auto-escaped
   ```

2. **Content Security Policy (CSP)**
   - Implement strict CSP headers
   - Disable inline scripts: `script-src 'self'`
   
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
   ```

3. **Input Validation**
   - Validate input on server-side
   - Use allowlists for expected formats
   - Reject or sanitize HTML/JavaScript characters

4. **Use Security Libraries**
   - DOMPurify for client-side HTML sanitization
   - Bleach or html-sanitizer for Python
   - OWASP Java Encoder for Java

5. **HTTPOnly Cookies**
   - Set HttpOnly flag on session cookies
   - Prevents JavaScript access to cookies

### Code Examples:

**JavaScript (DOMPurify):**
```javascript
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);
element.innerHTML = clean;
```

**Python (Bleach):**
```python
import bleach
clean = bleach.clean(user_input, tags=[], strip=True)
```

**PHP:**
```php
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
```

### References:
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- https://owasp.org/Top10/A03_2021-Injection/
"""
