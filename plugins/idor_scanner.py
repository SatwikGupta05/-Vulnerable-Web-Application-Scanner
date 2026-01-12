"""
IDOR (Insecure Direct Object Reference) scanner plugin.
OWASP A01:2021 - Broken Access Control
"""

import re
from typing import List, Any

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class IDORScanner(BasePlugin):
    """Insecure Direct Object Reference scanner."""
    
    name = "IDOR Scanner"
    description = "Detects Insecure Direct Object References"
    version = "1.0.0"
    owasp_category = OWASPCategory.A01_BROKEN_ACCESS_CONTROL
    
    # Patterns that suggest IDs in URLs/params
    ID_PATTERNS = [
        r'user[_-]?id', r'account[_-]?id', r'profile[_-]?id',
        r'order[_-]?id', r'invoice[_-]?id', r'document[_-]?id',
        r'file[_-]?id', r'record[_-]?id', r'^id$', r'uid'
    ]
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def _looks_like_id(self, param_name: str) -> bool:
        """Check if parameter name suggests an ID."""
        return any(re.search(p, param_name.lower()) for p in self.ID_PATTERNS)
    
    def _test_idor(self, url: str, param_name: str, original_value: str) -> List[Finding]:
        """Test for IDOR by manipulating ID values."""
        findings = []
        
        if not original_value or not original_value.isdigit():
            return findings
        
        try:
            # Get baseline response
            baseline = self.session.get(url, params={param_name: original_value}, 
                                         timeout=self.timeout, verify=False)
            baseline_len = len(baseline.text)
            
            # Test with modified IDs
            test_ids = [str(int(original_value) + 1), str(int(original_value) - 1), "1", "9999"]
            
            for test_id in test_ids:
                if self.is_cancelled:
                    break
                
                response = self.session.get(url, params={param_name: test_id}, 
                                            timeout=self.timeout, verify=False)
                
                # If similar content length and 200 status, potential IDOR
                if (response.status_code == 200 and 
                    abs(len(response.text) - baseline_len) < baseline_len * 0.2 and
                    len(response.text) > 500):  # Has substantial content
                    
                    finding = Finding(
                        title=f"Potential IDOR in '{param_name}'",
                        description=(
                            f"Changing '{param_name}' from {original_value} to {test_id} "
                            f"returns similar content. Verify authorization checks."
                        ),
                        severity=Severity.HIGH,
                        owasp_category=self.owasp_category,
                        affected_url=url,
                        evidence=f"ID {test_id} returned {len(response.text)} bytes (200 OK)",
                        payload_used=test_id,
                        impact=8.0, exploitability=9.0, exposure=9.0, confidence=0.75,
                        references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"]
                    )
                    findings.append(finding)
                    break
        except Exception:
            pass
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run IDOR scan."""
        self.findings = []
        self.session = session or __import__('requests').Session()
        
        self.report_progress("Starting IDOR scan", 0)
        
        # Find ID-like parameters
        id_params = [(p.url.split('?')[0], p.name, p.value) 
                     for p in target.url_parameters if self._looks_like_id(p.name)]
        
        for i, (url, name, value) in enumerate(id_params):
            if self.is_cancelled:
                break
            self.report_progress(f"Testing {name}", ((i+1)/max(len(id_params),1))*100)
            for f in self._test_idor(url, name, value):
                self.add_finding(f)
        
        self.report_progress("IDOR scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        return """
## Remediation for IDOR

1. **Implement proper authorization** - Always verify the user has permission to access the resource
2. **Use indirect references** - Map sequential IDs to random tokens/UUIDs
3. **Session-based access control** - Verify resource belongs to authenticated user

```python
def get_document(request, doc_id):
    doc = Document.objects.get(id=doc_id)
    if doc.owner != request.user:
        raise PermissionDenied()
    return doc
```
"""
