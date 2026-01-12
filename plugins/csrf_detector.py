"""
CSRF (Cross-Site Request Forgery) detection plugin.
OWASP A08:2021 - Software and Data Integrity Failures
"""

import re
from typing import List, Any

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class CSRFDetector(BasePlugin):
    """CSRF vulnerability detector."""
    
    name = "CSRF Detector"
    description = "Detects missing CSRF protection on forms"
    version = "1.0.0"
    owasp_category = OWASPCategory.A08_DATA_INTEGRITY_FAILURES
    
    # Common CSRF token field names
    CSRF_TOKEN_NAMES = [
        'csrf', 'csrf_token', 'csrftoken', '_csrf', 'token', 
        'authenticity_token', '_token', '__RequestVerificationToken',
        'xsrf', 'xsrf_token', '_xsrf', 'antiforgerytoken'
    ]
    
    def __init__(self):
        super().__init__()
    
    def _has_csrf_token(self, form) -> bool:
        """Check if form has a CSRF token field."""
        field_names = [f.name.lower() for f in form.fields if f.name]
        return any(token in field_names or any(token in fn for fn in field_names) 
                   for token in self.CSRF_TOKEN_NAMES)
    
    def _is_state_changing(self, form) -> bool:
        """Check if form performs state-changing actions."""
        # POST forms are typically state-changing
        if form.method.upper() == 'POST':
            return True
        # Check action URL for state-changing keywords
        state_patterns = ['delete', 'update', 'edit', 'create', 'add', 
                         'remove', 'submit', 'save', 'change', 'password']
        return any(p in form.action.lower() for p in state_patterns)
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run CSRF detection scan."""
        self.findings = []
        
        self.report_progress("Starting CSRF detection", 0)
        
        for i, form in enumerate(target.forms):
            if self.is_cancelled:
                break
            
            progress = ((i + 1) / max(len(target.forms), 1)) * 100
            self.report_progress(f"Checking form: {form.action}", progress)
            
            # Only check state-changing forms
            if not self._is_state_changing(form):
                continue
            
            # Check for CSRF token
            if not self._has_csrf_token(form):
                finding = Finding(
                    title=f"Missing CSRF Token on Form",
                    description=(
                        f"The form at {form.action} ({form.method}) does not appear to have "
                        f"CSRF protection. Attackers could trick users into performing "
                        f"unintended actions."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_category=self.owasp_category,
                    affected_url=form.action,
                    evidence=f"Form method: {form.method}, Fields: {form.get_field_names()[:5]}",
                    impact=6.0, exploitability=7.0, exposure=8.0, confidence=0.80,
                    references=["https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"]
                )
                self.add_finding(finding)
        
        self.report_progress("CSRF detection complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        return """
## Remediation for CSRF

1. **Implement CSRF tokens** - Include unique, unpredictable tokens in all state-changing forms
2. **Use SameSite cookies** - Set `SameSite=Strict` or `SameSite=Lax` on session cookies
3. **Verify Origin header** - Check Origin/Referer headers for same-origin requests

**Example (Django):**
```html
<form method="POST">
    {% csrf_token %}
    <!-- form fields -->
</form>
```

**Example (Express.js with csurf):**
```javascript
const csrf = require('csurf');
app.use(csrf({ cookie: true }));
```
"""
