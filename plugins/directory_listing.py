"""
Directory Listing detection plugin.
OWASP A05:2021 - Security Misconfiguration
"""

import re
from typing import List, Any

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class DirectoryListingScanner(BasePlugin):
    """Directory listing vulnerability scanner."""
    
    name = "Directory Listing Scanner"
    description = "Detects exposed directory listings"
    version = "1.0.0"
    owasp_category = OWASPCategory.A05_SECURITY_MISCONFIGURATION
    
    # Common directory paths to check
    COMMON_DIRS = [
        '/images/', '/img/', '/assets/', '/static/', '/uploads/',
        '/files/', '/backup/', '/admin/', '/config/', '/logs/',
        '/temp/', '/tmp/', '/data/', '/includes/', '/css/', '/js/',
    ]
    
    # Patterns indicating directory listing
    LISTING_PATTERNS = [
        r'Index of /', r'Directory Listing', r'Parent Directory',
        r'\[To Parent Directory\]', r'<title>Index of',
    ]
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def _check_directory(self, url: str) -> List[Finding]:
        """Check if directory listing is enabled."""
        findings = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                for pattern in self.LISTING_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        finding = Finding(
                            title=f"Directory Listing Enabled",
                            description=(
                                f"Directory listing is enabled at {url}. "
                                f"This exposes file structure and potentially sensitive files."
                            ),
                            severity=Severity.MEDIUM,
                            owasp_category=self.owasp_category,
                            affected_url=url,
                            evidence="Directory listing pattern detected",
                            impact=4.0, exploitability=5.0, exposure=7.0, confidence=0.95,
                            references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                        )
                        findings.append(finding)
                        break
        except Exception:
            pass
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run directory listing scan."""
        self.findings = []
        self.session = session or __import__('requests').Session()
        
        self.report_progress("Starting Directory Listing scan", 0)
        
        from urllib.parse import urljoin
        
        for i, dir_path in enumerate(self.COMMON_DIRS):
            if self.is_cancelled:
                break
            
            url = urljoin(target.base_url, dir_path)
            self.report_progress(f"Checking {dir_path}", ((i+1)/len(self.COMMON_DIRS))*100)
            
            for f in self._check_directory(url):
                self.add_finding(f)
        
        self.report_progress("Directory Listing scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        return """
## Remediation for Directory Listing

Disable directory listing in your web server:

**Nginx:**
```nginx
autoindex off;
```

**Apache (.htaccess):**
```apache
Options -Indexes
```

**IIS (web.config):**
```xml
<directoryBrowse enabled="false" />
```
"""
