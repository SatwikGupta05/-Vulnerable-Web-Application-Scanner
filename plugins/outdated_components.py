"""
Outdated Components detection plugin.
OWASP A06:2021 - Vulnerable and Outdated Components
"""

import re
from typing import List, Any, Dict

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class OutdatedComponentsScanner(BasePlugin):
    """Outdated and vulnerable components scanner."""
    
    name = "Outdated Components Scanner"
    description = "Detects outdated software versions via fingerprinting"
    version = "1.0.0"
    owasp_category = OWASPCategory.A06_VULNERABLE_COMPONENTS
    
    # Server headers to check
    VERSION_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']
    
    # Known vulnerable version patterns (simplified - real scanner would use CVE database)
    VULNERABLE_PATTERNS = {
        r'Apache/2\.[0-3]\.': ('Apache', 'Outdated Apache 2.x', Severity.MEDIUM),
        r'nginx/1\.([0-9]|1[0-7])\.': ('nginx', 'Outdated nginx', Severity.MEDIUM),
        r'PHP/[5-6]\.': ('PHP', 'PHP 5.x/6.x is EOL', Severity.HIGH),
        r'PHP/7\.[0-3]\.': ('PHP', 'PHP 7.0-7.3 is EOL', Severity.MEDIUM),
        r'Microsoft-IIS/[5-7]\.': ('IIS', 'Outdated IIS version', Severity.MEDIUM),
        r'OpenSSL/1\.0\.': ('OpenSSL', 'OpenSSL 1.0.x has vulnerabilities', Severity.HIGH),
        r'jQuery/[12]\.': ('jQuery', 'jQuery 1.x/2.x may have XSS issues', Severity.LOW),
    }
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run outdated components scan."""
        self.findings = []
        self.session = session or __import__('requests').Session()
        
        self.report_progress("Starting Outdated Components scan", 0)
        
        try:
            response = self.session.get(target.base_url, timeout=self.timeout, verify=False)
            
            # Check headers
            self.report_progress("Analyzing response headers", 30)
            for header in self.VERSION_HEADERS:
                if header in response.headers:
                    value = response.headers[header]
                    
                    # Check against vulnerable patterns
                    for pattern, (component, desc, severity) in self.VULNERABLE_PATTERNS.items():
                        if re.search(pattern, value, re.IGNORECASE):
                            finding = Finding(
                                title=f"Outdated {component} Version",
                                description=f"{desc}. Detected: {value}",
                                severity=severity,
                                owasp_category=self.owasp_category,
                                affected_url=target.base_url,
                                evidence=f"{header}: {value}",
                                impact=5.0, exploitability=4.0, exposure=7.0, confidence=0.85,
                                references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"]
                            )
                            self.add_finding(finding)
                    
                    # Report version disclosure even if not vulnerable
                    if not any(header.lower() in f.evidence.lower() for f in self.findings):
                        finding = Finding(
                            title=f"Version Information Disclosure",
                            description=f"Server exposes version in {header} header: {value}",
                            severity=Severity.LOW,
                            owasp_category=self.owasp_category,
                            affected_url=target.base_url,
                            evidence=f"{header}: {value}",
                            impact=2.0, exploitability=1.0, exposure=5.0, confidence=1.0
                        )
                        self.add_finding(finding)
            
            # Check page content for library versions
            self.report_progress("Checking page content for libraries", 60)
            content = response.text
            
            # jQuery version check
            jquery_match = re.search(r'jquery[.-]?(\d+\.\d+\.\d+)', content, re.IGNORECASE)
            if jquery_match:
                version = jquery_match.group(1)
                major = int(version.split('.')[0])
                if major < 3:
                    finding = Finding(
                        title="Outdated jQuery Version",
                        description=f"jQuery {version} detected. jQuery < 3.x may have security issues.",
                        severity=Severity.LOW,
                        owasp_category=self.owasp_category,
                        affected_url=target.base_url,
                        evidence=f"jQuery version: {version}",
                        impact=3.0, exploitability=3.0, exposure=6.0, confidence=0.80
                    )
                    self.add_finding(finding)
        
        except Exception as e:
            self.report_progress(f"Error: {str(e)}", 100)
        
        self.report_progress("Outdated Components scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        return """
## Remediation for Outdated Components

1. **Keep software updated** - Regularly update all frameworks, libraries, and servers
2. **Remove version banners** - Configure servers to hide version information
3. **Use dependency scanning** - Integrate OWASP Dependency-Check or Snyk in CI/CD
4. **Monitor CVE databases** - Subscribe to security advisories for your stack

**Hide server version (Nginx):**
```nginx
server_tokens off;
```

**Hide server version (Apache):**
```apache
ServerTokens Prod
ServerSignature Off
```
"""
