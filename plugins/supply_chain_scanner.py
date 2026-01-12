"""
Software Supply Chain Failures scanner plugin.
OWASP A03:2025 - Software Supply Chain Failures

Detects vulnerabilities in dependencies, build systems, and distribution.
"""

import re
from typing import List, Any, Dict

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class SupplyChainScanner(BasePlugin):
    """
    Software Supply Chain vulnerability scanner.
    
    Checks for:
    - Known vulnerable JavaScript libraries (CDN)
    - Outdated dependencies exposed in page source
    - Subresource Integrity (SRI) missing on CDN scripts
    - Third-party script risks
    """
    
    name = "Supply Chain Scanner"
    description = "Detects software supply chain vulnerabilities (OWASP 2025)"
    version = "1.0.0"
    owasp_category = OWASPCategory.A03_2025_SUPPLY_CHAIN
    
    # Known vulnerable library patterns
    VULNERABLE_LIBS = {
        r'jquery[.-]1\.': ('jQuery 1.x', 'Multiple XSS vulnerabilities', Severity.MEDIUM),
        r'jquery[.-]2\.': ('jQuery 2.x', 'Known security issues', Severity.LOW),
        r'angular[.-]1\.[0-5]': ('AngularJS 1.0-1.5', 'Multiple security issues', Severity.MEDIUM),
        r'bootstrap[.-]3\.[0-2]': ('Bootstrap 3.0-3.2', 'XSS vulnerabilities', Severity.LOW),
        r'lodash[.-][0-3]\.': ('Lodash < 4.x', 'Prototype pollution', Severity.MEDIUM),
        r'moment[.-]2\.[0-9]\.': ('Moment.js < 2.10', 'ReDoS vulnerability', Severity.LOW),
        r'vue[.-]2\.[0-5]': ('Vue.js 2.0-2.5', 'Known security issues', Severity.LOW),
        r'react[.-]0\.': ('React 0.x', 'Outdated, security issues', Severity.MEDIUM),
        r'axios[.-]0\.[0-9]\.': ('Axios < 0.10', 'SSRF vulnerabilities', Severity.MEDIUM),
        r'underscore[.-]1\.[0-7]': ('Underscore < 1.8', 'Known issues', Severity.LOW),
    }
    
    # CDN domains to check for SRI
    CDN_DOMAINS = [
        'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com',
        'ajax.googleapis.com', 'code.jquery.com', 'stackpath.bootstrapcdn.com',
        'maxcdn.bootstrapcdn.com', 'cdn.bootcss.com'
    ]
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def _check_vulnerable_libs(self, html: str, url: str) -> List[Finding]:
        """Check for vulnerable JavaScript libraries."""
        findings = []
        
        for pattern, (lib_name, issue, severity) in self.VULNERABLE_LIBS.items():
            if re.search(pattern, html, re.IGNORECASE):
                finding = Finding(
                    title=f"Vulnerable Library: {lib_name}",
                    description=(
                        f"The page uses {lib_name} which has known vulnerabilities. "
                        f"{issue}. Update to the latest stable version."
                    ),
                    severity=severity,
                    owasp_category=self.owasp_category,
                    affected_url=url,
                    evidence=f"Detected: {lib_name}",
                    impact=5.0, exploitability=6.0, exposure=8.0, confidence=0.85,
                    references=["https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/"]
                )
                findings.append(finding)
        
        return findings
    
    def _check_missing_sri(self, html: str, url: str) -> List[Finding]:
        """Check for CDN scripts without Subresource Integrity."""
        findings = []
        
        # Find script tags
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>'
        scripts = re.findall(script_pattern, html, re.IGNORECASE)
        
        for script_src in scripts:
            # Check if it's from a CDN
            for cdn in self.CDN_DOMAINS:
                if cdn in script_src:
                    # Check if integrity attribute is present
                    integrity_check = re.search(
                        rf'<script[^>]+src=["\'][^"\']*{re.escape(cdn)}[^"\']*["\'][^>]*integrity=["\']',
                        html, re.IGNORECASE
                    )
                    
                    if not integrity_check:
                        finding = Finding(
                            title="Missing Subresource Integrity (SRI)",
                            description=(
                                f"External script from {cdn} is loaded without SRI hash. "
                                "If the CDN is compromised, malicious code could be injected."
                            ),
                            severity=Severity.MEDIUM,
                            owasp_category=self.owasp_category,
                            affected_url=url,
                            evidence=f"Script: {script_src[:80]}",
                            impact=6.0, exploitability=4.0, exposure=8.0, confidence=0.95,
                            references=["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"]
                        )
                        findings.append(finding)
                    break
        
        return findings
    
    def _check_third_party_scripts(self, html: str, url: str) -> List[Finding]:
        """Identify third-party scripts for awareness."""
        findings = []
        
        # Count external scripts
        script_pattern = r'<script[^>]+src=["\']https?://([^/"\'>]+)'
        external_domains = set(re.findall(script_pattern, html, re.IGNORECASE))
        
        # Filter out common safe CDNs
        safe_cdns = {'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'ajax.googleapis.com', 
                     'code.jquery.com', 'unpkg.com', 'fonts.googleapis.com'}
        third_party = external_domains - safe_cdns
        
        if len(third_party) > 5:
            finding = Finding(
                title="Excessive Third-Party Scripts",
                description=(
                    f"Page loads scripts from {len(third_party)} third-party domains. "
                    "Each external dependency is a potential supply chain risk."
                ),
                severity=Severity.LOW,
                owasp_category=self.owasp_category,
                affected_url=url,
                evidence=f"Domains: {', '.join(list(third_party)[:5])}...",
                impact=3.0, exploitability=2.0, exposure=6.0, confidence=0.90
            )
            findings.append(finding)
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run supply chain scan."""
        self.findings = []
        self.session = session or __import__('requests').Session()
        
        self.report_progress("Starting Supply Chain scan", 0)
        
        urls_to_check = [target.base_url] + target.discovered_urls[:10]
        
        for i, url in enumerate(urls_to_check):
            if self.is_cancelled:
                break
            
            self.report_progress(f"Checking {url}", ((i+1)/len(urls_to_check))*100)
            
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                html = response.text
                
                # Check for vulnerable libraries
                for f in self._check_vulnerable_libs(html, url):
                    if not any(ef.title == f.title for ef in self.findings):
                        self.add_finding(f)
                
                # Check for missing SRI
                for f in self._check_missing_sri(html, url):
                    if not any(ef.evidence == f.evidence for ef in self.findings):
                        self.add_finding(f)
                
                # Check third-party scripts (only on main page)
                if url == target.base_url:
                    for f in self._check_third_party_scripts(html, url):
                        self.add_finding(f)
            
            except Exception as e:
                self.report_progress(f"Error: {str(e)}", 0)
        
        self.report_progress("Supply Chain scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        return """
## Remediation for Supply Chain Vulnerabilities

### For Vulnerable Libraries:
1. **Update to latest versions** - Use npm/yarn update or CDN latest
2. **Use dependency scanning** - Integrate Snyk, Dependabot, or OWASP Dependency-Check
3. **Lock versions** - Use package-lock.json or yarn.lock

### For Missing SRI:
Add integrity attributes to external scripts:
```html
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-HASH_HERE"
        crossorigin="anonymous"></script>
```

Generate SRI hashes: https://www.srihash.org/

### For Third-Party Scripts:
1. **Audit all dependencies** - Review what each script does
2. **Self-host critical libraries** - Reduce external dependencies
3. **Use CSP** - Restrict which domains can serve scripts
4. **Monitor for compromises** - Subscribe to security advisories

Reference: https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/
"""
