"""
SSL/TLS Certificate Validation scanner plugin.
Validates HTTPS configuration, certificate expiry, and cipher suites.
OWASP A02:2021 - Cryptographic Failures
"""

import ssl
import socket
from datetime import datetime, timedelta
from typing import List, Any, Dict, Optional
from urllib.parse import urlparse

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class SSLTLSScanner(BasePlugin):
    """
    SSL/TLS Certificate Validation scanner.
    
    Checks for:
    - Valid HTTPS configuration
    - Certificate expiration
    - Weak cipher suites
    - Protocol vulnerabilities
    """
    
    name = "SSL/TLS Scanner"
    description = "Validates SSL/TLS certificates and configuration"
    version = "1.0.0"
    owasp_category = OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES
    
    # Weak cipher suites to check for
    WEAK_CIPHERS = [
        'NULL', 'EXPORT', 'DES', 'RC2', 'RC4', 'MD5',
        'ANON', 'ADH', 'AECDH', '3DES', 'IDEA'
    ]
    
    # Deprecated protocols
    DEPRECATED_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
    
    # Certificate warning thresholds (days)
    CERT_EXPIRY_CRITICAL = 7
    CERT_EXPIRY_WARNING = 30
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def _get_certificate_info(self, hostname: str, port: int = 443) -> Optional[Dict]:
        """Retrieve SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    
                    # Get cipher info
                    cipher = ssock.cipher()
                    
                    # Get protocol version
                    protocol = ssock.version()
                    
                    return {
                        'cert': cert,
                        'cipher': cipher,
                        'protocol': protocol,
                        'hostname': hostname,
                        'port': port
                    }
        except Exception as e:
            self.report_progress(f"Error getting certificate: {str(e)}")
            return None
    
    def _get_certificate_raw(self, hostname: str, port: int = 443) -> Optional[bytes]:
        """Get raw certificate for advanced analysis"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False  
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert(binary_form=True)
        except:
            return None
    
    def _check_certificate_validity(self, cert: Dict, hostname: str) -> List[Finding]:
        """Check certificate validity and expiration"""
        findings = []
        
        if not cert:
            return findings
        
        # Check expiration
        try:
            not_after = cert.get('notAfter', '')
            if not_after:
                # Parse the date
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry_date - datetime.now()).days
                
                if days_until_expiry < 0:
                    # Certificate expired
                    finding = Finding(
                        title="SSL Certificate Expired",
                        description=(
                            f"The SSL certificate has expired on {not_after}. "
                            "Expired certificates cause browser warnings and prevent secure connections."
                        ),
                        severity=Severity.CRITICAL,
                        owasp_category=self.owasp_category,
                        affected_url=f"https://{hostname}",
                        evidence=f"Certificate expired on {not_after}",
                        impact=8.0,
                        exploitability=5.0,
                        exposure=10.0,
                        confidence=1.0,
                        references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"]
                    )
                    findings.append(finding)
                    
                elif days_until_expiry <= self.CERT_EXPIRY_CRITICAL:
                    finding = Finding(
                        title="SSL Certificate Expiring Soon (Critical)",
                        description=(
                            f"The SSL certificate will expire in {days_until_expiry} days on {not_after}. "
                            "Immediate renewal is required."
                        ),
                        severity=Severity.HIGH,
                        owasp_category=self.owasp_category,
                        affected_url=f"https://{hostname}",
                        evidence=f"Expires in {days_until_expiry} days",
                        impact=7.0,
                        exploitability=3.0,
                        exposure=8.0,
                        confidence=1.0
                    )
                    findings.append(finding)
                    
                elif days_until_expiry <= self.CERT_EXPIRY_WARNING:
                    finding = Finding(
                        title="SSL Certificate Expiring Soon (Warning)",
                        description=(
                            f"The SSL certificate will expire in {days_until_expiry} days on {not_after}. "
                            "Plan for renewal."
                        ),
                        severity=Severity.MEDIUM,
                        owasp_category=self.owasp_category,
                        affected_url=f"https://{hostname}",
                        evidence=f"Expires in {days_until_expiry} days",
                        impact=5.0,
                        exploitability=2.0,
                        exposure=5.0,
                        confidence=1.0
                    )
                    findings.append(finding)
        
        except Exception as e:
            self.report_progress(f"Error parsing certificate date: {str(e)}")
        
        return findings
    
    def _check_protocol(self, protocol: str, hostname: str) -> List[Finding]:
        """Check for deprecated TLS/SSL protocols"""
        findings = []
        
        if not protocol:
            return findings
        
        # Check for deprecated protocols
        if any(deprecated in protocol for deprecated in self.DEPRECATED_PROTOCOLS):
            finding = Finding(
                title=f"Deprecated TLS Protocol: {protocol}",
                description=(
                    f"The server is using {protocol} which is deprecated and vulnerable. "
                    "Modern security standards require TLS 1.2 or higher."
                ),
                severity=Severity.HIGH,
                owasp_category=self.owasp_category,
                affected_url=f"https://{hostname}",
                evidence=f"Server protocol: {protocol}",
                impact=7.0,
                exploitability=6.0,
                exposure=8.0,
                confidence=1.0,
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
                ]
            )
            findings.append(finding)
        
        return findings
    
    def _check_cipher(self, cipher: tuple, hostname: str) -> List[Finding]:
        """Check for weak cipher suites"""
        findings = []
        
        if not cipher or len(cipher) < 1:
            return findings
        
        cipher_name = cipher[0]
        
        # Check for weak ciphers
        for weak in self.WEAK_CIPHERS:
            if weak in cipher_name.upper():
                finding = Finding(
                    title=f"Weak Cipher Suite: {cipher_name}",
                    description=(
                        f"The server is using the weak cipher suite '{cipher_name}'. "
                        "This cipher has known vulnerabilities and should be disabled."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_category=self.owasp_category,
                    affected_url=f"https://{hostname}",
                    evidence=f"Cipher in use: {cipher_name}",
                    impact=5.0,
                    exploitability=4.0,
                    exposure=6.0,
                    confidence=0.9
                )
                findings.append(finding)
                break
        
        return findings
    
    def _check_https_redirect(self, target: ScanTarget) -> List[Finding]:
        """Check if HTTP redirects to HTTPS"""
        findings = []
        
        try:
            import requests
            
            # Parse base URL
            parsed = urlparse(target.base_url)
            http_url = f"http://{parsed.netloc}{parsed.path or '/'}"
            
            response = requests.get(
                http_url,
                allow_redirects=False,
                timeout=10,
                verify=False
            )
            
            # Check if it redirects to HTTPS
            if response.status_code not in (301, 302, 307, 308):
                finding = Finding(
                    title="HTTP Not Redirecting to HTTPS",
                    description=(
                        "The HTTP version of the site does not redirect to HTTPS. "
                        "This allows users to access the site over an insecure connection."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_category=self.owasp_category,
                    affected_url=http_url,
                    evidence=f"HTTP response code: {response.status_code}",
                    impact=5.0,
                    exploitability=3.0,
                    exposure=7.0,
                    confidence=0.95
                )
                findings.append(finding)
            else:
                location = response.headers.get('Location', '')
                if not location.startswith('https://'):
                    finding = Finding(
                        title="HTTP Redirect Not to HTTPS",
                        description=(
                            f"HTTP redirects to {location} instead of HTTPS. "
                            "Ensure all traffic is redirected to the secure version."
                        ),
                        severity=Severity.MEDIUM,
                        owasp_category=self.owasp_category,
                        affected_url=http_url,
                        evidence=f"Redirects to: {location}",
                        impact=4.0,
                        exploitability=3.0,
                        exposure=6.0,
                        confidence=0.9
                    )
                    findings.append(finding)
        
        except Exception as e:
            self.report_progress(f"Error checking HTTPS redirect: {str(e)}")
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run SSL/TLS scan on target"""
        self.findings = []
        self.session = session
        
        self.report_progress("Starting SSL/TLS scan", 0)
        
        # Parse target URL
        parsed = urlparse(target.base_url)
        hostname = parsed.netloc.split(':')[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        # Check if HTTPS
        if parsed.scheme != 'https':
            # Check if HTTP redirects to HTTPS
            findings = self._check_https_redirect(target)
            for finding in findings:
                self.add_finding(finding)
            
            # Try HTTPS anyway
            port = 443
        
        self.report_progress(f"Checking SSL certificate for {hostname}", 20)
        
        # Get certificate info
        cert_info = self._get_certificate_info(hostname, port)
        
        if cert_info:
            # Check certificate validity
            self.report_progress("Checking certificate validity", 40)
            validity_findings = self._check_certificate_validity(
                cert_info.get('cert', {}),
                hostname
            )
            for finding in validity_findings:
                self.add_finding(finding)
            
            # Check protocol
            self.report_progress("Checking TLS protocol version", 60)
            protocol_findings = self._check_protocol(
                cert_info.get('protocol', ''),
                hostname
            )
            for finding in protocol_findings:
                self.add_finding(finding)
            
            # Check cipher suite
            self.report_progress("Checking cipher suite", 80)
            cipher_findings = self._check_cipher(
                cert_info.get('cipher'),
                hostname
            )
            for finding in cipher_findings:
                self.add_finding(finding)
        else:
            # Could not get certificate
            finding = Finding(
                title="Unable to Retrieve SSL Certificate",
                description=(
                    f"Could not retrieve SSL certificate from {hostname}:{port}. "
                    "The server may not support HTTPS or is unreachable."
                ),
                severity=Severity.HIGH,
                owasp_category=self.owasp_category,
                affected_url=target.base_url,
                evidence="SSL handshake failed",
                impact=6.0,
                exploitability=5.0,
                exposure=8.0,
                confidence=0.8
            )
            self.add_finding(finding)
        
        self.report_progress("SSL/TLS scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        """Get remediation guidance for SSL/TLS issues"""
        if "expired" in finding.title.lower() or "expiring" in finding.title.lower():
            return """
## Remediation for SSL Certificate Expiration

1. **Renew the Certificate**
   - Contact your Certificate Authority (CA)
   - Or use Let's Encrypt for free automated renewal

2. **Set Up Auto-Renewal**
   ```bash
   # Let's Encrypt with Certbot
   certbot renew --dry-run
   certbot renew
   
   # Add to cron for automation
   0 0 1 * * /usr/bin/certbot renew --quiet
   ```

3. **Monitor Certificate Expiration**
   - Use monitoring tools (Nagios, Zabbix, UptimeRobot)
   - Set alerts for 30, 14, and 7 days before expiry
"""
        
        elif "protocol" in finding.title.lower():
            return """
## Remediation for Deprecated TLS Protocols

### Disable Old Protocols:

**Nginx:**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
```

**Apache:**
```apache
SSLProtocol TLSv1.2 TLSv1.3
```

**IIS (PowerShell):**
```powershell
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
```

### Recommended Configuration:
- Minimum: TLS 1.2
- Preferred: TLS 1.3
"""
        
        elif "cipher" in finding.title.lower():
            return """
## Remediation for Weak Cipher Suites

### Update Cipher Configuration:

**Nginx:**
```nginx
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers on;
```

**Apache:**
```apache
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder on
```

### Use Mozilla SSL Configuration Generator:
https://ssl-config.mozilla.org/
"""
        
        return """
## Remediation for SSL/TLS Issues

1. **Enable HTTPS** with a valid certificate
2. **Use TLS 1.2 or 1.3** only
3. **Configure strong cipher suites**
4. **Set up HSTS** header
5. **Implement certificate monitoring**
6. **Use automated certificate renewal**

Reference: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
"""
