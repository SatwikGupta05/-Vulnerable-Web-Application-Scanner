"""
Open Port Scanner plugin.
Scans for open ports and identifies potentially vulnerable services.
OWASP A05:2021 - Security Misconfiguration
"""

import socket
from typing import List, Any, Dict, Tuple
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class PortScanner(BasePlugin):
    """
    Open Port Scanner.
    
    Scans common ports to identify exposed or potentially
    vulnerable services.
    """
    
    name = "Open Port Scanner"
    description = "Scans for open ports and exposed services"
    version = "1.0.0"
    owasp_category = OWASPCategory.A05_SECURITY_MISCONFIGURATION
    
    # Common ports to scan with service information
    COMMON_PORTS = {
        # Web
        80: ('HTTP', 'Web server', Severity.INFO),
        443: ('HTTPS', 'Secure web server', Severity.INFO),
        8080: ('HTTP-Proxy', 'Web proxy/alternate HTTP', Severity.LOW),
        8443: ('HTTPS-Alt', 'Alternate HTTPS', Severity.INFO),
        8000: ('HTTP-Alt', 'Development web server', Severity.LOW),
        
        # Remote Access - HIGH RISK
        22: ('SSH', 'Secure Shell', Severity.MEDIUM),
        23: ('Telnet', 'Unencrypted remote access (INSECURE)', Severity.HIGH),
        3389: ('RDP', 'Remote Desktop Protocol', Severity.HIGH),
        5900: ('VNC', 'Virtual Network Computing', Severity.HIGH),
        5901: ('VNC-1', 'VNC Display 1', Severity.HIGH),
        
        # Database - HIGH RISK
        3306: ('MySQL', 'MySQL Database', Severity.HIGH),
        5432: ('PostgreSQL', 'PostgreSQL Database', Severity.HIGH),
        1433: ('MSSQL', 'Microsoft SQL Server', Severity.HIGH),
        1521: ('Oracle', 'Oracle Database', Severity.HIGH),
        27017: ('MongoDB', 'MongoDB Database', Severity.HIGH),
        6379: ('Redis', 'Redis Cache/Database', Severity.HIGH),
        9200: ('Elasticsearch', 'Elasticsearch', Severity.HIGH),
        
        # File Transfer
        21: ('FTP', 'File Transfer Protocol', Severity.MEDIUM),
        20: ('FTP-Data', 'FTP Data', Severity.MEDIUM),
        69: ('TFTP', 'Trivial FTP (INSECURE)', Severity.HIGH),
        445: ('SMB', 'Windows File Sharing', Severity.HIGH),
        139: ('NetBIOS', 'NetBIOS Session', Severity.HIGH),
        
        # Email
        25: ('SMTP', 'Mail Transfer', Severity.MEDIUM),
        587: ('SMTP-TLS', 'Mail Submission', Severity.LOW),
        110: ('POP3', 'Post Office Protocol', Severity.MEDIUM),
        143: ('IMAP', 'Internet Message Access Protocol', Severity.MEDIUM),
        993: ('IMAPS', 'IMAP over SSL', Severity.INFO),
        995: ('POP3S', 'POP3 over SSL', Severity.INFO),
        
        # Other Services
        53: ('DNS', 'Domain Name System', Severity.MEDIUM),
        161: ('SNMP', 'Simple Network Management Protocol', Severity.HIGH),
        389: ('LDAP', 'Lightweight Directory Access Protocol', Severity.HIGH),
        636: ('LDAPS', 'LDAP over SSL', Severity.MEDIUM),
        
        # Message Queues
        5672: ('AMQP', 'RabbitMQ/AMQP', Severity.MEDIUM),
        9092: ('Kafka', 'Apache Kafka', Severity.MEDIUM),
        
        # Container/Orchestration
        2375: ('Docker', 'Docker API (INSECURE)', Severity.CRITICAL),
        2376: ('Docker-TLS', 'Docker API with TLS', Severity.HIGH),
        6443: ('Kubernetes', 'Kubernetes API', Severity.HIGH),
        10250: ('Kubelet', 'Kubernetes Kubelet', Severity.HIGH),
        
        # Development
        9000: ('PHP-FPM', 'PHP FastCGI', Severity.MEDIUM),
        4443: ('Dev-HTTPS', 'Development HTTPS', Severity.LOW),
        3000: ('Node-Dev', 'Node.js Development', Severity.LOW),
        5000: ('Dev-Server', 'Development Server', Severity.LOW),
        8888: ('Jupyter', 'Jupyter Notebook', Severity.HIGH),
    }
    
    # Ports that should NEVER be exposed to the internet
    DANGEROUS_PORTS = {
        23: 'Telnet is unencrypted and easily sniffed',
        2375: 'Docker API without TLS allows container escape',
        6379: 'Redis often has no authentication by default',
        27017: 'MongoDB often has no authentication by default',
        9200: 'Elasticsearch often exposes sensitive data',
        11211: 'Memcached can be abused for DDoS amplification',
    }
    
    def __init__(self, timeout: float = 2.0, max_threads: int = 20):
        super().__init__()
        self.socket_timeout = timeout
        self.max_threads = max_threads
    
    def _check_port(self, host: str, port: int) -> Tuple[int, bool, str]:
        """
        Check if a port is open.
        
        Returns:
            (port, is_open, banner)
        """
        banner = ""
        is_open = False
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.socket_timeout)
            
            result = sock.connect_ex((host, port))
            
            if result == 0:
                is_open = True
                
                # Try to grab banner
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')[:200]
                except:
                    pass
            
            sock.close()
        
        except socket.timeout:
            pass
        except Exception as e:
            pass
        
        return (port, is_open, banner)
    
    def _scan_ports(self, host: str, ports: List[int]) -> Dict[int, Tuple[bool, str]]:
        """Scan multiple ports concurrently"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._check_port, host, port): port 
                for port in ports
            }
            
            for future in as_completed(futures):
                port, is_open, banner = future.result()
                if is_open:
                    results[port] = (is_open, banner)
        
        return results
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run port scan on target"""
        self.findings = []
        
        # Parse target URL
        parsed = urlparse(target.base_url)
        host = parsed.netloc.split(':')[0]
        
        self.report_progress(f"Starting port scan on {host}", 0)
        
        # Get list of ports to scan
        ports_to_scan = list(self.COMMON_PORTS.keys())
        total_ports = len(ports_to_scan)
        
        self.report_progress(f"Scanning {total_ports} common ports", 10)
        
        # Scan ports
        open_ports = self._scan_ports(host, ports_to_scan)
        
        self.report_progress(f"Found {len(open_ports)} open ports", 80)
        
        # Generate findings
        for port, (is_open, banner) in open_ports.items():
            if self.is_cancelled:
                break
            
            service_name, description, severity = self.COMMON_PORTS.get(
                port, 
                ('Unknown', 'Unknown service', Severity.LOW)
            )
            
            # Check if it's a dangerous port
            is_dangerous = port in self.DANGEROUS_PORTS
            if is_dangerous:
                severity = Severity.CRITICAL
                danger_reason = self.DANGEROUS_PORTS[port]
            else:
                danger_reason = ""
            
            # Determine if the port exposure is a concern
            # Web ports (80, 443) on a web server are expected
            expected_ports = {80, 443, 8080, 8443}
            is_expected = port in expected_ports
            
            if is_expected:
                # Still log it but as informational
                finding = Finding(
                    title=f"Open Port: {port} ({service_name})",
                    description=(
                        f"Port {port} ({service_name}) is open. {description}. "
                        f"This is expected for a web server."
                    ),
                    severity=Severity.INFO,
                    owasp_category=self.owasp_category,
                    affected_url=f"{host}:{port}",
                    evidence=f"Banner: {banner[:100]}" if banner else "Port is open",
                    impact=1.0,
                    exploitability=1.0,
                    exposure=3.0,
                    confidence=1.0
                )
            elif is_dangerous:
                finding = Finding(
                    title=f"Dangerous Port Exposed: {port} ({service_name})",
                    description=(
                        f"CRITICAL: Port {port} ({service_name}) is exposed to the internet. "
                        f"{danger_reason}. "
                        f"This port should never be publicly accessible."
                    ),
                    severity=Severity.CRITICAL,
                    owasp_category=self.owasp_category,
                    affected_url=f"{host}:{port}",
                    evidence=f"Banner: {banner[:100]}" if banner else "Port is open",
                    impact=9.0,
                    exploitability=8.0,
                    exposure=10.0,
                    confidence=1.0,
                    references=[
                        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
                    ]
                )
            else:
                finding = Finding(
                    title=f"Open Port: {port} ({service_name})",
                    description=(
                        f"Port {port} ({service_name}) is open. {description}. "
                        f"Ensure this service is required and properly secured."
                    ),
                    severity=severity,
                    owasp_category=self.owasp_category,
                    affected_url=f"{host}:{port}",
                    evidence=f"Banner: {banner[:100]}" if banner else "Port is open",
                    impact=self.COMMON_PORTS.get(port, ('', '', Severity.LOW, 4.0))[2].value if port in self.COMMON_PORTS else 4.0,
                    exploitability=5.0,
                    exposure=7.0,
                    confidence=1.0
                )
            
            self.add_finding(finding)
        
        self.report_progress("Port scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        """Get remediation guidance for open ports"""
        port_match = None
        for port in self.DANGEROUS_PORTS.keys():
            if str(port) in finding.title:
                port_match = port
                break
        
        if port_match:
            return f"""
## Remediation for Exposed Port {port_match}

### Immediate Actions:

1. **Close the Port**
   - Block port {port_match} in your firewall
   - Remove or disable the service if not needed

   **Linux (UFW):**
   ```bash
   sudo ufw deny {port_match}
   ```
   
   **Linux (iptables):**
   ```bash
   sudo iptables -A INPUT -p tcp --dport {port_match} -j DROP
   ```
   
   **Windows Firewall:**
   ```powershell
   New-NetFirewallRule -DisplayName "Block Port {port_match}" -Direction Inbound -LocalPort {port_match} -Protocol TCP -Action Block
   ```

2. **If the Service is Required:**
   - Use a VPN for access
   - Implement IP allowlisting
   - Use SSH tunneling
   - Place behind a reverse proxy with authentication

3. **Cloud Firewall (AWS):**
   ```
   Modify Security Group to remove port {port_match} from inbound rules
   ```

### Why This is Critical:
{self.DANGEROUS_PORTS.get(port_match, 'This service may have security vulnerabilities')}
"""
        
        return """
## Remediation for Open Ports

### General Guidelines:

1. **Minimize Attack Surface**
   - Only expose ports that are absolutely necessary
   - Close all unused services and ports

2. **Use Firewalls**
   - Configure host-based firewall (UFW, iptables, Windows Firewall)
   - Use network/cloud firewalls (AWS Security Groups, Azure NSGs)

3. **Secure Required Services**
   - Enable authentication on all services
   - Use encryption (TLS/SSL) where possible
   - Keep services updated

4. **Network Segmentation**
   - Place sensitive services in private subnets
   - Use bastion hosts for administrative access
   - Implement VPN for remote access

5. **Regular Auditing**
   - Periodically scan for open ports
   - Review firewall rules
   - Monitor for unauthorized changes

### Reference:
https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
"""
