"""
Command Injection vulnerability scanner plugin.
Tests for OS command injection vulnerabilities.
OWASP A03:2021 - Injection
"""

import re
import time
from typing import List, Any, Tuple

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class CommandInjectionScanner(BasePlugin):
    """
    Command Injection vulnerability scanner.
    
    Tests input fields and URL parameters for command injection
    vulnerabilities using safe, non-destructive payloads.
    """
    
    name = "Command Injection Scanner"
    description = "Detects OS command injection vulnerabilities"
    version = "1.0.0"
    owasp_category = OWASPCategory.A03_INJECTION
    
    # Command injection payloads (safe, non-destructive)
    PAYLOADS = [
        # Basic command separators
        ('; echo CMDINJTEST123', 'CMDINJTEST123', 'semicolon'),
        ('| echo CMDINJTEST123', 'CMDINJTEST123', 'pipe'),
        ('|| echo CMDINJTEST123', 'CMDINJTEST123', 'or_operator'),
        ('&& echo CMDINJTEST123', 'CMDINJTEST123', 'and_operator'),
        ('& echo CMDINJTEST123', 'CMDINJTEST123', 'background'),
        
        # Newline injection
        ('\necho CMDINJTEST123', 'CMDINJTEST123', 'newline'),
        ('\r\necho CMDINJTEST123', 'CMDINJTEST123', 'crlf'),
        
        # Backtick command substitution
        ('`echo CMDINJTEST123`', 'CMDINJTEST123', 'backtick'),
        ('$(echo CMDINJTEST123)', 'CMDINJTEST123', 'subshell'),
        
        # Windows-specific
        ('| echo CMDINJTEST123', 'CMDINJTEST123', 'win_pipe'),
        ('& echo CMDINJTEST123', 'CMDINJTEST123', 'win_amp'),
        
        # Error-based detection
        ('; cat /etc/passwd', 'root:', 'linux_passwd'),
        ('| type C:\\Windows\\win.ini', '[fonts]', 'windows_ini'),
        
        # Path separator injection
        ('; ls -la', 'total', 'ls_output'),
        ('| dir', '<DIR>', 'dir_output'),
        
        # Ping-based (no actual network traffic, just detection)
        ('; ping -c 1 localhost', 'ttl', 'ping_linux'),
        ('| ping -n 1 localhost', 'TTL', 'ping_windows'),
    ]
    
    # Environment variable disclosure payloads
    ENV_PAYLOADS = [
        ('; echo $PATH', '/usr', 'path_linux'),
        ('| echo %PATH%', 'Windows', 'path_windows'),
        ('; printenv', 'PATH=', 'printenv'),
        ('| set', 'Path=', 'set_windows'),
    ]
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def _test_parameter(
        self,
        url: str,
        param_name: str,
        param_value: str,
        method: str = 'GET',
        all_params: dict = None
    ) -> List[Finding]:
        """Test a single parameter for command injection"""
        findings = []
        baseline_response = ""
        
        # Get baseline response
        try:
            test_params = all_params.copy() if all_params else {}
            test_params[param_name] = param_value or 'test'
            
            if method.upper() == 'POST':
                baseline = self.session.post(url, data=test_params, timeout=self.timeout, verify=False)
            else:
                baseline = self.session.get(url, params=test_params, timeout=self.timeout, verify=False)
            
            baseline_response = baseline.text
        except:
            pass
        
        # Test command injection payloads
        for payload, expected_output, payload_type in self.PAYLOADS:
            if self.is_cancelled:
                break
            
            try:
                test_params = all_params.copy() if all_params else {}
                test_params[param_name] = (param_value or '') + payload
                
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
                
                # Check for expected output
                if expected_output.lower() in response.text.lower():
                    # Verify it's not in baseline (false positive check)
                    if expected_output.lower() not in baseline_response.lower():
                        finding = Finding(
                            title=f"Command Injection in parameter '{param_name}'",
                            description=(
                                f"OS Command Injection vulnerability detected in the '{param_name}' parameter. "
                                f"The application executes user-supplied input as system commands, "
                                f"allowing attackers to run arbitrary commands on the server."
                            ),
                            severity=Severity.CRITICAL,
                            owasp_category=self.owasp_category,
                            affected_url=url,
                            evidence=f"Command output detected: '{expected_output}' using {payload_type}",
                            payload_used=payload,
                            impact=10.0,
                            exploitability=9.0,
                            exposure=10.0,
                            confidence=0.95,
                            references=[
                                "https://owasp.org/Top10/A03_2021-Injection/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
                            ]
                        )
                        findings.append(finding)
                        self.report_progress(f"Found Command Injection in {param_name}")
                        return findings  # Critical finding, stop testing
            
            except Exception as e:
                self.report_progress(f"Error testing {param_name}: {str(e)}")
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run command injection scan on target"""
        self.findings = []
        self.session = session
        
        if not self.session:
            import requests
            self.session = requests.Session()
        
        total_tests = len(target.forms) + len(target.url_parameters)
        current_test = 0
        
        self.report_progress("Starting Command Injection scan", 0)
        
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
            
            form_data = {f.name: f.value or 'test' for f in form.fields}
            
            for field in form.fields:
                if field.field_type in ('submit', 'button', 'hidden', 'file'):
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
        
        self.report_progress("Command Injection scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        """Get remediation guidance for command injection"""
        return """
## Remediation for Command Injection

### Immediate Actions:

1. **Avoid System Commands**
   - Use built-in language functions instead of shell commands
   - Example: Use Python's `os.listdir()` instead of `ls`

2. **Input Validation**
   - Strict allowlist validation of user inputs
   - Reject inputs containing shell metacharacters: ; | & $ ` \\ > < ! 
   
   ```python
   import re
   if not re.match(r'^[a-zA-Z0-9_-]+$', user_input):
       raise ValueError("Invalid input")
   ```

3. **Parameterized Commands**
   - Never use shell=True with subprocess
   - Pass arguments as lists
   
   ```python
   # VULNERABLE:
   subprocess.call(f"ping {host}", shell=True)
   
   # SECURE:
   subprocess.call(["ping", "-c", "1", host])
   ```

4. **Use APIs Instead**
   - Replace command-line tools with native libraries
   - Example: Use Python's `shutil` instead of `cp`, `mv`

5. **Sandboxing**
   - Run application in a container with minimal permissions
   - Use AppArmor/SELinux profiles
   - Restrict available system commands

### Code Examples:

**Python (Safe subprocess):**
```python
import subprocess
import shlex

# If you must use user input, validate strictly
allowed_hosts = ['localhost', '127.0.0.1']
if host not in allowed_hosts:
    raise ValueError("Invalid host")

result = subprocess.run(
    ['ping', '-c', '1', host],
    capture_output=True,
    text=True,
    timeout=10
)
```

**Node.js (Safe execution):**
```javascript
const { execFile } = require('child_process');

// Use execFile instead of exec
execFile('ping', ['-c', '1', validatedHost], (error, stdout) => {
    console.log(stdout);
});
```

### References:
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- https://owasp.org/Top10/A03_2021-Injection/
"""
