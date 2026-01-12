"""
SQL Injection vulnerability scanner plugin.
Tests forms and URL parameters for SQL injection vulnerabilities.
OWASP A03:2021 - Injection
"""

import re
from typing import List, Any
from urllib.parse import urljoin

from plugins.base_plugin import BasePlugin
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class SQLInjectionScanner(BasePlugin):
    """
    SQL Injection vulnerability scanner.
    
    Tests login forms, search bars, and URL parameters with
    controlled SQL payloads to detect database errors or
    abnormal application behavior.
    """
    
    name = "SQL Injection Scanner"
    description = "Detects SQL injection vulnerabilities in forms and URL parameters"
    version = "1.0.0"
    owasp_category = OWASPCategory.A03_INJECTION
    
    # SQL injection test payloads (safe, non-destructive)
    PAYLOADS = [
        # Basic injection
        "'",
        "''",
        "\"",
        # Boolean-based
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin'--",
        "admin' #",
        "' OR 1=1 --",
        "\" OR 1=1 --",
        # Error-based
        "' AND 1=CONVERT(int, @@version) --",
        "' UNION SELECT NULL --",
        "' UNION SELECT NULL, NULL --",
        # Time-based (detection only, not exploitation)
        "'; WAITFOR DELAY '0:0:0' --",  # MSSQL
        "' OR SLEEP(0) #",  # MySQL
        "' || pg_sleep(0) --",  # PostgreSQL
    ]
    
    # Database error patterns
    ERROR_PATTERNS = [
        # MySQL
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"mysql_query",
        r"mysql_connect",
        r"mysqli_",
        # PostgreSQL
        r"pg_query",
        r"pg_exec",
        r"postgresql.*error",
        r"unterminated quoted string",
        r"syntax error at or near",
        # MS SQL Server
        r"microsoft sql server",
        r"odbc sql server driver",
        r"sqlserver",
        r"unclosed quotation mark",
        r"incorrect syntax near",
        r"\[sql server\]",
        # Oracle
        r"ora-\d{5}",
        r"oracle.*error",
        r"oracle.*driver",
        r"quoted string not properly terminated",
        # SQLite
        r"sqlite.*error",
        r"sqlite3_",
        r"unrecognized token",
        # Generic
        r"sql syntax.*error",
        r"sql error",
        r"syntax error.*sql",
        r"database error",
        r"db error",
        r"jdbc",
        r"odbc",
    ]
    
    def __init__(self):
        super().__init__()
        self.session = None
        self.error_regex = re.compile(
            '|'.join(self.ERROR_PATTERNS),
            re.IGNORECASE
        )
    
    def _test_parameter(
        self,
        url: str,
        param_name: str,
        param_value: str,
        method: str = 'GET',
        all_params: dict = None
    ) -> List[Finding]:
        """Test a single parameter for SQL injection"""
        findings = []
        
        for payload in self.PAYLOADS:
            if self.is_cancelled:
                break
            
            try:
                # Prepare test data
                test_value = param_value + payload if param_value else payload
                test_params = all_params.copy() if all_params else {}
                test_params[param_name] = test_value
                
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
                
                # Check for SQL errors in response
                error_match = self.error_regex.search(response.text)
                
                if error_match:
                    finding = Finding(
                        title=f"SQL Injection in parameter '{param_name}'",
                        description=(
                            f"SQL injection vulnerability detected in the '{param_name}' parameter. "
                            f"The application returned a database error message when tested with SQL payload, "
                            f"indicating that user input is being directly interpolated into SQL queries."
                        ),
                        severity=Severity.CRITICAL,
                        owasp_category=self.owasp_category,
                        affected_url=url,
                        evidence=f"Error found: {error_match.group(0)}",
                        payload_used=payload,
                        impact=9.5,
                        exploitability=9.0,
                        exposure=10.0,
                        confidence=0.95,
                        references=[
                            "https://owasp.org/Top10/A03_2021-Injection/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                        ]
                    )
                    findings.append(finding)
                    self.report_progress(f"Found SQL Injection in {param_name}")
                    break  # One finding per parameter is enough
                
                # Check for behavioral anomalies (basic boolean-based detection)
                if "' OR '1'='1" in payload:
                    # Store baseline for comparison
                    baseline_len = getattr(self, '_baseline_len', None)
                    if baseline_len is None:
                        self._baseline_len = len(response.text)
                    elif abs(len(response.text) - baseline_len) > baseline_len * 0.3:
                        # Significant length difference might indicate SQLi
                        finding = Finding(
                            title=f"Potential SQL Injection in parameter '{param_name}'",
                            description=(
                                f"Possible SQL injection vulnerability detected. "
                                f"Boolean-based payload caused significant response size change, "
                                f"suggesting query manipulation is possible."
                            ),
                            severity=Severity.HIGH,
                            owasp_category=self.owasp_category,
                            affected_url=url,
                            evidence=f"Response size changed significantly with boolean payload",
                            payload_used=payload,
                            impact=9.0,
                            exploitability=8.0,
                            exposure=10.0,
                            confidence=0.70,
                            references=[
                                "https://owasp.org/Top10/A03_2021-Injection/"
                            ]
                        )
                        findings.append(finding)
                        break
            
            except Exception as e:
                self.report_progress(f"Error testing {param_name}: {str(e)}")
        
        return findings
    
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """Run SQL injection scan on target"""
        self.findings = []
        self.session = session
        
        if not self.session:
            import requests
            self.session = requests.Session()
        
        total_tests = len(target.forms) + len(target.url_parameters)
        current_test = 0
        
        self.report_progress("Starting SQL Injection scan", 0)
        
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
            
            # Test each field
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
                url=param.url.split('?')[0],  # Base URL without params
                param_name=param.name,
                param_value=param.value,
                method='GET'
            )
            
            for finding in findings:
                self.add_finding(finding)
        
        self.report_progress("SQL Injection scan complete", 100)
        return self.findings
    
    def get_remediation(self, finding: Finding) -> str:
        """Get remediation guidance for SQL injection"""
        return """
## Remediation for SQL Injection

### Immediate Actions:
1. **Use Parameterized Queries (Prepared Statements)**
   - Never concatenate user input directly into SQL queries
   - Use placeholders and bind parameters
   
   ```python
   # VULNERABLE:
   query = f"SELECT * FROM users WHERE username = '{username}'"
   
   # SECURE:
   cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
   ```

2. **Use ORM (Object-Relational Mapping)**
   - Use frameworks like SQLAlchemy, Django ORM, or Entity Framework
   - These handle parameterization automatically

3. **Input Validation**
   - Validate and sanitize all user inputs
   - Use allowlists for expected input formats
   - Reject inputs containing SQL special characters when not needed

4. **Least Privilege**
   - Database accounts should have minimal required permissions
   - Never use admin/root database accounts for web applications

5. **Web Application Firewall (WAF)**
   - Deploy WAF rules to detect and block SQL injection attempts

### Code Examples:

**Python with SQLAlchemy:**
```python
from sqlalchemy import text
result = session.execute(
    text("SELECT * FROM users WHERE username = :username"),
    {"username": user_input}
)
```

**PHP with PDO:**
```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE username = ?');
$stmt->execute([$username]);
```

**Node.js with pg:**
```javascript
const { rows } = await pool.query(
    'SELECT * FROM users WHERE username = $1',
    [username]
);
```

### References:
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://owasp.org/Top10/A03_2021-Injection/
"""
