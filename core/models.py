"""
Data models for the vulnerability scanner.
Contains dataclasses for findings, targets, and scan progress.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime


class Severity(Enum):
    """Severity levels based on CVSS scoring"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


class ModuleStatus(Enum):
    """Status of a vulnerability module during scanning"""
    PENDING = "Pending"
    RUNNING = "Running"
    COMPLETED = "Completed"
    ERROR = "Error"
    SKIPPED = "Skipped"


class OWASPCategory(Enum):
    """OWASP Top 10 2021 + 2025 Categories"""
    # OWASP 2021 Categories
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    A03_INJECTION = "A03:2021 - Injection"
    A04_INSECURE_DESIGN = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021 - Identification and Authentication Failures"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021 - Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 - Server-Side Request Forgery"
    
    # OWASP 2025 NEW Categories
    A01_2025_BROKEN_ACCESS_CONTROL = "A01:2025 - Broken Access Control (incl. SSRF)"
    A02_2025_SECURITY_MISCONFIGURATION = "A02:2025 - Security Misconfiguration"
    A03_2025_SUPPLY_CHAIN = "A03:2025 - Software Supply Chain Failures"
    A04_2025_CRYPTOGRAPHIC_FAILURES = "A04:2025 - Cryptographic Failures"
    A05_2025_INJECTION = "A05:2025 - Injection"
    A06_2025_INSECURE_DESIGN = "A06:2025 - Insecure Design"
    A07_2025_AUTH_FAILURES = "A07:2025 - Authentication Failures"
    A08_2025_DATA_INTEGRITY = "A08:2025 - Software or Data Integrity Failures"
    A09_2025_LOGGING_ALERTING = "A09:2025 - Logging & Alerting Failures"
    A10_2025_EXCEPTIONAL_CONDITIONS = "A10:2025 - Mishandling of Exceptional Conditions"


@dataclass
class Finding:
    """Represents a single vulnerability finding"""
    title: str
    description: str
    severity: Severity
    owasp_category: OWASPCategory
    affected_url: str
    evidence: str = ""
    payload_used: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    confidence: float = 1.0  # 0.0 to 1.0
    
    # CVSS-like scoring components
    impact: float = 5.0  # 0.0 to 10.0
    exploitability: float = 5.0  # 0.0 to 10.0
    exposure: float = 5.0  # 0.0 to 10.0
    
    # Metadata
    module_name: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    references: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Calculate CVSS score after initialization"""
        if self.cvss_score == 0.0:
            self.cvss_score = self.calculate_cvss_score()
    
    def calculate_cvss_score(self) -> float:
        """
        Calculate a CVSS-inspired score (0.0 - 10.0)
        Based on Impact, Exploitability, Exposure, and Confidence
        """
        score = (
            self.impact * 0.4 +
            self.exploitability * 0.3 +
            self.exposure * 0.2 +
            self.confidence * 10 * 0.1
        )
        return round(min(10.0, max(0.0, score)), 1)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for reporting"""
        return {
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'owasp_category': self.owasp_category.value,
            'affected_url': self.affected_url,
            'evidence': self.evidence,
            'payload_used': self.payload_used,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'confidence': self.confidence,
            'module_name': self.module_name,
            'timestamp': self.timestamp.isoformat(),
            'references': self.references
        }


@dataclass
class FormField:
    """Represents an input field in a form"""
    name: str
    field_type: str  # text, password, email, hidden, etc.
    value: str = ""
    required: bool = False


@dataclass
class Form:
    """Represents a discovered HTML form"""
    action: str
    method: str  # GET or POST
    fields: List[FormField] = field(default_factory=list)
    page_url: str = ""
    
    def get_field_names(self) -> List[str]:
        """Get all field names in the form"""
        return [f.name for f in self.fields if f.name]


@dataclass
class URLParameter:
    """Represents a URL parameter for testing"""
    name: str
    value: str
    url: str


@dataclass
class ScanTarget:
    """Represents a target URL with discovered attack surfaces"""
    base_url: str
    forms: List[Form] = field(default_factory=list)
    url_parameters: List[URLParameter] = field(default_factory=list)
    discovered_urls: List[str] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    
    def get_all_input_points(self) -> int:
        """Count total input points discovered"""
        form_fields = sum(len(f.fields) for f in self.forms)
        return form_fields + len(self.url_parameters)


@dataclass
class ModuleProgress:
    """Tracks progress of a single module"""
    module_name: str
    status: ModuleStatus = ModuleStatus.PENDING
    current_action: str = ""
    findings_count: int = 0
    progress_percent: float = 0.0
    error_message: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class ScanProgress:
    """Tracks overall scan progress"""
    target_url: str
    total_modules: int
    completed_modules: int = 0
    current_module: str = ""
    overall_percent: float = 0.0
    modules: Dict[str, ModuleProgress] = field(default_factory=dict)
    total_findings: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    is_running: bool = False
    is_cancelled: bool = False
    
    def update_progress(self):
        """Update overall progress percentage"""
        if self.total_modules > 0:
            self.overall_percent = (self.completed_modules / self.total_modules) * 100


@dataclass
class ScanResult:
    """Final scan results container"""
    target_url: str
    findings: List[Finding] = field(default_factory=list)
    scan_duration: float = 0.0  # seconds
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    modules_run: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def get_findings_by_severity(self) -> Dict[Severity, List[Finding]]:
        """Group findings by severity level"""
        grouped = {severity: [] for severity in Severity}
        for finding in self.findings:
            grouped[finding.severity].append(finding)
        return grouped
    
    def get_findings_by_owasp(self) -> Dict[OWASPCategory, List[Finding]]:
        """Group findings by OWASP category"""
        grouped = {category: [] for category in OWASPCategory}
        for finding in self.findings:
            grouped[finding.owasp_category].append(finding)
        return grouped
    
    def get_severity_counts(self) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts
    
    def get_highest_severity(self) -> Optional[Severity]:
        """Get the highest severity level found"""
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for severity in severity_order:
            if any(f.severity == severity for f in self.findings):
                return severity
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert results to dictionary for reporting"""
        return {
            'target_url': self.target_url,
            'findings': [f.to_dict() for f in self.findings],
            'scan_duration': self.scan_duration,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'modules_run': self.modules_run,
            'severity_counts': self.get_severity_counts(),
            'total_findings': len(self.findings),
            'errors': self.errors
        }
