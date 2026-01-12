"""
Severity scoring engine using CVSS-inspired methodology.
Calculates vulnerability severity based on multiple factors.
"""

from typing import Dict, Tuple
from core.models import Finding, Severity


class SeverityEngine:
    """
    CVSS-inspired severity scoring engine.
    
    Calculates scores based on:
    - Impact: Potential damage if exploited
    - Exploitability: Ease of exploitation
    - Exposure: How accessible the vulnerability is
    - Confidence: Detection reliability
    """
    
    # Severity thresholds (CVSS v3.1 aligned)
    CRITICAL_THRESHOLD = 9.0
    HIGH_THRESHOLD = 7.0
    MEDIUM_THRESHOLD = 4.0
    LOW_THRESHOLD = 0.1
    
    # Impact weights for different vulnerability types
    IMPACT_WEIGHTS = {
        'data_breach': 10.0,
        'remote_code_execution': 10.0,
        'privilege_escalation': 9.0,
        'authentication_bypass': 9.0,
        'sql_injection': 8.5,
        'command_injection': 9.5,
        'xss_stored': 7.0,
        'xss_reflected': 5.0,
        'ssrf': 7.5,
        'csrf': 6.0,
        'directory_traversal': 7.0,
        'idor': 7.0,
        'weak_ssl': 5.0,
        'missing_headers': 3.5,
        'information_disclosure': 4.0,
        'open_ports': 3.0,
        'outdated_software': 5.0,
    }
    
    # Exploitability weights
    EXPLOITABILITY_WEIGHTS = {
        'trivial': 10.0,      # No skills required, automated tools available
        'easy': 8.0,          # Basic knowledge required
        'moderate': 6.0,      # Intermediate knowledge required
        'difficult': 4.0,     # Expert knowledge required
        'complex': 2.0,       # Multiple conditions must be met
    }
    
    # Exposure weights
    EXPOSURE_WEIGHTS = {
        'public': 10.0,       # Internet-facing, no auth required
        'authenticated': 7.0,  # Requires authentication
        'local': 4.0,         # Requires local access
        'internal': 5.0,      # Internal network only
    }
    
    def __init__(self):
        self.findings_history: list = []
    
    def calculate_score(
        self,
        impact: float,
        exploitability: float,
        exposure: float,
        confidence: float
    ) -> float:
        """
        Calculate CVSS-inspired score (0.0 - 10.0)
        
        Args:
            impact: Impact score (0-10)
            exploitability: Exploitability score (0-10)
            exposure: Exposure score (0-10)
            confidence: Detection confidence (0-1)
        
        Returns:
            Final severity score (0.0 - 10.0)
        """
        # Weighted calculation
        raw_score = (
            impact * 0.40 +
            exploitability * 0.30 +
            exposure * 0.20 +
            (confidence * 10) * 0.10
        )
        
        # Clamp to valid range
        return round(min(10.0, max(0.0, raw_score)), 1)
    
    def get_severity_label(self, score: float) -> Severity:
        """Convert numeric score to severity label"""
        if score >= self.CRITICAL_THRESHOLD:
            return Severity.CRITICAL
        elif score >= self.HIGH_THRESHOLD:
            return Severity.HIGH
        elif score >= self.MEDIUM_THRESHOLD:
            return Severity.MEDIUM
        elif score >= self.LOW_THRESHOLD:
            return Severity.LOW
        else:
            return Severity.INFO
    
    def get_severity_color(self, severity: Severity) -> str:
        """Get color code for severity level (for GUI/reports)"""
        colors = {
            Severity.CRITICAL: "#DC2626",  # Red
            Severity.HIGH: "#EA580C",       # Orange
            Severity.MEDIUM: "#CA8A04",     # Yellow
            Severity.LOW: "#2563EB",        # Blue
            Severity.INFO: "#6B7280",       # Gray
        }
        return colors.get(severity, "#6B7280")
    
    def calculate_finding_score(self, finding: Finding) -> float:
        """Calculate score for a Finding object"""
        return self.calculate_score(
            impact=finding.impact,
            exploitability=finding.exploitability,
            exposure=finding.exposure,
            confidence=finding.confidence
        )
    
    def get_impact_for_type(self, vuln_type: str) -> float:
        """Get default impact score for vulnerability type"""
        return self.IMPACT_WEIGHTS.get(vuln_type.lower(), 5.0)
    
    def get_exploitability_for_difficulty(self, difficulty: str) -> float:
        """Get exploitability score for difficulty level"""
        return self.EXPLOITABILITY_WEIGHTS.get(difficulty.lower(), 6.0)
    
    def get_exposure_for_context(self, context: str) -> float:
        """Get exposure score for access context"""
        return self.EXPOSURE_WEIGHTS.get(context.lower(), 5.0)
    
    def create_scored_finding(
        self,
        title: str,
        description: str,
        vuln_type: str,
        difficulty: str,
        context: str,
        confidence: float,
        affected_url: str,
        **kwargs
    ) -> Tuple[Finding, float, Severity]:
        """
        Create a Finding with calculated severity
        
        Returns:
            Tuple of (Finding, score, severity)
        """
        impact = self.get_impact_for_type(vuln_type)
        exploitability = self.get_exploitability_for_difficulty(difficulty)
        exposure = self.get_exposure_for_context(context)
        
        score = self.calculate_score(impact, exploitability, exposure, confidence)
        severity = self.get_severity_label(score)
        
        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            affected_url=affected_url,
            impact=impact,
            exploitability=exploitability,
            exposure=exposure,
            confidence=confidence,
            cvss_score=score,
            **kwargs
        )
        
        return finding, score, severity
    
    def get_risk_summary(self, findings: list) -> Dict[str, any]:
        """Generate risk summary from list of findings"""
        if not findings:
            return {
                'overall_risk': 'None',
                'highest_score': 0.0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'info_count': 0,
                'average_score': 0.0,
            }
        
        scores = [f.cvss_score for f in findings]
        severities = [f.severity for f in findings]
        
        summary = {
            'highest_score': max(scores),
            'average_score': round(sum(scores) / len(scores), 1),
            'critical_count': severities.count(Severity.CRITICAL),
            'high_count': severities.count(Severity.HIGH),
            'medium_count': severities.count(Severity.MEDIUM),
            'low_count': severities.count(Severity.LOW),
            'info_count': severities.count(Severity.INFO),
        }
        
        # Determine overall risk level
        if summary['critical_count'] > 0:
            summary['overall_risk'] = 'Critical'
        elif summary['high_count'] > 0:
            summary['overall_risk'] = 'High'
        elif summary['medium_count'] > 0:
            summary['overall_risk'] = 'Medium'
        elif summary['low_count'] > 0:
            summary['overall_risk'] = 'Low'
        else:
            summary['overall_risk'] = 'Informational'
        
        return summary
