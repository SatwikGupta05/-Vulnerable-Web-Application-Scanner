"""
Base plugin class for vulnerability scanners.
All vulnerability modules must inherit from this class.
"""

from abc import ABC, abstractmethod
from typing import List, Callable, Optional, Dict, Any
from core.models import Finding, ScanTarget, OWASPCategory, Severity


class BasePlugin(ABC):
    """
    Abstract base class for vulnerability scanner plugins.
    
    All vulnerability modules must inherit from this class and implement
    the required methods.
    """
    
    # Plugin metadata (override in subclasses)
    name: str = "Base Plugin"
    description: str = "Base vulnerability scanner plugin"
    version: str = "1.0.0"
    author: str = "Security Team"
    
    # OWASP mapping
    owasp_category: OWASPCategory = OWASPCategory.A05_SECURITY_MISCONFIGURATION
    
    # Plugin configuration
    enabled: bool = True
    timeout: int = 30  # seconds per test
    max_tests: int = 100  # maximum number of tests to run
    
    def __init__(self):
        """Initialize the plugin"""
        self.findings: List[Finding] = []
        self.progress_callback: Optional[Callable] = None
        self.is_cancelled: bool = False
    
    def set_progress_callback(self, callback: Callable):
        """Set the progress callback function"""
        self.progress_callback = callback
    
    def report_progress(self, message: str, percent: float = 0.0):
        """Report progress via callback"""
        if self.progress_callback:
            self.progress_callback({
                'module': self.name,
                'message': message,
                'percent': percent
            })
    
    def add_finding(self, finding: Finding):
        """Add a finding to the results"""
        finding.module_name = self.name
        self.findings.append(finding)
        self.report_progress(f"Found: {finding.title}", 0)
    
    def cancel(self):
        """Cancel the scan"""
        self.is_cancelled = True
    
    @abstractmethod
    def run(self, target: ScanTarget, session: Any = None) -> List[Finding]:
        """
        Execute the vulnerability scan.
        
        Args:
            target: ScanTarget with discovered attack surfaces
            session: Optional requests.Session for HTTP requests
        
        Returns:
            List of Finding objects
        """
        pass
    
    @abstractmethod
    def get_remediation(self, finding: Finding) -> str:
        """
        Get remediation guidance for a finding.
        
        Args:
            finding: The Finding to get remediation for
        
        Returns:
            Remediation guidance string
        """
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'author': self.author,
            'owasp_category': self.owasp_category.value,
            'enabled': self.enabled
        }
    
    def reset(self):
        """Reset plugin state for new scan"""
        self.findings.clear()
        self.is_cancelled = False


class PluginRegistry:
    """Registry for managing loaded plugins"""
    
    _plugins: Dict[str, BasePlugin] = {}
    
    @classmethod
    def register(cls, plugin_class: type):
        """Register a plugin class"""
        instance = plugin_class()
        cls._plugins[instance.name] = instance
        return plugin_class
    
    @classmethod
    def get_plugin(cls, name: str) -> Optional[BasePlugin]:
        """Get a plugin by name"""
        return cls._plugins.get(name)
    
    @classmethod
    def get_all_plugins(cls) -> List[BasePlugin]:
        """Get all registered plugins"""
        return list(cls._plugins.values())
    
    @classmethod
    def get_enabled_plugins(cls) -> List[BasePlugin]:
        """Get all enabled plugins"""
        return [p for p in cls._plugins.values() if p.enabled]
    
    @classmethod
    def clear(cls):
        """Clear all registered plugins"""
        cls._plugins.clear()
