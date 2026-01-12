"""
Main scan engine that orchestrates vulnerability scanning.
Coordinates plugins, manages progress, and aggregates results.
"""

import threading
import time
from datetime import datetime
from typing import List, Callable, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.models import (
    ScanTarget, ScanProgress, ScanResult, ModuleProgress, 
    ModuleStatus, Finding
)
from core.plugin_loader import PluginLoader
from core.crawler import WebCrawler
from core.severity_engine import SeverityEngine
from plugins.base_plugin import BasePlugin


class ScanEngine:
    """
    Main vulnerability scanning engine.
    
    Orchestrates the scanning process:
    1. Crawls target to discover attack surfaces
    2. Loads and executes vulnerability plugins
    3. Aggregates findings and generates results
    """
    
    def __init__(
        self,
        progress_callback: Optional[Callable] = None,
        max_threads: int = 1,  # Sequential by default for stability
        crawl_depth: int = 2,
        crawl_max_pages: int = 50
    ):
        """
        Initialize the scan engine.
        
        Args:
            progress_callback: Callback for progress updates
            max_threads: Maximum concurrent threads
            crawl_depth: Crawler maximum depth
            crawl_max_pages: Crawler maximum pages
        """
        self.progress_callback = progress_callback
        self.max_threads = max_threads
        self.crawl_depth = crawl_depth
        self.crawl_max_pages = crawl_max_pages
        
        self.plugin_loader = PluginLoader()
        self.severity_engine = SeverityEngine()
        self.crawler: Optional[WebCrawler] = None
        
        self.progress: Optional[ScanProgress] = None
        self.result: Optional[ScanResult] = None
        self.is_running: bool = False
        self.is_cancelled: bool = False
        
        self._scan_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
    
    def _notify_progress(self, update: Dict[str, Any]):
        """Send progress update via callback"""
        if self.progress_callback:
            try:
                self.progress_callback(update)
            except Exception as e:
                print(f"Progress callback error: {e}")
    
    def _update_module_status(
        self,
        module_name: str,
        status: ModuleStatus,
        action: str = "",
        findings_count: int = 0,
        progress_percent: float = 0.0,
        error: str = ""
    ):
        """Update status for a specific module"""
        if self.progress and module_name in self.progress.modules:
            module = self.progress.modules[module_name]
            module.status = status
            module.current_action = action
            module.findings_count = findings_count
            module.progress_percent = progress_percent
            module.error_message = error
            
            if status == ModuleStatus.RUNNING and not module.started_at:
                module.started_at = datetime.now()
            elif status in (ModuleStatus.COMPLETED, ModuleStatus.ERROR):
                module.completed_at = datetime.now()
            
            self._notify_progress({
                'type': 'module_update',
                'module_name': module_name,
                'status': status.value,
                'action': action,
                'findings_count': findings_count,
                'progress_percent': progress_percent,
                'error': error
            })
    
    def _update_overall_progress(self):
        """Update overall scan progress"""
        if self.progress:
            self.progress.update_progress()
            
            self._notify_progress({
                'type': 'overall_update',
                'percent': self.progress.overall_percent,
                'completed_modules': self.progress.completed_modules,
                'total_modules': self.progress.total_modules,
                'current_module': self.progress.current_module,
                'total_findings': self.progress.total_findings
            })
    
    def _run_plugin(
        self,
        plugin: BasePlugin,
        target: ScanTarget,
        session: Any
    ) -> List[Finding]:
        """Run a single plugin and collect findings"""
        findings = []
        
        try:
            # Set up plugin progress callback
            def plugin_progress(update):
                self._update_module_status(
                    plugin.name,
                    ModuleStatus.RUNNING,
                    action=update.get('message', ''),
                    progress_percent=update.get('percent', 0)
                )
            
            plugin.set_progress_callback(plugin_progress)
            plugin.reset()
            
            # Update status to running
            self._update_module_status(plugin.name, ModuleStatus.RUNNING, "Starting...")
            
            # Execute the plugin
            findings = plugin.run(target, session)
            
            # Add remediation to findings
            for finding in findings:
                if not finding.remediation:
                    finding.remediation = plugin.get_remediation(finding)
            
            # Update status to completed
            self._update_module_status(
                plugin.name,
                ModuleStatus.COMPLETED,
                action="Completed",
                findings_count=len(findings),
                progress_percent=100.0
            )
        
        except Exception as e:
            self._update_module_status(
                plugin.name,
                ModuleStatus.ERROR,
                error=str(e)
            )
            print(f"Plugin {plugin.name} error: {e}")
        
        return findings
    
    def _scan_worker(self, target_url: str):
        """Main scanning worker (runs in thread)"""
        all_findings: List[Finding] = []
        
        try:
            self.is_running = True
            start_time = datetime.now()
            
            # Initialize result
            self.result = ScanResult(
                target_url=target_url,
                started_at=start_time
            )
            
            # Phase 1: Crawl target
            self._notify_progress({
                'type': 'phase',
                'phase': 'crawling',
                'message': 'Crawling target website...'
            })
            
            self.crawler = WebCrawler(
                max_depth=self.crawl_depth,
                max_pages=self.crawl_max_pages,
                callback=lambda msg: self._notify_progress({
                    'type': 'crawl_update',
                    'message': msg
                })
            )
            
            target = self.crawler.crawl(target_url)
            session = self.crawler.get_session()
            
            self._notify_progress({
                'type': 'crawl_complete',
                'forms': len(target.forms),
                'params': len(target.url_parameters),
                'urls': len(target.discovered_urls)
            })
            
            if self.is_cancelled:
                return
            
            # Phase 2: Load plugins
            self._notify_progress({
                'type': 'phase',
                'phase': 'loading_plugins',
                'message': 'Loading vulnerability plugins...'
            })
            
            plugins = self.plugin_loader.load_all_plugins()
            enabled_plugins = [p for p in plugins if p.enabled]
            
            # Initialize progress tracking
            self.progress = ScanProgress(
                target_url=target_url,
                total_modules=len(enabled_plugins),
                started_at=start_time,
                is_running=True
            )
            
            for plugin in enabled_plugins:
                self.progress.modules[plugin.name] = ModuleProgress(
                    module_name=plugin.name,
                    status=ModuleStatus.PENDING
                )
            
            self._update_overall_progress()
            
            # Phase 3: Run plugins sequentially
            self._notify_progress({
                'type': 'phase',
                'phase': 'scanning',
                'message': f'Running {len(enabled_plugins)} vulnerability checks...'
            })
            
            for plugin in enabled_plugins:
                if self.is_cancelled:
                    plugin.cancel()
                    break
                
                self.progress.current_module = plugin.name
                self.result.modules_run.append(plugin.name)
                
                findings = self._run_plugin(plugin, target, session)
                all_findings.extend(findings)
                
                self.progress.completed_modules += 1
                self.progress.total_findings = len(all_findings)
                self._update_overall_progress()
            
            # Phase 4: Finalize results
            end_time = datetime.now()
            
            self.result.findings = all_findings
            self.result.completed_at = end_time
            self.result.scan_duration = (end_time - start_time).total_seconds()
            
            self.progress.completed_at = end_time
            self.progress.is_running = False
            self.progress.overall_percent = 100.0
            
            self._notify_progress({
                'type': 'complete',
                'total_findings': len(all_findings),
                'duration': self.result.scan_duration,
                'severity_counts': self.result.get_severity_counts()
            })
        
        except Exception as e:
            self.result.errors.append(str(e))
            self._notify_progress({
                'type': 'error',
                'message': str(e)
            })
        
        finally:
            self.is_running = False
    
    def start_scan(self, target_url: str):
        """
        Start an asynchronous scan.
        
        Args:
            target_url: URL to scan
        """
        if self.is_running:
            raise RuntimeError("Scan already in progress")
        
        self.is_cancelled = False
        self._scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(target_url,),
            daemon=True
        )
        self._scan_thread.start()
    
    def stop_scan(self):
        """Stop the current scan"""
        self.is_cancelled = True
        if self.progress:
            self.progress.is_cancelled = True
    
    def wait_for_completion(self, timeout: float = None) -> ScanResult:
        """Wait for scan to complete and return results"""
        if self._scan_thread:
            self._scan_thread.join(timeout)
        return self.result
    
    def get_progress(self) -> Optional[ScanProgress]:
        """Get current scan progress"""
        return self.progress
    
    def get_result(self) -> Optional[ScanResult]:
        """Get scan results"""
        return self.result
    
    def get_loaded_plugins(self) -> List[Dict]:
        """Get info about loaded plugins"""
        return self.plugin_loader.get_plugin_info()
