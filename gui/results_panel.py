"""
Results panel for displaying vulnerability findings.
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, List

from core.models import Finding, Severity


class ResultsPanel:
    """Panel showing vulnerability findings."""
    
    def __init__(self, parent, colors: Dict[str, str]):
        self.parent = parent
        self.colors = colors
        self.findings: List[Finding] = []
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create results widgets."""
        # Header with filter
        header_frame = tk.Frame(self.parent, bg=self.colors['bg'])
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(
            header_frame,
            text="Vulnerability Findings",
            bg=self.colors['bg'],
            fg=self.colors['text'],
            font=('Segoe UI', 12, 'bold')
        ).pack(side=tk.LEFT)
        
        # Filter dropdown
        self.filter_var = tk.StringVar(value="All Severities")
        filter_options = ["All Severities", "Critical", "High", "Medium", "Low", "Informational"]
        filter_dropdown = ttk.Combobox(
            header_frame,
            textvariable=self.filter_var,
            values=filter_options,
            state='readonly',
            width=15
        )
        filter_dropdown.pack(side=tk.RIGHT)
        filter_dropdown.bind('<<ComboboxSelected>>', self._apply_filter)
        
        tk.Label(
            header_frame,
            text="Filter: ",
            bg=self.colors['bg'],
            fg=self.colors['text'],
            font=('Segoe UI', 10)
        ).pack(side=tk.RIGHT, padx=(0, 5))
        
        # Findings count
        self.count_label = tk.Label(
            header_frame,
            text="0 findings",
            bg=self.colors['bg'],
            fg=self.colors['text_dim'],
            font=('Segoe UI', 10)
        )
        self.count_label.pack(side=tk.RIGHT, padx=20)
        
        # Scrollable findings list
        list_frame = tk.Frame(self.parent, bg=self.colors['bg'])
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10)
        
        self.canvas = tk.Canvas(list_frame, bg=self.colors['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.canvas.yview)
        
        self.findings_frame = tk.Frame(self.canvas, bg=self.colors['bg'])
        
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.canvas_window = self.canvas.create_window((0, 0), window=self.findings_frame, anchor=tk.NW)
        
        self.findings_frame.bind('<Configure>', 
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>', 
            lambda e: self.canvas.itemconfig(self.canvas_window, width=e.width))
        
        # Mouse wheel scrolling - bind only when mouse enters canvas
        self.canvas.bind('<Enter>', self._bind_mousewheel)
        self.canvas.bind('<Leave>', self._unbind_mousewheel)
    
    def _bind_mousewheel(self, event):
        """Bind mouse wheel when mouse enters canvas."""
        self.canvas.bind_all('<MouseWheel>', self._on_mousewheel)
    
    def _unbind_mousewheel(self, event):
        """Unbind mouse wheel when mouse leaves canvas."""
        self.canvas.unbind_all('<MouseWheel>')
    
    def _on_mousewheel(self, event):
        """Handle mouse wheel scroll."""
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')
    
    def _get_severity_color(self, severity: Severity) -> str:
        """Get color for severity level."""
        return {
            Severity.CRITICAL: self.colors['critical'],
            Severity.HIGH: self.colors['high'],
            Severity.MEDIUM: self.colors['medium'],
            Severity.LOW: self.colors['low'],
            Severity.INFO: self.colors['info'],
        }.get(severity, self.colors['info'])
    
    def _create_finding_card(self, finding: Finding):
        """Create a finding card widget."""
        card = tk.Frame(
            self.findings_frame,
            bg=self.colors['bg_secondary'],
            highlightbackground=self._get_severity_color(finding.severity),
            highlightthickness=2
        )
        card.pack(fill=tk.X, pady=5, ipady=10, ipadx=10)
        
        # Header row
        header = tk.Frame(card, bg=self.colors['bg_secondary'])
        header.pack(fill=tk.X, padx=10, pady=5)
        
        # Severity badge
        severity_badge = tk.Label(
            header,
            text=finding.severity.value.upper(),
            bg=self._get_severity_color(finding.severity),
            fg='white',
            font=('Segoe UI', 9, 'bold'),
            padx=8,
            pady=2
        )
        severity_badge.pack(side=tk.LEFT)
        
        # CVSS Score
        score_label = tk.Label(
            header,
            text=f"CVSS: {finding.cvss_score}",
            bg=self.colors['bg_secondary'],
            fg=self.colors['text'],
            font=('Segoe UI', 9, 'bold')
        )
        score_label.pack(side=tk.LEFT, padx=10)
        
        # OWASP Category
        owasp_label = tk.Label(
            header,
            text=finding.owasp_category.value.split(' - ')[0],
            bg=self.colors['accent'],
            fg=self.colors['text'],
            font=('Segoe UI', 8),
            padx=5,
            pady=1
        )
        owasp_label.pack(side=tk.RIGHT)
        
        # Module name
        module_label = tk.Label(
            header,
            text=finding.module_name,
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_dim'],
            font=('Segoe UI', 9)
        )
        module_label.pack(side=tk.RIGHT, padx=10)
        
        # Title
        title_label = tk.Label(
            card,
            text=finding.title,
            bg=self.colors['bg_secondary'],
            fg=self.colors['text'],
            font=('Segoe UI', 11, 'bold'),
            anchor=tk.W,
            wraplength=800
        )
        title_label.pack(fill=tk.X, padx=10, pady=(5, 0))
        
        # URL
        url_label = tk.Label(
            card,
            text=finding.affected_url,
            bg=self.colors['bg_secondary'],
            fg=self.colors['low'],
            font=('Consolas', 9),
            anchor=tk.W
        )
        url_label.pack(fill=tk.X, padx=10)
        
        # Description (truncated)
        desc_text = finding.description[:300] + ('...' if len(finding.description) > 300 else '')
        desc_label = tk.Label(
            card,
            text=desc_text,
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_dim'],
            font=('Segoe UI', 9),
            anchor=tk.W,
            justify=tk.LEFT,
            wraplength=800
        )
        desc_label.pack(fill=tk.X, padx=10, pady=5)
        
        # Evidence if available
        if finding.evidence:
            evidence_frame = tk.Frame(card, bg=self.colors['bg'])
            evidence_frame.pack(fill=tk.X, padx=10, pady=5)
            
            tk.Label(
                evidence_frame,
                text="Evidence:",
                bg=self.colors['bg'],
                fg=self.colors['text'],
                font=('Segoe UI', 9, 'bold')
            ).pack(side=tk.LEFT, padx=5)
            
            tk.Label(
                evidence_frame,
                text=finding.evidence[:200],
                bg=self.colors['bg'],
                fg=self.colors['text_dim'],
                font=('Consolas', 8)
            ).pack(side=tk.LEFT, padx=5)
        
        return card
    
    def display_findings(self, findings: List[Finding]):
        """Display list of findings."""
        self.findings = findings
        self._render_findings(findings)
    
    def _render_findings(self, findings: List[Finding]):
        """Render findings to the panel."""
        # Clear existing
        for widget in self.findings_frame.winfo_children():
            widget.destroy()
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))
        
        # Update count
        self.count_label.config(text=f"{len(sorted_findings)} findings")
        
        # Create cards
        for finding in sorted_findings:
            self._create_finding_card(finding)
        
        # Update scroll region
        self.canvas.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox('all'))
    
    def _apply_filter(self, event=None):
        """Apply severity filter."""
        filter_value = self.filter_var.get()
        
        if filter_value == "All Severities":
            self._render_findings(self.findings)
        else:
            # Map filter to severity
            severity_map = {
                "Critical": Severity.CRITICAL,
                "High": Severity.HIGH,
                "Medium": Severity.MEDIUM,
                "Low": Severity.LOW,
                "Informational": Severity.INFO
            }
            target_severity = severity_map.get(filter_value)
            filtered = [f for f in self.findings if f.severity == target_severity]
            self._render_findings(filtered)
    
    def clear(self):
        """Clear all findings."""
        self.findings = []
        for widget in self.findings_frame.winfo_children():
            widget.destroy()
        self.count_label.config(text="0 findings")
