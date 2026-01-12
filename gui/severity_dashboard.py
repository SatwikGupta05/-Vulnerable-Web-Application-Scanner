"""
Severity dashboard showing summary statistics.
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, Optional

from core.models import ScanResult, Severity


class SeverityDashboard:
    """Dashboard showing severity breakdown and statistics."""
    
    def __init__(self, parent, colors: Dict[str, str]):
        self.parent = parent
        self.colors = colors
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create dashboard widgets."""
        # Title
        tk.Label(
            self.parent,
            text="Security Assessment Summary",
            bg=self.colors['bg'],
            fg=self.colors['text'],
            font=('Segoe UI', 14, 'bold')
        ).pack(anchor=tk.W, padx=20, pady=15)
        
        # Summary cards row
        cards_frame = tk.Frame(self.parent, bg=self.colors['bg'])
        cards_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Create severity cards
        severity_data = [
            ('Critical', self.colors['critical'], '0'),
            ('High', self.colors['high'], '0'),
            ('Medium', self.colors['medium'], '0'),
            ('Low', self.colors['low'], '0'),
            ('Info', self.colors['info'], '0'),
        ]
        
        self.severity_labels = {}
        
        for severity, color, count in severity_data:
            card = tk.Frame(cards_frame, bg=color)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            
            count_label = tk.Label(
                card,
                text=count,
                bg=color,
                fg='white',
                font=('Segoe UI', 28, 'bold')
            )
            count_label.pack(pady=(15, 5))
            
            tk.Label(
                card,
                text=severity,
                bg=color,
                fg='white',
                font=('Segoe UI', 11)
            ).pack(pady=(0, 15))
            
            self.severity_labels[severity] = count_label
        
        # Details section
        details_frame = tk.Frame(self.parent, bg=self.colors['bg_secondary'])
        details_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left column - Stats
        left_frame = tk.Frame(details_frame, bg=self.colors['bg_secondary'])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(
            left_frame,
            text="Scan Statistics",
            bg=self.colors['bg_secondary'],
            fg=self.colors['text'],
            font=('Segoe UI', 12, 'bold')
        ).pack(anchor=tk.W, pady=(0, 15))
        
        self.stats_labels = {}
        stats = [
            ('Target URL', '-'),
            ('Scan Duration', '-'),
            ('Total Findings', '-'),
            ('Modules Run', '-'),
            ('Risk Level', '-'),
        ]
        
        for stat_name, stat_value in stats:
            row = tk.Frame(left_frame, bg=self.colors['bg_secondary'])
            row.pack(fill=tk.X, pady=5)
            
            tk.Label(
                row,
                text=stat_name + ':',
                bg=self.colors['bg_secondary'],
                fg=self.colors['text_dim'],
                font=('Segoe UI', 10),
                width=15,
                anchor=tk.W
            ).pack(side=tk.LEFT)
            
            value_label = tk.Label(
                row,
                text=stat_value,
                bg=self.colors['bg_secondary'],
                fg=self.colors['text'],
                font=('Segoe UI', 10, 'bold'),
                anchor=tk.W
            )
            value_label.pack(side=tk.LEFT, padx=10)
            
            self.stats_labels[stat_name] = value_label
        
        # Right column - OWASP breakdown
        right_frame = tk.Frame(details_frame, bg=self.colors['bg_secondary'])
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(
            right_frame,
            text="OWASP Top 10 Coverage",
            bg=self.colors['bg_secondary'],
            fg=self.colors['text'],
            font=('Segoe UI', 12, 'bold')
        ).pack(anchor=tk.W, pady=(0, 15))
        
        self.owasp_frame = tk.Frame(right_frame, bg=self.colors['bg_secondary'])
        self.owasp_frame.pack(fill=tk.BOTH, expand=True)
    
    def update(self, result: ScanResult):
        """Update dashboard with scan results."""
        # Update severity counts
        counts = result.get_severity_counts()
        self.severity_labels['Critical'].config(text=str(counts.get('Critical', 0)))
        self.severity_labels['High'].config(text=str(counts.get('High', 0)))
        self.severity_labels['Medium'].config(text=str(counts.get('Medium', 0)))
        self.severity_labels['Low'].config(text=str(counts.get('Low', 0)))
        self.severity_labels['Info'].config(text=str(counts.get('Informational', 0)))
        
        # Update stats
        self.stats_labels['Target URL'].config(text=result.target_url[:50] + '...' if len(result.target_url) > 50 else result.target_url)
        self.stats_labels['Scan Duration'].config(text=f"{result.scan_duration:.1f} seconds")
        self.stats_labels['Total Findings'].config(text=str(len(result.findings)))
        self.stats_labels['Modules Run'].config(text=str(len(result.modules_run)))
        
        # Calculate risk level
        highest = result.get_highest_severity()
        if highest:
            risk_colors = {
                Severity.CRITICAL: (self.colors['critical'], 'CRITICAL'),
                Severity.HIGH: (self.colors['high'], 'HIGH'),
                Severity.MEDIUM: (self.colors['medium'], 'MEDIUM'),
                Severity.LOW: (self.colors['low'], 'LOW'),
                Severity.INFO: (self.colors['info'], 'LOW'),
            }
            color, text = risk_colors.get(highest, (self.colors['success'], 'NONE'))
            self.stats_labels['Risk Level'].config(text=text, fg=color)
        else:
            self.stats_labels['Risk Level'].config(text='NONE', fg=self.colors['success'])
        
        # Update OWASP breakdown
        for widget in self.owasp_frame.winfo_children():
            widget.destroy()
        
        owasp_counts = {}
        for finding in result.findings:
            cat = finding.owasp_category.value.split(' - ')[0]
            owasp_counts[cat] = owasp_counts.get(cat, 0) + 1
        
        for cat, count in sorted(owasp_counts.items()):
            row = tk.Frame(self.owasp_frame, bg=self.colors['bg_secondary'])
            row.pack(fill=tk.X, pady=2)
            
            tk.Label(
                row,
                text=cat,
                bg=self.colors['bg_secondary'],
                fg=self.colors['text'],
                font=('Segoe UI', 9),
                width=15,
                anchor=tk.W
            ).pack(side=tk.LEFT)
            
            # Progress bar for visual
            bar_frame = tk.Frame(row, bg=self.colors['bg'], height=15)
            bar_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
            
            max_count = max(owasp_counts.values()) if owasp_counts else 1
            bar_width = int((count / max_count) * 200)
            
            bar = tk.Frame(bar_frame, bg=self.colors['accent'], width=bar_width, height=15)
            bar.pack(side=tk.LEFT)
            bar.pack_propagate(False)
            
            tk.Label(
                row,
                text=str(count),
                bg=self.colors['bg_secondary'],
                fg=self.colors['text'],
                font=('Segoe UI', 9, 'bold'),
                width=5
            ).pack(side=tk.RIGHT)
    
    def clear(self):
        """Clear the dashboard."""
        for label in self.severity_labels.values():
            label.config(text='0')
        
        for label in self.stats_labels.values():
            label.config(text='-', fg=self.colors['text'])
        
        for widget in self.owasp_frame.winfo_children():
            widget.destroy()
