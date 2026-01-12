"""
Main application window for the vulnerability scanner GUI.
Built with Tkinter for cross-platform compatibility.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from datetime import datetime
from typing import Optional, Callable
import webbrowser

from gui.progress_panel import ProgressPanel
from gui.results_panel import ResultsPanel
from gui.severity_dashboard import SeverityDashboard
from core.engine import ScanEngine
from core.models import ScanResult
from reports.report_generator import ReportGenerator
from utils.validators import validate_url


class MainWindow:
    """Main application window."""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SOC Security Scanner - Web Vulnerability Assessment Tool")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        
        # Configure theme colors
        self.colors = {
            'bg': '#1a1a2e',
            'bg_secondary': '#16213e',
            'accent': '#0f3460',
            'text': '#e4e4e4',
            'text_dim': '#8b8b8b',
            'critical': '#DC2626',
            'high': '#EA580C',
            'medium': '#CA8A04',
            'low': '#2563EB',
            'info': '#6B7280',
            'success': '#10B981',
        }
        
        # Configure root
        self.root.configure(bg=self.colors['bg'])
        
        # Initialize components
        self.engine: Optional[ScanEngine] = None
        self.current_result: Optional[ScanResult] = None
        self.is_scanning = False
        
        # Create UI
        self._setup_styles()
        self._create_widgets()
        
        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _setup_styles(self):
        """Configure ttk styles."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors for various widgets
        style.configure('TFrame', background=self.colors['bg'])
        style.configure('Secondary.TFrame', background=self.colors['bg_secondary'])
        style.configure('TLabel', background=self.colors['bg'], 
                       foreground=self.colors['text'])
        style.configure('Title.TLabel', font=('Segoe UI', 24, 'bold'),
                       foreground=self.colors['text'])
        style.configure('Subtitle.TLabel', font=('Segoe UI', 11),
                       foreground=self.colors['text_dim'])
        style.configure('TButton', font=('Segoe UI', 10))
        style.configure('Scan.TButton', font=('Segoe UI', 12, 'bold'))
        
        # Entry style
        style.configure('TEntry', fieldbackground=self.colors['bg_secondary'],
                       foreground=self.colors['text'])
        
        # Progress bar style
        style.configure('Green.Horizontal.TProgressbar',
                       troughcolor=self.colors['bg_secondary'],
                       background=self.colors['success'])
    
    def _create_widgets(self):
        """Create all UI widgets."""
        # Main container
        main_frame = ttk.Frame(self.root, style='TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header section
        self._create_header(main_frame)
        
        # Target input section
        self._create_target_section(main_frame)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(15, 0))
        
        # Progress tab
        progress_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(progress_frame, text='  Scan Progress  ')
        self.progress_panel = ProgressPanel(progress_frame, self.colors)
        
        # Results tab
        results_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(results_frame, text='  Findings  ')
        self.results_panel = ResultsPanel(results_frame, self.colors)
        
        # Dashboard tab
        dashboard_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(dashboard_frame, text='  Dashboard  ')
        self.severity_dashboard = SeverityDashboard(dashboard_frame, self.colors)
        
        # Footer with status
        self._create_footer(main_frame)
    
    def _create_header(self, parent):
        """Create header section."""
        header_frame = ttk.Frame(parent, style='TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Title
        title = ttk.Label(header_frame, text="🛡️ SOC Security Scanner",
                         style='Title.TLabel')
        title.pack(side=tk.LEFT)
        
        # Subtitle
        subtitle = ttk.Label(header_frame,
                            text="Enterprise Web Vulnerability Assessment",
                            style='Subtitle.TLabel')
        subtitle.pack(side=tk.LEFT, padx=(15, 0), pady=(8, 0))
        
        # Report button
        self.report_btn = tk.Button(
            header_frame,
            text="📄 Generate Report",
            command=self._generate_report,
            bg=self.colors['accent'],
            fg=self.colors['text'],
            font=('Segoe UI', 10),
            relief=tk.FLAT,
            padx=15,
            pady=5,
            state=tk.DISABLED
        )
        self.report_btn.pack(side=tk.RIGHT)
    
    def _create_target_section(self, parent):
        """Create target URL input section."""
        target_frame = ttk.Frame(parent, style='Secondary.TFrame')
        target_frame.pack(fill=tk.X, pady=10, ipady=15, ipadx=15)
        
        # Configure inner frame
        inner = ttk.Frame(target_frame, style='Secondary.TFrame')
        inner.pack(fill=tk.X, padx=15, pady=10)
        
        # Label
        label = tk.Label(inner, text="Target URL:",
                        bg=self.colors['bg_secondary'],
                        fg=self.colors['text'],
                        font=('Segoe UI', 11))
        label.pack(side=tk.LEFT)
        
        # URL Entry
        self.url_var = tk.StringVar(value="")
        self.url_entry = tk.Entry(
            inner,
            textvariable=self.url_var,
            font=('Consolas', 12),
            bg=self.colors['bg'],
            fg=self.colors['text'],
            insertbackground=self.colors['text'],
            relief=tk.FLAT,
            width=60
        )
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=15)
        self.url_entry.bind('<Return>', lambda e: self._start_scan())
        
        # Add placeholder
        self.url_entry.insert(0, "Enter target URL (e.g., example.com)")
        self.url_entry.config(fg=self.colors['text_dim'])
        self.url_entry.bind('<FocusIn>', self._on_url_focus_in)
        self.url_entry.bind('<FocusOut>', self._on_url_focus_out)
        
        # Start button
        self.start_btn = tk.Button(
            inner,
            text="▶ Start Scan",
            command=self._start_scan,
            bg=self.colors['success'],
            fg='white',
            font=('Segoe UI', 11, 'bold'),
            relief=tk.FLAT,
            padx=25,
            pady=8,
            cursor='hand2'
        )
        self.start_btn.pack(side=tk.LEFT)
        
        # Stop button (hidden initially)
        self.stop_btn = tk.Button(
            inner,
            text="⬛ Stop",
            command=self._stop_scan,
            bg=self.colors['critical'],
            fg='white',
            font=('Segoe UI', 11, 'bold'),
            relief=tk.FLAT,
            padx=25,
            pady=8,
            cursor='hand2'
        )
    
    def _create_footer(self, parent):
        """Create footer with status bar."""
        footer = ttk.Frame(parent, style='TFrame')
        footer.pack(fill=tk.X, pady=(10, 0))
        
        # Status label
        self.status_var = tk.StringVar(value="Ready to scan")
        status_label = tk.Label(
            footer,
            textvariable=self.status_var,
            bg=self.colors['bg'],
            fg=self.colors['text_dim'],
            font=('Segoe UI', 9)
        )
        status_label.pack(side=tk.LEFT)
        
        # OWASP badge
        owasp_label = tk.Label(
            footer,
            text="OWASP Top 10 Coverage",
            bg=self.colors['bg'],
            fg=self.colors['accent'],
            font=('Segoe UI', 9)
        )
        owasp_label.pack(side=tk.RIGHT)
    
    def _handle_progress(self, update: dict):
        """Handle progress updates from scan engine."""
        # Use after() to update GUI from main thread
        self.root.after(0, lambda: self._update_gui(update))
    
    def _update_gui(self, update: dict):
        """Update GUI with progress info."""
        update_type = update.get('type', '')
        
        if update_type == 'phase':
            self.status_var.set(update.get('message', ''))
        
        elif update_type == 'crawl_complete':
            self.status_var.set(
                f"Crawl complete: {update['forms']} forms, "
                f"{update['params']} params, {update['urls']} URLs"
            )
        
        elif update_type == 'module_update':
            self.progress_panel.update_module(
                update['module_name'],
                update['status'],
                update.get('action', ''),
                update.get('findings_count', 0)
            )
        
        elif update_type == 'overall_update':
            self.progress_panel.update_overall(
                update['percent'],
                update['completed_modules'],
                update['total_modules'],
                update.get('current_module', '')
            )
        
        elif update_type == 'complete':
            self._on_scan_complete(update)
        
        elif update_type == 'error':
            messagebox.showerror("Scan Error", update.get('message', 'Unknown error'))
            self._reset_ui()
    
    def _start_scan(self):
        """Start vulnerability scan."""
        url = self.url_var.get().strip()
        
        # Validate URL
        valid, result = validate_url(url)
        if not valid:
            messagebox.showerror("Invalid URL", result)
            return
        
        url = result  # Use normalized URL
        
        # Update UI
        self.is_scanning = True
        self.start_btn.pack_forget()
        self.stop_btn.pack(side=tk.LEFT)
        self.url_entry.config(state=tk.DISABLED)
        self.report_btn.config(state=tk.DISABLED)
        self.status_var.set(f"Starting scan of {url}...")
        
        # Switch to progress tab
        self.notebook.select(0)
        
        # Reset panels
        self.progress_panel.reset()
        self.results_panel.clear()
        self.severity_dashboard.clear()
        
        # Create and start engine
        self.engine = ScanEngine(progress_callback=self._handle_progress)
        self.engine.start_scan(url)
    
    def _stop_scan(self):
        """Stop the current scan."""
        if self.engine:
            self.engine.stop_scan()
        self.status_var.set("Scan stopped by user")
        self._reset_ui()
    
    def _on_scan_complete(self, update: dict):
        """Handle scan completion."""
        self.current_result = self.engine.get_result()
        
        if self.current_result:
            # Update results panel
            self.results_panel.display_findings(self.current_result.findings)
            
            # Update dashboard
            self.severity_dashboard.update(self.current_result)
            
            # Show summary
            counts = update.get('severity_counts', {})
            duration = update.get('duration', 0)
            total = update.get('total_findings', 0)
            
            self.status_var.set(
                f"Scan complete in {duration:.1f}s - "
                f"{total} findings: {counts.get('Critical', 0)} Critical, "
                f"{counts.get('High', 0)} High, {counts.get('Medium', 0)} Medium, "
                f"{counts.get('Low', 0)} Low"
            )
            
            # Switch to results tab
            self.notebook.select(1)
        
        self._reset_ui()
        self.report_btn.config(state=tk.NORMAL)
    
    def _reset_ui(self):
        """Reset UI after scan."""
        self.is_scanning = False
        self.stop_btn.pack_forget()
        self.start_btn.pack(side=tk.LEFT)
        self.url_entry.config(state=tk.NORMAL)
    
    def _generate_report(self):
        """Generate HTML report."""
        if not self.current_result:
            messagebox.showinfo("No Results", "Run a scan first to generate a report.")
            return
        
        # Ask for save location
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html")],
            initialfile=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        
        if not filename:
            return
        
        try:
            generator = ReportGenerator()
            generator.generate_html_report(self.current_result, filename)
            
            # Ask to open
            if messagebox.askyesno("Report Generated",
                                   f"Report saved to {filename}\n\nOpen in browser?"):
                webbrowser.open(f'file://{filename}')
        
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report: {str(e)}")
    
    def _on_close(self):
        """Handle window close."""
        if self.is_scanning:
            if messagebox.askyesno("Scan in Progress",
                                   "A scan is in progress. Stop and exit?"):
                self._stop_scan()
            else:
                return
        self.root.destroy()
    
    def _on_url_focus_in(self, event):
        """Handle URL entry focus in - remove placeholder."""
        if self.url_entry.get() == "Enter target URL (e.g., example.com)":
            self.url_entry.delete(0, tk.END)
            self.url_entry.config(fg=self.colors['text'])
    
    def _on_url_focus_out(self, event):
        """Handle URL entry focus out - restore placeholder if empty."""
        if not self.url_entry.get():
            self.url_entry.insert(0, "Enter target URL (e.g., example.com)")
            self.url_entry.config(fg=self.colors['text_dim'])
    
    def run(self):
        """Start the application."""
        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - self.root.winfo_width()) // 2
        y = (self.root.winfo_screenheight() - self.root.winfo_height()) // 2
        self.root.geometry(f"+{x}+{y}")
        
        self.root.mainloop()
