"""
Progress panel for displaying real-time scan progress.
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict


class ProgressPanel:
    """Panel showing scan progress and module status."""
    
    def __init__(self, parent, colors: Dict[str, str]):
        self.parent = parent
        self.colors = colors
        self.module_widgets: Dict[str, Dict] = {}
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create progress widgets."""
        # Overall progress section
        overall_frame = tk.Frame(self.parent, bg=self.colors['bg_secondary'])
        overall_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Overall label
        self.overall_label = tk.Label(
            overall_frame,
            text="Overall Progress: 0%",
            bg=self.colors['bg_secondary'],
            fg=self.colors['text'],
            font=('Segoe UI', 12, 'bold')
        )
        self.overall_label.pack(anchor=tk.W, padx=10, pady=5)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(
            overall_frame,
            style='Green.Horizontal.TProgressbar',
            length=400,
            mode='determinate'
        )
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
        
        # Current action label
        self.action_label = tk.Label(
            overall_frame,
            text="Ready to scan",
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_dim'],
            font=('Segoe UI', 10)
        )
        self.action_label.pack(anchor=tk.W, padx=10, pady=(0, 10))
        
        # Separator
        ttk.Separator(self.parent, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        # Module status section
        tk.Label(
            self.parent,
            text="Module Status",
            bg=self.colors['bg'],
            fg=self.colors['text'],
            font=('Segoe UI', 11, 'bold')
        ).pack(anchor=tk.W, padx=10, pady=5)
        
        # Scrollable module list
        canvas_frame = tk.Frame(self.parent, bg=self.colors['bg'])
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=10)
        
        self.canvas = tk.Canvas(canvas_frame, bg=self.colors['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL, command=self.canvas.yview)
        
        self.modules_frame = tk.Frame(self.canvas, bg=self.colors['bg'])
        
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.canvas_window = self.canvas.create_window((0, 0), window=self.modules_frame, anchor=tk.NW)
        
        self.modules_frame.bind('<Configure>', self._on_frame_configure)
        self.canvas.bind('<Configure>', self._on_canvas_configure)
        
        # Bind mouse wheel for scrolling
        self.canvas.bind('<Enter>', self._bind_mousewheel)
        self.canvas.bind('<Leave>', self._unbind_mousewheel)
    
    def _on_frame_configure(self, event):
        """Update scroll region when frame size changes."""
        self.canvas.configure(scrollregion=self.canvas.bbox('all'))
    
    def _on_canvas_configure(self, event):
        """Update canvas window width when canvas size changes."""
        self.canvas.itemconfig(self.canvas_window, width=event.width)
    
    def _bind_mousewheel(self, event):
        """Bind mouse wheel when mouse enters canvas."""
        self.canvas.bind_all('<MouseWheel>', self._on_mousewheel)
    
    def _unbind_mousewheel(self, event):
        """Unbind mouse wheel when mouse leaves canvas."""
        self.canvas.unbind_all('<MouseWheel>')
    
    def _on_mousewheel(self, event):
        """Handle mouse wheel scroll."""
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')
    
    def update_overall(self, percent: float, completed: int, total: int, current: str):
        """Update overall progress."""
        self.progress_bar['value'] = percent
        self.overall_label.config(text=f"Overall Progress: {percent:.1f}% ({completed}/{total} modules)")
        if current:
            self.action_label.config(text=f"Running: {current}")
    
    def update_module(self, module_name: str, status: str, action: str, findings: int):
        """Update module status."""
        if module_name not in self.module_widgets:
            self._add_module_widget(module_name)
        
        widgets = self.module_widgets[module_name]
        
        # Update status icon
        if status == 'Completed':
            icon = '✅'
            color = self.colors['success']
        elif status == 'Running':
            icon = '🔄'
            color = self.colors['medium']
        elif status == 'Error':
            icon = '❌'
            color = self.colors['critical']
        else:
            icon = '⏳'
            color = self.colors['text_dim']
        
        widgets['icon'].config(text=icon)
        widgets['status'].config(text=status, fg=color)
        widgets['action'].config(text=action if action else '-')
        widgets['findings'].config(text=str(findings))
    
    def _add_module_widget(self, module_name: str):
        """Add a module row to the display."""
        row_frame = tk.Frame(self.modules_frame, bg=self.colors['bg_secondary'])
        row_frame.pack(fill=tk.X, pady=2)
        
        # Icon
        icon_label = tk.Label(
            row_frame, text='⏳',
            bg=self.colors['bg_secondary'],
            fg=self.colors['text'],
            font=('Segoe UI', 12),
            width=3
        )
        icon_label.pack(side=tk.LEFT, padx=5)
        
        # Module name
        name_label = tk.Label(
            row_frame, text=module_name,
            bg=self.colors['bg_secondary'],
            fg=self.colors['text'],
            font=('Segoe UI', 10),
            width=30,
            anchor=tk.W
        )
        name_label.pack(side=tk.LEFT, padx=5)
        
        # Status
        status_label = tk.Label(
            row_frame, text='Pending',
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_dim'],
            font=('Segoe UI', 10),
            width=12
        )
        status_label.pack(side=tk.LEFT, padx=5)
        
        # Action
        action_label = tk.Label(
            row_frame, text='-',
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_dim'],
            font=('Segoe UI', 9),
            width=30,
            anchor=tk.W
        )
        action_label.pack(side=tk.LEFT, padx=5)
        
        # Findings count
        findings_label = tk.Label(
            row_frame, text='0',
            bg=self.colors['bg_secondary'],
            fg=self.colors['text'],
            font=('Segoe UI', 10, 'bold'),
            width=5
        )
        findings_label.pack(side=tk.RIGHT, padx=10)
        
        tk.Label(
            row_frame, text='Findings:',
            bg=self.colors['bg_secondary'],
            fg=self.colors['text_dim'],
            font=('Segoe UI', 9)
        ).pack(side=tk.RIGHT)
        
        self.module_widgets[module_name] = {
            'frame': row_frame,
            'icon': icon_label,
            'name': name_label,
            'status': status_label,
            'action': action_label,
            'findings': findings_label
        }
    
    def reset(self):
        """Reset the progress panel."""
        self.progress_bar['value'] = 0
        self.overall_label.config(text="Overall Progress: 0%")
        self.action_label.config(text="Initializing...")
        
        # Clear module widgets
        for name, widgets in self.module_widgets.items():
            widgets['frame'].destroy()
        self.module_widgets.clear()
