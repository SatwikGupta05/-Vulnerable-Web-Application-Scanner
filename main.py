"""
SOC Security Scanner - Web Vulnerability Assessment Tool

Enterprise-grade web vulnerability scanner with:
- Plugin-based architecture
- Full OWASP Top 10 coverage
- Real-time GUI progress
- CVSS-inspired severity scoring
- Professional HTML reports

Author: Security Team
Version: 1.0.0
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tkinter as tk
from gui.main_window import MainWindow


def main():
    """Application entry point."""
    # Suppress SSL warnings for testing
    import warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    
    # Create root window
    root = tk.Tk()
    
    # Set application icon (if available)
    try:
        # Windows icon
        root.iconbitmap(default='')
    except:
        pass
    
    # Create and run application
    app = MainWindow(root)
    app.run()


if __name__ == '__main__':
    main()
