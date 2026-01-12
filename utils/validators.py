"""
Input validation utilities.
"""

import re
from urllib.parse import urlparse
from typing import Optional


def validate_url(url: str) -> tuple:
    """
    Validate URL format.
    Returns (is_valid, error_message or normalized_url)
    """
    if not url:
        return False, "URL cannot be empty"
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        
        if not parsed.netloc:
            return False, "Invalid URL format"
        
        # Basic domain validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        hostname = parsed.netloc.split(':')[0]
        
        if not re.match(domain_pattern, hostname) and not is_valid_ip(hostname):
            return False, "Invalid domain name"
        
        return True, url
    
    except Exception as e:
        return False, f"URL parsing error: {str(e)}"


def is_valid_ip(ip: str) -> bool:
    """Check if string is valid IP address."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def validate_port(port: str) -> tuple:
    """Validate port number."""
    try:
        port_int = int(port)
        if 1 <= port_int <= 65535:
            return True, port_int
        return False, "Port must be between 1-65535"
    except ValueError:
        return False, "Port must be a number"


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file system operations."""
    # Remove or replace unsafe characters
    unsafe_chars = '<>:"/\\|?*'
    for char in unsafe_chars:
        filename = filename.replace(char, '_')
    return filename[:255]  # Limit length
