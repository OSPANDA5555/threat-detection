import re
import html
import time
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta, timezone

def sanitize_input_string(value: str) -> str:
    """
    Sanitize input string by removing control characters, NULL bytes,
    and escaping potentially dangerous characters.
    """
    if not isinstance(value, str):
        return value
    # Remove null bytes & non-printable ASCII control characters
    cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
    # Escape HTML to prevent injection in UI rendering
    return html.escape(cleaned.strip())

def is_valid_ip(ip_str: str) -> bool:
    """Simple check for IPv4 string validity."""
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ipv4_pattern, ip_str):
        return False
    parts = ip_str.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

# In-memory sliding window rate limiter state
RATE_LIMIT_STORE: Dict[str, list] = {}

def check_rate_limit(client_ip: str, max_requests: int = 120, window_seconds: int = 60) -> Tuple[bool, str]:
    """
    Sliding window rate limiting check for API endpoints.
    """
    now = time.time()
    cutoff = now - window_seconds
    timestamps = RATE_LIMIT_STORE.get(client_ip, [])
    # Filter timestamps within active window
    valid_timestamps = [ts for ts in timestamps if ts > cutoff]
    
    if len(valid_timestamps) >= max_requests:
        return False, "Rate limit exceeded. Please wait before retrying."

    valid_timestamps.append(now)
    RATE_LIMIT_STORE[client_ip] = valid_timestamps
    return True, "OK"
