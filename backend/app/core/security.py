import re
import html
import time
import threading
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta, timezone

# Hard cap on any single sanitized string (DoS guard for huge inputs).
MAX_INPUT_CHARS = 2000

# Upper bound on tracked client IPs so the in-memory limiter cannot grow
# without limit (each entry holds at most max_requests timestamps).
MAX_RATE_LIMIT_KEYS = 5000


def sanitize_input_string(value: str, max_length: int = MAX_INPUT_CHARS) -> str:
    """
    Sanitize input string by removing control characters, NULL bytes,
    truncating to max_length, and escaping potentially dangerous characters.
    """
    if not isinstance(value, str):
        return value
    # Remove null bytes & non-printable ASCII control characters
    cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
    cleaned = cleaned.strip()
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    # Escape HTML to prevent injection in UI rendering
    return html.escape(cleaned)

def is_valid_ip(ip_str: str) -> bool:
    """Simple check for IPv4 string validity."""
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ipv4_pattern, ip_str):
        return False
    parts = ip_str.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

# In-memory sliding window rate limiter state (guarded by a lock for
# multi-worker-thread safety; entries are pruned on every check).
RATE_LIMIT_STORE: Dict[str, list] = {}
_RATE_LIMIT_LOCK = threading.Lock()

RESOURCE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.:]{1,64}$")

def validate_resource_id(resource_id: str) -> bool:
    """Validate resource identifier against path traversal and malformed inputs."""
    if not resource_id or not isinstance(resource_id, str):
        return False
    return bool(RESOURCE_ID_REGEX.match(resource_id))

def check_rate_limit(
    client_ip: str,
    max_requests: int = 120,
    window_seconds: int = 60,
    key_prefix: str = "global"
) -> Tuple[bool, str]:
    """
    Sliding window rate limiting check for API endpoints with optional prefix (e.g. 'auth', 'hunt').
    Thread-safe, prunes stale entries, and bounds total tracked keys.
    """
    now = time.time()
    cutoff = now - window_seconds
    store_key = f"{key_prefix}:{client_ip}"
    with _RATE_LIMIT_LOCK:
        timestamps = RATE_LIMIT_STORE.get(store_key, [])
        # Filter timestamps within active window
        valid_timestamps = [ts for ts in timestamps if ts > cutoff]

        if len(valid_timestamps) >= max_requests:
            RATE_LIMIT_STORE[store_key] = valid_timestamps
            return False, f"Rate limit exceeded for {key_prefix}. Please wait before retrying."

        valid_timestamps.append(now)
        RATE_LIMIT_STORE[store_key] = valid_timestamps

        # Opportunistic cleanup: drop fully-expired keys and enforce key cap.
        if len(RATE_LIMIT_STORE) > MAX_RATE_LIMIT_KEYS:
            expired = [k for k, v in RATE_LIMIT_STORE.items()
                       if not v or max(v) <= cutoff]
            for k in expired:
                RATE_LIMIT_STORE.pop(k, None)
            # If still over capacity (active flood from many IPs), evict oldest.
            while len(RATE_LIMIT_STORE) > MAX_RATE_LIMIT_KEYS:
                oldest = min(RATE_LIMIT_STORE, key=lambda k: max(RATE_LIMIT_STORE[k]) if RATE_LIMIT_STORE[k] else 0)
                RATE_LIMIT_STORE.pop(oldest, None)
        return True, "OK"


def reset_rate_limit(client_ip: Optional[str] = None, key_prefix: Optional[str] = None) -> None:
    """Clear limiter state — primarily for tests."""
    with _RATE_LIMIT_LOCK:
        if client_ip is None and key_prefix is None:
            RATE_LIMIT_STORE.clear()
        else:
            for k in list(RATE_LIMIT_STORE.keys()):
                match = True
                if client_ip is not None and not (k == client_ip or k.endswith(f":{client_ip}")):
                    match = False
                if key_prefix is not None and not k.startswith(f"{key_prefix}:"):
                    match = False
                if match:
                    RATE_LIMIT_STORE.pop(k, None)

