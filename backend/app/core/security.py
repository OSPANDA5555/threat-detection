import re
import html
import time
import os
import threading
from urllib.parse import urlparse
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timedelta, timezone

# Hard cap on any single sanitized string (DoS guard for huge inputs).
MAX_INPUT_CHARS = 2000

# Upper bound on tracked client IPs so the in-memory limiter cannot grow
# without limit (each entry holds at most max_requests timestamps).
MAX_RATE_LIMIT_KEYS = 5000


def sanitize_input_string(value: str, max_length: int = MAX_INPUT_CHARS) -> str:
    """
    Sanitize input string by removing control characters, NULL bytes,
    truncating to max_length, and escaping potentially dangerous HTML/script characters.
    """
    if not isinstance(value, str):
        return value
    # Remove null bytes & non-printable ASCII control characters
    cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
    cleaned = cleaned.strip()
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    # Escape HTML to prevent injection in UI rendering (XSS mitigation)
    return html.escape(cleaned)


def sanitize_filename(filename: str, max_length: int = 128) -> str:
    """
    Sanitize uploaded filename by stripping directory paths (preventing path traversal),
    removing null bytes, disallowing leading dots, and permitting only safe characters.
    """
    if not filename or not isinstance(filename, str):
        return "uploaded_dataset.csv"

    # Remove null bytes & control characters
    cleaned = re.sub(r'[\x00-\x1F\x7F]', '', filename).strip()

    # Strip directory components (handles Unix / and Windows \)
    cleaned = os.path.basename(cleaned.replace("\\", "/"))

    # Remove dangerous characters, allow only alphanumeric, underscores, hyphens, and dots
    cleaned = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', cleaned)

    # Disallow leading dots to prevent hidden files or relative path confusion
    cleaned = cleaned.lstrip('.')

    if not cleaned:
        cleaned = "uploaded_dataset.csv"

    if len(cleaned) > max_length:
        # Preserve file extension if possible
        parts = cleaned.rsplit('.', 1)
        if len(parts) == 2:
            base, ext = parts
            ext = ext[:10]
            base = base[: max_length - len(ext) - 1]
            cleaned = f"{base}.{ext}"
        else:
            cleaned = cleaned[:max_length]

    return cleaned


DANGEROUS_EXTENSIONS = {
    "exe", "dll", "so", "dylib", "bin", "elf", "sh", "bash", "zsh", "bat",
    "cmd", "ps1", "vbs", "py", "pyc", "pyd", "php", "jsp", "asp", "aspx",
    "cgi", "pl", "com", "scr", "msi", "jar", "war", "hta", "vbe", "wsf"
}

def is_dangerous_executable_upload(content: bytes, filename: str) -> Tuple[bool, str]:
    """
    Inspect uploaded file content and filename to reject executable payloads,
    scripts, and binary executables.
    """
    # 1. Extension check
    fn_lower = filename.lower()
    ext = fn_lower.rsplit('.', 1)[-1] if '.' in fn_lower else ""
    if ext in DANGEROUS_EXTENSIONS:
        return True, f"File extension '.{ext}' is an executable or script type and is strictly forbidden."

    if not content:
        return False, "OK"

    # 2. Magic bytes inspection
    # Linux ELF executable
    if content.startswith(b"\x7fELF"):
        return True, "Linux ELF binary executable detected."

    # Windows PE executable (EXE / DLL / SYS)
    if content.startswith(b"MZ"):
        return True, "Windows PE binary executable detected."

    # Mach-O executable binaries (macOS / iOS)
    macho_magics = [
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe"
    ]
    for mm in macho_magics:
        if content.startswith(mm):
            return True, "Mach-O binary executable detected."

    # Unix script shebang (e.g. #!/bin/sh, #!/usr/bin/env python)
    if content.startswith(b"#!"):
        return True, "Script shebang header detected."

    # Compiled Python bytecode
    if content.startswith(b"\x61\x0d\x0d\x0a") or content.startswith(b"\x55\x0d\x0d\x0a"):
        return True, "Compiled Python bytecode detected."

    return False, "OK"


def is_valid_ip(ip_str: str) -> bool:
    """Check for valid IPv4 string format."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ipv4_pattern, ip_str.strip()):
        return False
    parts = ip_str.strip().split('.')
    return all(0 <= int(part) <= 255 for part in parts)


HOSTNAME_REGEX = re.compile(r'^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63}(?<!-))*$')

def is_valid_hostname(hostname: str) -> bool:
    """Validate RFC 1123 compliant hostname."""
    if not hostname or not isinstance(hostname, str) or len(hostname) > 253:
        return False
    return bool(HOSTNAME_REGEX.match(hostname.strip()))


USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_\-\.@]{1,64}$')

def is_valid_username(username: str) -> bool:
    """Validate username format (alphanumeric, underscores, hyphens, dots, emails)."""
    if not username or not isinstance(username, str):
        return False
    return bool(USERNAME_REGEX.match(username.strip()))


def is_valid_url(url: str) -> bool:
    """Validate HTTP/HTTPS URL and reject dangerous schemes (javascript:, file:, etc.)."""
    if not url or not isinstance(url, str) or len(url) > 2048:
        return False
    try:
        parsed = urlparse(url.strip())
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


SSRF_BLOCKED_HOSTNAMES = {
    "169.254.169.254", "metadata.google.internal", "metadata", "instance-data",
    "127.0.0.1", "localhost", "::1", "0.0.0.0"
}

def is_ssrf_blocked_target(target: str) -> bool:
    """
    Check if a target host, IP, or URL attempts Server-Side Request Forgery (SSRF)
    against cloud metadata services, link-local IPs, or loopback interfaces.
    """
    if not target or not isinstance(target, str):
        return False
    target_clean = target.strip().lower()
    
    # Check if target is a URL
    if target_clean.startswith("http://") or target_clean.startswith("https://"):
        try:
            parsed = urlparse(target_clean)
            hostname = parsed.hostname or ""
            if hostname in SSRF_BLOCKED_HOSTNAMES:
                return True
            if hostname.startswith("169.254.") or hostname.startswith("127."):
                return True
        except Exception:
            return True
    
    # Check if target is raw host/IP string
    if target_clean in SSRF_BLOCKED_HOSTNAMES:
        return True
    if target_clean.startswith("169.254.") or target_clean.startswith("127."):
        return True
    if "metadata.google" in target_clean or "169.254.169.254" in target_clean:
        return True

    return False


def is_ssrf_safe_url(url: str) -> Tuple[bool, str]:
    """
    Verify that an AI-supplied or user-supplied URL is safe from SSRF.
    """
    if not is_valid_url(url):
        return False, "Invalid URL format or unsupported scheme (must be http/https)."
    if is_ssrf_blocked_target(url):
        return False, "SSRF Violation: Access to metadata services, loopback, and internal addresses is strictly forbidden."
    return True, "OK"


# Injection detection patterns for auditing and testing
SQL_INJECTION_PATTERNS = [
    r"(?i)\b(union\s+select)\b",
    r"(?i)\b(drop\s+table)\b",
    r"(?i)\b(insert\s+into)\b",
    r"(?i)\b(delete\s+from)\b",
    r"(?i)\b(update\s+.*\s+set)\b",
    r"(?i)\b(exec\s*\(|xp_cmdshell)\b",
    r"(?i)'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+",
    r"--\s*",
    r"/\*.*?\*/"
]

def detect_sql_injection(value: str) -> bool:
    """Scan string for SQL injection markers."""
    if not value or not isinstance(value, str):
        return False
    return any(re.search(pat, value) for pat in SQL_INJECTION_PATTERNS)


COMMAND_INJECTION_PATTERNS = [
    r";\s*(cat|rm|whoami|id|sh|bash|curl|wget|nc|chmod|chown|uname)\b",
    r"\|\s*(cat|rm|whoami|id|sh|bash|curl|wget|nc)\b",
    r"&&\s*(cat|rm|whoami|id|sh|bash|curl|wget)\b",
    r"\$\([^\)]+\)",
    r"`[^`]+`"
]

def detect_command_injection(value: str) -> bool:
    """Scan string for command / shell injection markers."""
    if not value or not isinstance(value, str):
        return False
    return any(re.search(pat, value) for pat in COMMAND_INJECTION_PATTERNS)


PATH_TRAVERSAL_PATTERNS = [
    r"\.\.[/\\]",
    r"%2e%2e[/\\]",
    r"%2e%2e%2f",
    r"\0",
    r"^/etc/",
    r"^[a-zA-Z]:[/\\]"
]

def detect_path_traversal(value: str) -> bool:
    """Scan string for path traversal attempts."""
    if not value or not isinstance(value, str):
        return False
    return any(re.search(pat, value, re.IGNORECASE) for pat in PATH_TRAVERSAL_PATTERNS)


TEMPLATE_INJECTION_PATTERNS = [
    r"\{\{\s*.*?\s*\}\}",
    r"\$\{\s*.*?\s*\}",
    r"\{%\s*.*?\s*%\}",
    r"<%\s*.*?\s*%>"
]

def detect_template_injection(value: str) -> bool:
    """Scan string for Server-Side Template Injection (SSTI) expressions."""
    if not value or not isinstance(value, str):
        return False
    return any(re.search(pat, value) for pat in TEMPLATE_INJECTION_PATTERNS)


XSS_PATTERNS = [
    r"(?i)<script\b[^>]*>",
    r"(?i)javascript\s*:",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)onclick\s*=",
    r"(?i)<iframe\b",
    r"(?i)<svg\b"
]

def detect_xss(value: str) -> bool:
    """Scan string for Cross-Site Scripting (XSS) payload signatures."""
    if not value or not isinstance(value, str):
        return False
    return any(re.search(pat, value) for pat in XSS_PATTERNS)


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


