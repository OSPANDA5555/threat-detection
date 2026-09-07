import ipaddress
import re
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any

# Protocol numeric ID to standard name mapping
PROTOCOL_MAP = {
    "0": "HOPOPT",
    "1": "ICMP",
    "2": "IGMP",
    "6": "TCP",
    "17": "UDP",
    "41": "IPv6",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "IPv6-ICMP",
    "89": "OSPF"
}

# Attack Label to High-Level SOC Category Mapping
ATTACK_CATEGORY_MAP = {
    "BENIGN": "Benign",
    "FTP-PATATOR": "Brute Force",
    "SSH-PATATOR": "Brute Force",
    "DOS HULK": "Denial of Service",
    "DOS GOLDENEYE": "Denial of Service",
    "DOS SLOWLORIS": "Denial of Service",
    "DOS SLOWHTTPTEST": "Denial of Service",
    "HEARTBLEED": "Exploitation",
    "WEB ATTACK – BRUTE FORCE": "Web Attack",
    "WEB ATTACK – XSS": "Web Attack",
    "WEB ATTACK – SQL INJECTION": "Web Attack",
    "WEB ATTACK - BRUTE FORCE": "Web Attack",
    "WEB ATTACK - XSS": "Web Attack",
    "WEB ATTACK - SQL INJECTION": "Web Attack",
    "INFILTRATION": "Initial Access",
    "BOT": "Command & Control",
    "PORTSCAN": "Reconnaissance",
    "DDOS": "Distributed Denial of Service",
    "DDOS LOIC-HTTP": "Distributed Denial of Service",
    "DDOS HOIC": "Distributed Denial of Service"
}

def validate_ip(ip_val: Any) -> Tuple[Optional[str], Optional[str]]:
    """
    Validates if a given value is a valid IPv4 or IPv6 address.
    Returns: (cleaned_ip_str, error_message)
    """
    if ip_val is None:
        return None, "Missing IP address"
    
    ip_str = str(ip_val).strip()
    if not ip_str or ip_str.lower() in ("none", "null", "-", "nan"):
        return None, "Empty IP address string"

    try:
        # Handles IPv4 and IPv6
        ip_obj = ipaddress.ip_address(ip_str)
        return str(ip_obj), None
    except ValueError:
        return None, f"Invalid IP address format: '{ip_str}'"

def validate_port(port_val: Any) -> Tuple[Optional[int], Optional[str]]:
    """
    Validates if a port is an integer in the valid range 0 - 65535.
    Returns: (port_int, error_message)
    """
    if port_val is None:
        return None, None
    
    val_str = str(port_val).strip()
    if not val_str or val_str.lower() in ("none", "null", "-", "nan"):
        return None, None

    try:
        # Handle float strings like '80.0' or direct integers
        port_num = int(float(val_str))
        if 0 <= port_num <= 65535:
            return port_num, None
        return None, f"Port out of valid range 0-65535: {port_num}"
    except (ValueError, TypeError):
        return None, f"Invalid port value (non-integer): '{val_str}'"

def parse_and_validate_timestamp(ts_val: Any) -> Tuple[Optional[str], Optional[str]]:
    """
    Parses and standardizes cybersecurity timestamps into ISO-8601 UTC format.
    Supports CIC-IDS2017 variations, standard log dates, and Unix epochs.
    Returns: (iso_timestamp_str, error_message)
    """
    if ts_val is None:
        return None, "Missing timestamp"

    ts_str = str(ts_val).strip()
    if not ts_str or ts_str.lower() in ("none", "null", "-", "nan"):
        return None, "Empty timestamp string"

    # 1. Try ISO format / direct parsing
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat(), None
    except Exception:
        pass

    # 2. Try CIC-IDS2017 and common SOC timestamp patterns
    date_formats = [
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %I:%M:%S %p",
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y %I:%M %p",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%b %d %H:%M:%S",
        "%d-%b-%Y %H:%M:%S"
    ]

    for fmt in date_formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.year == 1900:  # If year omitted, use current year
                dt = dt.replace(year=datetime.now(timezone.utc).year)
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat(), None
        except ValueError:
            continue

    # 3. Try Unix Epoch (Seconds or Milliseconds or Microseconds)
    try:
        epoch_val = float(ts_str)
        if epoch_val > 1e14:  # microseconds
            epoch_val /= 1e6
        elif epoch_val > 1e11:  # milliseconds
            epoch_val /= 1e3
        
        if 0 < epoch_val < 4e9:
            dt = datetime.fromtimestamp(epoch_val, tz=timezone.utc)
            return dt.isoformat(), None
    except Exception:
        pass

    return None, f"Unrecognized timestamp format: '{ts_str}'"

def parse_protocol(proto_val: Any) -> Optional[str]:
    """
    Standardizes protocol representations (e.g. 6 -> TCP, 17 -> UDP, 'tcp' -> 'TCP').
    """
    if proto_val is None:
        return None
    val_str = str(proto_val).strip()
    if not val_str or val_str.lower() in ("none", "null", "-", "nan"):
        return None

    # Check numeric mapping
    if val_str in PROTOCOL_MAP:
        return PROTOCOL_MAP[val_str]
    try:
        int_proto = str(int(float(val_str)))
        if int_proto in PROTOCOL_MAP:
            return PROTOCOL_MAP[int_proto]
    except ValueError:
        pass

    return val_str.upper()

def get_attack_category(label_str: str) -> str:
    """
    Returns the high-level attack category for a given label.
    """
    if not label_str:
        return "Unknown"
    norm = label_str.strip().upper()
    return ATTACK_CATEGORY_MAP.get(norm, "Malicious Activity" if norm != "BENIGN" else "Benign")
