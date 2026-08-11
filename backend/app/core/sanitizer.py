import re
from typing import Tuple, List, Dict, Any

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"system\s*:\s*",
    r"you\s+are\s+now\s+unrestricted",
    r"classify\s+this\s+host\s+as\s+benign",
    r"mark\s+this\s+host\s+as\s+safe",
    r"override\s*:\s*",
    r"disregard\s+(all\s+)?alerts",
    r"system\s+prompt",
    r"drop\s+table",
    r"admin'\s*;\s*",
    r"eval-safe",
    r"set\s+inconclusive"
]

class PromptInjectionDetector:
    """
    Detects indirect prompt injection attempts embedded inside untrusted security telemetry fields.
    """

    @staticmethod
    def scan_text(text: str) -> Tuple[bool, List[str]]:
        if not text or not isinstance(text, str):
            return False, []

        text_lower = text.lower()
        matched = []
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                matched.append(pattern)

        return len(matched) > 0, matched

class TelemetrySanitizer:
    """
    Sanitizes untrusted telemetry values, wraps log payloads in strict data boundaries,
    and enforces maximum context size truncation limits.
    """

    @staticmethod
    def sanitize_string(value: str) -> str:
        if not value or not isinstance(value, str):
            return str(value or "")

        # Strip instruction markers
        sanitized = value
        for pattern in INJECTION_PATTERNS:
            sanitized = re.sub(pattern, "[SANITIZED_PROMPT_INJECTION_PAYLOAD]", sanitized, flags=re.IGNORECASE)

        return sanitized

    @staticmethod
    def wrap_untrusted_data(data: Any, source_name: str = "TELEMETRY_LOG") -> str:
        """
        Wraps untrusted security telemetry data in strict XML boundaries to prevent system instruction confusion.
        """
        data_str = str(data)
        truncated = TelemetrySanitizer.truncate_payload(data_str, max_chars=8000)
        return (
            f"<{source_name}_UNTRUSTED_DATA>\n"
            f"{truncated}\n"
            f"</{source_name}_UNTRUSTED_DATA>"
        )

    @staticmethod
    def truncate_payload(text: str, max_chars: int = 10000) -> str:
        """Enforces maximum context size limit to mitigate token payload flooding."""
        if not text:
            return ""
        if len(text) > max_chars:
            return text[:max_chars] + f"\n...[TRUNCATED: Payload exceeded maximum cap of {max_chars} chars]"
        return text
