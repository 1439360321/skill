"""CWE mapper — maps vulnerability type strings to CWE IDs."""

from __future__ import annotations


class CWEMapper:
    """Map vulnerability descriptions to standard CWE identifiers."""

    # Primary mapping: NORMALISED string → CWE-XXX
    _MAP: dict[str, str] = {
        # Injection
        "sql injection": "CWE-89",
        "sql_injection": "CWE-89",
        "command injection": "CWE-78",
        "command_injection": "CWE-78",
        "os command injection": "CWE-78",
        "code injection": "CWE-94",
        "code_injection": "CWE-94",
        "xss": "CWE-79",
        "cross-site scripting": "CWE-79",
        "cross site scripting": "CWE-79",
        "ldap injection": "CWE-90",
        "xpath injection": "CWE-643",
        "xml injection": "CWE-91",
        "xxe": "CWE-611",
        "xml external entity": "CWE-611",
        # Memory
        "buffer overflow": "CWE-120",
        "buffer_overflow": "CWE-120",
        "stack buffer overflow": "CWE-121",
        "heap buffer overflow": "CWE-122",
        "out-of-bounds read": "CWE-125",
        "out-of-bounds write": "CWE-787",
        "format string": "CWE-134",
        "format_string": "CWE-134",
        "use after free": "CWE-416",
        "use_after_free": "CWE-416",
        "double free": "CWE-415",
        "double_free": "CWE-415",
        "null pointer": "CWE-476",
        "null_pointer_dereference": "CWE-476",
        "integer overflow": "CWE-190",
        "integer_overflow": "CWE-190",
        # Path / file
        "path traversal": "CWE-22",
        "path_traversal": "CWE-22",
        "directory traversal": "CWE-22",
        "arbitrary file read": "CWE-22",
        "arbitrary file write": "CWE-22",
        # Auth / access
        "hardcoded credentials": "CWE-798",
        "hardcoded password": "CWE-798",
        "hardcoded key": "CWE-321",
        "missing authentication": "CWE-306",
        "privilege escalation": "CWE-269",
        # Crypto
        "weak cryptography": "CWE-327",
        "weak encryption": "CWE-327",
        "insufficient key size": "CWE-326",
        # Deserialization
        "deserialization": "CWE-502",
        "insecure deserialization": "CWE-502",
        "unsafe deserialization": "CWE-502",
        # SSRF
        "ssrf": "CWE-918",
        "server-side request forgery": "CWE-918",
        # Race
        "race condition": "CWE-362",
        "time of check time of use": "CWE-367",
        "toctou": "CWE-367",
        # Resource
        "resource exhaustion": "CWE-400",
        "denial of service": "CWE-400",
        "memory leak": "CWE-401",
    }

    @classmethod
    def map_to_cwe(cls, vuln_type: str) -> tuple[str, float]:
        """Return ``(CWE-XXX, confidence)`` for a vulnerability type string."""
        if not vuln_type or vuln_type == "UNKNOWN":
            return ("UNKNOWN", 0.0)

        # Direct CWE match
        if vuln_type.upper().startswith("CWE-"):
            return (vuln_type.upper(), 0.9)

        # Normalise and try exact match
        norm = vuln_type.lower().strip()
        if norm in cls._MAP:
            return (cls._MAP[norm], 0.85)

        # Fuzzy match
        for key, cwe in cls._MAP.items():
            if key in norm or norm in key:
                return (cwe, 0.7)

        return (vuln_type, 0.3)
