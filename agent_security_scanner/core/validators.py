"""
Input validation utilities for Agent Security Scanner.

Provides validation functions for URLs, paths, and other user inputs
to prevent injection attacks and ensure safe operations.

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse


# Blocked hostnames and address ranges
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}

# AWS metadata endpoint range (169.254.169.254)
AWS_METADATA_CIDR = "169.254.169.254/32"

# Google Cloud metadata endpoint
GCP_METADATA_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.google.internal.",
}

# Azure metadata endpoint
AZURE_METADATA_HOSTNAME = "169.254.169.254"

# Blocked schemes
ALLOWED_URL_SCHEMES = {"http", "https"}


class ValidationError(Exception):
    """Raised when input validation fails."""

    pass


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a URL for safety (SSRF protection).

    Checks:
    - URL scheme is http or https
    - Hostname is not localhost or similar
    - IP address is not private, loopback, or link-local
    - Hostname is not a cloud metadata endpoint

    Args:
        url: URL to validate

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is None.
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string"

    # Limit URL length to prevent DoS
    if len(url) > 2048:
        return False, "URL exceeds maximum length of 2048 characters"

    try:
        parsed = urlparse(url)

        # Check scheme
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_URL_SCHEMES:
            return False, f"URL scheme must be http or https, got '{scheme}'"

        # Check netloc (host)
        host = parsed.netloc
        if not host:
            return False, "URL must have a host component"

        # Remove port if present
        if ":" in host:
            host = host.rsplit(":", 1)[0]

        # Check for localhost variants
        if host.lower() in BLOCKED_HOSTNAMES:
            return False, f"Host '{host}' is not allowed (localhost)"

        # Check for empty host after port removal
        if not host:
            return False, "URL must have a valid host"

        # Check if host is an IP address
        try:
            ip_addr = ipaddress.ip_address(host)

            # Block loopback
            if ip_addr.is_loopback:
                return False, f"IP address {ip_addr} is loopback and not allowed"

            # Block private addresses
            if ip_addr.is_private:
                return False, f"IP address {ip_addr} is private and not allowed"

            # Block link-local (includes169.254.x.x which is AWS metadata)
            if ip_addr.is_link_local:
                return False, f"IP address {ip_addr} is link-local and not allowed"

            # Block multicast
            if ip_addr.is_multicast:
                return False, f"IP address {ip_addr} is multicast and not allowed"

            # Block reserved
            if ip_addr.is_reserved:
                return False, f"IP address {ip_addr} is reserved and not allowed"

        except ValueError:
            # Not an IP address, treat as hostname
            hostname = host.lower()

            # Remove trailing dot
            if hostname.endswith("."):
                hostname = hostname[:-1]

            # Check blocked hostnames
            if hostname in BLOCKED_HOSTNAMES:
                return False, f"Host '{host}' is not allowed"

            # Check GCP metadata
            if hostname in GCP_METADATA_HOSTNAMES:
                return False, f"Host '{host}' is a GCP metadata endpoint"

            # Check Azure metadata
            if hostname == AZURE_METADATA_HOSTNAME:
                return False, f"Host '{host}' is an Azure metadata endpoint"

            # Check for AWS metadata via IP (already caught by link-local)
            # but also check if hostname looks like it
            if host == "169.254.169.254":
                return False, f"Host '{host}' is an AWS metadata endpoint"

            # Check for internal hostnames
            internal_patterns = [
                r"^.*\.internal$",
                r"^.*\.private$",
                r"^.*\.local$",
                r"^.*\.localhost$",
                r"^metadata[0-9]*\.googleapis\.com$",
            ]
            for pattern in internal_patterns:
                if re.match(pattern, hostname, re.IGNORECASE):
                    return False, f"Host '{host}' appears to be an internal endpoint"

        return True, None

    except Exception as e:
        return False, f"Invalid URL format: {str(e)}"


def validate_path(path: str, base_dir: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Validate a file path for safety (path traversal protection).

    Checks:
    - Path doesn't contain traversal sequences (.., ./)
    - Path doesn't escape base_dir when base_dir is provided
    - Path is not an absolute path when relative is expected

    Args:
        path: Path to validate
        base_dir: Optional base directory to restrict path within

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is None.
    """
    if not path or not isinstance(path, str):
        return False, "Path must be a non-empty string"

    # Block actual path traversal sequences - not just dots
    # The key pattern is "../" or "..\\" or trailing ".."
    normalized = path.replace("\\", "/")

    # Check for path traversal: ".." followed by "/" or end of string
    if ".." in normalized:
        # Make sure it's actually a traversal and not just "output.." or something
        import re
        if re.search(r'\.\.(?:/|$)', normalized):
            return False, "Path contains forbidden traversal sequence '..'"

    # If base_dir is provided, verify path stays within it
    if base_dir:
        import os.path
        try:
            base_resolved = os.path.abspath(base_dir)
            path_resolved = os.path.abspath(os.path.join(base_dir, path))

            # Ensure path is within base_dir
            if not path_resolved.startswith(base_resolved + os.sep) and path_resolved != base_resolved:
                return False, f"Path escapes base directory '{base_dir}'"
        except Exception as e:
            return False, f"Error validating path: {str(e)}"

    return True, None


def validate_module_name(name: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a module name for safety.

    Module names must be alphanumeric with underscores only.

    Args:
        name: Module name to validate

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not name or not isinstance(name, str):
        return False, "Module name must be a non-empty string"

    if len(name) > 64:
        return False, "Module name exceeds maximum length of 64 characters"

    if not re.match(r"^[a-zA-Z0-9_]+$", name):
        return False, "Module name must contain only alphanumeric characters and underscores"

    return True, None


def sanitize_for_json(value: str, max_length: int = 10000) -> str:
    """
    Sanitize a string value for safe inclusion in JSON output.

    Removes or escapes potentially dangerous characters.

    Args:
        value: String to sanitize
        max_length: Maximum length to allow

    Returns:
        Sanitized string safe for JSON.
    """
    if not isinstance(value, str):
        value = str(value)

    # Truncate if too long
    if len(value) > max_length:
        value = value[:max_length] + "... [truncated]"

    # Remove null bytes
    value = value.replace("\x00", "")

    return value
