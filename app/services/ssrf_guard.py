"""SSRF guard for server-side fetches of user-supplied URLs.

Used by endpoints that fetch an administrator-supplied base_url
(e.g. AI provider test-connection).  Validates that the URL cannot be
used to probe the internal network:

  - scheme must be http or https (no file://, gopher://, etc.)
  - no credentials (userinfo) embedded in the URL
  - hostname must resolve via DNS, and NONE of the resolved IPs may be
    private, loopback, link-local, multicast, or otherwise reserved
    (this blocks 169.254.169.254 and RFC1918 targets even behind DNS)

Raises SSRFBlockedError with a safe message on any violation.
"""

import ipaddress
import socket
from urllib.parse import urlparse


class SSRFBlockedError(ValueError):
    """Raised when a URL fails SSRF validation."""
    pass


def validate_outbound_url(raw_url: str, *, field_name: str = "URL") -> str:
    """Validate a user-supplied URL for safe server-side fetching.

    Returns the normalized URL (scheme + host + port + path, no
    credentials, no fragment) on success.

    Raises:
        SSRFBlockedError: if the URL is malformed or points at a
            non-public target.
    """
    url = (raw_url or "").strip()
    if not url:
        raise SSRFBlockedError(f"{field_name} is empty.")

    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise SSRFBlockedError(f"{field_name} is not a valid URL.") from exc

    if parsed.scheme not in ("http", "https"):
        raise SSRFBlockedError(
            f"{field_name} must use http:// or https://."
        )

    if parsed.username or parsed.password:
        raise SSRFBlockedError(
            f"{field_name} must not contain credentials."
        )

    host = (parsed.hostname or "").strip()
    if not host:
        raise SSRFBlockedError(f"{field_name} has no hostname.")

    # Resolve and check every IP the hostname maps to (DNS rebinding
    # protection: block if ANY resolved address is non-public).
    try:
        addr_infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC,
                                        type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFBlockedError(
            f"{field_name} hostname could not be resolved."
        ) from exc

    ips = {info[4][0] for info in addr_infos}
    if not ips:
        raise SSRFBlockedError(f"{field_name} hostname could not be resolved.")

    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise SSRFBlockedError(
                f"{field_name} resolved to an invalid address."
            ) from exc
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise SSRFBlockedError(
                f"{field_name} must point to a public address "
                f"(resolved to a non-public IP)."
            )

    # Rebuild without fragment; userinfo already rejected above.
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    return normalized.rstrip("/")
