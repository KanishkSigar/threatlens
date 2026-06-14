"""
SSL Certificate Checker Service
Validates SSL certificates and extracts certificate metadata.
Invalid or missing SSL certificates are a phishing indicator.
"""

import asyncio
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional


async def check_ssl_certificate(hostname: str) -> dict:
    """
    Check the SSL certificate of a hostname.
    Returns certificate validity, issuer, and expiration info.
    """
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _check_ssl_sync, hostname)
        return result
    except Exception:
        return {
            "valid": False,
            "issuer": "unknown",
            "days_remaining": -1,
            "error": "SSL check failed",
        }


def _check_ssl_sync(hostname: str) -> dict:
    """Perform synchronous SSL certificate check (runs in thread pool)."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                if not cert:
                    return {"valid": False, "issuer": "unknown", "days_remaining": -1}

                # Extract issuer
                issuer_parts = dict(x[0] for x in cert.get("issuer", []))
                issuer = issuer_parts.get("organizationName", "unknown")

                # Check expiration
                not_after = cert.get("notAfter", "")
                if not_after:
                    # Parse SSL date format: 'Sep 15 12:00:00 2025 GMT'
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    expiry = expiry.replace(tzinfo=timezone.utc)
                    days_remaining = (expiry - datetime.now(timezone.utc)).days
                else:
                    days_remaining = -1

                return {
                    "valid": True,
                    "issuer": issuer,
                    "days_remaining": days_remaining,
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                }

    except ssl.SSLCertVerificationError:
        return {"valid": False, "issuer": "invalid", "days_remaining": -1, "error": "Certificate verification failed"}
    except socket.timeout:
        return {"valid": False, "issuer": "unknown", "days_remaining": -1, "error": "Connection timeout"}
    except ConnectionRefusedError:
        return {"valid": False, "issuer": "unknown", "days_remaining": -1, "error": "Connection refused"}
    except Exception as e:
        return {"valid": False, "issuer": "unknown", "days_remaining": -1, "error": str(e)}
