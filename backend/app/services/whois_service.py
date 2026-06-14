"""
WHOIS Lookup Service
Retrieves domain registration information to determine domain age.
Young domains are a strong phishing indicator.
"""

import asyncio
from typing import Optional
from datetime import datetime, timezone

import whois


async def get_domain_age_days(hostname: str) -> Optional[int]:
    """
    Get the age of a domain in days via WHOIS lookup.
    Returns None if WHOIS data is unavailable.
    """
    try:
        # Run the blocking WHOIS lookup in a thread pool
        loop = asyncio.get_event_loop()
        domain_info = await loop.run_in_executor(None, _whois_lookup, hostname)

        if domain_info and domain_info.get("creation_date"):
            creation_date = domain_info["creation_date"]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if isinstance(creation_date, datetime):
                age = datetime.now(timezone.utc) - creation_date.replace(tzinfo=timezone.utc)
                return max(0, age.days)

        return None

    except Exception:
        return None


def _whois_lookup(hostname: str) -> Optional[dict]:
    """Perform a synchronous WHOIS lookup (runs in thread pool)."""
    try:
        # Extract the registrable domain (remove subdomains)
        parts = hostname.split(".")
        if len(parts) > 2:
            # Try the last two parts first (e.g., example.com)
            domain = ".".join(parts[-2:])
        else:
            domain = hostname

        w = whois.whois(domain)
        if w and w.domain_name:
            return {
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "registrar": w.registrar,
                "domain_name": w.domain_name,
            }
        return None

    except Exception:
        return None
