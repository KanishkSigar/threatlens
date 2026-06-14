"""
DNS Analyzer Service
Analyzes DNS records for a domain to detect suspicious configurations.
Domains without proper DNS records are often used for phishing.
"""

import asyncio
from typing import Optional

import dns.resolver
import dns.exception


async def analyze_dns(hostname: str) -> dict:
    """
    Analyze DNS records for a hostname.
    Returns record counts and existence flags.
    """
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _dns_lookup_sync, hostname)
        return result
    except Exception:
        return {
            "has_record": False,
            "record_count": 0,
            "a_records": [],
            "mx_records": [],
            "error": "DNS lookup failed",
        }


def _dns_lookup_sync(hostname: str) -> dict:
    """Perform synchronous DNS lookup (runs in thread pool)."""
    result = {
        "has_record": False,
        "record_count": 0,
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "has_mx": False,
        "has_ns": False,
    }

    # A records (IP addresses)
    try:
        answers = dns.resolver.resolve(hostname, "A")
        a_records = [str(rdata) for rdata in answers]
        result["a_records"] = a_records
        result["record_count"] += len(a_records)
        result["has_record"] = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        pass

    # MX records (mail servers)
    try:
        answers = dns.resolver.resolve(hostname, "MX")
        mx_records = [str(rdata.exchange) for rdata in answers]
        result["mx_records"] = mx_records
        result["record_count"] += len(mx_records)
        result["has_mx"] = len(mx_records) > 0
        result["has_record"] = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        pass

    # NS records (name servers)
    try:
        answers = dns.resolver.resolve(hostname, "NS")
        ns_records = [str(rdata) for rdata in answers]
        result["ns_records"] = ns_records
        result["record_count"] += len(ns_records)
        result["has_ns"] = len(ns_records) > 0
        result["has_record"] = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        pass

    return result
