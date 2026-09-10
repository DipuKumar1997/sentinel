"""DNS/reverse-DNS forensics: passive DNS queries recorded append-only
per case, for domains and IPs surfaced as IOCs.

Every observation is recorded whether it succeeds or fails -- a failed
lookup produces a row with `success=False` and `error_detail` set,
never a silently missing row and never a fabricated answer. This
mirrors the project-wide rule: if it can't be determined, say so.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import dns.exception
import dns.resolver
import dns.reversename

from app.models.ioc import DNSObservation

_QUERY_TIMEOUT = 3.0


@dataclass
class DNSQueryResult:
    query_type: str
    query_name: str
    answers: list[str]
    success: bool
    ttl: int | None = None
    error_detail: str | None = None


def _run_query(query_name: str, record_type: str) -> DNSQueryResult:
    try:
        answers = dns.resolver.resolve(query_name, record_type, lifetime=_QUERY_TIMEOUT)
        values = [str(rdata).rstrip(".") for rdata in answers]
        ttl = answers.rrset.ttl if answers.rrset is not None else None
        return DNSQueryResult(query_type=record_type, query_name=query_name, answers=values, success=True, ttl=ttl)
    except dns.resolver.NXDOMAIN:
        return DNSQueryResult(
            query_type=record_type, query_name=query_name, answers=[], success=False,
            error_detail="Domain does not exist (NXDOMAIN).",
        )
    except dns.resolver.NoAnswer:
        return DNSQueryResult(
            query_type=record_type, query_name=query_name, answers=[], success=False,
            error_detail=f"Domain exists but has no {record_type} record.",
        )
    except dns.exception.DNSException as exc:
        return DNSQueryResult(
            query_type=record_type, query_name=query_name, answers=[], success=False,
            error_detail=f"DNS query failed: {exc}",
        )


def query_domain_records(domain: str, record_types: tuple[str, ...] = ("A", "MX", "NS", "TXT")) -> list[DNSQueryResult]:
    return [_run_query(domain, rtype) for rtype in record_types]


def query_ptr(ip_address: str) -> DNSQueryResult:
    try:
        rev_name = dns.reversename.from_address(ip_address)
    except (ValueError, dns.exception.SyntaxError) as exc:
        return DNSQueryResult(
            query_type="PTR", query_name=ip_address, answers=[], success=False,
            error_detail=f"Could not construct reverse-DNS name: {exc}",
        )
    return _run_query(str(rev_name), "PTR")


def persist_observation(case_id: uuid.UUID, result: DNSQueryResult) -> DNSObservation:
    return DNSObservation(
        case_id=case_id,
        query_type=result.query_type,
        query_name=result.query_name,
        result=json.dumps(result.answers) if result.answers else None,
        success=result.success,
        source="dnspython",
        ttl=result.ttl,
        error_detail=result.error_detail,
    )
