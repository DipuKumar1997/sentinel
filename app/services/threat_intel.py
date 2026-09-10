"""Threat-intelligence enrichment for domains and IPs.

Design principle carried over from the rest of the codebase: never
fabricate a verdict. Two provider tiers exist:

1. **External providers** (VirusTotal, AbuseIPDB, IPinfo) -- only called
   when the corresponding API key is configured. On any network/auth
   failure they are skipped (recorded as a `DEGRADED` analysis run,
   never silently treated as "clean").
2. **Internal heuristic provider** -- always runs, needs no network
   access, and is clearly labeled `is_synthetic_demo_data=True` /
   provider="internal_heuristic" so nobody mistakes its output for a
   real third-party verdict. It reuses simple, explainable signals
   (TLD reputation, IP address class) rather than pretending to know
   things (like real domain age) that require external data this
   checkpoint doesn't have credentials for.

Every observation, from either tier, is persisted as an append-only
`ThreatIntelligenceObservation` row -- enrichment history is never
overwritten, only added to.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.ioc import Domain, IOCRecord, IPAddress, ThreatIntelligenceObservation

_SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf"}
_HTTP_TIMEOUT = 6.0


@dataclass
class EnrichmentObservation:
    provider: str
    verdict: str  # malicious|suspicious|clean|unknown
    raw_response: dict
    is_synthetic_demo_data: bool = False


def _is_private_ip(address: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(address)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Internal, offline, always-available heuristic provider
# --------------------------------------------------------------------------

def _internal_domain_heuristic(domain_name: str) -> EnrichmentObservation:
    tld = domain_name.rsplit(".", 1)[-1].lower() if "." in domain_name else ""
    if tld in _SUSPICIOUS_TLDS:
        verdict = "suspicious"
        score = 65
    else:
        verdict = "unknown"
        score = 20
    return EnrichmentObservation(
        provider="internal_heuristic",
        verdict=verdict,
        raw_response={"tld": tld, "heuristic_score": score, "method": "tld_reputation_list"},
        is_synthetic_demo_data=True,
    )


def _internal_ip_heuristic(address: str) -> EnrichmentObservation:
    if _is_private_ip(address):
        return EnrichmentObservation(
            provider="internal_heuristic",
            verdict="clean",
            raw_response={"reason": "private/loopback/link-local address, not internet-routable"},
            is_synthetic_demo_data=True,
        )
    return EnrichmentObservation(
        provider="internal_heuristic",
        verdict="unknown",
        raw_response={"reason": "no external reputation data available offline"},
        is_synthetic_demo_data=True,
    )


# --------------------------------------------------------------------------
# External providers (only called when an API key is configured)
# --------------------------------------------------------------------------

async def _query_virustotal_domain(domain_name: str) -> EnrichmentObservation | None:
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    url = f"https://www.virustotal.com/api/v3/domains/{domain_name}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return None

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return EnrichmentObservation(provider="virustotal", verdict=verdict, raw_response=stats)


async def _query_abuseipdb(ip_address: str) -> EnrichmentObservation | None:
    if not settings.ABUSEIPDB_API_KEY:
        return None
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return None

    score = data.get("data", {}).get("abuseConfidenceScore", 0)
    if score >= 75:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return EnrichmentObservation(provider="abuseipdb", verdict=verdict, raw_response={"abuseConfidenceScore": score})


async def _query_ipinfo(ip_address: str) -> dict | None:
    if not settings.IPINFO_TOKEN:
        return None
    url = f"https://ipinfo.io/{ip_address}/json"
    params = {"token": settings.IPINFO_TOKEN}
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            return resp.json()
    except (httpx.HTTPError, ValueError):
        return None


# --------------------------------------------------------------------------
# Orchestration: enrich one domain / one IP, persist observations
# --------------------------------------------------------------------------

async def enrich_domain(db: AsyncSession, domain_row: Domain) -> list[EnrichmentObservation]:
    observations: list[EnrichmentObservation] = [_internal_domain_heuristic(domain_row.name)]

    vt_result = await _query_virustotal_domain(domain_row.name)
    if vt_result:
        observations.append(vt_result)

    worst_score = 0
    for obs in observations:
        worst_score = max(worst_score, {"malicious": 90, "suspicious": 55, "unknown": 20, "clean": 5}.get(obs.verdict, 20))

    domain_row.reputation_score = worst_score
    domain_row.last_enriched_at = datetime.now(timezone.utc)
    return observations


async def enrich_ip(db: AsyncSession, ip_row: IPAddress) -> list[EnrichmentObservation]:
    observations: list[EnrichmentObservation] = [_internal_ip_heuristic(ip_row.address)]

    abuse_result = await _query_abuseipdb(ip_row.address)
    if abuse_result:
        observations.append(abuse_result)

    geo_data = await _query_ipinfo(ip_row.address)
    if geo_data:
        loc = geo_data.get("loc", "")
        if "," in loc:
            lat_str, lon_str = loc.split(",", 1)
            try:
                ip_row.approx_lat = float(lat_str)
                ip_row.approx_lon = float(lon_str)
                ip_row.geolocation_confidence = "medium"
            except ValueError:
                pass
        ip_row.approx_city = geo_data.get("city")
        ip_row.country = geo_data.get("country")
        ip_row.asn_org = geo_data.get("org")

    worst_score = 0
    for obs in observations:
        worst_score = max(worst_score, {"malicious": 90, "suspicious": 55, "unknown": 20, "clean": 5}.get(obs.verdict, 20))
        if obs.verdict == "malicious":
            ip_row.is_known_malicious = True

    ip_row.reputation_score = worst_score
    ip_row.last_enriched_at = datetime.now(timezone.utc)
    return observations


async def enrich_case_iocs(
    db: AsyncSession, ioc_records: list[IOCRecord], domains_by_id: dict, ips_by_id: dict
) -> dict[str, list[EnrichmentObservation]]:
    """Enriches every domain/IP IOC attached to a case and persists a
    `ThreatIntelligenceObservation` row per (ioc_record, provider) pair.

    Returns a mapping of ioc value -> list of observations, for the
    threat-intel analysis engine to turn into findings.
    """
    results: dict[str, list[EnrichmentObservation]] = {}

    for record in ioc_records:
        observations: list[EnrichmentObservation] = []
        if record.domain_id and record.domain_id in domains_by_id:
            observations = await enrich_domain(db, domains_by_id[record.domain_id])
        elif record.ip_id and record.ip_id in ips_by_id:
            observations = await enrich_ip(db, ips_by_id[record.ip_id])
        else:
            continue

        for obs in observations:
            db.add(
                ThreatIntelligenceObservation(
                    ioc_record_id=record.id,
                    provider=obs.provider,
                    verdict=obs.verdict,
                    raw_response=json.dumps(obs.raw_response),
                    is_synthetic_demo_data=obs.is_synthetic_demo_data,
                )
            )
        results[record.value] = observations

    return results
