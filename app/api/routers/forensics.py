"""Forensic intelligence endpoints: earliest reliable origin, IP
infrastructure intelligence, DNS observations, on-demand domain WHOIS,
and blockchain (hash-chain) evidence-integrity verification.

All scoped to the caller's own organization exactly like every other
case-related endpoint in this codebase -- no new authorization model.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.case import Case
from app.models.evidence import EvidenceHash, EvidenceKind, EvidenceObject
from app.models.ioc import DNSObservation, Domain, IOCRecord, IOCType, IPAddress
from app.models.user import User
from app.security.deps import get_current_user
from app.services import blockchain_ledger, whois_lookup

router = APIRouter(prefix="/cases", tags=["forensics"])


async def _get_org_case(db: AsyncSession, case_id: uuid.UUID, organization_id: uuid.UUID) -> Case:
    case = await db.get(Case, case_id)
    if case is None or case.organization_id != organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return case


@router.get("/{case_id}/origin")
async def get_earliest_origin(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The Earliest Reliable External Origin -- see
    app/services/origin_resolution.py for the trust model. Distinct from
    the risk score: this is a confidence about WHERE the message came
    from, not how dangerous it is.
    """
    await _get_org_case(db, case_id, current_user.organization_id)
    from app.models.email import EmailMessage

    email_message = await db.scalar(select(EmailMessage).where(EmailMessage.case_id == case_id))
    if email_message is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No parsed email found for this case.")

    return {
        "origin_determined": email_message.origin_determined,
        "origin_ip": email_message.origin_ip,
        "origin_confidence": email_message.origin_confidence,
        "reasoning": email_message.origin_reasoning,
        "disclaimer": (
            "This identifies observed sending infrastructure, not the physical location or "
            "identity of any individual. See docs/threat_model.md."
        ),
    }


@router.get("/{case_id}/ip-intelligence")
async def get_ip_intelligence(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """IP infrastructure intelligence for every IP IOC on this case:
    ASN/ISP/hosting (from threat-intel enrichment), reverse DNS, and
    hosting-provider classification (see app/services/ip_intelligence.py).
    """
    await _get_org_case(db, case_id, current_user.organization_id)

    ioc_records = (
        await db.execute(select(IOCRecord).where(IOCRecord.case_id == case_id, IOCRecord.ioc_type == IOCType.IP))
    ).scalars().all()

    results = []
    for record in ioc_records:
        if record.ip_id is None:
            continue
        ip_row = await db.get(IPAddress, record.ip_id)
        if ip_row is None:
            continue
        results.append({
            "ip": ip_row.address,
            "asn": ip_row.asn,
            "asn_organization": ip_row.asn_org,
            "country": ip_row.country,
            "geolocation": {
                "city": ip_row.approx_city,
                "latitude": ip_row.approx_lat,
                "longitude": ip_row.approx_lon,
                "confidence": ip_row.geolocation_confidence,
                "source": ip_row.geolocation_source or "unavailable",
            },
            "reverse_dns_hostname": ip_row.ptr_hostname,
            "hosting_classification": ip_row.hosting_classification or "unavailable",
            "hosting_classification_source": ip_row.hosting_classification_source,
            "vpn_or_proxy_suspected": ip_row.is_vpn_or_proxy_suspected,
            "tor_exit_node_suspected": ip_row.is_tor_exit_node_suspected,
            "reputation_score": ip_row.reputation_score,
            "is_known_malicious": ip_row.is_known_malicious,
        })

    return {
        "ips": results,
        "disclaimer": (
            "IP geolocation represents the registered/observed network location and does not "
            "necessarily represent the physical location of the sender. VPN/Tor fields are null "
            "when no data source for that specific determination is configured -- this means "
            "'unknown', never 'confirmed absent'."
        ),
    }


@router.get("/{case_id}/dns-observations")
async def get_dns_observations(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Every passive DNS query performed for this case's domain/IP IOCs,
    including failed lookups -- nothing is fabricated or hidden.
    """
    await _get_org_case(db, case_id, current_user.organization_id)
    observations = (
        await db.execute(
            select(DNSObservation).where(DNSObservation.case_id == case_id).order_by(DNSObservation.created_at)
        )
    ).scalars().all()

    return [
        {
            "query_type": o.query_type,
            "query_name": o.query_name,
            "success": o.success,
            "result": o.result,
            "ttl": o.ttl,
            "error_detail": o.error_detail,
            "source": o.source,
            "queried_at": o.created_at,
        }
        for o in observations
    ]


@router.get("/{case_id}/domain-intelligence/{domain_name}")
async def get_domain_intelligence(
    case_id: uuid.UUID,
    domain_name: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """On-demand WHOIS lookup (not run automatically at ingestion time --
    see app/services/ingestion.py comment on why -- raw WHOIS is slow and
    unreliable across networks, so it's queried live here instead).
    """
    await _get_org_case(db, case_id, current_user.organization_id)

    domain_row = await db.scalar(select(Domain).where(Domain.name == domain_name))
    if domain_row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found among this case's IOCs.")

    ioc_exists = await db.scalar(
        select(IOCRecord).where(IOCRecord.case_id == case_id, IOCRecord.domain_id == domain_row.id)
    )
    if ioc_exists is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="This domain is not an IOC on this case.")

    whois_result = whois_lookup.lookup_domain_whois(domain_name)
    if whois_result.available:
        domain_row.registrar = whois_result.registrar or domain_row.registrar
        domain_row.creation_date = whois_result.creation_date or domain_row.creation_date
        domain_row.age_days = whois_result.age_days
        domain_row.is_newly_registered = bool(whois_result.age_days is not None and whois_result.age_days < 30)
        domain_row.whois_source = "whois"
        await db.commit()

    return {
        "domain": domain_name,
        "available": whois_result.available,
        "registrar": whois_result.registrar,
        "creation_date": whois_result.creation_date,
        "age_days": whois_result.age_days,
        "is_newly_registered": bool(whois_result.age_days is not None and whois_result.age_days < 30),
        "nameservers": whois_result.nameservers,
        "error_detail": whois_result.error_detail,
    }


@router.get("/{case_id}/blockchain-verify")
async def verify_case_blockchain(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Compares the case's CURRENT evidence hash against what was
    anchored into the organization's hash chain at ingestion time.
    """
    case = await _get_org_case(db, case_id, current_user.organization_id)

    evidence = await db.scalar(
        select(EvidenceObject).where(EvidenceObject.case_id == case_id, EvidenceObject.kind == EvidenceKind.RAW_EMAIL)
    )
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No raw evidence found for this case.")
    hash_row = await db.scalar(select(EvidenceHash).where(EvidenceHash.evidence_object_id == evidence.id))
    if hash_row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No evidence hash recorded for this case.")

    result = await blockchain_ledger.verify_case_evidence(db, case_id=case_id, current_evidence_sha256=hash_row.hex_digest)
    return result


organization_router = APIRouter(prefix="/organizations", tags=["forensics"])


@organization_router.get("/blockchain-verify")
async def verify_organization_blockchain(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verifies the ENTIRE hash chain for the caller's organization, not
    just one case -- detects tampering anywhere in the chain's history.
    """
    return await blockchain_ledger.verify_chain_integrity(db, current_user.organization_id)
