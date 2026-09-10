"""End-to-end orchestration: raw email bytes in, a fully analyzed Case out.

This is the "spine" the master prompt describes:
RAW EMAIL -> EVIDENCE PRESERVATION -> STRUCTURED FORENSIC EXTRACTION ->
THREAT-INTEL ENRICHMENT -> SPECIALIZED ANALYSIS ENGINES (deterministic +
heuristic-model) -> RISK FUSION -> CAMPAIGN/GRAPH CORRELATION -> CASE.

Supports both `.eml` (RFC 5322/MIME) and Outlook `.msg` as input formats;
both are normalized to the same `ParsedEmail` shape before entering the
shared pipeline below, so every step past parsing is format-agnostic.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import AnalysisFinding, AnalysisRun, AnalysisRunStatus, ModelPrediction, RiskScore
from app.models.case import Case, CaseStatus, CaseStatusHistory
from app.models.email import AuthenticationResult, EmailHeader, EmailMessage, ReceivedHop, SenderIdentity
from app.models.evidence import EvidenceHash, EvidenceKind, EvidenceObject
from app.models.ioc import Attachment, Domain, IOCRecord, IOCType, IPAddress, URLRecord
from app.services import auth_results as auth_results_svc
from app.services import campaign_correlation, ml_scoring, threat_intel
from app.services.analysis_engines import header_forensics, threat_intel_engine, url_domain_analysis
from app.services.eml_parser import ParsedEmail, parse_eml_bytes
from app.services.evidence_storage import store_evidence_bytes
from app.services.ioc_extraction import extract_iocs, normalize_url
from app.services.msg_parser import parse_msg_bytes
from app.services.risk_fusion import fuse

SourceFormat = Literal["eml", "msg"]


class IngestionError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _generate_case_number() -> str:
    now = datetime.now(timezone.utc)
    return f"SM-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"


async def _get_or_create_domain(db: AsyncSession, name: str) -> Domain:
    domain = await db.scalar(select(Domain).where(Domain.name == name))
    if domain is None:
        domain = Domain(name=name)
        db.add(domain)
        await db.flush()
    return domain


async def _get_or_create_ip(db: AsyncSession, address: str) -> IPAddress:
    ip = await db.scalar(select(IPAddress).where(IPAddress.address == address))
    if ip is None:
        ip = IPAddress(address=address)
        db.add(ip)
        await db.flush()
    return ip


def _parse_bytes(raw_bytes: bytes, fmt: SourceFormat) -> ParsedEmail:
    if fmt == "eml":
        return parse_eml_bytes(raw_bytes)
    if fmt == "msg":
        return parse_msg_bytes(raw_bytes)
    raise ValueError(f"Unsupported source format: {fmt}")  # pragma: no cover -- guarded upstream


_CONTENT_TYPE_BY_FORMAT = {"eml": "message/rfc822", "msg": "application/vnd.ms-outlook"}
_SUFFIX_BY_FORMAT = {"eml": ".eml", "msg": ".msg"}


async def ingest_email_and_create_case(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    reporter_user_id: uuid.UUID,
    raw_bytes: bytes,
    original_filename: str | None,
    source_format: SourceFormat = "eml",
) -> tuple[Case, EmailMessage, RiskScore]:
    """The single entry point used by the ingestion router, for either
    supported source format.

    Order of operations matters for evidence integrity: the raw bytes are
    hashed and persisted BEFORE any parsing is attempted, so even a file
    that fails to parse still leaves a preserved, hashed evidence record.
    """
    case = Case(
        organization_id=organization_id,
        case_number=_generate_case_number(),
        reporter_user_id=reporter_user_id,
        status=CaseStatus.NEW,
        priority="medium",
    )
    db.add(case)
    await db.flush()

    db.add(
        CaseStatusHistory(
            case_id=case.id, from_status=None, to_status=CaseStatus.NEW.value,
            changed_by_user_id=reporter_user_id, note="Case created from email submission.",
        )
    )

    storage_uri, digest = store_evidence_bytes(case.id, raw_bytes, suffix=_SUFFIX_BY_FORMAT[source_format])
    evidence = EvidenceObject(
        case_id=case.id,
        kind=EvidenceKind.RAW_EMAIL,
        original_filename=original_filename,
        content_type=_CONTENT_TYPE_BY_FORMAT[source_format],
        size_bytes=len(raw_bytes),
        storage_uri=storage_uri,
        ingested_by_user_id=reporter_user_id,
        ingest_method="upload",
    )
    db.add(evidence)
    await db.flush()
    db.add(EvidenceHash(evidence_object_id=evidence.id, algorithm="sha256", hex_digest=digest))

    try:
        parsed: ParsedEmail = _parse_bytes(raw_bytes, source_format)
    except Exception as exc:
        case.status = CaseStatus.TRIAGE
        case.summary = f"Automated parsing failed: {exc}. Manual analyst review required."
        await db.commit()
        raise IngestionError(f"Failed to parse .{source_format} file: {exc}", 422) from exc

    email_message = EmailMessage(
        case_id=case.id,
        raw_evidence_object_id=evidence.id,
        message_id=parsed.message_id,
        subject=parsed.subject,
        date_header=parsed.date_header,
        from_display_name=parsed.from_display_name,
        from_address=parsed.from_address,
        reply_to_address=parsed.reply_to_address,
        return_path=parsed.return_path,
        to_addresses=json.dumps(parsed.to_addresses),
        cc_addresses=json.dumps(parsed.cc_addresses),
        body_text=parsed.body_text,
        body_html=parsed.body_html,
        has_attachments=bool(parsed.attachments),
        attachment_count=len(parsed.attachments),
    )
    db.add(email_message)
    await db.flush()

    for header in parsed.headers:
        db.add(
            EmailHeader(
                email_message_id=email_message.id,
                sequence=header.sequence,
                name=header.name,
                value=header.value,
            )
        )

    for hop in parsed.received_hops:
        db.add(
            ReceivedHop(
                email_message_id=email_message.id,
                hop_index=hop.hop_index,
                raw_value=hop.raw_value,
                from_host=hop.from_host,
                from_ip=hop.from_ip,
                by_host=hop.by_host,
                with_protocol=hop.with_protocol,
                timestamp=hop.timestamp,
                parse_confidence=hop.parse_confidence,
            )
        )

    db.add(
        SenderIdentity(
            email_message_id=email_message.id,
            claimed_display_name=parsed.from_display_name,
            claimed_address=parsed.from_address,
            display_name_address_mismatch=False,  # set by header_forensics finding, not stored redundantly here
        )
    )

    # --- Authentication evidence (SPF/DKIM/DMARC) ---
    auth_header_values = [h.value for h in parsed.headers if h.name.lower() == "authentication-results"]
    auth_findings = auth_results_svc.parse_authentication_results_header(auth_header_values)

    if not any(f.mechanism == "spf" for f in auth_findings) and parsed.from_address:
        from_domain = parsed.from_address.rsplit("@", 1)[-1]
        sender_ip = parsed.received_hops[-1].from_ip if parsed.received_hops else None
        auth_findings.append(auth_results_svc.live_check_spf(from_domain, sender_ip))
    if not any(f.mechanism == "dmarc" for f in auth_findings) and parsed.from_address:
        from_domain = parsed.from_address.rsplit("@", 1)[-1]
        auth_findings.append(auth_results_svc.live_check_dmarc(from_domain))

    for auth in auth_findings:
        db.add(
            AuthenticationResult(
                email_message_id=email_message.id,
                mechanism=auth.mechanism,
                result=auth.result,
                domain=auth.domain,
                raw_detail=auth.raw_detail,
                source=auth.source,
            )
        )

    # --- IOC extraction ---
    iocs = extract_iocs(parsed)
    ioc_records: list[IOCRecord] = []
    domains_by_id: dict[uuid.UUID, Domain] = {}
    ips_by_id: dict[uuid.UUID, IPAddress] = {}

    for domain_name in iocs.domains:
        domain_row = await _get_or_create_domain(db, domain_name)
        domains_by_id[domain_row.id] = domain_row
        record = IOCRecord(case_id=case.id, ioc_type=IOCType.DOMAIN, value=domain_name, domain_id=domain_row.id)
        db.add(record)
        await db.flush()
        ioc_records.append(record)

    for ip_value in iocs.ips:
        ip_row = await _get_or_create_ip(db, ip_value)
        ips_by_id[ip_row.id] = ip_row
        record = IOCRecord(case_id=case.id, ioc_type=IOCType.IP, value=ip_value, ip_id=ip_row.id)
        db.add(record)
        await db.flush()
        ioc_records.append(record)

    for url_value in iocs.urls:
        url_row = URLRecord(full_url=url_value, normalized_url=normalize_url(url_value))
        db.add(url_row)
        await db.flush()
        record = IOCRecord(case_id=case.id, ioc_type=IOCType.URL, value=url_value, url_id=url_row.id)
        db.add(record)
        await db.flush()
        ioc_records.append(record)

    for att in parsed.attachments:
        att_storage_uri, att_digest = store_evidence_bytes(case.id, att.payload, suffix="")
        att_evidence = EvidenceObject(
            case_id=case.id,
            kind=EvidenceKind.ATTACHMENT,
            original_filename=att.filename,
            content_type=att.declared_mime_type,
            size_bytes=len(att.payload),
            storage_uri=att_storage_uri,
            ingested_by_user_id=reporter_user_id,
            ingest_method="upload",
        )
        db.add(att_evidence)
        await db.flush()
        db.add(EvidenceHash(evidence_object_id=att_evidence.id, algorithm="sha256", hex_digest=att_digest))

        attachment_row = Attachment(
            email_message_id=email_message.id,
            evidence_object_id=att_evidence.id,
            filename=att.filename,
            declared_mime_type=att.declared_mime_type,
            size_bytes=len(att.payload),
            sha256=att_digest,
            is_archive=att.is_archive,
        )
        db.add(attachment_row)
        await db.flush()
        record = IOCRecord(
            case_id=case.id, ioc_type=IOCType.ATTACHMENT_HASH, value=att_digest,
            attachment_id=attachment_row.id,
        )
        db.add(record)
        await db.flush()
        ioc_records.append(record)

    await db.flush()

    # --- Analysis run scaffold ---
    correlation_id = uuid.uuid4().hex
    run = AnalysisRun(
        case_id=case.id,
        correlation_id=correlation_id,
        status=AnalysisRunStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
    )
    db.add(run)
    await db.flush()

    # --- Phase 6: threat-intel enrichment (domains/IPs only; degrades
    # gracefully to the offline heuristic provider if enrichment errors) ---
    run_degraded = False
    threat_intel_observations: dict[str, list] = {}
    try:
        threat_intel_observations = await threat_intel.enrich_case_iocs(
            db, ioc_records, domains_by_id, ips_by_id
        )
    except Exception:
        run_degraded = True

    # --- Deterministic + heuristic-model analysis engines ---
    hf_findings = header_forensics.run(parsed, auth_findings)
    ud_findings = url_domain_analysis.run(iocs.urls, iocs.domains, parsed.body_text, parsed.body_html)
    ti_findings = threat_intel_engine.run(threat_intel_observations)

    model_output = ml_scoring.score_email(
        parsed, auth_findings, len(iocs.urls), domains=iocs.domains, urls=iocs.urls
    )
    db.add(
        ModelPrediction(
            analysis_run_id=run.id,
            model_name=model_output.model_name,
            model_version=model_output.model_version,
            label=model_output.label,
            probability=model_output.probability,
            is_external_model=model_output.is_external_model,
        )
    )
    model_finding = ml_scoring.model_output_to_finding(model_output)

    all_findings = hf_findings + ud_findings + ti_findings + ([model_finding] if model_finding else [])

    for f in all_findings:
        db.add(
            AnalysisFinding(
                analysis_run_id=run.id,
                engine=f.engine,
                code=f.code,
                severity=f.severity,
                confidence=f.confidence,
                description=f.description,
                evidence_ref=f.evidence_ref,
            )
        )

    fused = fuse(all_findings)
    risk_score = RiskScore(
        analysis_run_id=run.id,
        case_id=case.id,
        score=fused.score,
        classification=fused.classification,
        confidence_band=fused.confidence_band,
        rationale_summary=fused.rationale_summary,
    )
    db.add(risk_score)

    run.status = AnalysisRunStatus.DEGRADED if run_degraded else AnalysisRunStatus.COMPLETED
    run.completed_at = datetime.now(timezone.utc)

    # --- Phase 7: campaign & graph correlation (best-effort; a failure
    # here must never prevent the case/risk-score from being saved) ---
    try:
        await campaign_correlation.build_graph_for_case(
            db, organization_id=organization_id, case_id=case.id, ioc_records=ioc_records
        )
        await campaign_correlation.correlate_case_into_campaigns(
            db, organization_id=organization_id, case_id=case.id, ioc_records=ioc_records
        )
    except Exception:
        pass

    case.status = CaseStatus.ANALYZING
    case.summary = fused.rationale_summary
    db.add(
        CaseStatusHistory(
            case_id=case.id, from_status=CaseStatus.NEW.value, to_status=CaseStatus.ANALYZING.value,
            changed_by_user_id=None, note="Automated analysis pipeline completed.",
        )
    )

    await db.commit()
    await db.refresh(case)
    await db.refresh(email_message)
    await db.refresh(risk_score)
    return case, email_message, risk_score


# Backwards-compatible alias for the .eml-only entry point used by earlier
# checkpoint code / tests.
async def ingest_eml_and_create_case(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    reporter_user_id: uuid.UUID,
    raw_bytes: bytes,
    original_filename: str | None,
) -> tuple[Case, EmailMessage, RiskScore]:
    return await ingest_email_and_create_case(
        db,
        organization_id=organization_id,
        reporter_user_id=reporter_user_id,
        raw_bytes=raw_bytes,
        original_filename=original_filename,
        source_format="eml",
    )
