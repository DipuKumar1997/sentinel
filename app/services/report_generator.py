"""Case report generation.

Assembles exactly what docs/forensic_workflow.md promises a future
export would need: the evidence hash, the full findings list with
engine/confidence, the case status history, and the model prediction(s)
-- everything a reviewer needs to reconstruct how the platform reached
its risk score without relying on the platform staying online.

Two output formats are supported from the same gathered data:
- HTML (self-contained, no external assets, printable to PDF by any browser)
- PDF (native, via fpdf2 -- a pure-Python PDF library with no system-level
  rendering dependency, unlike e.g. WeasyPrint's Cairo/Pango requirement)
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from fpdf import FPDF
from jinja2 import Environment
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Report
from app.models.analysis import AnalysisFinding, AnalysisRun, ModelPrediction, RiskScore
from app.models.case import Case, CaseStatusHistory
from app.models.email import EmailMessage
from app.models.evidence import EvidenceHash, EvidenceKind, EvidenceObject
from app.models.ioc import DNSObservation, IOCRecord, IOCType, IPAddress
from app.services import blockchain_ledger
from app.services.evidence_storage import store_evidence_bytes

ReportFormat = Literal["html", "pdf"]


@dataclass
class ReportData:
    case: Case
    risk_score: RiskScore | None
    findings: list[AnalysisFinding] = field(default_factory=list)
    model_predictions: list[ModelPrediction] = field(default_factory=list)
    evidence: EvidenceObject | None = None
    evidence_sha256: str | None = None
    status_history: list[CaseStatusHistory] = field(default_factory=list)
    generated_at: str = ""
    # Forensic intelligence additions
    email_message: EmailMessage | None = None
    ip_intelligence: list[IPAddress] = field(default_factory=list)
    dns_observations: list[DNSObservation] = field(default_factory=list)
    blockchain_verification: dict | None = None


async def _gather_report_data(db: AsyncSession, *, case: Case) -> ReportData:
    risk_score = await db.scalar(
        select(RiskScore).where(RiskScore.case_id == case.id).order_by(RiskScore.created_at.desc())
    )
    latest_run = await db.scalar(
        select(AnalysisRun).where(AnalysisRun.case_id == case.id).order_by(AnalysisRun.created_at.desc())
    )
    findings: list[AnalysisFinding] = []
    model_predictions: list[ModelPrediction] = []
    if latest_run:
        findings = (
            await db.execute(select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == latest_run.id))
        ).scalars().all()
        model_predictions = (
            await db.execute(select(ModelPrediction).where(ModelPrediction.analysis_run_id == latest_run.id))
        ).scalars().all()

    evidence = await db.scalar(
        select(EvidenceObject).where(
            EvidenceObject.case_id == case.id, EvidenceObject.kind == EvidenceKind.RAW_EMAIL
        )
    )
    evidence_sha256 = None
    if evidence:
        hash_row = await db.scalar(select(EvidenceHash).where(EvidenceHash.evidence_object_id == evidence.id))
        evidence_sha256 = hash_row.hex_digest if hash_row else None

    status_history = (
        await db.execute(
            select(CaseStatusHistory).where(CaseStatusHistory.case_id == case.id).order_by(CaseStatusHistory.created_at)
        )
    ).scalars().all()

    email_message = await db.scalar(select(EmailMessage).where(EmailMessage.case_id == case.id))

    ip_records = (
        await db.execute(select(IOCRecord).where(IOCRecord.case_id == case.id, IOCRecord.ioc_type == IOCType.IP))
    ).scalars().all()
    ip_intelligence_rows: list[IPAddress] = []
    for record in ip_records:
        if record.ip_id:
            ip_row = await db.get(IPAddress, record.ip_id)
            if ip_row:
                ip_intelligence_rows.append(ip_row)

    dns_observations = (
        await db.execute(select(DNSObservation).where(DNSObservation.case_id == case.id).order_by(DNSObservation.created_at))
    ).scalars().all()

    blockchain_verification = None
    if evidence_sha256:
        try:
            blockchain_verification = await blockchain_ledger.verify_case_evidence(
                db, case_id=case.id, current_evidence_sha256=evidence_sha256
            )
        except Exception:
            blockchain_verification = {"verified": False, "message": "Blockchain verification unavailable."}

    return ReportData(
        case=case,
        risk_score=risk_score,
        findings=findings,
        model_predictions=model_predictions,
        evidence=evidence,
        evidence_sha256=evidence_sha256,
        status_history=status_history,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        email_message=email_message,
        ip_intelligence=ip_intelligence_rows,
        dns_observations=dns_observations,
        blockchain_verification=blockchain_verification,
    )


# --------------------------------------------------------------------------
# HTML rendering
# --------------------------------------------------------------------------

_env = Environment(autoescape=True)

_HTML_TEMPLATE_SOURCE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SentinelMail AI Report -- {{ case.case_number }}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 900px; margin: 2rem auto; color: #1a1a1a; }
  h1 { font-size: 1.5rem; }
  h2 { font-size: 1.1rem; margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: .25rem; }
  .badge { display: inline-block; padding: .2rem .6rem; border-radius: 999px; font-weight: 600; font-size: .85rem; }
  .malicious { background: #fde2e1; color: #8a1c1c; }
  .likely_malicious { background: #fde8d2; color: #8a4a1c; }
  .suspicious { background: #fef6d2; color: #8a6f1c; }
  .benign { background: #e0f3e0; color: #1c5a1c; }
  table { width: 100%; border-collapse: collapse; margin-top: .5rem; }
  th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #eee; font-size: .9rem; }
  th { color: #555; }
  .mono { font-family: ui-monospace, SFMono-Regular, monospace; font-size: .85rem; word-break: break-all; }
  .severity-critical { color: #8a1c1c; font-weight: 700; }
  .severity-high { color: #b33a00; font-weight: 600; }
  .severity-medium { color: #8a6f1c; }
  .severity-low, .severity-info { color: #555; }
  footer { margin-top: 2rem; font-size: .8rem; color: #888; }
</style>
</head>
<body>
  <h1>SentinelMail AI &mdash; Forensic Case Report</h1>
  <p><strong>Case:</strong> {{ case.case_number }} &nbsp;|&nbsp;
     <strong>Status:</strong> {{ case.status.value }} &nbsp;|&nbsp;
     <strong>Generated:</strong> {{ generated_at }}</p>

  <h2>Risk Assessment</h2>
  {% if risk_score %}
  <p>
    <span class="badge {{ risk_score.classification }}">{{ risk_score.classification | upper }}</span>
    &nbsp; Score: <strong>{{ risk_score.score }}/100</strong>
    &nbsp; Confidence: {{ risk_score.confidence_band }}
  </p>
  <pre style="white-space: pre-wrap; background:#f7f7f7; padding: .75rem; border-radius: 6px;">{{ risk_score.rationale_summary }}</pre>
  {% else %}
  <p>No risk score computed yet.</p>
  {% endif %}

  <h2>Evidence Integrity</h2>
  <table>
    <tr><th>Original filename</th><td>{{ evidence.original_filename if evidence else "n/a" }}</td></tr>
    <tr><th>Size</th><td>{{ evidence.size_bytes if evidence else "n/a" }} bytes</td></tr>
    <tr><th>SHA-256</th><td class="mono">{{ evidence_sha256 or "unavailable" }}</td></tr>
    <tr><th>Ingested</th><td>{{ evidence.created_at if evidence else "n/a" }}</td></tr>
  </table>

  <h2>Analysis Findings ({{ findings | length }})</h2>
  <table>
    <tr><th>Engine</th><th>Code</th><th>Severity</th><th>Confidence</th><th>Description</th></tr>
    {% for f in findings %}
    <tr>
      <td>{{ f.engine }}</td>
      <td>{{ f.code }}</td>
      <td class="severity-{{ f.severity }}">{{ f.severity }}</td>
      <td>{{ "%.2f"|format(f.confidence) }}</td>
      <td>{{ f.description }}</td>
    </tr>
    {% endfor %}
  </table>

  <h2>Model Predictions</h2>
  <table>
    <tr><th>Model</th><th>Version</th><th>Label</th><th>Probability</th></tr>
    {% for m in model_predictions %}
    <tr><td>{{ m.model_name }}</td><td>{{ m.model_version }}</td><td>{{ m.label }}</td><td>{{ "%.2f"|format(m.probability) }}</td></tr>
    {% endfor %}
  </table>

  <h2>Sender Identity Analysis</h2>
  <table>
    <tr><th>Claimed display name</th><td>{{ email_message.from_display_name if email_message else "n/a" }}</td></tr>
    <tr><th>Claimed From address</th><td>{{ email_message.from_address if email_message else "n/a" }}</td></tr>
    <tr><th>Reply-To</th><td>{{ email_message.reply_to_address if email_message else "n/a" }}</td></tr>
    <tr><th>Return-Path</th><td>{{ email_message.return_path if email_message else "n/a" }}</td></tr>
  </table>
  <p class="mono" style="font-size:.75rem;color:#888;">
    These are UNVERIFIED CLAIMS parsed from the message's own headers, not authenticated facts.
    See Authentication Analysis (SPF/DKIM/DMARC findings above) for what could actually be verified.
  </p>

  <h2>Earliest Reliable Origin</h2>
  {% if email_message and email_message.origin_determined %}
  <table>
    <tr><th>Origin IP</th><td class="mono">{{ email_message.origin_ip }}</td></tr>
    <tr><th>Origin confidence</th><td>{{ "%.0f"|format(email_message.origin_confidence * 100) }}%</td></tr>
  </table>
  <pre style="white-space: pre-wrap; background:#f7f7f7; padding: .75rem; border-radius: 6px; font-size:.85rem;">{{ email_message.origin_reasoning }}</pre>
  {% else %}
  <p>Origin IP could not be established with high confidence.{{ " " + email_message.origin_reasoning if email_message and email_message.origin_reasoning else "" }}</p>
  {% endif %}
  <p class="mono" style="font-size:.75rem;color:#888;">
    This identifies observed sending infrastructure, not the physical location or identity of any individual.
  </p>

  <h2>IP Intelligence &amp; Geolocation</h2>
  <table>
    <tr><th>IP</th><th>ASN</th><th>ASN Org</th><th>Country</th><th>City</th><th>Reverse DNS</th><th>Hosting</th></tr>
    {% for ip in ip_intelligence %}
    <tr>
      <td class="mono">{{ ip.address }}</td>
      <td>{{ ip.asn or "unavailable" }}</td>
      <td>{{ ip.asn_org or "unavailable" }}</td>
      <td>{{ ip.country or "unavailable" }}</td>
      <td>{{ ip.approx_city or "unavailable" }}</td>
      <td>{{ ip.ptr_hostname or "unavailable" }}</td>
      <td>{{ ip.hosting_classification or "unavailable" }}</td>
    </tr>
    {% endfor %}
  </table>
  <p class="mono" style="font-size:.75rem;color:#888;">
    IP geolocation represents the registered/observed network location and does not necessarily
    represent the physical location of the sender. VPN/Tor/proxy status is only reported when a
    real data source is configured -- "unavailable" means unknown, never "confirmed absent."
  </p>

  <h2>DNS Intelligence</h2>
  <table>
    <tr><th>Type</th><th>Query</th><th>Result</th><th>Status</th></tr>
    {% for obs in dns_observations %}
    <tr>
      <td>{{ obs.query_type }}</td>
      <td class="mono">{{ obs.query_name }}</td>
      <td>{{ obs.result or (obs.error_detail or "unavailable") }}</td>
      <td>{{ "success" if obs.success else "failed" }}</td>
    </tr>
    {% endfor %}
  </table>

  <h2>Blockchain Evidence Verification</h2>
  {% if blockchain_verification %}
  <p>
    <span class="badge {{ 'benign' if blockchain_verification.verified else 'malicious' }}">
      {{ "VERIFIED" if blockchain_verification.verified else "MISMATCH" }}
    </span>
    {{ blockchain_verification.message }}
  </p>
  {% else %}
  <p>Blockchain verification unavailable for this case.</p>
  {% endif %}
  <p class="mono" style="font-size:.75rem;color:#888;">
    This is a cryptographic hash chain for tamper-evidence, anchoring evidence hashes only --
    never email content, bodies, or attachments -- not a distributed/public blockchain network.
  </p>

  <h2>Case Status History</h2>
  <table>
    <tr><th>From</th><th>To</th><th>At</th><th>Note</th></tr>
    {% for h in status_history %}
    <tr><td>{{ h.from_status or "\u2014" }}</td><td>{{ h.to_status }}</td><td>{{ h.created_at }}</td><td>{{ h.note or "" }}</td></tr>
    {% endfor %}
  </table>

  <h2>Limitations &amp; Disclaimer</h2>
  <p class="mono" style="font-size:.8rem;color:#888;">
    This report is a triage aid produced by automated analysis, not a definitive legal or
    forensic determination. IP geolocation, hosting classification, and VPN/Tor indicators are
    approximate and provider-dependent. WHOIS/DNS data reflects what was queryable at analysis
    time and may change. No claim is made about the physical identity or location of any
    individual. See docs/threat_model.md for what each signal does and does not establish.
  </p>

  <footer>
    Generated by SentinelMail AI v0.1.0. This report is a triage aid, not a
    definitive legal determination -- see docs/threat_model.md for what
    each signal does and does not establish.
  </footer>
</body>
</html>
"""

_html_template = _env.from_string(_HTML_TEMPLATE_SOURCE)


def render_html(data: ReportData) -> str:
    return _html_template.render(
        case=data.case,
        risk_score=data.risk_score,
        findings=data.findings,
        model_predictions=data.model_predictions,
        evidence=data.evidence,
        evidence_sha256=data.evidence_sha256,
        status_history=data.status_history,
        generated_at=data.generated_at,
        email_message=data.email_message,
        ip_intelligence=data.ip_intelligence,
        dns_observations=data.dns_observations,
        blockchain_verification=data.blockchain_verification,
    )


async def generate_case_report_html(db: AsyncSession, *, case: Case) -> str:
    """Backward-compatible wrapper used by earlier checkpoint routers/tests."""
    data = await _gather_report_data(db, case=case)
    return render_html(data)


async def generate_both_formats(db: AsyncSession, *, case: Case) -> tuple[str, bytes]:
    """Gathers report data ONCE and renders both HTML and PDF from it --
    used by the mailbox-forwarding email notification (which needs both
    in a single pass) rather than calling the HTML and PDF paths
    separately and querying the database twice.
    """
    data = await _gather_report_data(db, case=case)
    return render_html(data), render_pdf(data)


# --------------------------------------------------------------------------
# PDF rendering (native, via fpdf2 -- no system rendering deps required)
# --------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class _ReportPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 10, "SentinelMail AI -- Forensic Case Report", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, "This report is a triage aid, not a definitive legal determination.", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    def section_title(self, text: str):
        self.set_font("Helvetica", "B", 12)
        self.set_fill_color(240, 240, 240)
        self.cell(0, 8, text, fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def kv_row(self, key: str, value: str):
        self.set_font("Helvetica", "B", 9)
        self.cell(45, 6, key)
        self.set_font("Helvetica", "", 9)
        self.multi_cell(0, 6, value, new_x="LMARGIN", new_y="NEXT")


def _ascii_safe(text: str | None) -> str:
    """fpdf2's core Helvetica font is latin-1 only; replace anything
    outside that range rather than raising, since forensic report
    content (email subjects, etc.) may contain arbitrary unicode.
    """
    if text is None:
        return ""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def render_pdf(data: ReportData) -> bytes:
    pdf = _ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    pdf.section_title(f"Case {data.case.case_number}")
    pdf.kv_row("Status:", _ascii_safe(data.case.status.value))
    pdf.kv_row("Generated:", data.generated_at)
    pdf.ln(3)

    pdf.section_title("Risk Assessment")
    if data.risk_score:
        pdf.kv_row("Classification:", _ascii_safe(data.risk_score.classification.upper()))
        pdf.kv_row("Score:", f"{data.risk_score.score}/100")
        pdf.kv_row("Confidence:", _ascii_safe(data.risk_score.confidence_band))
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, _ascii_safe(data.risk_score.rationale_summary), new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 6, "No risk score computed yet.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    pdf.section_title("Evidence Integrity")
    pdf.kv_row("Original filename:", _ascii_safe(data.evidence.original_filename if data.evidence else "n/a"))
    pdf.kv_row("Size:", f"{data.evidence.size_bytes} bytes" if data.evidence else "n/a")
    pdf.kv_row("SHA-256:", data.evidence_sha256 or "unavailable")
    pdf.ln(3)

    pdf.section_title(f"Analysis Findings ({len(data.findings)})")
    sorted_findings = sorted(data.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))
    for f in sorted_findings:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 5, _ascii_safe(f"[{f.severity.upper()}] {f.engine} :: {f.code} (confidence {f.confidence:.2f})"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, _ascii_safe(f.description), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
    pdf.ln(2)

    pdf.section_title("Model Predictions")
    for m in data.model_predictions:
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(
            0, 5,
            _ascii_safe(f"{m.model_name} v{m.model_version}: label={m.label}, probability={m.probability:.2f}"),
            new_x="LMARGIN", new_y="NEXT",
        )
    pdf.ln(2)

    pdf.section_title("Sender Identity Analysis")
    if data.email_message:
        pdf.kv_row("Claimed display name:", _ascii_safe(data.email_message.from_display_name or "n/a"))
        pdf.kv_row("Claimed From address:", _ascii_safe(data.email_message.from_address or "n/a"))
        pdf.kv_row("Reply-To:", _ascii_safe(data.email_message.reply_to_address or "n/a"))
        pdf.kv_row("Return-Path:", _ascii_safe(data.email_message.return_path or "n/a"))
    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(0, 4, "These are unverified claims from the message's own headers, not authenticated facts.",
                   new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.section_title("Earliest Reliable Origin")
    if data.email_message and data.email_message.origin_determined:
        pdf.kv_row("Origin IP:", _ascii_safe(data.email_message.origin_ip))
        pdf.kv_row("Confidence:", f"{data.email_message.origin_confidence * 100:.0f}%")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, _ascii_safe(data.email_message.origin_reasoning or ""), new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.set_font("Helvetica", "", 9)
        reasoning = data.email_message.origin_reasoning if data.email_message else ""
        pdf.multi_cell(0, 5, _ascii_safe(f"Origin IP could not be established with high confidence. {reasoning}"),
                       new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.section_title(f"IP Intelligence & Geolocation ({len(data.ip_intelligence)})")
    for ip in data.ip_intelligence:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 5, _ascii_safe(ip.address), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(
            0, 5,
            _ascii_safe(
                f"ASN: {ip.asn or 'unavailable'}  Org: {ip.asn_org or 'unavailable'}  "
                f"Country: {ip.country or 'unavailable'}  City: {ip.approx_city or 'unavailable'}  "
                f"PTR: {ip.ptr_hostname or 'unavailable'}  Hosting: {ip.hosting_classification or 'unavailable'}"
            ),
            new_x="LMARGIN", new_y="NEXT",
        )
    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(
        0, 4,
        "IP geolocation represents the registered/observed network location, not necessarily the "
        "physical location of the sender.",
        new_x="LMARGIN", new_y="NEXT",
    )
    pdf.ln(2)

    pdf.section_title(f"DNS Intelligence ({len(data.dns_observations)})")
    for obs in data.dns_observations:
        pdf.set_font("Helvetica", "", 9)
        result_text = obs.result if obs.success else (obs.error_detail or "unavailable")
        pdf.multi_cell(
            0, 5,
            _ascii_safe(f"[{obs.query_type}] {obs.query_name}: {result_text}"),
            new_x="LMARGIN", new_y="NEXT",
        )
    pdf.ln(2)

    pdf.section_title("Blockchain Evidence Verification")
    pdf.set_font("Helvetica", "", 9)
    if data.blockchain_verification:
        verdict = "VERIFIED" if data.blockchain_verification.get("verified") else "MISMATCH"
        pdf.cell(0, 5, _ascii_safe(f"{verdict}: {data.blockchain_verification.get('message', '')}"),
                 new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 5, "Blockchain verification unavailable for this case.", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(
        0, 4,
        "A cryptographic hash chain for tamper-evidence anchoring evidence hashes only -- never "
        "email content -- not a distributed/public blockchain network.",
        new_x="LMARGIN", new_y="NEXT",
    )
    pdf.ln(2)

    pdf.section_title("Case Status History")
    for h in data.status_history:
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(
            0, 5,
            _ascii_safe(f"{h.from_status or '-'} -> {h.to_status}  ({h.created_at})  {h.note or ''}"),
            new_x="LMARGIN", new_y="NEXT",
        )
    pdf.ln(2)

    pdf.section_title("Limitations & Disclaimer")
    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(
        0, 4,
        "This report is a triage aid produced by automated analysis, not a definitive legal or "
        "forensic determination. IP geolocation, hosting classification, and VPN/Tor indicators "
        "are approximate and provider-dependent. No claim is made about the physical identity or "
        "location of any individual.",
        new_x="LMARGIN", new_y="NEXT",
    )

    output = pdf.output()
    return bytes(output)


async def generate_and_store_report(
    db: AsyncSession, *, case: Case, generated_by_user_id: uuid.UUID, fmt: ReportFormat = "html"
) -> tuple[Report, bytes | str, str]:
    """Generates a report in the requested format, persists it as an
    evidence object (content-addressed, hashed) plus a `Report` row, and
    returns (report, content, media_type).
    """
    data = await _gather_report_data(db, case=case)

    if fmt == "pdf":
        content_bytes = render_pdf(data)
        media_type = "application/pdf"
        suffix = ".report.pdf"
        content_type = "application/pdf"
        filename = f"{case.case_number}_report.pdf"
    else:
        content_str = render_html(data)
        content_bytes = content_str.encode("utf-8")
        media_type = "text/html"
        suffix = ".report.html"
        content_type = "text/html"
        filename = f"{case.case_number}_report.html"

    storage_uri, digest = store_evidence_bytes(case.id, content_bytes, suffix=suffix)

    evidence = EvidenceObject(
        case_id=case.id,
        kind=EvidenceKind.REPORT_EXPORT,
        original_filename=filename,
        content_type=content_type,
        size_bytes=len(content_bytes),
        storage_uri=storage_uri,
        ingested_by_user_id=generated_by_user_id,
        ingest_method="report_generation",
    )
    db.add(evidence)
    await db.flush()
    db.add(EvidenceHash(evidence_object_id=evidence.id, algorithm="sha256", hex_digest=digest))

    report = Report(
        case_id=case.id,
        template_id=None,
        generated_by_user_id=generated_by_user_id,
        format=fmt,
        evidence_object_id=evidence.id,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    return_content: bytes | str = content_bytes if fmt == "pdf" else content_bytes.decode("utf-8")
    return report, return_content, media_type
