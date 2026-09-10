"""IP infrastructure intelligence: reverse DNS (PTR) resolution and a
best-effort hosting/datacenter classification heuristic.

Honesty note: there is no free, reliable, always-available VPN/Tor/proxy
detection data source wired into this project (real-time Tor exit-node
lists and VPN-IP databases are typically paid products). Rather than
fabricate a "VPN: Possible" verdict from nothing, this module:
- Performs REAL reverse DNS (PTR) lookups (dnspython, already proven to
  work in this environment).
- Classifies "hosting/datacenter" via a real, explainable heuristic:
  matching the ASN organization name (already fetched from IPinfo in
  app/services/threat_intel.py) against known cloud/hosting-provider
  name fragments. This is not a claim of certainty -- it's what the
  wording says: "IP is classified as hosting/datacenter infrastructure"
  based on ASN organization name, with the matched provider shown as
  evidence.
- Leaves VPN/Tor detection explicitly `None` (not False, not True) with
  the reasoning "no VPN/Tor data source configured" unless a real
  provider is wired in later (see NEXT_STEPS.md) -- never guesses.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.services.dns_forensics import query_ptr

# ASN organization name fragments strongly associated with cloud/hosting
# infrastructure rather than residential ISPs. Case-insensitive substring
# match against the ASN org string already captured from IPinfo.
_HOSTING_ASN_FRAGMENTS = (
    "amazon", "aws", "google cloud", "google llc", "microsoft", "azure",
    "digitalocean", "ovh", "hetzner", "linode", "akamai", "cloudflare",
    "vultr", "scaleway", "contabo", "leaseweb", "hostinger", "namecheap",
    "godaddy", "rackspace", "oracle cloud", "alibaba cloud", "tencent cloud",
    "choopa", "m247", "psychz", "quadranet",
)


@dataclass
class IPIntelligenceResult:
    ptr_hostname: str | None
    ptr_lookup_success: bool
    ptr_error_detail: str | None
    hosting_classification: str | None  # hosting_datacenter | unknown
    hosting_classification_source: str | None
    vpn_or_proxy_suspected: bool | None  # None = no data source configured
    tor_exit_node_suspected: bool | None  # None = no data source configured


def classify_hosting_from_asn_org(asn_org: str | None) -> tuple[str | None, str | None]:
    """Returns (classification, source) or (None, None) if no ASN org
    string is available to classify from at all.
    """
    if not asn_org:
        return None, None
    org_lower = asn_org.lower()
    for fragment in _HOSTING_ASN_FRAGMENTS:
        if fragment in org_lower:
            return "hosting_datacenter", f"asn_org_heuristic (matched '{fragment}')"
    return "unknown", "asn_org_heuristic (no known hosting-provider fragment matched)"


def enrich_ip_intelligence(ip_address: str, asn_org: str | None) -> IPIntelligenceResult:
    ptr_result = query_ptr(ip_address)
    classification, source = classify_hosting_from_asn_org(asn_org)

    return IPIntelligenceResult(
        ptr_hostname=ptr_result.answers[0] if ptr_result.success and ptr_result.answers else None,
        ptr_lookup_success=ptr_result.success,
        ptr_error_detail=ptr_result.error_detail,
        hosting_classification=classification,
        hosting_classification_source=source,
        vpn_or_proxy_suspected=None,
        tor_exit_node_suspected=None,
    )
