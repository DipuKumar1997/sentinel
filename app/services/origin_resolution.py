"""Earliest Reliable External Origin IP resolution.

This answers a genuinely hard forensic question honestly: given a chain
of Received: headers, which IP is the most defensible "this is where
the message entered from outside our trusted infrastructure" answer?

Trust model (stated plainly, because this is a heuristic, not a proof):
- Received headers are added by each relay a message passes through,
  each one recording the IP address it observed connecting to it.
- Hops closest to the recipient (hop_index 0, 1, 2...) are typically
  YOUR OWN organization's infrastructure (internal load balancers, spam
  filters, the receiving MTA itself) -- these are trusted because you
  control them and they can't lie about what IP connected to them.
- Once the walk crosses from a private/internal IP to the first PUBLIC
  IP, that is the boundary where the message entered from outside your
  network -- and critically, THAT external IP was still observed
  directly by a server you trust (the internal hop that recorded it),
  making it more defensible than any hop claims made further back in
  the chain (which could theoretically be forged by an upstream party
  before your infrastructure ever saw the message).
- We continue walking past that first public IP, through subsequent
  external relays, AS LONG AS the chain stays well-formed and
  internally consistent (parseable IPs, non-degrading parse
  confidence) -- going as deep toward the true origin as the evidence
  supports, while allocating LOWER confidence the deeper/less
  corroborated the walk becomes.
- We explicitly refuse to guess when the chain is entirely private,
  entirely unparseable, or contradictory -- returning "could not be
  determined" rather than fabricating an answer (see docs/threat_model.md
  and the project-wide "never fabricate forensic information" rule).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from app.services.eml_parser import ParsedHop


@dataclass
class OriginResult:
    ip: str | None
    confidence: float  # 0.0-1.0
    reasoning: list[str] = field(default_factory=list)
    determined: bool = False

    @property
    def reasoning_text(self) -> str:
        return " ".join(self.reasoning) if self.reasoning else ""


def _classify_ip(value: str | None) -> str:
    """Returns 'private', 'public', or 'missing'/'invalid'."""
    if not value:
        return "missing"
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
        return "private"
    # Carrier-grade NAT range (RFC 6598) -- effectively private for our
    # purposes even though ipaddress doesn't always flag it as such
    # depending on Python version.
    if ip_obj in ipaddress.ip_network("100.64.0.0/10"):
        return "private"
    return "public"


def resolve_earliest_reliable_origin(hops: list[ParsedHop]) -> OriginResult:
    if not hops:
        return OriginResult(
            ip=None, confidence=0.0, determined=False,
            reasoning=["No Received: headers were present to analyze."],
        )

    # Walk from the recipient side (hop_index 0) outward toward the
    # deepest hop, tracking classification of each hop's claimed from_ip.
    ordered = sorted(hops, key=lambda h: h.hop_index)

    crossed_to_public = False
    best_public_ip: str | None = None
    best_hop_index: int | None = None
    hops_walked = 0
    low_confidence_hops_in_walk = 0
    broke_reason: str | None = None

    for hop in ordered:
        classification = _classify_ip(hop.from_ip)

        if not crossed_to_public:
            if classification == "public":
                crossed_to_public = True
                best_public_ip = hop.from_ip
                best_hop_index = hop.hop_index
                hops_walked = 1
                if hop.parse_confidence == "low":
                    low_confidence_hops_in_walk += 1
            # Still inside private/internal/missing territory -- keep
            # walking without recording anything yet.
            continue

        # Already past the boundary into external territory: keep
        # walking deeper as long as the chain stays coherent.
        if classification == "invalid":
            broke_reason = (
                f"Stopped extending past hop {hop.hop_index}: the claimed from_ip "
                f"'{hop.from_ip}' is not a valid IP address."
            )
            break
        if classification == "missing":
            # A hop with no parsed IP breaks the chain of custody for
            # going deeper -- we stop here rather than skip over the gap.
            broke_reason = (
                f"Stopped extending past hop {hop.hop_index}: no IP address could be "
                "parsed from this hop, so deeper hops cannot be reliably chained."
            )
            break

        # public or private are both fine to continue through (a
        # private IP reappearing deeper in the chain is unusual but not
        # disqualifying on its own -- some relay topologies do this)
        best_public_ip = hop.from_ip if classification == "public" else best_public_ip
        best_hop_index = hop.hop_index if classification == "public" else best_hop_index
        hops_walked += 1
        if hop.parse_confidence == "low":
            low_confidence_hops_in_walk += 1

    if not crossed_to_public or best_public_ip is None:
        return OriginResult(
            ip=None,
            confidence=0.0,
            determined=False,
            reasoning=[
                "Origin IP could not be established with high confidence.",
                "No hop in the Received: chain contained a parseable public IP address "
                "-- either all hops were private/internal, or none could be parsed.",
            ],
        )

    # Confidence scoring: start high, penalize for each low-confidence
    # hop we had to trust, and for walking very deep (more hops = more
    # unverified claims chained together).
    confidence = 0.95
    confidence -= 0.15 * low_confidence_hops_in_walk
    confidence -= 0.03 * max(0, hops_walked - 2)
    confidence = max(0.05, min(0.95, confidence))

    reasoning = [
        f"External/public IP first appears at hop {best_hop_index} when walking outward "
        "from the recipient's own trusted infrastructure.",
        f"Preceding hops (closer to the recipient) were private/internal or unset, "
        "consistent with the message having entered from outside the organization at this point.",
    ]
    if hops_walked > 1:
        reasoning.append(
            f"The walk continued {hops_walked} hop(s) deep into external infrastructure "
            "while the chain remained well-formed and consistent."
        )
    if low_confidence_hops_in_walk:
        reasoning.append(
            f"{low_confidence_hops_in_walk} hop(s) in this walk had low parse confidence, "
            "reducing overall confidence in this conclusion."
        )
    if broke_reason:
        reasoning.append(broke_reason)

    return OriginResult(
        ip=best_public_ip,
        confidence=round(confidence, 2),
        determined=True,
        reasoning=reasoning,
    )
