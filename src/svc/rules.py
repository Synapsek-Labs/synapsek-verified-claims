"""Claim derivation — the anti-overclaiming layer.

The BUYER re-derives every claim status from measured values + the
documented thresholds, and re-derives the recommendation set from the
claim statuses. If the issuer claimed more than the numbers support,
verification FAILS. This is the property that makes SVC different from a
self-reported eval dashboard.
"""


def status_from_threshold(threshold: dict, value: float) -> str:
    """'proven' iff value satisfies every bound in threshold."""
    if "min" in threshold and not (value >= threshold["min"]):
        return "not_proven"
    if "max" in threshold and not (value <= threshold["max"]):
        return "not_proven"
    return "proven"


def recompute_field(evidence_lines: list, name: str, agg: str):
    """field:<name>|last|mean over evidence lines."""
    if not evidence_lines:
        raise ValueError("empty evidence for field rule")
    vals = [ln[name] for ln in evidence_lines]
    if agg == "last":
        return float(vals[-1])
    return float(sum(vals) / len(vals))


def derive_recommendations(claims: list, claim_statuses: dict) -> dict:
    """claim_statuses: {claim_id: 'proven'|'not_proven'}.

    recommended_for  = labels of proven claims
    not_recommended_for must contain labels of not-proven claims
    -> returns {"recommended_for": sorted list,
                "required_not_recommended": sorted list}
    """
    rec, notrec = set(), set()
    for c in claims:
        lab = c.get("label")
        if not lab:
            continue
        if claim_statuses.get(c["id"]) == "proven":
            rec.add(lab)
        else:
            notrec.add(lab)
    return {"recommended_for": sorted(rec),
            "required_not_recommended": sorted(notrec)}
