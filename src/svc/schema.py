"""SVC claim schema v0.1 — validation + skeleton helpers.

A claim document (JSON) has:
  svc_version   "0.1.0"
  claim_id      unique id, e.g. "synapsek.claim/cartridge-v1.1/1"
  created_at    ISO-8601 UTC
  subject       {kind, id, description, base_dir, files[], evidence[]}
                files:    {path, role: artifact|data|code, sha256}
                evidence: {path, sha256, merkle_root, n_items}
  pinned        {environment, dataset, code, config}
  claims[]      {id, metric, value, unit, threshold, status, label,
                 derivation: {evidence?, rule, rerun?}}
  disclosures[] honest limitations (free text)
  issuer        {id, public_key}
  signature     Ed25519 over everything except this field

Rule grammar (derivation.rule) — deliberately tiny, no code eval:
  "field:<name>|last"   value = <name> of the LAST evidence line
  "field:<name>|mean"   value = mean of <name> over all evidence lines
  "script:<path>#<id>"  run `python3 <path>` (pinned code file) in base_dir;
                        stdout must be one JSON object; value = obj[<id>]
  "attested:<json-path>"  value = that path inside the pinned attestation
                          document (subject file with role "attestation") —
                          used to carry forward statistics that were
                          themselves recomputed by the attested pipeline
                          (see examples/cartridge-v11).

threshold: {"min": x} and/or {"max": x}; status is proven iff measured
satisfies all present bounds.
"""
import re

SCHEMA_VERSION = "0.1.0"
FILE_ROLES = ("artifact", "data", "code", "attestation", "other")
SUBJECT_KINDS = ("cartridge", "pipeline", "model", "agent")

def parse_rule(rule: str):
    """-> ("field", name, "last"|"mean") | ("file", path, field)
       | ("script", path, id) | ("attested", json_path)
       — raises ValueError on malformed rule."""
    m = re.match(r"^field:([A-Za-z0-9_.]+)\|(last|mean)$", rule)
    if m:
        return ("field", m.group(1), m.group(2))
    m = re.match(r"^file:(.+)#([A-Za-z0-9_.-]+)$", rule)
    if m:
        return ("file", m.group(1), m.group(2))
    m = re.match(r"^script:(.+)#([A-Za-z0-9_.-]+)$", rule)
    if m:
        return ("script", m.group(1), m.group(2))
    m = re.match(r"^attested:([A-Za-z0-9_.,\[\]-]+)$", rule)
    if m:
        return ("attested", m.group(1))
    raise ValueError(f"malformed rule: {rule!r}")


def get_json_path(obj, path: str):
    """Dotted index path into nested dicts/lists: 'qualification.gist_dimensions.0.measured'."""
    cur = obj
    for part in path.split("."):
        cur = cur[int(part)] if isinstance(cur, list) else cur[part]
    return cur


def validate_claim(claim: dict, strict: bool = True) -> list:
    """Return list of problems (empty = valid)."""
    problems = []
    for k in ("svc_version", "claim_id", "created_at", "subject", "pinned",
              "claims", "issuer"):
        if k not in claim:
            problems.append(f"missing top-level key: {k}")
    if problems:
        return problems
    if claim["svc_version"] != SCHEMA_VERSION:
        problems.append(f"unsupported svc_version {claim['svc_version']!r}")
    sub = claim["subject"]
    if sub.get("kind") not in SUBJECT_KINDS:
        problems.append(f"bad subject.kind: {sub.get('kind')!r}")
    for f in sub.get("files", []):
        if f.get("role") not in FILE_ROLES:
            problems.append(f"bad file role: {f.get('role')!r}")
        if not re.match(r"^[a-f0-9]{64}$", f.get("sha256", "")):
            problems.append(f"bad file sha256 for {f.get('path')}")
    for e in sub.get("evidence", []):
        if not re.match(r"^[a-f0-9]{64}$", e.get("sha256", "")):
            problems.append(f"bad evidence sha256 for {e.get('path')}")
        if not re.match(r"^[a-f0-9]{64}$", e.get("merkle_root", "")):
            problems.append(f"bad evidence merkle_root for {e.get('path')}")
        if not isinstance(e.get("n_items"), int):
            problems.append(f"bad evidence n_items for {e.get('path')}")
    for c in claim["claims"]:
        for k in ("id", "metric", "value", "threshold", "status", "derivation"):
            if k not in c:
                problems.append(f"claim {c.get('id', '?')} missing {k}")
        if c.get("status") not in ("proven", "not_proven"):
            problems.append(f"claim {c.get('id', '?')} bad status")
        t = c.get("threshold", {})
        if "min" not in t and "max" not in t:
            problems.append(f"claim {c.get('id', '?')} threshold needs min and/or max")
        try:
            parse_rule(c.get("derivation", {}).get("rule", ""))
        except ValueError as ex:
            problems.append(f"claim {c.get('id', '?')}: {ex}")
    if not re.match(r"^[A-Za-z0-9_-]{16,}$", claim["issuer"].get("public_key", "")):
        problems.append("bad issuer.public_key")
    return problems
