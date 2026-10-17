"""SVC — Synapsek Verified Claims.

Neutral, cryptographic verification of MEASURED CLAIMS about AI artifacts
and pipelines. A claim is a signed document stating: "on pinned data, with
pinned code, in a pinned environment, artifact X produces metric Y".

Verification is 5 layers, all buyer-side, no trust in the issuer:
  L1 AUTHENTICITY  Ed25519 signature over the canonical claim (trusted pubkey)
  L2 INTEGRITY     sha256 of every subject file (artifacts, data, code)
  L3 EVIDENCE      sha256 + Merkle root of every evidence trace
  L4 SOUNDNESS     every claimed value RECOMPUTED from evidence (static rule)
                   and, with --rerun, RE-EXECUTED from pinned artifacts
  L5 CLAIMS        claim statuses RE-DERIVED from measured values + thresholds;
                   overclaiming fails

Design doc: docs/DESIGN.md. Examples: examples/.
"""
__version__ = "0.1.0"
