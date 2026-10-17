"""Pinned dedup evaluation for the verified-claims example.

Deterministic, CPU-only. Reads (all relative to the claim dir):
  artifact/encoder.pt   pinned encoder weights
  code/tokenizer/       pinned Qwen2.5-1.5B tokenizer files
  data/docs.jsonl       pinned 100-doc set (hotpotqa, offset 200)

Writes:
  evidence/pairs.jsonl  one row per doc pair: {"blob_cos": x, "jaccard": y}
  evidence/summary.json {"spearman_rho": ..., "auc_highlow": ..., "n_pairs": ...}
Prints the summary JSON on stdout (last line).
"""
import json
import math
import os
import re

import torch
import torch.nn.functional as F

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
import sys
sys.path.insert(0, HERE)

from config import EncoderConfig      # noqa: E402
from encoder import KnowledgeEncoder  # noqa: E402


# ---- metric functions copied VERBATIM from the attested gist_metrics.py ----
def normalize(s):
    s = str(s).lower().strip()
    s = re.sub(r"[^\w\s]", "", s)
    return re.sub(r"\s+", " ", s).strip()


def tokens(s):
    return normalize(s).split()


def jaccard(a, b):
    sa, sb = set(tokens(a)), set(tokens(b))
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def spearman(xs, ys):
    """Spearman rho on paired lists (ties: average rank)."""
    def ranks(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
                j += 1
            avg = (i + j) / 2 + 1
            for k in range(i, j + 1):
                r[order[k]] = avg
            i = j + 1
        return r
    rx, ry = ranks(xs), ranks(ys)
    mx, my = sum(rx) / len(rx), sum(ry) / len(ry)
    cov = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    vx = math.sqrt(sum((a - mx) ** 2 for a in rx))
    vy = math.sqrt(sum((b - my) ** 2 for b in ry))
    if vx == 0 or vy == 0:
        return 0.0
    return cov / (vx * vy)


def auc(scores, labels):
    """Rank-based AUC (Mann-Whitney)."""
    pos = [s for s, l in zip(scores, labels) if l == 1]
    neg = [s for s, l in zip(scores, labels) if l == 0]
    if not pos or not neg:
        return 0.5
    w = 0
    for p in pos:
        w += sum(1 for q in neg if p > q) + 0.5 * sum(1 for q in neg if p == q)
    return w / (len(pos) * len(neg))




# ---- evaluation (same pipeline as gist_metrics.py D2, pinned) ----
def main():
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(os.path.join(HERE, "tokenizer"))
    enc_cfg = EncoderConfig(vocab_size=len(tok), d_model=256, nhead=4,
                            num_layers=2, dim_feedforward=512, chunk_size=2048,
                            max_chunks=64, max_doc_tokens=8192, K=128,
                            d_latent=256)
    enc = KnowledgeEncoder(enc_cfg)
    enc.load_state_dict(torch.load(os.path.join(BASE, "artifact", "encoder.pt"),
                                   map_location="cpu"))
    enc.eval()

    docs = [json.loads(l) for l in open(os.path.join(BASE, "data", "docs.jsonl"))
            if l.strip()]
    n = len(docs)

    latents = []
    with torch.no_grad():
        for d in docs:
            ids = torch.tensor(tok.encode(d["doc_text"])[:8192],
                               dtype=torch.long).unsqueeze(0)
            latents.append(enc(ids).squeeze(0))          # (K, d_latent)
    L = torch.stack(latents)                             # n x K x d
    pool = L.mean(dim=1)                                 # n x d
    pool = F.normalize(pool, dim=-1)
    blob_cos = (pool @ pool.T).tolist()

    texts = [d["doc_text"] for d in docs]
    jac = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            v = jaccard(texts[i], texts[j])
            jac[i][j] = jac[j][i] = v

    pairs_b, pairs_j = [], []
    for i in range(n):
        for j in range(i + 1, n):
            pairs_b.append(blob_cos[i][j])
            pairs_j.append(jac[i][j])

    rho = spearman(pairs_b, pairs_j)
    med = sorted(pairs_j)[len(pairs_j) // 2]
    labels = [1 if x >= med else 0 for x in pairs_j]
    a = auc(pairs_b, labels)

    os.makedirs(os.path.join(BASE, "evidence"), exist_ok=True)
    with open(os.path.join(BASE, "evidence", "pairs.jsonl"), "w") as f:
        for b, j in zip(pairs_b, pairs_j):
            f.write(json.dumps({"blob_cos": b, "jaccard": j}) + "\n")
    summary = {"spearman_rho": rho, "auc_highlow": a, "n_pairs": len(pairs_b)}
    with open(os.path.join(BASE, "evidence", "summary.json"), "w") as f:
        json.dump(summary, f)  # single line: valid 1-item JSONL for the Merkle trace
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
