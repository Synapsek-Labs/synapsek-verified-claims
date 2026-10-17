"""Knowledge Encoder (E) — shared, model-agnostic.

A chunked Transformer backbone encodes the document, then a Perceiver-style
resampler (K learnable queries) cross-attends over the whole encoding to emit
K latent vectors in a UNIVERSAL space. The same encoder serves every target
family — that is what makes the artifact portable by construction.
"""
import torch
import torch.nn as nn

from layers import CrossAttentionLayer


class PerceiverResampler(nn.Module):
    """K learnable queries cross-attend to source hidden states -> K vectors."""

    def __init__(self, d_model: int, K: int, nhead: int, num_layers: int = 2,
                 dim_ff: int = 512):
        super().__init__()
        self.queries = nn.Parameter(torch.randn(K, d_model) * 0.02)
        self.layers = nn.ModuleList(
            [CrossAttentionLayer(d_model, nhead, dim_ff) for _ in range(num_layers)])
        self.out_norm = nn.LayerNorm(d_model)

    def forward(self, src):  # src: (B, T, d)
        B = src.size(0)
        q = self.queries.unsqueeze(0).expand(B, -1, -1)
        for lay in self.layers:
            q = lay(q, src)
        return self.out_norm(q)  # (B, K, d)


class KnowledgeEncoder(nn.Module):
    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        self.tok_embed = nn.Embedding(cfg.vocab_size, cfg.d_model)
        self.pos_embed = nn.Embedding(cfg.chunk_size, cfg.d_model)
        layer = nn.TransformerEncoderLayer(
            cfg.d_model, cfg.nhead, cfg.dim_feedforward,
            batch_first=True, norm_first=True)
        self.backbone = nn.TransformerEncoder(layer, cfg.num_layers)
        self.resampler = PerceiverResampler(
            cfg.d_model, cfg.K, cfg.nhead, 2, cfg.dim_feedforward)
        self.proj = (nn.Identity() if cfg.d_latent == cfg.d_model
                     else nn.Linear(cfg.d_model, cfg.d_latent))

    def forward(self, tok_ids, pad_id=None):
        """tok_ids: (B, T) -> (B, K, d_latent)"""
        if pad_id is None:
            pad_id = self.cfg.pad_id
        B, T = tok_ids.shape
        C = self.cfg.chunk_size
        Tc = min(T, self.cfg.max_chunks * C, self.cfg.max_doc_tokens)
        tok_ids = tok_ids[:, :Tc]
        n_chunks = (Tc + C - 1) // C
        if Tc < n_chunks * C:  # right-pad last chunk
            pad = torch.full((B, n_chunks * C - Tc), pad_id,
                             dtype=tok_ids.dtype, device=tok_ids.device)
            tok_ids = torch.cat([tok_ids, pad], dim=1)
        ids = tok_ids.view(B, n_chunks, C)                    # (B, nC, C)
        ids = ids.reshape(B * n_chunks, C)
        pos = torch.arange(C, device=ids.device).unsqueeze(0).expand(B * n_chunks, -1)
        h = self.tok_embed(ids) + self.pos_embed(pos)         # (B*nC, C, d)
        hmask = ids == pad_id
        # NaN guard: a fully-masked chunk (short doc right-padded into a
        # longer-doc batch) makes src_key_padding_mask all-True -> softmax
        # over empty keys -> NaN. Unmasking one position is a no-op for
        # every currently-finite path and makes degenerate chunks finite.
        allm = hmask.all(dim=1)
        if allm.any():
            hmask = hmask.clone()
            hmask[allm, 0] = False
        h = self.backbone(h, src_key_padding_mask=hmask)      # (B*nC, C, d)
        h = h.view(B, n_chunks * C, self.cfg.d_model)
        q = self.resampler(h)                                 # (B, K, d)
        return self.proj(q)                                   # (B, K, d_latent)
