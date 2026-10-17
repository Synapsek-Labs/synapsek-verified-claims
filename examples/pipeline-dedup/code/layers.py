"""Shared building blocks."""
import torch
import torch.nn as nn


class CrossAttentionLayer(nn.Module):
    """Perceiver / Q-Former block: query self-attends, then cross-attends to source.

    nn.TransformerEncoderLayer cannot express this (its 2nd arg is a mask, not
    an independent key/value source), so we build it from nn.MultiheadAttention.
    """

    def __init__(self, d_model, nhead, dim_ff, dropout=0.0):
        super().__init__()
        self.self_attn = nn.MultiheadAttention(d_model, nhead, batch_first=True,
                                               dropout=dropout)
        self.cross_attn = nn.MultiheadAttention(d_model, nhead, batch_first=True,
                                                dropout=dropout)
        self.ff = nn.Sequential(nn.Linear(d_model, dim_ff), nn.GELU(),
                                nn.Dropout(dropout), nn.Linear(dim_ff, d_model))
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        self.norm3 = nn.LayerNorm(d_model)

    def forward(self, q, src):
        q2, _ = self.self_attn(q, q, q, need_weights=False)
        q = self.norm1(q + q2)
        q2, _ = self.cross_attn(q, src, src, need_weights=False)
        q = self.norm2(q + q2)
        q = self.norm3(q + self.ff(q))
        return q
