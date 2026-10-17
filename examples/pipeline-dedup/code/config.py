"""Configuration dataclasses for the Knowledge Encoder + Universal Reader."""
from dataclasses import dataclass


@dataclass
class EncoderConfig:
    """Shared Knowledge Encoder: doc -> K latent vectors in a universal space."""
    vocab_size: int = 50257
    d_model: int = 256          # backbone hidden size
    nhead: int = 4
    num_layers: int = 2
    dim_feedforward: int = 512
    chunk_size: int = 2048      # tokens per backbone window (long docs are chunked)
    max_chunks: int = 64        # cap: max_chunks * chunk_size tokens
    max_doc_tokens: int = 8192  # truncate docs longer than this
    K: int = 64                 # number of latent vectors (the artifact size)
    d_latent: int = 256         # latent dimension
    pad_id: int = 0


@dataclass
class ReaderConfig:
    """Per-family Universal Reader: latent -> K' soft tokens in the target's embed space."""
    d_latent: int = 256
    d_model: int = 256          # target LLM hidden size
    K_prime: int = 32           # number of soft tokens to inject (crossattn mode)
    nhead: int = 4
    num_layers: int = 1
    kind: str = "crossattn"     # "crossattn" | "linear" | "mlp"
    cond: bool = False          # E4: question-conditioned (reader sees latent + question)
