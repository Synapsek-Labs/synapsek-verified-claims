# Trust anchor — synapsek.compiler/v1

Issuer:            synapsek.compiler/v1
Public key:        MHYuRK-KEKtx3w-MQYnEJ7oiHWWJsJfP0WzNwn_Fi1M
Key file:          examples/trusted-issuer.pub (base64url, no padding)

This key signed the v1.1 cartridge attestation (G4 buyer-verified clean room)
and both claims in this repository. Obtain it out-of-band (this file, or the
v1.1 attestation bundle) — do not take it from a claim document.

Verify:
  svc verify examples/pipeline-dedup/claim.json \
      --trusted-pubkey examples/trusted-issuer.pub \
      --base-dir examples/pipeline-dedup --rerun
  svc verify examples/cartridge-v11/claim.json \
      --trusted-pubkey examples/trusted-issuer.pub \
      --base-dir examples/cartridge-v11
