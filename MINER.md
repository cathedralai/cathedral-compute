# Run a Compute (Intel-TDX) miner (SN39)

A compute miner earns on the **TDX lane** by doing **attested confidential compute**: it runs
a worker *inside an Intel-TDX confidential VM*, serves a fresh attestation quote bound to the
validator's channel, and does lane work (e.g. SAT). The validator verifies the quote and only
then sends work — no SSH, no trust in the host.

## Hardware requirement (read first)

Unlike the CyberGym lane, this lane is **hardware-gated**: production evidence must come from a
real **Intel TDX confidential VM** (a TDX-capable cloud instance), and the worker's TLS key must
terminate *inside* the measured guest. A plain server cannot produce a valid channel claim. If
you don't have TDX hardware, you can develop against the hardware-free mock (below) but cannot
earn on-chain.

## 1. Install (no root)

```bash
git clone https://github.com/cathedralai/cathedral-compute.git
cd cathedral-compute
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```
This gives you the `cathedral` operator CLI (`cathedral worker …`).

## 2. Register a hotkey

```bash
btcli subnet register --netuid 39 --wallet.name <coldkey> --wallet.hotkey <hotkey>
```

## 3. Serve the worker (inside the TDX VM)

Terminate TLS inside the measured guest, then serve the worker bound to that channel:
```bash
export MINER_HOTKEY=<your-hotkey-ss58>
export TLS_SPKI_SHA256=<sha256 of your in-guest TLS SPKI>   # public, not a secret

cathedral worker serve \
  --hotkey "$MINER_HOTKEY" \
  --channel-binding-type tls_spki_sha256 \
  --channel-binding-digest "$TLS_SPKI_SHA256"
```
The validator requests attestation over TLS, verifies the quote binds your channel, then sends
work and its bearer credential. You earn proportional to verified work.

See [docs/TDX_LAUNCH.md](docs/TDX_LAUNCH.md) for the full verifier contract + the five
`CATHEDRAL_TDX_VERIFY_*` variables, and [docs/GPU_ATTESTATION.md](docs/GPU_ATTESTATION.md) for
the GPU-composite path.

## Develop without TDX hardware (mock)

The `MockMiner` in `cathedral/neuron/miner.py` serves **mock** evidence (the real REPORT_DATA
binding + policy check, no vendor crypto) and does real SAT work, so you can exercise the
serve → verify → score path on any box. It cannot earn — the validator runs the real
vendor-crypto verifier in production — but it's the way to build and test the worker locally.

---
Prereqs: Python 3.11/3.12; for production, an Intel-TDX confidential VM; a registered SN39 hotkey.
</content>
