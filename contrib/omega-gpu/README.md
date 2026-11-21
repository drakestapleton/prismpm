# Omega GPU Conformance Shim (`omega-gpu`)

Experimental `prism/conformance-shim/1` shim for the **`hologram:gpu/omega-om@1`** GPU bundle world (`UOR-GPU-1`), backed by the pure seeded-Omega implementation in [omega-mv `protocol/uor-gpu/`](https://interplane.io/drakestapleton/omega-mv) (`fb18bb7736535229d370f60a1b2cee2f86c6d9e9`).

## Run the conformance suite

```bash
node sdk/npm/conformance/bin/prism-conformance.mjs run --runtime omega-gpu
```

## Optional pure seeded-Omega `prism-gpu` binary delegation

On an AArch64 Linux host with `omega-mv` checked out and `prism-gpu` built by `seed/out/omc`, set `PRISM_GPU_BIN=/path/to/prism-gpu` to delegate `UOR-GPU-1` `inspect` calls directly to the pure seeded-Omega binary.

## Honest scope

- Registered under capability **`HO-51`** (`model/ids.toml`, `features/suites/holo.feature`, `crates/conformance/tests/conformance.rs`, `contrib/omega-gpu/test/omega-gpu.test.mjs`).
- Implements `describe`, `inspect`, `verify`, and `load` for canonical 384-byte `UOR-GPU-1` GPU bundles (including unsigned-envelope invariants, dual SHA-256 + BLAKE3 seals, SM121 896B QMD v05.00 SKEDCHECK05 and SPIR-V 1.0 OpenCL Kernel framing, caller-supplied world/digest pins, registered diagnostic codes, and schema-valid `prism/verdict/1` verdicts) plus `.holo` container refusal checks (`empty`, `too-short`, `bad-magic`, `bad-version`, `bad-flags`, `truncated-table`, `section-overrun`, `unknown-kind`) and policy validation.
- Declares `notApplicable` for Core-Wasm-only / host features (`auth`, `capabilities`, `dispatch`, `replay`) and `xfail` in `declaration.json` for Core-Wasm guest archive checks.
- Physical GB10 silicon execution is `NOT_RUN`; kernel replay in `omega-mv` runs in deterministic pure seeded-Omega host VMs (`HOST_TESTED` / `EMULATED`).
