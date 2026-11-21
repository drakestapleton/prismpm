# Omega GPU Conformance Shim (`omega-gpu`)

Experimental `prism/conformance-shim/1` shim for the **`hologram:gpu/omega-om@1`** GPU bundle world (`UOR-GPU-1`), backed by the pure seeded-Omega implementation in [omega-mv `protocol/uor-gpu/`](https://interplane.io/drakestapleton/omega-mv) (`fb18bb7736535229d370f60a1b2cee2f86c6d9e9`).

## Run the conformance suite

```bash
node sdk/npm/conformance/bin/prism-conformance.mjs run --runtime omega-gpu
```

## Optional pure seeded-Omega `prism-gpu` binary delegation

On an AArch64 Linux host with `omega-mv` checked out and `prism-gpu` built by `seed/out/omc`, set `PRISM_GPU_BIN=/path/to/prism-gpu` to delegate `UOR-GPU-1` `inspect` calls directly to the pure seeded-Omega binary.

## Honest scope

- Implements `describe`, `inspect`, `verify`, and `load` for `UOR-GPU-1` GPU bundles and `.holo` container refusal checks (`empty`, `too-short`, `bad-magic`, `bad-version`, `bad-flags`, `truncated-table`, `section-overrun`, `unknown-kind`) plus policy validation.
- Declares `notApplicable` for Core-Wasm-only / host features (`auth`, `capabilities`, `dispatch`, `replay`) and `xfail` in `declaration.json` for Core-Wasm guest archive checks.
- Physical GB10 silicon execution is `NOT_RUN`; kernel replay in `omega-mv` runs in deterministic pure seeded-Omega host VMs (`HOST_TESTED` / `EMULATED`).
