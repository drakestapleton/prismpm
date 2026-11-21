# Proposal: Omega GPU Bundle World (`hologram:gpu/omega-om@1`)

| | |
| --- | --- |
| Status | Proposed, Experimental |
| Capability | `HO-51` (suite `holo`, level `build`; `SPEC.md` §12.19, `features/suites/holo.feature`) |
| Reference implementation | [omega-mv `protocol/uor-gpu/`](https://interplane.io/drakestapleton/omega-mv) at commit `fb18bb7736535229d370f60a1b2cee2f86c6d9e9` |
| Depends on | #278 (WIT world registry), #287 (`@prism-code/conformance`), #269 (assurance levels `P0..P3`) |
| Related | #310 (ML-BOM for model inputs) |

## Summary

Adds a GPU kernel bundle world contract, `hologram:gpu/omega-om@1` (`sdk/npm/spec/worlds/gpu-omega.wit`), together with an experimental `@prism-code/conformance` runtime shim (`contrib/omega-gpu/`).

The world models offline-verifiable, content-addressed GPU kernel bundles (`UOR-GPU-1`) compiled in pure seeded Omega (OM-2) by the SHA-256-pinned `seed/out/omc` compiler, carrying dual SHA-256 + BLAKE3 seals, local `UORTRST1` trust anchors with strict authority/signer key separation, pinned Lean 4 proof digests (`P2` default policy), deterministic host VM replay (`P3`, decoding and executing SM121 SASS or SPIR-V 1.0 machine-code bytes), and fail-closed pre-dispatch capability admission.

## Motivation

PrismPM's existing worlds (`core-wasm@1`, `@2`, `@3`) specify pure WebAssembly guest modules. GPU workloads require target-specific machine code (such as Blackwell SM121 SASS + QMD v05.00 launch descriptors or OpenCL SPIR-V 1.0 kernels) that cannot be expressed inside `wasm32` alone, yet still need the same Prism guarantees:

1. **Identity from canonical bytes:** Content-addressed dual digests (`uor_id_sha256` + `.holo` BLAKE3 seal) independent of host paths, PCI slots, or driver handles.
2. **No central authority:** Offline verification against verifier-owned `UORTRST1` local trust anchors (`omc_sha256`, `lean_proof_sha256`, capability authority Ed25519 key, and 1..16 trusted signer keys with `authority != signer`).
3. **Honest assurance levels (`P0..P3`):** Unsigned bundles can never pass above `P0` and cannot smuggle non-zero signature bytes or claim `P1..P3`.
4. **Fail-closed pre-dispatch admission:** Every structural invariant (Blackwell QMD v05.00 SKEDCHECK05 or SPIR-V 1.0 OpenCL framing), digest, signature, proof pin, and authority-signed live capability lease (`RX_RIGHT_EFFECT`) is checked before touching any GPU driver.

### Goals

1. Register the WIT contract `sdk/npm/spec/worlds/gpu-omega.wit` (`package hologram:gpu@1.0.0; world omega-om`) without modifying `@1`, `@2`, `@3`, or any existing `.holo` v4/v5 bytes.
2. Add a conformance check in `sdk/npm/conformance/scenarios/world.json` verifying that a Core-Wasm `@1` archive is refused when a policy pins `hologram:gpu/omega-om@1`.
3. Provide a `prism/conformance-shim/1` runtime shim (`contrib/omega-gpu/shim.mjs`) with an explicit `prism/conformance-declaration/1` declaration and optional delegation to the compiled pure seeded-Omega `prism-gpu` binary (`PRISM_GPU_BIN`).

### Non-goals

- Changing the `.holo` v4 or v5 container format or `FORMAT_REVISIONS`.
- Claiming physical GPU silicon equivalence from the Lean 4 proof or host VM replay. In the reference implementation, SM121 SASS and SPIR-V 1.0 kernel replay are `HOST_TESTED` / `EMULATED` in pure seeded-Omega VMs; physical GB10 silicon execution is `NOT_RUN`.
- Inventing a bespoke ML-BOM document format (#310). The `mlbom_sha256` header slot (bytes `192..224`) is a 32-byte SHA-256 digest slot; the reference emitter currently hashes a deterministic manifest + golden input slab and is ready to pin a CycloneDX 1.7 or SPDX 3.0.1 AI profile BOM once #310 lands.

## Proposal

### The world

`sdk/npm/spec/worlds/gpu-omega.wit`, package `hologram:gpu@1.0.0`, world `omega-om` (`hologram:gpu/omega-om@1`):

```wit
export holo-alloc: func(length: u32) -> u32;
export holo-gpu-verify: func(bundle-offset: u32, bundle-length: u32, anchors-offset: u32, anchors-length: u32, min-level: u32) -> u64;
export holo-gpu-replay: func(bundle-offset: u32, bundle-length: u32, anchors-offset: u32, anchors-length: u32) -> u64;
export holo-gpu-admit: func(bundle-offset: u32, bundle-length: u32, anchors-offset: u32, anchors-length: u32, grant-offset: u32, grant-length: u32) -> u64;
```

The world declares no guest imports.

### Canonical `UOR-GPU-1` bundle header (384 bytes)

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 8 | Magic `"UORGPU1\0"` |
| 8 | 4 | Version (`1` u32 LE) |
| 12 | 4 | Target ISA (`1=SM121`, `2=SPIRV` u32 LE) |
| 16 | 4 | Math contract (`1=IEEE754_RN`, `2=FTZ` u32 LE) |
| 20 | 4 | Claimed evidence level (`0=P0..3=P3` u32 LE) |
| 24 | 4 | Payload length (`u32 LE`, `> 0`; exact `896` for SM121: 512B SASS + 384B QMD v5) |
| 28 | 4 | Launch `block_x` (`u32 LE`, `1..1024`; must equal QMD word 34 `threads_x` for SM121) |
| 32 | 32 | `omc_sha256` (pinned `seed/out/omc` digest) |
| 64 | 32 | `source_sha256` |
| 96 | 32 | `payload_sha256` |
| 128 | 32 | `lean_proof_sha256` (pinned `UorGpuWorld.lean` digest; required for `P2`/`P3`) |
| 160 | 32 | `replay_sha256` (deterministic VM replay output digest; verified at `P3`) |
| 192 | 32 | `mlbom_sha256` (32B ML-BOM digest slot) |
| 224 | 32 | `uor_id_sha256` (`SHA-256(header[0..224))`) |
| 256 | 32 | `holo_blake3` (`BLAKE3(header[0..256) \|\| payload)`) |
| 288 | 32 | `signer_pubkey` (RFC 8032 Ed25519 public key; all-zero = unsigned) |
| 320 | 64 | `attest_sig` (RFC 8032 Ed25519 signature over `header[224..288)`) |

### Machine-checked Lean 4 specification (external reference)

The reference implementation pins `protocol/uor-gpu/proofs/UorGpuWorld.lean` (SHA-256 `4242bcf69741fc3064f67083694e0e09f969eb4cc9ed4369d96154dc02a7238a`, 78 theorems, core Lean 4 only, zero `sorry`, zero `native_decide`, standard axioms `[propext, Classical.choice, Quot.sound]` only), proving:

1. Wire-layout contiguity, pairwise disjointness, and exact tiling (`384B`, `104B`, `128B`, `896B`).
2. Bit-exact `BitVec` round-trips, injectivity, and pairwise opcode disjointness for LE32, QMD v5 words 34/35/36, and SM121 SASS `w0`.
3. Multi-thread bounded `runVecadd` correctness and OOB canary preservation, plus `mnist`-style `vecadd_satisfies_contract`.
4. Two-stage SHA-256/BLAKE3 tamper evidence and `LexLeanBoot.ContentId`-style domain-separated framing under explicit collision resistance.
5. QMD v5 SKEDCHECK05 invariants, `UORTRST1` authority/signer privilege separation, reason-coded `evalPolicy`/`evalAdmit` equivalence, monotonicity, unsigned-P0 cap, and `uor-comms`-style forward/converse refusal-reason theorems.
6. Inductive `Step`/`Reachable`/`SafeInv` pre-dispatch lifecycle reachability (`no_unverified_gpu_touch`).
7. UOR $\mathbb{Z}/2^{32}\mathbb{Z}$ ring critical identity (`-~~~x = x + 1#32`) and `Foundation.Proof.V1.Statement` axiom-policy & replay verdict enforcement, with load-bearing negative controls in every section.

## Trusted base

- `seed/out/omc` (rebuilt from the 408-byte seed ladder; SHA-256 `708fdc0f81866594ed6df2f492b7a8a6bc7456f2d733a838b7f840549ebba6c3`).
- `lean4` kernel (`v4.35.0`) checking `UorGpuWorld.lean` with standard axioms only.
- Verifier's offline `UORTRST1` local trust anchors file.
- Pure seeded-Omega SM121 SASS and SPIR-V 1.0 host VMs for `P3` replay (`HOST_TESTED` / `EMULATED`; physical GB10 silicon execution is `NOT_RUN`).

## Test plan

- `cargo run --locked -p xtask -- validate-model` and `cargo run --locked -p xtask -- validate-spec-links` verify `HO-51` registration across `model/ids.toml`, `features/suites/holo.feature`, `SPEC.md`, `CONFORMANCE.md`, and `crates/conformance`.
- `cargo test --locked -p repo-conformance --test conformance conformance_ho_51 -- --exact` and `node --test "contrib/omega-gpu/test/omega-gpu.test.mjs"` exercise all 8 `HO-51` GPU bundle fixtures (SM121 896B QMD v05.00 SKEDCHECK05, SPIR-V 1.0 OpenCL framing, unsigned-envelope invariants, canonical header discriminants, caller-supplied world/digest pins, bounded verdict messages, registered diagnostic codes, and `prism/verdict/1` schema validation).
- `node sdk/npm/conformance/bin/prism-conformance.mjs gate --base origin/main --head HEAD` passes the `world` format rule via `world.gpu-omega.pin-contract-mismatch`.
- `node sdk/npm/conformance/bin/prism-conformance.mjs run --runtime omega-gpu` passes with every non-GPU feature honestly declared in `contrib/omega-gpu/declaration.json`.
- `node sdk/npm/conformance/bin/prism-conformance.mjs run --runtime js` and `--runtime rust` pass the updated `world.json` scenario suite, and `COMPLIANCE.md` passes `matrix --check`.
- `node --test "sdk/npm/spec/test/*.test.mjs"`, `node --test "sdk/npm/conformance/test/*.test.mjs"`, and `node --test "sdk/npm/prism-code/test/errors-registered.test.mjs"` pass.

## Alternatives

- Embedding GPU machine code inside a `core-wasm@1` guest module. Rejected: Wasm linear memory cannot carry native Blackwell SM121 QMD v5 descriptors or native SASS instructions without an extra wrapper layer and loses direct offline structural validation (`SKEDCHECK05` / SPIR-V 1.0) before driver submission.
- Modifying `.holo` v4 container magic or section tables immediately. Rejected: keeping `UOR-GPU-1` behind an experimental world contract and conformance shim lets runtimes adopt and test it without disturbing existing v4/v5 archives.

## Unresolved questions

1. Should `hologram:gpu/omega-om@1` wrap `UOR-GPU-1` inside a `.holo` v5 Extension section once a future format revision admits non-Wasm compute worlds, or keep a standalone canonical binary framed by `.holo` BLAKE3 seals?
2. How should `mlbom_sha256` bind a CycloneDX 1.7 / SPDX 3.0.1 AI profile attestation once #310 lands?
