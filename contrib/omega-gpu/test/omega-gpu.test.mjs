// Conformance tests for HO-51: Omega GPU bundle world (`hologram:gpu/omega-om@1`)
// and its `prism/conformance-shim/1` runtime shim (`contrib/omega-gpu/shim.mjs`).
// Exercises UOR-GPU-1 SM121 and SPIR-V 1.0 inspect/verify/load paths, caller-supplied
// pins, boundary message lengths, unsigned-envelope & header-discriminant refusals,
// SM121 896B QMD v05.00 SKEDCHECK05 and SPIR-V 1.0 OpenCL framing, registered error
// codes, and `prism/verdict/1` JSON Schema conformance.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { blake3Hex } from '../../../sdk/npm/prism-code/src/blake3.mjs';
import { callShim } from '../../../sdk/npm/conformance/src/shim.mjs';
import { validate } from '../../../sdk/npm/conformance/src/vendor/json-schema.mjs';
import { VERDICT_SCHEMA } from '../../../sdk/npm/conformance/src/vendor/verdict-schema.mjs';

const REPO = fileURLToPath(new URL('../../..', import.meta.url));
const SHIM = [process.execPath, fileURLToPath(new URL('../shim.mjs', import.meta.url))];
const WIT_BYTES = new Uint8Array(
  Buffer.from(readFileSync(join(REPO, 'sdk/npm/spec/worlds/gpu-omega.wit'), 'utf8').replaceAll('\r\n', '\n'), 'utf8'),
);
const WORLD_SHA256 = createHash('sha256').update(WIT_BYTES).digest('hex');
const WORLD_BLAKE3 = blake3Hex(WIT_BYTES);

const REGISTERED_SDK_CODES = new Set(
  [...readFileSync(join(REPO, 'model/sdk-diagnostics.toml'), 'utf8').matchAll(/^code = "([^"]+)"$/gm)].map((m) => m[1]),
);

const sha256Buf = (buf) => createHash('sha256').update(buf).digest();
const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex');

/** Build a valid 896-byte SM121 payload (512B SASS + 384B QMD v05.00 passing SKEDCHECK05). */
function buildSm121Payload(blockX = 256, { versionMajor = 5, qmdType = 2, threadsX = blockX, gprCount = 16 } = {}) {
  const payload = Buffer.alloc(896, 0);
  const q = (idx, val) => payload.writeUInt32LE(val >>> 0, 512 + idx * 4);
  q(4, ((qmdType & 0x7) << 23) | 0x003f0000);
  q(14, (0x2f0003a4 | ((versionMajor & 0xf) << 20)) >>> 0);
  q(17, 1); // semEnable != 0
  q(32, 0x10000000); // codeVa != 0
  q(33, (0xa << 21) >>> 0); // prefetchTag == 0xa
  q(34, ((1 << 16) | (threadsX & 0xffff)) >>> 0);
  q(35, (1 | ((gprCount & 0x1ff) << 8) | (1 << 17)) >>> 0);
  q(36, 0x04b44808);
  q(37, 0);
  q(39, 1);
  q(40, 1);
  q(41, 1);
  q(42, 0x10010000); // cbankVa != 0
  q(58, 0x10300011); // cb0Valid
  return payload;
}

/** Build a valid minimal OpenCL Kernel SPIR-V 1.0 binary payload matching `payload_vm.om`. */
function buildSpirvPayload({
  magic = 0x07230203,
  version = 0x00010000,
  bound = 8,
  schema = 0,
  includeKernelCap = true,
  extraEntryId = null,
  defineExtraEntryFn = false,
  secondMemModel = false,
  truncateInst = false,
} = {}) {
  const words = [
    magic,
    version,
    0, // generator
    bound,
    schema,
    (2 << 16) | 17, 4, // OpCapability Addresses
  ];
  if (includeKernelCap) words.push((2 << 16) | 17, 6); // OpCapability Kernel
  words.push((3 << 16) | 14, 2, 2); // OpMemoryModel Physical64 OpenCL
  if (secondMemModel) words.push((3 << 16) | 14, 0, 1); // conflicting duplicate OpMemoryModel
  words.push((5 << 16) | 15, 6, 3, 0x64646176, 0); // OpEntryPoint Kernel %3 "vadd"
  if (extraEntryId !== null) words.push((5 << 16) | 15, 6, extraEntryId, 0x62626176, 0);
  if (extraEntryId !== null && defineExtraEntryFn) {
    words.push(
      (5 << 16) | 54, 1, extraEntryId, 0, 2, // OpFunction %1 %extraEntryId None %2
      (1 << 16) | 56, // OpFunctionEnd
    );
  }
  if (extraEntryId === null || defineExtraEntryFn) {
    words.push(
      (5 << 16) | 54, 1, 3, 0, 2, // OpFunction %1 %3 None %2
      (1 << 16) | 56, // OpFunctionEnd
    );
  } else {
    // Only define the second entry point, leaving %3 undefined.
    words.push(
      (5 << 16) | 54, 1, extraEntryId, 0, 2,
      (1 << 16) | 56,
    );
  }
  if (truncateInst) words.push((5 << 16) | 17, 6); // claims 5 words, only 2 present
  const buf = Buffer.alloc(words.length * 4);
  words.forEach((v, i) => buf.writeUInt32LE(v >>> 0, i * 4));
  return buf;
}

/** Seal a canonical 384-byte UOR-GPU-1 header + payload. */
function buildUorGpuBundle({
  version = 1,
  isa = 1,
  math = 1,
  claimedLevel = 0,
  blockX = 256,
  payload,
  signerPubByte = 0,
  sigByte0 = 0,
}) {
  const hdr = Buffer.alloc(384, 0);
  Buffer.from('UORGPU1\0', 'ascii').copy(hdr, 0);
  hdr.writeUInt32LE(version >>> 0, 8);
  hdr.writeUInt32LE(isa >>> 0, 12);
  hdr.writeUInt32LE(math >>> 0, 16);
  hdr.writeUInt32LE(claimedLevel >>> 0, 20);
  hdr.writeUInt32LE(payload.length >>> 0, 24);
  hdr.writeUInt32LE(blockX >>> 0, 28);
  sha256Buf(payload).copy(hdr, 96);
  sha256Buf(hdr.subarray(0, 224)).copy(hdr, 224);
  const holoHex = blake3Hex(new Uint8Array(Buffer.concat([hdr.subarray(0, 256), payload])));
  Buffer.from(holoHex, 'hex').copy(hdr, 256);
  if (signerPubByte !== 0) hdr[288] = signerPubByte;
  if (sigByte0 !== 0) hdr[320] = sigByte0;
  return Buffer.concat([hdr, payload]);
}

function assertValidVerdict(verdict) {
  const errors = validate(VERDICT_SCHEMA, verdict);
  assert.deepEqual(errors, [], `verdict violated prism/verdict/1 schema: ${JSON.stringify(errors)}`);
}

function assertRegisteredCode(code, context) {
  assert.ok(
    REGISTERED_SDK_CODES.has(code),
    `${context}: error.code ${JSON.stringify(code)} is not registered in model/sdk-diagnostics.toml`,
  );
}

async function withBundle(bytes, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'omega-gpu-test-'));
  const path = join(dir, 'bundle.holo');
  writeFileSync(path, bytes);
  try {
    return await fn(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('valid SM121 UOR-GPU-1 bundle inspects, loads, and passes P0 with schema-valid prism/verdict/1', async () => {
  const bundle = buildUorGpuBundle({ payload: buildSm121Payload(256) });
  await withBundle(bundle, async (archive) => {
    const ins = await callShim(SHIM, { op: 'inspect', archive, input: {} });
    assert.equal(ins.broken, undefined);
    assert.equal(ins.response.ok, true);
    assert.equal(ins.response.result.world.contract, 'hologram:gpu/omega-om@1');
    assert.equal(ins.response.result.world.conforms, true);
    assert.deepEqual(ins.response.result.world.digest, { sha256: WORLD_SHA256, blake3: WORLD_BLAKE3 });

    const ld = await callShim(SHIM, { op: 'load', archive, input: {} });
    assert.equal(ld.response.ok, true);
    assert.equal(ld.response.result.verified, true);
    assert.equal(ld.response.result.world.contract, 'hologram:gpu/omega-om@1');

    const ver = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' } } });
    assert.equal(ver.response.ok, true);
    assertValidVerdict(ver.response.result);
    assert.equal(ver.response.result.passed, true);
    assert.equal(ver.response.result.level, 'P0');
    assert.equal(ver.response.result.policy.minimum, 'P0');

    const defVer = await callShim(SHIM, { op: 'verify', archive, input: { throw: true } });
    assert.equal(defVer.response.ok, false);
    assertRegisteredCode(defVer.response.error.code, 'default P2 throw');
    assert.equal(defVer.response.error.code, 'verification_failed');
    assertValidVerdict(defVer.response.error.verdict);
    assert.equal(defVer.response.error.verdict.passed, false);
  });
});

test('caller-supplied world and digest pins are enforced at P0 and unsupported pins fail policy.invalid', async () => {
  const payload = buildSm121Payload(256);
  const bundle = buildUorGpuBundle({ payload });
  const archiveSha = sha256Hex(bundle);
  const archiveB3 = blake3Hex(new Uint8Array(bundle));
  const payloadSha = sha256Hex(payload);
  const payloadB3 = blake3Hex(new Uint8Array(payload));
  const wrongHex = '0'.repeat(64);

  await withBundle(bundle, async (archive) => {
    const ok = await callShim(SHIM, {
      op: 'verify',
      archive,
      input: {
        policy: {
          minimum: 'P0',
          world: { contract: 'hologram:gpu/omega-om@1', sha256: WORLD_SHA256, blake3: WORLD_BLAKE3 },
          digests: {
            archive: { sha256: archiveSha, blake3: archiveB3 },
            payload: { sha256: payloadSha, blake3: payloadB3 },
          },
        },
      },
    });
    assert.equal(ok.response.ok, true);
    assertValidVerdict(ok.response.result);
    assert.equal(ok.response.result.passed, true);

    for (const [label, policy, expectedCheck, expectedThrowCode] of [
      ['world.contract', { minimum: 'P0', world: { contract: 'hologram:guest/core-wasm@1' } }, 'world.hash', 'world_mismatch'],
      ['world.sha256', { minimum: 'P0', world: { sha256: wrongHex } }, 'world.hash', 'world_mismatch'],
      ['world.blake3', { minimum: 'P0', world: { blake3: wrongHex } }, 'world.hash', 'world_mismatch'],
      ['world.null', { minimum: 'P0', world: null }, 'world.hash', 'world_mismatch'],
      ['digests.archive.sha256', { minimum: 'P0', digests: { archive: { sha256: wrongHex } } }, 'policy.digests.archive', 'verification_failed'],
      ['digests.archive.blake3', { minimum: 'P0', digests: { archive: { blake3: wrongHex } } }, 'policy.digests.archive', 'verification_failed'],
      ['digests.payload.sha256', { minimum: 'P0', digests: { payload: { sha256: wrongHex } } }, 'policy.digests.payload', 'verification_failed'],
    ]) {
      const res = await callShim(SHIM, { op: 'verify', archive, input: { policy } });
      assert.equal(res.response.ok, true, label);
      assertValidVerdict(res.response.result);
      assert.equal(res.response.result.passed, false, `${label} must fail`);
      assert.ok(res.response.result.reasons.some((r) => r.check === expectedCheck), `${label} missing ${expectedCheck}`);

      const thr = await callShim(SHIM, { op: 'verify', archive, input: { policy, throw: true } });
      assert.equal(thr.response.ok, false, `${label} throw`);
      assertRegisteredCode(thr.response.error.code, label);
      assert.equal(thr.response.error.code, expectedThrowCode, label);
      assertValidVerdict(thr.response.error.verdict);
    }

    for (const [label, policy] of [
      ['unsupported digest target', { minimum: 'P0', digests: { guest: { sha256: wrongHex } } }],
      ['unknown policy key', { minimum: 'P0', trust: {} }],
      ['empty world contract', { minimum: 'P0', world: { contract: '' } }],
      ['duplicate impure effect', { minimum: 'P0', effects: ['clock', 'clock'] }],
      ['capability kind as effect', { minimum: 'P0', effects: ['outbound-hosts'] }],
    ]) {
      const res = await callShim(SHIM, { op: 'verify', archive, input: { policy } });
      assert.equal(res.response.ok, false, label);
      assertRegisteredCode(res.response.error.code, label);
      assert.equal(res.response.error.check, 'policy.invalid', label);
    }

    // Null policy / null optional fields and pure/impure effect lists match @prism-code/verify semantics.
    for (const [label, policy, expectedPassed, env, expectedMin] of [
      ['null policy (default P2)', null, false, {}, 'P2'],
      ['null policy inherits PRISM_MINIMUM_LEVEL=P0', null, true, { PRISM_MINIMUM_LEVEL: 'P0' }, 'P0'],
      ['explicit minimum: null ignores PRISM_MINIMUM_LEVEL=P0 (stays P2)', { minimum: null }, false, { PRISM_MINIMUM_LEVEL: 'P0' }, 'P2'],
      ['explicit minimum: null ignores invalid PRISM_MINIMUM_LEVEL', { minimum: null }, false, { PRISM_MINIMUM_LEVEL: 'high' }, 'P2'],
      ['empty PRISM_MINIMUM_LEVEL treated as unset (P2)', {}, false, { PRISM_MINIMUM_LEVEL: '' }, 'P2'],
      ['null optional policy fields at P0', { name: null, minimum: 'P0', digests: null, effects: null }, true, {}, 'P0'],
      ['pure-only effects []', { minimum: 'P0', effects: [] }, true, {}, 'P0'],
      ['impure effects [clock, random]', { minimum: 'P0', effects: ['clock', 'random'] }, true, {}, 'P0'],
    ]) {
      const res = await callShim(SHIM, { op: 'verify', archive, input: { policy } }, { env });
      assert.equal(res.response.ok, true, label);
      assertValidVerdict(res.response.result);
      assert.equal(res.response.result.passed, expectedPassed, label);
      assert.equal(res.response.result.policy.minimum, expectedMin, label);
    }

    const badEnv = await callShim(SHIM, { op: 'verify', archive, input: {} }, { env: { PRISM_MINIMUM_LEVEL: 'high' } });
    assert.equal(badEnv.response.ok, false);
    assertRegisteredCode(badEnv.response.error.code, 'invalid PRISM_MINIMUM_LEVEL');
    assert.equal(badEnv.response.error.check, 'policy.invalid');
  });
});

test('oversized policy world contract pins still emit bounded schema-valid verdicts', async () => {
  const bundle = buildUorGpuBundle({ payload: buildSm121Payload(256) });
  await withBundle(bundle, async (archive) => {
    for (const length of [1024, 2500]) {
      const longContract = 'a'.repeat(length);
      const res = await callShim(SHIM, {
        op: 'verify',
        archive,
        input: { policy: { minimum: 'P0', world: { contract: longContract } } },
      });
      assert.equal(res.response.ok, true);
      assertValidVerdict(res.response.result);
      assert.equal(res.response.result.passed, false);
      for (const r of res.response.result.reasons) assert.ok(r.message.length <= 1024);

      const thr = await callShim(SHIM, {
        op: 'verify',
        archive,
        input: { policy: { minimum: 'P0', world: { contract: longContract } }, throw: true },
      });
      assert.equal(thr.response.ok, false);
      assertRegisteredCode(thr.response.error.code, `longContract ${length}`);
      assert.equal(thr.response.error.code, 'world_mismatch');
      assertValidVerdict(thr.response.error.verdict);
    }
  });
});

test('SM121 bundles without 896B SASS + valid QMD v05.00 SKEDCHECK05 framing are rejected with registered codes', async () => {
  const badCases = [
    ['1-byte SM121 payload', buildUorGpuBundle({ payload: Buffer.from([0x42]) })],
    ['wrong QMD versionMajor=4', buildUorGpuBundle({ payload: buildSm121Payload(256, { versionMajor: 4 }) })],
    ['wrong QMD qmdType=1', buildUorGpuBundle({ payload: buildSm121Payload(256, { qmdType: 1 }) })],
    ['QMD threadsX != blockX', buildUorGpuBundle({ blockX: 256, payload: buildSm121Payload(256, { threadsX: 128 }) })],
    ['QMD gprCount < 16', buildUorGpuBundle({ payload: buildSm121Payload(256, { gprCount: 8 }) })],
  ];
  for (const [label, bundle] of badCases) {
    await withBundle(bundle, async (archive) => {
      const ins = await callShim(SHIM, { op: 'inspect', archive, input: {} });
      assert.equal(ins.response.ok, true, label);
      assert.equal(ins.response.result.world.conforms, false, label);

      const ld = await callShim(SHIM, { op: 'load', archive, input: {} });
      assert.equal(ld.response.ok, false, label);
      assertRegisteredCode(ld.response.error.code, label);
      assert.equal(ld.response.error.code, 'world_mismatch', label);
      assert.equal(ld.response.error.check, 'world.contract', label);

      const ver = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' } } });
      assert.equal(ver.response.ok, true, label);
      assertValidVerdict(ver.response.result);
      assert.equal(ver.response.result.passed, false, label);
      assert.ok(ver.response.result.reasons.some((r) => r.check === 'world.contract'), label);

      const thr = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' }, throw: true } });
      assert.equal(thr.response.ok, false, label);
      assertRegisteredCode(thr.response.error.code, `${label} throw`);
      assert.equal(thr.response.error.code, 'world_mismatch', label);
    });
  }
});

test('SPIR-V 1.0 OpenCL Kernel framing and exact version 1.0 are enforced', async () => {
  const goodSpirv = buildUorGpuBundle({ isa: 2, blockX: 64, payload: buildSpirvPayload() });
  await withBundle(goodSpirv, async (archive) => {
    const ins = await callShim(SHIM, { op: 'inspect', archive, input: {} });
    assert.equal(ins.response.ok, true);
    assert.equal(ins.response.result.world.conforms, true);

    const ld = await callShim(SHIM, { op: 'load', archive, input: {} });
    assert.equal(ld.response.ok, true);
    assert.equal(ld.response.result.verified, true);

    const ver = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' } } });
    assert.equal(ver.response.ok, true);
    assertValidVerdict(ver.response.result);
    assert.equal(ver.response.result.passed, true);
  });

  const goodMultiSpirv = buildUorGpuBundle({
    isa: 2,
    blockX: 64,
    payload: buildSpirvPayload({ extraEntryId: 4, defineExtraEntryFn: true }),
  });
  await withBundle(goodMultiSpirv, async (archive) => {
    const ver = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' } } });
    assert.equal(ver.response.ok, true);
    assertValidVerdict(ver.response.result);
    assert.equal(ver.response.result.passed, true);
  });

  const spvWords = (words) => {
    const b = Buffer.alloc(words.length * 4);
    words.forEach((v, i) => b.writeUInt32LE(v >>> 0, i * 4));
    return b;
  };
  const badSpirvCases = [
    ['bad SPIR-V magic', buildSpirvPayload({ magic: 0xdeadbeef })],
    ['bad SPIR-V version 0xffffffff', buildSpirvPayload({ version: 0xffffffff })],
    ['non-1.0 SPIR-V version 1.5', buildSpirvPayload({ version: 0x00010500 })],
    ['non-zero SPIR-V schema', buildSpirvPayload({ schema: 1 })],
    ['entryId >= bound', buildSpirvPayload({ bound: 3 })],
    ['multiple OpEntryPoint with first undefined', buildSpirvPayload({ extraEntryId: 4, defineExtraEntryFn: false })],
    ['duplicate OpEntryPoint id', buildSpirvPayload({ extraEntryId: 3, defineExtraEntryFn: true })],
    ['duplicate conflicting OpMemoryModel', buildSpirvPayload({ secondMemModel: true })],
    ['OpEntryPoint after OpFunction', spvWords([0x07230203, 0x00010000, 0, 8, 0, (2 << 16) | 17, 4, (2 << 16) | 17, 6, (3 << 16) | 14, 2, 2, (5 << 16) | 54, 1, 3, 0, 2, (1 << 16) | 56, (5 << 16) | 15, 6, 3, 0x64646176, 0])],
    ['OpCapability after OpMemoryModel', spvWords([0x07230203, 0x00010000, 0, 8, 0, (2 << 16) | 17, 4, (3 << 16) | 14, 2, 2, (2 << 16) | 17, 6, (5 << 16) | 15, 6, 3, 0x64646176, 0, (5 << 16) | 54, 1, 3, 0, 2, (1 << 16) | 56])],
    ['empty OpEntryPoint name', spvWords([0x07230203, 0x00010000, 0, 8, 0, (2 << 16) | 17, 4, (2 << 16) | 17, 6, (3 << 16) | 14, 2, 2, (4 << 16) | 15, 6, 3, 0, (5 << 16) | 54, 1, 3, 0, 2, (1 << 16) | 56])],
    ['unterminated OpEntryPoint name', spvWords([0x07230203, 0x00010000, 0, 8, 0, (2 << 16) | 17, 4, (2 << 16) | 17, 6, (3 << 16) | 14, 2, 2, (4 << 16) | 15, 6, 3, 0x41414141, (5 << 16) | 54, 1, 3, 0, 2, (1 << 16) | 56])],
    ['OpEntryPoint interface id >= bound', spvWords([0x07230203, 0x00010000, 0, 8, 0, (2 << 16) | 17, 4, (2 << 16) | 17, 6, (3 << 16) | 14, 2, 2, (6 << 16) | 15, 6, 3, 0x64646176, 0, 99, (5 << 16) | 54, 1, 3, 0, 2, (1 << 16) | 56])],
    ['missing Kernel capability', buildSpirvPayload({ includeKernelCap: false })],
    ['truncated instruction', buildSpirvPayload({ truncateInst: true })],
  ];
  for (const [label, payload] of badSpirvCases) {
    await withBundle(buildUorGpuBundle({ isa: 2, blockX: 64, payload }), async (archive) => {
      const ins = await callShim(SHIM, { op: 'inspect', archive, input: {} });
      assert.equal(ins.response.ok, true, label);
      assert.equal(ins.response.result.world.conforms, false, label);

      const ld = await callShim(SHIM, { op: 'load', archive, input: {} });
      assert.equal(ld.response.ok, false, label);
      assertRegisteredCode(ld.response.error.code, label);
      assert.equal(ld.response.error.code, 'world_mismatch', label);

      const ver = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' } } });
      assert.equal(ver.response.ok, true, label);
      assertValidVerdict(ver.response.result);
      assert.equal(ver.response.result.passed, false, label);
      assert.ok(ver.response.result.reasons.some((r) => r.check === 'world.contract'), label);
    });
  }
});

test('unsigned GPU bundles with nonzero attest_sig or claimed level > P0 are refused', async () => {
  // Mutate byte 320 without resealing (signer/signature region is outside uor_id/holo seals).
  const smuggledSig = buildUorGpuBundle({ payload: buildSm121Payload(256) });
  smuggledSig[320] = 0xff;

  const unsignedClaimP1 = buildUorGpuBundle({ claimedLevel: 1, payload: buildSm121Payload(256) });
  const unsignedClaimP3 = buildUorGpuBundle({ claimedLevel: 3, payload: buildSm121Payload(256) });
  const signedZeroSig = buildUorGpuBundle({ claimedLevel: 1, signerPubByte: 1, sigByte0: 0, payload: buildSm121Payload(256) });

  for (const [label, bundle] of [
    ['smuggled attest_sig byte', smuggledSig],
    ['unsigned claiming P1', unsignedClaimP1],
    ['unsigned claiming P3', unsignedClaimP3],
    ['signed with all-zero attest_sig', signedZeroSig],
  ]) {
    await withBundle(bundle, async (archive) => {
      for (const op of ['inspect', 'load', 'verify']) {
        const res = await callShim(SHIM, { op, archive, input: op === 'verify' ? { policy: { minimum: 'P0' } } : {} });
        assert.equal(res.response.ok, false, `${label} (${op}) must fail`);
        assertRegisteredCode(res.response.error.code, `${label} (${op})`);
      }
    });
  }
});

test('malformed UOR-GPU-1 headers and out-of-range discriminants are refused with registered codes', async () => {
  const validPayload = buildSm121Payload(256);
  const trailingByte = Buffer.concat([buildUorGpuBundle({ payload: validPayload }), Buffer.from([0x00])]);
  const truncatedHdr = Buffer.concat([Buffer.from('UORGPU1\0', 'ascii'), Buffer.alloc(64, 0)]);

  const cases = [
    ['truncated header (<384B)', truncatedHdr, 'archive.bounds'],
    ['trailing byte after payload', trailingByte, 'archive.bounds'],
    ['unsupported version 2', buildUorGpuBundle({ version: 2, payload: validPayload }), 'archive.version'],
    ['unknown target ISA 99', buildUorGpuBundle({ isa: 99, payload: validPayload }), 'archive.kind'],
    ['undefined math contract 77', buildUorGpuBundle({ math: 77, payload: validPayload }), 'archive.kind'],
    ['out-of-range claimed level 99', buildUorGpuBundle({ claimedLevel: 99, signerPubByte: 1, sigByte0: 1, payload: validPayload }), 'archive.kind'],
    ['invalid block_x 0', buildUorGpuBundle({ blockX: 0, payload: validPayload }), 'archive.kind'],
    ['invalid block_x 1025', buildUorGpuBundle({ blockX: 1025, payload: validPayload }), 'archive.kind'],
  ];

  for (const [label, bundle, expectedLoadCode] of cases) {
    await withBundle(bundle, async (archive) => {
      const ins = await callShim(SHIM, { op: 'inspect', archive, input: {} });
      assert.equal(ins.response.ok, false, `${label} inspect`);
      assertRegisteredCode(ins.response.error.code, `${label} inspect`);
      assert.equal(ins.response.error.code, expectedLoadCode, `${label} inspect`);

      const ld = await callShim(SHIM, { op: 'load', archive, input: {} });
      assert.equal(ld.response.ok, false, `${label} load`);
      assertRegisteredCode(ld.response.error.code, `${label} load`);
      assert.equal(ld.response.error.code, expectedLoadCode, `${label} load`);

      const ver = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' } } });
      assert.equal(ver.response.ok, false, `${label} verify`);
      assertRegisteredCode(ver.response.error.code, `${label} verify`);
      assert.equal(ver.response.error.code, 'verification_failed', `${label} verify`);
    });
  }

  // Non-existent archive path and omitted archive return registered SDK codes (never raw ENOENT / internal).
  const missing = await callShim(SHIM, { op: 'inspect', archive: join(tmpdir(), 'omega-gpu-does-not-exist.holo'), input: {} });
  assert.equal(missing.response.ok, false);
  assertRegisteredCode(missing.response.error.code, 'missing archive path');
  assert.equal(missing.response.error.code, 'load.path');

  const omitted = await callShim(SHIM, { op: 'load', input: {} });
  assert.equal(omitted.response.ok, false);
  assertRegisteredCode(omitted.response.error.code, 'omitted archive');
  assert.equal(omitted.response.error.code, 'archive.input');

  // Prototype-property operation names are reported as unsupported, never invoked.
  for (const op of ['toString', 'constructor', '__proto__']) {
    const res = await callShim(SHIM, { op, input: {} });
    assert.equal(res.response.ok, false, op);
    assert.ok(typeof res.response.unsupported === 'string', `${op} must be unsupported`);
  }
});

test('tampered UOR-GPU-1 payload fails integrity, reports computed seal identity, and respects allowUnverified on load', async () => {
  const intact = buildUorGpuBundle({ payload: buildSm121Payload(256) });
  const intactSeal = intact.subarray(256, 288).toString('hex');
  const tamperedA = Buffer.from(intact);
  tamperedA[384] ^= 0xff;
  const tamperedB = Buffer.from(intact);
  tamperedB[385] ^= 0xff;
  const expectedSealA = blake3Hex(new Uint8Array(Buffer.concat([tamperedA.subarray(0, 256), tamperedA.subarray(384)])));
  const expectedSealB = blake3Hex(new Uint8Array(Buffer.concat([tamperedB.subarray(0, 256), tamperedB.subarray(384)])));
  assert.notEqual(expectedSealA, intactSeal);
  assert.notEqual(expectedSealA, expectedSealB);

  await withBundle(tamperedA, async (archive) => {
    const ver = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' } } });
    assert.equal(ver.response.ok, true);
    assertValidVerdict(ver.response.result);
    assert.equal(ver.response.result.passed, false);
    assert.equal(ver.response.result.holo, `blake3:${expectedSealA}`);
    assert.ok(ver.response.result.reasons.some((r) => r.check === 'holo.integrity'));
    assert.ok(ver.response.result.reasons.some((r) => r.check === 'policy.integrity'));

    const ld = await callShim(SHIM, { op: 'load', archive, input: {} });
    assert.equal(ld.response.ok, false);
    assertRegisteredCode(ld.response.error.code, 'tampered load');
    assert.equal(ld.response.error.code, 'digest_mismatch');
    assert.equal(ld.response.error.check, 'holo.integrity');

    const allowed = await callShim(SHIM, { op: 'load', archive, input: { allowUnverified: true } });
    assert.equal(allowed.response.ok, true);
    assert.equal(allowed.response.result.verified, false);
    assert.equal(allowed.response.result.fingerprint, expectedSealA);
  });

  await withBundle(tamperedB, async (archive) => {
    const ver = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' } } });
    assert.equal(ver.response.ok, true);
    assertValidVerdict(ver.response.result);
    assert.equal(ver.response.result.holo, `blake3:${expectedSealB}`);

    const allowed = await callShim(SHIM, { op: 'load', archive, input: { allowUnverified: true } });
    assert.equal(allowed.response.ok, true);
    assert.equal(allowed.response.result.fingerprint, expectedSealB);
  });
});
