// Conformance tests for the Omega GPU bundle world (`hologram:gpu/omega-om@1`, HO-51):
// exercises UOR-GPU-1 SM121 and SPIR-V inspect/verify/load paths, caller-supplied
// world/archive/payload pins, SM121 896B + QMD v05.00 SKEDCHECK05 framing, and
// validates every returned verdict against `prism/verdict/1` JSON Schema.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { blake3Hex } from '../../../sdk/npm/prism-code/src/blake3.mjs';
import { callShim } from '../../../sdk/npm/conformance/src/shim.mjs';
import { validate } from '../../../sdk/npm/conformance/src/vendor/json-schema.mjs';
import { VERDICT_SCHEMA } from '../../../sdk/npm/conformance/src/vendor/verdict-schema.mjs';

const SHIM = [process.execPath, fileURLToPath(new URL('../shim.mjs', import.meta.url))];
const WORLD_SHA256 = '0988cffdeef13828befbb37028e99ce07ee0c4a31b0804a92448613a1def66f9';
const WORLD_BLAKE3 = '1aaa920c34346ff9ba31f485e9bebdef628e6041cf8a3171d8cbe7c2ff196801';

const sha256Buf = (buf) => createHash('sha256').update(buf).digest();
const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex');

/** Build a valid 896-byte SM121 payload (512B SASS + 384B QMD v05.00 passing SKEDCHECK05). */
function buildSm121Payload(blockX = 256, { versionMajor = 5 } = {}) {
  const payload = Buffer.alloc(896, 0);
  const q = (idx, val) => payload.writeUInt32LE(val >>> 0, 512 + idx * 4);
  q(4, 0x013f0000); // qmdType == 2
  q(14, (0x2f0003a4 | ((versionMajor & 0xf) << 20)) >>> 0); // versionMajor
  q(17, 1); // semEnable != 0
  q(32, 0x10000000); // codeVa != 0
  q(33, (0xa << 21) >>> 0); // prefetchTag == 0xa
  q(34, ((1 << 16) | (blockX & 0xffff)) >>> 0); // threadsX | (threadsY << 16)
  q(35, (1 | (16 << 8) | (1 << 17)) >>> 0); // gprCount == 16
  q(36, 0x04b44808); // SMEM config
  q(37, 0); // word37 == 0
  q(39, 1); // gridX
  q(40, 1); // gridY
  q(41, 1); // gridZ
  q(42, 0x10010000); // cbankVa != 0
  q(58, 0x10300011); // cb0Valid
  return payload;
}

/** Build a minimal valid SPIR-V 1.0 binary payload (5 x u32 header). */
function buildSpirvPayload(magic = 0x07230203) {
  const payload = Buffer.alloc(20, 0);
  payload.writeUInt32LE(magic >>> 0, 0);
  payload.writeUInt32LE(0x00010000, 4); // SPIR-V 1.0
  return payload;
}

/** Seal a canonical 384-byte UOR-GPU-1 header + payload. */
function buildUorGpuBundle({ isa = 1, blockX = 256, payload }) {
  const hdr = Buffer.alloc(384, 0);
  Buffer.from('UORGPU1\0', 'ascii').copy(hdr, 0);
  hdr.writeUInt32LE(1, 8); // version
  hdr.writeUInt32LE(isa, 12); // 1=SM121, 2=SPIRV
  hdr.writeUInt32LE(1, 16); // IEEE754_RN
  hdr.writeUInt32LE(0, 20); // P0
  hdr.writeUInt32LE(payload.length, 24);
  hdr.writeUInt32LE(blockX, 28);
  sha256Buf(payload).copy(hdr, 96); // payload_sha256
  sha256Buf(hdr.subarray(0, 224)).copy(hdr, 224); // uor_id_sha256
  const holoHex = blake3Hex(new Uint8Array(Buffer.concat([hdr.subarray(0, 256), payload])));
  Buffer.from(holoHex, 'hex').copy(hdr, 256); // holo_blake3
  return Buffer.concat([hdr, payload]);
}

function assertValidVerdict(verdict) {
  const errors = validate(VERDICT_SCHEMA, verdict);
  assert.deepEqual(errors, [], `verdict violated prism/verdict/1 schema: ${JSON.stringify(errors)}`);
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
  const bundle = buildUorGpuBundle({ isa: 1, blockX: 256, payload: buildSm121Payload(256) });
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

    // Default policy (minimum P2) must fail at P0 and still be schema-valid.
    const defVer = await callShim(SHIM, { op: 'verify', archive, input: {} });
    assert.equal(defVer.response.ok, true);
    assertValidVerdict(defVer.response.result);
    assert.equal(defVer.response.result.passed, false);
    assert.ok(defVer.response.result.reasons.some((r) => r.check === 'policy.level'));
  });
});

test('caller-supplied world and digest pins are enforced at P0', async () => {
  const bundle = buildUorGpuBundle({ isa: 1, blockX: 256, payload: buildSm121Payload(256) });
  const archiveSha = sha256Hex(bundle);
  const archiveB3 = blake3Hex(new Uint8Array(bundle));
  const wrongHex = '0'.repeat(64);
  await withBundle(bundle, async (archive) => {
    // Exact matching world + archive pins pass.
    const ok = await callShim(SHIM, {
      op: 'verify',
      archive,
      input: {
        policy: {
          minimum: 'P0',
          world: { contract: 'hologram:gpu/omega-om@1', sha256: WORLD_SHA256, blake3: WORLD_BLAKE3 },
          digests: { archive: { sha256: archiveSha, blake3: archiveB3 } },
        },
      },
    });
    assert.equal(ok.response.ok, true);
    assertValidVerdict(ok.response.result);
    assert.equal(ok.response.result.passed, true);

    // Wrong world.sha256, world.blake3, archive.sha256, and null world pin all fail.
    for (const [label, policy, expectedCheck] of [
      ['world.sha256', { minimum: 'P0', world: { sha256: wrongHex } }, 'world.hash'],
      ['world.blake3', { minimum: 'P0', world: { blake3: wrongHex } }, 'world.hash'],
      ['world.null', { minimum: 'P0', world: null }, 'world.hash'],
      ['digests.archive.sha256', { minimum: 'P0', digests: { archive: { sha256: wrongHex } } }, 'digest.archive'],
      ['digests.archive.blake3', { minimum: 'P0', digests: { archive: { blake3: wrongHex } } }, 'digest.archive'],
    ]) {
      const res = await callShim(SHIM, { op: 'verify', archive, input: { policy } });
      assert.equal(res.response.ok, true, label);
      assertValidVerdict(res.response.result);
      assert.equal(res.response.result.passed, false, `${label} must fail verification`);
      assert.ok(res.response.result.reasons.some((r) => r.check === expectedCheck), `${label} missing ${expectedCheck}`);
    }

    // Unsupported digest target is refused as policy.invalid, never silently ignored.
    const badTarget = await callShim(SHIM, {
      op: 'verify',
      archive,
      input: { policy: { minimum: 'P0', digests: { guest: { sha256: wrongHex } } } },
    });
    assert.equal(badTarget.response.ok, false);
    assert.equal(badTarget.response.error.check, 'policy.invalid');
  });
});

test('SM121 bundles without 896B SASS + valid QMD v05.00 framing are rejected', async () => {
  // 1-byte SM121 payload with recomputed hashes must NOT conform or pass P0.
  const oneByte = buildUorGpuBundle({ isa: 1, blockX: 256, payload: Buffer.from([0x42]) });
  await withBundle(oneByte, async (archive) => {
    const ins = await callShim(SHIM, { op: 'inspect', archive, input: {} });
    assert.equal(ins.response.ok, true);
    assert.equal(ins.response.result.world.conforms, false);

    const ld = await callShim(SHIM, { op: 'load', archive, input: {} });
    assert.equal(ld.response.ok, false);
    assert.equal(ld.response.error.code, 'world.contract');

    const ver = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' } } });
    assert.equal(ver.response.ok, true);
    assertValidVerdict(ver.response.result);
    assert.equal(ver.response.result.passed, false);
    assert.ok(ver.response.result.reasons.some((r) => r.check === 'world.contract'));
  });

  // 896B SM121 payload with wrong QMD versionMajor (4 instead of 5) must be rejected.
  const badQmd = buildUorGpuBundle({ isa: 1, blockX: 256, payload: buildSm121Payload(256, { versionMajor: 4 }) });
  await withBundle(badQmd, async (archive) => {
    const ver = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' } } });
    assert.equal(ver.response.ok, true);
    assertValidVerdict(ver.response.result);
    assert.equal(ver.response.result.passed, false);
    assert.ok(ver.response.result.reasons.some((r) => r.check === 'world.contract'));
  });
});

test('tampered UOR-GPU-1 payload fails integrity and SPIR-V framing is checked', async () => {
  const tampered = buildUorGpuBundle({ isa: 1, blockX: 256, payload: buildSm121Payload(256) });
  tampered[384] ^= 0xff;
  await withBundle(tampered, async (archive) => {
    const ver = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' } } });
    assert.equal(ver.response.ok, true);
    assertValidVerdict(ver.response.result);
    assert.equal(ver.response.result.passed, false);
    assert.ok(ver.response.result.reasons.some((r) => r.check === 'holo.integrity'));
    assert.ok(ver.response.result.reasons.some((r) => r.check === 'policy.integrity'));

    const ld = await callShim(SHIM, { op: 'load', archive, input: {} });
    assert.equal(ld.response.ok, false);
    assert.equal(ld.response.error.code, 'digest_mismatch');
  });

  const goodSpirv = buildUorGpuBundle({ isa: 2, blockX: 64, payload: buildSpirvPayload() });
  await withBundle(goodSpirv, async (archive) => {
    const ver = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' } } });
    assert.equal(ver.response.ok, true);
    assertValidVerdict(ver.response.result);
    assert.equal(ver.response.result.passed, true);
  });

  const badSpirv = buildUorGpuBundle({ isa: 2, blockX: 64, payload: buildSpirvPayload(0xdeadbeef) });
  await withBundle(badSpirv, async (archive) => {
    const ver = await callShim(SHIM, { op: 'verify', archive, input: { policy: { minimum: 'P0' } } });
    assert.equal(ver.response.ok, true);
    assertValidVerdict(ver.response.result);
    assert.equal(ver.response.result.passed, false);
    assert.ok(ver.response.result.reasons.some((r) => r.check === 'world.contract'));
  });
});
