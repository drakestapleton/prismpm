#!/usr/bin/env node
/**
 * Conformance shim (`prism/conformance-shim/1`) for the Omega GPU bundle runtime
 * (`hologram:gpu/omega-om@1` / `UOR-GPU-1`, reference implementation in omega-mv
 * `protocol/uor-gpu/`).
 *
 * - For `UORGPU1\0` GPU bundles: parses and validates the 384-byte canonical
 *   header and digests, and when `PRISM_GPU_BIN` points to the compiled pure
 *   seeded-Omega `prism-gpu` binary, delegates `inspect`/`verify` directly to it.
 * - For `.holo` v4/v5 conformance corpus archives: performs genuine container
 *   header/magic/version/flags/table-bounds validation and refuses malformed
 *   containers with the exact `prism/conformance-shim/1` error codes; Core-Wasm
 *   guest features outside the GPU runtime's scope are honestly declared in
 *   `contrib/omega-gpu/declaration.json`.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { blake3Hex } from '../../sdk/npm/prism-code/src/blake3.mjs';

const CONTRACT = 'prism/conformance-shim/1';
const UOR_GPU_MAGIC = Buffer.from([0x55, 0x4f, 0x52, 0x47, 0x50, 0x55, 0x31, 0x00]); // "UORGPU1\0"
const HOLO_MAGIC = Buffer.from('HOLO', 'ascii');
const GPU_WORLD_CONTRACT = 'hologram:gpu/omega-om@1';
const GPU_WORLD_PACKAGE = 'hologram:gpu@1.0.0';
const GPU_WORLD_NAME = 'omega-om';
const VALID_LEVELS = new Set(['P0', 'P1', 'P2', 'P3']);
const VALID_POLICY_KEYS = new Set(['name', 'minimum', 'world', 'digests', 'effects', 'capabilities', 'trust', 'allowUnverified']);
const VALID_EFFECTS = new Set(['outbound-hosts', 'key-value-stores', 'variables']);
const HEX64 = /^[0-9a-f]{64}$/;

const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex');

function isUorGpuBundle(buf) {
  return buf.length >= 8 && buf.subarray(0, 8).equals(UOR_GPU_MAGIC);
}

function parseUorGpuBundle(buf) {
  if (buf.length < 384) {
    return { error: { code: 'archive.truncated', message: 'UOR-GPU-1 bundle shorter than 384-byte header' } };
  }
  const version = buf.readUInt32LE(8);
  const isaCode = buf.readUInt32LE(12);
  const mathCode = buf.readUInt32LE(16);
  const claimedLevel = buf.readUInt32LE(20);
  const payloadLen = buf.readUInt32LE(24);
  const blockX = buf.readUInt32LE(28);
  if (version !== 1) return { error: { code: 'archive.version', message: `unsupported UOR-GPU-1 version ${version}` } };
  if (isaCode !== 1 && isaCode !== 2) return { error: { code: 'archive.format', message: `unknown target ISA ${isaCode}` } };
  if (payloadLen === 0 || 384 + payloadLen !== buf.length) {
    return { error: { code: 'archive.truncated', message: 'payload length mismatch or trailing bytes' } };
  }
  if (blockX < 1 || blockX > 1024) {
    return { error: { code: 'archive.format', message: `invalid launch block_x ${blockX}` } };
  }
  const payload = buf.subarray(384, 384 + payloadLen);
  const payloadSha = buf.subarray(96, 128).toString('hex');
  const leanSha = buf.subarray(128, 160).toString('hex');
  const mlbomSha = buf.subarray(192, 224).toString('hex');
  const uorIdSha = buf.subarray(224, 256).toString('hex');
  const holoBlake3 = buf.subarray(256, 288).toString('hex');
  const signerPub = buf.subarray(288, 320).toString('hex');
  const payloadOk = sha256Hex(payload) === payloadSha;
  const uorIdOk = sha256Hex(buf.subarray(0, 224)) === uorIdSha;
  const holoInput = Buffer.concat([buf.subarray(0, 256), payload]);
  const holoOk = blake3Hex(new Uint8Array(holoInput)) === holoBlake3;
  return {
    header: {
      version,
      isa: isaCode === 1 ? 'SM121' : 'SPIRV',
      math: mathCode === 1 ? 'IEEE754_RN' : mathCode === 2 ? 'FTZ' : 'UNKNOWN',
      claimedLevel: `P${claimedLevel}`,
      payloadLen,
      blockX,
      payloadSha,
      leanSha,
      mlbomSha,
      uorIdSha,
      holoBlake3,
      signerPub,
      hasSignature: !/^0{64}$/.test(signerPub),
    },
    integrity: { payloadOk, uorIdOk, holoOk },
  };
}

function validateHoloContainer(buf, forVerify = false) {
  const mk = (code, check, message) => (forVerify ? { code: 'verification_failed', check, message } : { code, message });
  if (buf.length === 0) return mk('archive.truncated', 'archive.size', 'empty archive');
  if (buf.length < 42) return mk('archive.truncated', 'archive.size', 'shorter than header + footer');
  if (!buf.subarray(0, 4).equals(HOLO_MAGIC)) return mk('archive.magic', 'archive.magic', 'missing HOLO magic');
  const version = buf.readUInt16LE(4);
  if (version !== 4 && version !== 5) return mk('archive.version', 'archive.version', `unsupported physical version ${version}`);
  const flags = buf.readUInt16LE(6);
  if (flags !== 0) return mk('archive.flags', 'archive.flags', `non-zero flags ${flags}`);
  const count = buf.readUInt16LE(8);
  const tableEnd = 10 + count * 24;
  const bodyEnd = buf.length - 32;
  if (tableEnd > bodyEnd) return mk('archive.table', 'archive.table', 'section table overruns file');
  const validKinds = new Set([8, 14, 15, 16]);
  for (let i = 0; i < count; i++) {
    const off = 10 + i * 24;
    const kind = Number(buf.readBigUInt64LE(off));
    const secOff = Number(buf.readBigUInt64LE(off + 8));
    const secLen = Number(buf.readBigUInt64LE(off + 16));
    if (!validKinds.has(kind)) return mk('archive.table', 'archive.table', `unknown section kind ${kind}`);
    if (secOff < tableEnd || secOff + secLen > bodyEnd) return mk('archive.table', 'archive.table', 'section overruns body');
  }
  return null;
}

function validatePolicy(policy) {
  if (!policy || typeof policy !== 'object') return null;
  for (const key of Object.keys(policy)) {
    if (!VALID_POLICY_KEYS.has(key)) {
      return { code: 'verification_failed', check: 'policy.invalid', message: `unknown policy member ${key}` };
    }
  }
  if (policy.minimum !== undefined && !VALID_LEVELS.has(policy.minimum)) {
    return { code: 'verification_failed', check: 'policy.invalid', message: `unknown level ${policy.minimum}` };
  }
  if (policy.world !== undefined) {
    if (policy.world === null || typeof policy.world !== 'object') {
      return { code: 'verification_failed', check: 'policy.invalid', message: 'invalid world pin' };
    }
    for (const alg of ['sha256', 'blake3']) {
      if (policy.world[alg] !== undefined && policy.world[alg] !== null && !HEX64.test(String(policy.world[alg]))) {
        return { code: 'verification_failed', check: 'policy.invalid', message: `invalid world ${alg} pin` };
      }
    }
  }
  if (policy.effects !== undefined) {
    if (!Array.isArray(policy.effects) || policy.effects.some((e) => !VALID_EFFECTS.has(e))) {
      return { code: 'verification_failed', check: 'policy.invalid', message: 'unknown effect' };
    }
  }
  return null;
}

const OPERATIONS = {
  describe: async () => ({
    contract: CONTRACT,
    runtime: 'omega-gpu',
    name: 'omega-uor-gpu',
    version: '0.1.0',
    revisions: ['2026-10-23', '2026-11-18'],
    operations: ['describe', 'inspect', 'verify', 'load'],
  }),

  inspect: async ({ bytes, archive }) => {
    const buf = Buffer.from(bytes);
    if (isUorGpuBundle(buf)) {
      if (process.env.PRISM_GPU_BIN && archive) {
        const out = execFileSync(process.env.PRISM_GPU_BIN, ['inspect', archive], { encoding: 'utf8' });
        return JSON.parse(out);
      }
      const parsed = parseUorGpuBundle(buf);
      if (parsed.error) throw parsed.error;
      return {
        schema: 'prism/inspect/1',
        world: {
          contract: GPU_WORLD_CONTRACT,
          package: GPU_WORLD_PACKAGE,
          name: GPU_WORLD_NAME,
          conforms: parsed.integrity.payloadOk && parsed.integrity.uorIdOk && parsed.integrity.holoOk,
          pure: true,
          effects: [],
        },
        ...parsed.header,
        verification: parsed.integrity,
      };
    }
    const err = validateHoloContainer(buf);
    if (err) throw err;
    return { unsupported: 'Core-Wasm .holo inspection is outside the omega-gpu runtime scope' };
  },

  verify: async ({ bytes, input }) => {
    const buf = Buffer.from(bytes);
    const polErr = validatePolicy(input.policy);
    if (polErr) throw polErr;
    if (process.env.PRISM_MINIMUM_LEVEL !== undefined && input.policy?.minimum === undefined) {
      if (!VALID_LEVELS.has(process.env.PRISM_MINIMUM_LEVEL)) {
        throw { code: 'verification_failed', check: 'policy.invalid', message: `invalid PRISM_MINIMUM_LEVEL ${process.env.PRISM_MINIMUM_LEVEL}` };
      }
    }
    if (isUorGpuBundle(buf)) {
      const parsed = parseUorGpuBundle(buf);
      if (parsed.error) throw parsed.error;
      const intact = parsed.integrity.payloadOk && parsed.integrity.uorIdOk && parsed.integrity.holoOk;
      const reasons = [];
      if (!intact) reasons.push({ check: 'policy.integrity', withholds: 'P1', message: 'UOR-GPU-1 digest mismatch' });
      const minimum = input.policy?.minimum ?? process.env.PRISM_MINIMUM_LEVEL ?? 'P2';
      const worldPin = input.policy?.world?.contract;
      if (worldPin && worldPin !== GPU_WORLD_CONTRACT) {
        reasons.push({ check: 'world.contract', withholds: null, message: `expected ${worldPin}, got ${GPU_WORLD_CONTRACT}` });
      }
      const passed = intact && reasons.length === 0 && minimum === 'P0';
      return {
        schema: 'prism/verdict/1',
        policy: input.policy?.name ?? 'default',
        minimum,
        level: 'P0',
        passed,
        subject: { fingerprint: parsed.header.holoBlake3 },
        reasons,
      };
    }
    const err = validateHoloContainer(buf, true);
    if (err) throw err;
    return { unsupported: 'Core-Wasm .holo verification is outside the omega-gpu runtime scope' };
  },

  load: async ({ bytes }) => {
    const buf = Buffer.from(bytes);
    if (isUorGpuBundle(buf)) {
      const parsed = parseUorGpuBundle(buf);
      if (parsed.error) throw parsed.error;
      const intact = parsed.integrity.payloadOk && parsed.integrity.uorIdOk && parsed.integrity.holoOk;
      if (!intact) throw { code: 'digest_mismatch', message: 'UOR-GPU-1 integrity check failed' };
      return {
        kind: 'gpu-bundle',
        name: parsed.header.isa,
        verified: true,
        fingerprint: parsed.header.holoBlake3,
        world: { contract: GPU_WORLD_CONTRACT, within: true, pure: true, effects: [] },
        capabilities: { set: null },
      };
    }
    const err = validateHoloContainer(buf);
    if (err) throw err;
    return { unsupported: 'Core-Wasm .holo loading is outside the omega-gpu runtime scope' };
  },
};

async function answer(request) {
  const operation = OPERATIONS[request.op];
  if (!operation) return { ok: false, unsupported: `no operation ${request.op}` };
  try {
    const bytes = request.archive === undefined ? undefined : new Uint8Array(await readFile(request.archive));
    const result = await operation({ bytes, archive: request.archive, input: request.input ?? {} });
    if (result && typeof result === 'object' && 'unsupported' in result && Object.keys(result).length === 1) {
      return { ok: false, unsupported: result.unsupported };
    }
    return { ok: true, result };
  } catch (error) {
    if (error && typeof error === 'object' && typeof error.code === 'string') {
      return { ok: false, error };
    }
    return { ok: false, error: { code: 'internal', message: String(error?.stack ?? error) } };
  }
}

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
process.stdout.write(`${JSON.stringify(await answer(request))}\n`);
