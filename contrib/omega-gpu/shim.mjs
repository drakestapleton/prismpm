#!/usr/bin/env node
/**
 * Conformance shim (`prism/conformance-shim/1`) for the Omega GPU bundle runtime
 * (`hologram:gpu/omega-om@1` / `UOR-GPU-1`, reference implementation in omega-mv
 * `protocol/uor-gpu/`).
 *
 * - For `UORGPU1\0` GPU bundles: parses and validates the 384-byte canonical
 *   header, ISA-specific payload framing (896B SM121 SASS + QMD v05.00
 *   SKEDCHECK05 invariants; SPIR-V 1.0 word framing + magic), dual digests,
 *   and all caller-supplied policy pins, emitting schema-valid `prism/verdict/1`
 *   objects. When `PRISM_GPU_BIN` points to the compiled pure seeded-Omega
 *   `prism-gpu` binary, `inspect` delegates directly to it.
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
// Digests of sdk/npm/spec/worlds/gpu-omega.wit (LF-normalized UTF-8 bytes).
const GPU_WORLD_SHA256 = '0988cffdeef13828befbb37028e99ce07ee0c4a31b0804a92448613a1def66f9';
const GPU_WORLD_BLAKE3 = '1aaa920c34346ff9ba31f485e9bebdef628e6041cf8a3171d8cbe7c2ff196801';

const VALID_LEVELS = new Set(['P0', 'P1', 'P2', 'P3']);
const VALID_POLICY_KEYS = new Set(['name', 'minimum', 'world', 'digests', 'effects']);
const VALID_WORLD_KEYS = new Set(['contract', 'sha256', 'blake3']);
const VALID_DIGEST_TARGETS = new Set(['archive', 'payload']);
const VALID_DIGEST_ALGS = new Set(['sha256', 'blake3']);
const VALID_EFFECTS = new Set(['outbound-hosts', 'key-value-stores', 'variables']);
const HEX64 = /^[0-9a-f]{64}$/;

const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex');

function isUorGpuBundle(buf) {
  return buf.length >= 8 && buf.subarray(0, 8).equals(UOR_GPU_MAGIC);
}

/**
 * Validate Blackwell SM121 payload framing (512B SASS + 384B QMD v05.00) and
 * QMD v05.00 SKEDCHECK05 invariants matching `protocol/uor-gpu/payload_vm.om`.
 */
function validateSm121Payload(payload, hdrBlockX) {
  if (payload.length !== 896) {
    return `SM121 payload must be exactly 896 bytes (512B SASS + 384B QMD v5), got ${payload.length}`;
  }
  const q = (idx) => payload.readUInt32LE(512 + idx * 4);
  const versionMajor = (q(14) >>> 20) & 0xf;
  const qmdType = (q(4) >>> 23) & 0x7;
  const word37 = q(37);
  const semEnable = q(17);
  const prefetchTag = (q(33) >>> 21) & 0x1ff;
  const cb0Valid = (q(58) & 1) !== 0;
  const threadsX = q(34) & 0xffff;
  const threadsY = (q(34) >>> 16) & 0xffff;
  const gridX = q(39);
  const gridY = q(40);
  const gridZ = q(41);
  const gprCount = (q(35) >>> 8) & 0x1ff;
  const codeVa = q(32);
  const cbankVa = q(42);
  if (versionMajor !== 5) return `QMD versionMajor must be 5, got ${versionMajor}`;
  if (qmdType !== 2) return `QMD type must be 2 (GRID_CTA), got ${qmdType}`;
  if (word37 !== 0) return `QMD word 37 must be 0, got ${word37}`;
  if (semEnable === 0) return 'QMD word 17 semaphore enable must be non-zero';
  if (prefetchTag !== 0xa) return `QMD prefetch tag must be 0xa, got 0x${prefetchTag.toString(16)}`;
  if (!cb0Valid) return 'QMD word 58 CB0 valid bit must be set';
  if (threadsX !== hdrBlockX) return `QMD threads_x (${threadsX}) != header block_x (${hdrBlockX})`;
  if (threadsY < 1) return 'QMD threads_y must be >= 1';
  if (gridX < 1 || gridY < 1 || gridZ < 1) return 'QMD grid dimensions must be >= 1';
  if (gprCount < 16) return `QMD gpr_count must be >= 16, got ${gprCount}`;
  if (codeVa === 0 || cbankVa === 0) return 'QMD code VA and constant-bank VA must be non-zero';
  return null;
}

/** Validate OpenCL SPIR-V 1.0 binary framing matching `protocol/uor-gpu/payload_vm.om`. */
function validateSpirvPayload(payload) {
  if (payload.length < 20 || (payload.length % 4) !== 0) {
    return `SPIR-V payload must be >= 20 bytes and 4-byte aligned, got ${payload.length}`;
  }
  const magic = payload.readUInt32LE(0);
  if (magic !== 0x07230203) {
    return `SPIR-V magic must be 0x07230203, got 0x${magic.toString(16)}`;
  }
  return null;
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
  const actualPayloadSha = sha256Hex(payload);
  const actualPayloadBlake3 = blake3Hex(new Uint8Array(payload));
  const payloadOk = actualPayloadSha === payloadSha;
  const uorIdOk = sha256Hex(buf.subarray(0, 224)) === uorIdSha;
  const holoInput = Buffer.concat([buf.subarray(0, 256), payload]);
  const holoOk = blake3Hex(new Uint8Array(holoInput)) === holoBlake3;
  const isaStructError = isaCode === 1 ? validateSm121Payload(payload, blockX) : validateSpirvPayload(payload);
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
    digests: {
      archive: { sha256: sha256Hex(buf), blake3: blake3Hex(new Uint8Array(buf)) },
      payload: { sha256: actualPayloadSha, blake3: actualPayloadBlake3 },
    },
    integrity: { payloadOk, uorIdOk, holoOk, isaStructOk: isaStructError === null, isaStructError },
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
  if (policy === undefined) return null;
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
    return { code: 'verification_failed', check: 'policy.invalid', message: 'policy must be an object' };
  }
  for (const key of Object.keys(policy)) {
    if (!VALID_POLICY_KEYS.has(key)) {
      return { code: 'verification_failed', check: 'policy.invalid', message: `unknown or unsupported policy member ${key}` };
    }
  }
  if (policy.name !== undefined && (typeof policy.name !== 'string' || policy.name.length === 0 || policy.name.length > 1024)) {
    return { code: 'verification_failed', check: 'policy.invalid', message: 'invalid policy name' };
  }
  if (policy.minimum !== undefined && !VALID_LEVELS.has(policy.minimum)) {
    return { code: 'verification_failed', check: 'policy.invalid', message: `unknown level ${policy.minimum}` };
  }
  if (policy.world !== undefined && policy.world !== null) {
    if (typeof policy.world !== 'object' || Array.isArray(policy.world)) {
      return { code: 'verification_failed', check: 'policy.invalid', message: 'invalid world pin' };
    }
    const wKeys = Object.keys(policy.world);
    if (wKeys.length === 0) {
      return { code: 'verification_failed', check: 'policy.invalid', message: 'empty world pin' };
    }
    for (const k of wKeys) {
      if (!VALID_WORLD_KEYS.has(k)) {
        return { code: 'verification_failed', check: 'policy.invalid', message: `unknown world pin member ${k}` };
      }
    }
    if (policy.world.contract !== undefined && typeof policy.world.contract !== 'string') {
      return { code: 'verification_failed', check: 'policy.invalid', message: 'world contract pin must be a string' };
    }
    for (const alg of ['sha256', 'blake3']) {
      if (policy.world[alg] !== undefined && (typeof policy.world[alg] !== 'string' || !HEX64.test(policy.world[alg]))) {
        return { code: 'verification_failed', check: 'policy.invalid', message: `invalid world ${alg} pin` };
      }
    }
  }
  if (policy.digests !== undefined) {
    if (policy.digests === null || typeof policy.digests !== 'object' || Array.isArray(policy.digests)) {
      return { code: 'verification_failed', check: 'policy.invalid', message: 'digests must be an object' };
    }
    for (const [target, pin] of Object.entries(policy.digests)) {
      if (!VALID_DIGEST_TARGETS.has(target)) {
        return { code: 'verification_failed', check: 'policy.invalid', message: `unknown or unsupported digest target ${target}` };
      }
      if (pin === null || typeof pin !== 'object' || Array.isArray(pin) || Object.keys(pin).length === 0) {
        return { code: 'verification_failed', check: 'policy.invalid', message: `empty digest pin for ${target}` };
      }
      for (const [alg, val] of Object.entries(pin)) {
        if (!VALID_DIGEST_ALGS.has(alg)) {
          return { code: 'verification_failed', check: 'policy.invalid', message: `unknown digest algorithm ${alg}` };
        }
        if (typeof val !== 'string' || !HEX64.test(val)) {
          return { code: 'verification_failed', check: 'policy.invalid', message: `invalid ${alg} digest for ${target}` };
        }
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
      const intact = parsed.integrity.payloadOk && parsed.integrity.uorIdOk && parsed.integrity.holoOk;
      return {
        schema: 'prism/inspect/1',
        world: {
          contract: GPU_WORLD_CONTRACT,
          package: GPU_WORLD_PACKAGE,
          name: GPU_WORLD_NAME,
          conforms: intact && parsed.integrity.isaStructOk,
          pure: true,
          effects: [],
          digest: { sha256: GPU_WORLD_SHA256, blake3: GPU_WORLD_BLAKE3 },
        },
        ...parsed.header,
        digests: parsed.digests,
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
      const minimum = input.policy?.minimum ?? process.env.PRISM_MINIMUM_LEVEL ?? 'P2';
      const policyName = input.policy?.name ?? 'default';
      const reasons = [];
      let policyDenied = false;

      if (!intact) {
        reasons.push({ check: 'holo.integrity', withholds: 'P1', message: 'UOR-GPU-1 digest check failed.' });
        reasons.push({ check: 'policy.integrity', withholds: null, message: 'Damaged bundles fail every policy.' });
        policyDenied = true;
      }
      if (!parsed.integrity.isaStructOk) {
        reasons.push({ check: 'world.contract', withholds: 'P1', message: parsed.integrity.isaStructError });
        policyDenied = true;
      }

      // Enforce caller-supplied world pins (including null pin).
      if (input.policy && 'world' in input.policy) {
        const wp = input.policy.world;
        if (wp === null) {
          reasons.push({ check: 'world.hash', withholds: null, message: 'Null world pin does not match hologram:gpu/omega-om@1.' });
          policyDenied = true;
        } else {
          if (wp.contract !== undefined && wp.contract !== GPU_WORLD_CONTRACT) {
            reasons.push({ check: 'world.hash', withholds: null, message: `World contract mismatch: expected ${wp.contract}, got ${GPU_WORLD_CONTRACT}.` });
            policyDenied = true;
          }
          if (wp.sha256 !== undefined && wp.sha256 !== GPU_WORLD_SHA256) {
            reasons.push({ check: 'world.hash', withholds: null, message: 'World SHA-256 pin mismatch.' });
            policyDenied = true;
          }
          if (wp.blake3 !== undefined && wp.blake3 !== GPU_WORLD_BLAKE3) {
            reasons.push({ check: 'world.hash', withholds: null, message: 'World BLAKE3 pin mismatch.' });
            policyDenied = true;
          }
        }
      }

      // Enforce caller-supplied archive/payload digest pins.
      if (input.policy?.digests) {
        for (const [target, pin] of Object.entries(input.policy.digests)) {
          const actual = parsed.digests[target];
          for (const [alg, expected] of Object.entries(pin)) {
            if (actual[alg] !== expected) {
              reasons.push({ check: `digest.${target}`, withholds: null, message: `Pinned ${target} ${alg} digest mismatch.` });
              policyDenied = true;
            }
          }
        }
      }

      // Level invariant of prism/verdict/1: level P0 must always carry a reason withholding P1.
      if (!reasons.some((r) => r.withholds === 'P1')) {
        reasons.push({
          check: 'attestation.provenance',
          withholds: 'P1',
          message: 'Offline UOR-GPU-1 shim checks digests and ISA framing at P0; P1+ requires local UORTRST1 trust anchors.',
        });
      }

      if (minimum !== 'P0') {
        reasons.push({ check: 'policy.level', withholds: null, message: `Assurance level P0 is below policy minimum ${minimum}.` });
        policyDenied = true;
      }

      const verdict = {
        schema: 'prism/verdict/1',
        holo: `blake3:${parsed.header.holoBlake3}`,
        level: 'P0',
        policy: { name: policyName, minimum },
        passed: !policyDenied,
        reasons,
      };
      if (input.throw === true && !verdict.passed) {
        throw { code: 'verification_failed', check: reasons[0].check, verdict, message: reasons[0].message };
      }
      return verdict;
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
      if (!parsed.integrity.isaStructOk) throw { code: 'world.contract', message: parsed.integrity.isaStructError };
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
