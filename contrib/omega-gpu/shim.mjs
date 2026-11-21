#!/usr/bin/env node
/**
 * Conformance shim (`prism/conformance-shim/1`) for the Omega GPU bundle runtime
 * (`hologram:gpu/omega-om@1` / `UOR-GPU-1`, reference implementation in omega-mv
 * `protocol/uor-gpu/`).
 *
 * - For `UORGPU1\0` GPU bundles: validates every canonical 384-byte header field
 *   (magic, version=1, ISA 1..2, math 1..2, claimed level 0..3, block_x 1..1024,
 *   exact payload length, unsigned envelope invariant: zero signer_pubkey =>
 *   claimed level P0 and all-zero attest_sig), ISA-specific payload framing
 *   (896B SM121 SASS + QMD v05.00 SKEDCHECK05 invariants; SPIR-V 1.0 OpenCL
 *   Kernel binary framing & instruction stream), dual SHA-256 + BLAKE3 seals,
 *   and all caller-supplied policy pins, emitting schema-valid `prism/verdict/1`
 *   verdicts and registered diagnostic codes only.
 * - For `.holo` v4/v5 conformance corpus archives: performs container header,
 *   magic, version, flags, and section-table bounds checks with registered
 *   diagnostic codes; Core-Wasm guest features outside the GPU runtime's scope
 *   are honestly declared in `contrib/omega-gpu/declaration.json`.
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

const LEVEL_RANK = Object.freeze({ P0: 0, P1: 1, P2: 2, P3: 3 });
const VALID_LEVELS = new Set(['P0', 'P1', 'P2', 'P3']);
const VALID_POLICY_KEYS = new Set(['name', 'minimum', 'world', 'digests', 'effects']);
const VALID_WORLD_KEYS = new Set(['contract', 'sha256', 'blake3']);
const VALID_DIGEST_TARGETS = new Set(['archive', 'payload']);
const VALID_DIGEST_ALGS = new Set(['sha256', 'blake3']);
const VALID_EFFECTS = new Set(['clock', 'random', 'socket', 'filesystem', 'unknown']);
const HEX64 = /^[0-9a-f]{64}$/;
const ZERO32_HEX = '0'.repeat(64);
const ZERO64_HEX = '0'.repeat(128);

class ShimError extends Error {
  constructor(payload) {
    super(payload.message ?? payload.code);
    this.payload = payload;
  }
}

const shimErr = (payload) => new ShimError(payload);

const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex');

/** Bound any verdict reason or error sentence to the 1..1024 character schema limit. */
function sentence(text) {
  const s = String(text ?? '').trim();
  if (s.length === 0) return 'Validation failed.';
  return s.length <= 1024 ? s : `${s.slice(0, 1021)}...`;
}

function clipToken(text, max = 96) {
  const s = String(text ?? '');
  return s.length <= max ? s : `${s.slice(0, max - 3)}...`;
}

function isUorGpuBundle(buf) {
  return buf.length >= 8 && buf.subarray(0, 8).equals(UOR_GPU_MAGIC);
}

/**
 * Validate Blackwell SM121 payload framing (512B SASS + 384B QMD v05.00) and
 * QMD v05.00 SKEDCHECK05 invariants matching `protocol/uor-gpu/payload_vm.om`.
 */
function validateSm121Payload(payload, hdrBlockX) {
  if (payload.length !== 896) {
    return `SM121 payload must be exactly 896 bytes (512B SASS + 384B QMD v5), got ${payload.length}.`;
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
  if (versionMajor !== 5) return `QMD versionMajor must be 5, got ${versionMajor}.`;
  if (qmdType !== 2) return `QMD type must be 2 (GRID_CTA), got ${qmdType}.`;
  if (word37 !== 0) return `QMD word 37 must be 0, got ${word37}.`;
  if (semEnable === 0) return 'QMD word 17 semaphore enable must be non-zero.';
  if (prefetchTag !== 0xa) return `QMD prefetch tag must be 0xa, got 0x${prefetchTag.toString(16)}.`;
  if (!cb0Valid) return 'QMD word 58 CB0 valid bit must be set.';
  if (threadsX !== hdrBlockX) return `QMD threads_x (${threadsX}) != header block_x (${hdrBlockX}).`;
  if (threadsY < 1) return 'QMD threads_y must be >= 1.';
  if (gridX < 1 || gridY < 1 || gridZ < 1) return 'QMD grid dimensions must be >= 1.';
  if (gprCount < 16) return `QMD gpr_count must be >= 16, got ${gprCount}.`;
  if (codeVa === 0 || cbankVa === 0) return 'QMD code VA and constant-bank VA must be non-zero.';
  return null;
}

/**
 * Validate OpenCL SPIR-V 1.0 binary framing and OpenCL Kernel module structure
 * matching `protocol/uor-gpu/payload_vm.om` (`uvm_check_spirv`).
 */
function validateSpirvPayload(payload) {
  if (payload.length < 20 || payload.length > 65536 || (payload.length % 4) !== 0) {
    return `SPIR-V payload must be 20..65536 bytes and 4-byte aligned, got ${payload.length}.`;
  }
  const w = (idx) => payload.readUInt32LE(idx * 4);
  if (w(0) !== 0x07230203) return `SPIR-V magic must be 0x07230203, got 0x${w(0).toString(16)}.`;
  if (w(1) !== 0x00010000) return `SPIR-V version must be 1.0 (0x00010000), got 0x${w(1).toString(16)}.`;
  const bound = w(3);
  if (bound === 0 || bound > 1024) return `SPIR-V id bound must be 1..1024, got ${bound}.`;
  if (w(4) !== 0) return `SPIR-V reserved schema word must be 0, got ${w(4)}.`;

  const nw = payload.length / 4;
  let capMask = 0; // bit 0: Addresses (4), bit 1: Kernel (6)
  let hasMemModel = false;
  let entryId = 0;
  let hasEntryFn = false;
  let inFn = false;

  for (let p = 5; p < nw; ) {
    const hd = w(p);
    const wc = hd >>> 16;
    const op = hd & 0xffff;
    if (wc === 0 || p + wc > nw) {
      return `SPIR-V instruction at word ${p} has invalid word count ${wc}.`;
    }
    if (op === 17) {
      // OpCapability
      if (wc !== 2) return 'SPIR-V OpCapability must have word count 2.';
      const cap = w(p + 1);
      if (cap === 4) capMask |= 1;
      if (cap === 6) capMask |= 2;
    } else if (op === 14) {
      // OpMemoryModel Physical64(2) OpenCL(2)
      if (wc !== 3) return 'SPIR-V OpMemoryModel must have word count 3.';
      if (w(p + 1) === 2 && w(p + 2) === 2) hasMemModel = true;
    } else if (op === 15) {
      // OpEntryPoint Kernel(6) <id> <name...>
      if (wc < 4 || w(p + 1) !== 6) return 'SPIR-V OpEntryPoint must target OpenCL Kernel execution model (6).';
      const eid = w(p + 2);
      if (eid === 0 || eid >= bound) return `SPIR-V OpEntryPoint id ${eid} is outside 1..${bound - 1}.`;
      entryId = eid;
    } else if (op === 54) {
      // OpFunction
      if (inFn || wc < 5) return 'SPIR-V malformed or nested OpFunction.';
      const fnId = w(p + 2);
      if (fnId === 0 || fnId >= bound) return `SPIR-V OpFunction id ${fnId} is outside 1..${bound - 1}.`;
      inFn = true;
      if (entryId !== 0 && fnId === entryId) hasEntryFn = true;
    } else if (op === 56) {
      // OpFunctionEnd
      if (!inFn || wc !== 1) return 'SPIR-V malformed OpFunctionEnd.';
      inFn = false;
    }
    p += wc;
  }

  if (capMask !== 3) return 'SPIR-V OpenCL module must declare both Addresses and Kernel capabilities.';
  if (!hasMemModel) return 'SPIR-V OpenCL module must declare Physical64 OpenCL memory model.';
  if (entryId === 0 || !hasEntryFn) return 'SPIR-V OpenCL module must define its Kernel OpEntryPoint function.';
  if (inFn) return 'SPIR-V OpenCL module has an unterminated OpFunction.';
  return null;
}

/**
 * Parse and validate all canonical 384-byte UOR-GPU-1 header fields.
 * Uses only registered diagnostic codes from `model/sdk-diagnostics.toml` and
 * `sdk/npm/prism-code/src/errors.mjs`.
 */
function parseUorGpuBundle(buf, forVerify = false) {
  const fail = (loadCode, verifyCheck, message) => ({
    error: forVerify
      ? { code: 'verification_failed', check: verifyCheck, message: sentence(message) }
      : { code: loadCode, message: sentence(message) },
  });

  if (buf.length < 384) {
    return fail('archive.bounds', 'archive.table', 'UOR-GPU-1 bundle is shorter than the 384-byte canonical header.');
  }
  const version = buf.readUInt32LE(8);
  const isaCode = buf.readUInt32LE(12);
  const mathCode = buf.readUInt32LE(16);
  const claimedLevel = buf.readUInt32LE(20);
  const payloadLen = buf.readUInt32LE(24);
  const blockX = buf.readUInt32LE(28);

  if (version !== 1) {
    return fail('archive.version', 'archive.version', `Unsupported UOR-GPU-1 version ${version}; expected 1.`);
  }
  if (isaCode !== 1 && isaCode !== 2) {
    return fail('archive.kind', 'archive.table', `Unknown UOR-GPU-1 target ISA ${isaCode}; expected 1 (SM121) or 2 (SPIRV).`);
  }
  if (mathCode !== 1 && mathCode !== 2) {
    return fail('archive.kind', 'archive.table', `Unknown UOR-GPU-1 math contract ${mathCode}; expected 1 (IEEE754_RN) or 2 (FTZ).`);
  }
  if (claimedLevel > 3) {
    return fail('archive.kind', 'archive.table', `Out-of-range UOR-GPU-1 claimed evidence level ${claimedLevel}; expected 0..3.`);
  }
  if (payloadLen === 0 || 384 + payloadLen !== buf.length) {
    return fail('archive.bounds', 'archive.table', `UOR-GPU-1 payload length ${payloadLen} disagrees with file length ${buf.length}.`);
  }
  if (blockX < 1 || blockX > 1024) {
    return fail('archive.kind', 'archive.table', `Invalid UOR-GPU-1 launch block_x ${blockX}; expected 1..1024.`);
  }

  const signerPub = buf.subarray(288, 320).toString('hex');
  const attestSig = buf.subarray(320, 384).toString('hex');
  const hasSignature = signerPub !== ZERO32_HEX;
  if (!hasSignature) {
    if (claimedLevel !== 0) {
      return fail('archive.kind', 'holo.documents', `Unsigned UOR-GPU-1 bundle cannot claim level P${claimedLevel}; must claim P0.`);
    }
    if (attestSig !== ZERO64_HEX) {
      return fail('archive.kind', 'holo.documents', 'Unsigned UOR-GPU-1 bundle carries non-zero bytes in attest_sig.');
    }
  }

  const payload = buf.subarray(384, 384 + payloadLen);
  const payloadSha = buf.subarray(96, 128).toString('hex');
  const leanSha = buf.subarray(128, 160).toString('hex');
  const mlbomSha = buf.subarray(192, 224).toString('hex');
  const uorIdSha = buf.subarray(224, 256).toString('hex');
  const holoBlake3 = buf.subarray(256, 288).toString('hex');
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
      math: mathCode === 1 ? 'IEEE754_RN' : 'FTZ',
      claimedLevel: `P${claimedLevel}`,
      payloadLen,
      blockX,
      payloadSha,
      leanSha,
      mlbomSha,
      uorIdSha,
      holoBlake3,
      signerPub,
      hasSignature,
    },
    digests: {
      archive: { sha256: sha256Hex(buf), blake3: blake3Hex(new Uint8Array(buf)) },
      payload: { sha256: actualPayloadSha, blake3: actualPayloadBlake3 },
    },
    integrity: { payloadOk, uorIdOk, holoOk, isaStructOk: isaStructError === null, isaStructError },
  };
}

/**
 * Validate `.holo` container framing using only registered diagnostic codes
 * (`archive.bounds`, `archive.magic`, `archive.version`, `archive.flags`, `archive.kind`)
 * for load/inspect and `verification_failed` checks matching `sdk/npm/verify/src/reader.mjs`
 * for verify.
 */
function validateHoloContainer(buf, forVerify = false) {
  const mk = (code, check, message) => (
    forVerify
      ? { code: 'verification_failed', check, message: sentence(message) }
      : { code, message: sentence(message) }
  );
  if (!forVerify && buf.length < 42) return mk('archive.bounds', 'archive.version', 'Archive shorter than header and footer.');
  if (buf.length === 0) return mk('archive.bounds', 'archive.magic', 'Empty archive.');
  if (buf.length < 4) return mk('archive.bounds', 'archive.magic', 'Archive shorter than 4-byte magic.');
  if (!buf.subarray(0, 4).equals(HOLO_MAGIC)) return mk('archive.magic', 'archive.magic', 'Missing HOLO magic.');
  if (buf.length < 42) return mk('archive.bounds', 'archive.version', 'Archive shorter than header and footer.');
  const version = buf.readUInt16LE(4);
  if (version !== 4 && version !== 5) return mk('archive.version', 'archive.version', `Unsupported physical version ${version}.`);
  const flags = buf.readUInt16LE(6);
  if (flags !== 0) return mk('archive.flags', 'archive.flags', `Non-zero flags ${flags}.`);
  const count = buf.readUInt16LE(8);
  const tableEnd = 10 + count * 24;
  const bodyEnd = buf.length - 32;
  if (tableEnd > bodyEnd) return mk('archive.bounds', 'archive.table', 'Section table overruns file.');
  const validKinds = new Set([8, 14, 15, 16]);
  for (let i = 0; i < count; i++) {
    const off = 10 + i * 24;
    const kindBig = buf.readBigUInt64LE(off);
    const secOffBig = buf.readBigUInt64LE(off + 8);
    const secLenBig = buf.readBigUInt64LE(off + 16);
    if (kindBig > 0xffffffffn || secOffBig > BigInt(bodyEnd) || secLenBig > BigInt(bodyEnd)) {
      return mk('archive.bounds', 'archive.table', 'Section bounds exceed archive body.');
    }
    const kind = Number(kindBig);
    const secOff = Number(secOffBig);
    const secLen = Number(secLenBig);
    if (!validKinds.has(kind)) return mk('archive.kind', 'archive.table', `Unknown section kind ${kind}.`);
    if (secOff < tableEnd || secOff + secLen > bodyEnd) return mk('archive.bounds', 'archive.table', 'Section overruns body.');
  }
  return null;
}

function validatePolicy(policy) {
  const invalid = (msg) => ({ code: 'verification_failed', check: 'policy.invalid', message: sentence(msg) });
  if (policy === undefined || policy === null) return null;
  if (typeof policy !== 'object' || Array.isArray(policy)) {
    return invalid('Policy must be an object.');
  }
  for (const key of Object.keys(policy)) {
    if (!VALID_POLICY_KEYS.has(key)) {
      return invalid(`Unknown or unsupported policy member ${clipToken(key)}.`);
    }
  }
  if (policy.name !== undefined && policy.name !== null && (typeof policy.name !== 'string' || policy.name.length === 0 || policy.name.length > 1024)) {
    return invalid('Policy name must be a string of 1..1024 characters.');
  }
  if (policy.minimum !== undefined && policy.minimum !== null && !VALID_LEVELS.has(policy.minimum)) {
    return invalid(`Unknown policy minimum level ${clipToken(policy.minimum)}.`);
  }
  if (policy.world !== undefined && policy.world !== null) {
    if (typeof policy.world !== 'object' || Array.isArray(policy.world)) {
      return invalid('Invalid world pin.');
    }
    const wKeys = Object.keys(policy.world);
    if (wKeys.length === 0) return invalid('Empty world pin.');
    for (const k of wKeys) {
      if (!VALID_WORLD_KEYS.has(k)) return invalid(`Unknown world pin member ${clipToken(k)}.`);
    }
    if (policy.world.contract !== undefined && (typeof policy.world.contract !== 'string' || policy.world.contract.length === 0)) {
      return invalid('World contract pin must be a non-empty string.');
    }
    for (const alg of ['sha256', 'blake3']) {
      if (policy.world[alg] !== undefined && (typeof policy.world[alg] !== 'string' || !HEX64.test(policy.world[alg]))) {
        return invalid(`Invalid world ${alg} pin.`);
      }
    }
  }
  if (policy.digests !== undefined && policy.digests !== null) {
    if (typeof policy.digests !== 'object' || Array.isArray(policy.digests)) {
      return invalid('Policy digests must be an object.');
    }
    for (const [target, pin] of Object.entries(policy.digests)) {
      if (!VALID_DIGEST_TARGETS.has(target)) {
        return invalid(`Unknown or unsupported digest target ${clipToken(target)}.`);
      }
      if (pin === null || typeof pin !== 'object' || Array.isArray(pin) || Object.keys(pin).length === 0) {
        return invalid(`Empty digest pin for ${target}.`);
      }
      for (const [alg, val] of Object.entries(pin)) {
        if (!VALID_DIGEST_ALGS.has(alg)) return invalid(`Unknown digest algorithm ${clipToken(alg)}.`);
        if (typeof val !== 'string' || !HEX64.test(val)) return invalid(`Invalid ${alg} digest for ${target}.`);
      }
    }
  }
  if (policy.effects !== undefined && policy.effects !== null) {
    if (!Array.isArray(policy.effects) || policy.effects.some((e) => !VALID_EFFECTS.has(e))) {
      return invalid('Unknown effect in policy.');
    }
    if (new Set(policy.effects).size !== policy.effects.length) {
      return invalid('Policy effects repeats an effect.');
    }
  }
  return null;
}

/** Map a failed prism/verdict/1 to the typed error envelope matching `sdk/npm/prism-code/src/errors.mjs`. */
function errorFromVerdict(verdict) {
  const minRank = LEVEL_RANK[verdict.policy.minimum];
  const damaged = verdict.reasons.find((r) => r.check === 'holo.integrity');
  const pinned = verdict.reasons.find((r) => r.withholds === null && r.check !== 'policy.level');
  const contractFail = verdict.reasons.find((r) => r.check === 'world.contract');
  const blocking = verdict.reasons.find((r) => r.withholds && LEVEL_RANK[r.withholds] <= minRank);
  const reason = damaged ?? pinned ?? contractFail ?? blocking ?? verdict.reasons[0];
  const code = (reason.check === 'world.contract' || reason.check === 'world.hash')
    ? 'world_mismatch'
    : 'verification_failed';
  return { code, check: reason.check, verdict, message: sentence(reason.message) };
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
    if (bytes === undefined) throw shimErr({ code: 'archive.input', message: sentence('Missing archive path.') });
    const buf = Buffer.from(bytes);
    if (isUorGpuBundle(buf)) {
      const parsed = parseUorGpuBundle(buf, false);
      if (parsed.error) throw shimErr(parsed.error);
      if (process.env.PRISM_GPU_BIN && archive) {
        try {
          const out = execFileSync(process.env.PRISM_GPU_BIN, ['inspect', archive], { encoding: 'utf8' });
          return JSON.parse(out);
        } catch (err) {
          throw shimErr({ code: 'provider_failed', message: sentence(`PRISM_GPU_BIN inspect failed: ${err.message}`) });
        }
      }
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
    const err = validateHoloContainer(buf, false);
    if (err) throw shimErr(err);
    return { unsupported: 'Core-Wasm .holo inspection is outside the omega-gpu runtime scope' };
  },

  verify: async ({ bytes, input }) => {
    if (bytes === undefined) throw shimErr({ code: 'archive.input', message: sentence('Missing archive path.') });
    const buf = Buffer.from(bytes);
    const polErr = validatePolicy(input.policy);
    if (polErr) throw shimErr(polErr);
    const explicitMin = input.policy?.minimum ?? null;
    if (process.env.PRISM_MINIMUM_LEVEL !== undefined && explicitMin === null) {
      if (!VALID_LEVELS.has(process.env.PRISM_MINIMUM_LEVEL)) {
        throw shimErr({
          code: 'verification_failed',
          check: 'policy.invalid',
          message: sentence(`Invalid PRISM_MINIMUM_LEVEL ${clipToken(process.env.PRISM_MINIMUM_LEVEL)}.`),
        });
      }
    }
    if (isUorGpuBundle(buf)) {
      const parsed = parseUorGpuBundle(buf, true);
      if (parsed.error) throw shimErr(parsed.error);
      const intact = parsed.integrity.payloadOk && parsed.integrity.uorIdOk && parsed.integrity.holoOk;
      const minimum = explicitMin ?? process.env.PRISM_MINIMUM_LEVEL ?? 'P2';
      const policyName = input.policy?.name ?? 'default';
      const reasons = [];
      let policyDenied = false;

      if (!intact) {
        reasons.push({ check: 'holo.integrity', withholds: 'P1', message: sentence('UOR-GPU-1 digest check failed.') });
        reasons.push({ check: 'policy.integrity', withholds: null, message: sentence('Damaged bundles fail every policy.') });
        policyDenied = true;
      }
      if (!parsed.integrity.isaStructOk) {
        reasons.push({ check: 'world.contract', withholds: 'P1', message: sentence(parsed.integrity.isaStructError) });
        policyDenied = true;
      }

      // Enforce caller-supplied world pins (including null pin).
      if (input.policy && input.policy.world !== undefined) {
        const wp = input.policy.world;
        if (wp === null) {
          reasons.push({ check: 'world.hash', withholds: null, message: sentence('Null world pin does not match hologram:gpu/omega-om@1.') });
          policyDenied = true;
        } else {
          if (wp.contract !== undefined && wp.contract !== GPU_WORLD_CONTRACT) {
            reasons.push({
              check: 'world.hash',
              withholds: null,
              message: sentence(`World contract mismatch: expected ${clipToken(wp.contract)}, got ${GPU_WORLD_CONTRACT}.`),
            });
            policyDenied = true;
          }
          if (wp.sha256 !== undefined && wp.sha256 !== GPU_WORLD_SHA256) {
            reasons.push({ check: 'world.hash', withholds: null, message: sentence('World SHA-256 pin mismatch.') });
            policyDenied = true;
          }
          if (wp.blake3 !== undefined && wp.blake3 !== GPU_WORLD_BLAKE3) {
            reasons.push({ check: 'world.hash', withholds: null, message: sentence('World BLAKE3 pin mismatch.') });
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
              reasons.push({
                check: `policy.digests.${target}`,
                withholds: null,
                message: sentence(`Pinned ${target} ${alg} digest mismatch.`),
              });
              policyDenied = true;
            }
          }
        }
      }

      // Level invariant of prism/verdict/1: level P0 must always carry a reason withholding P1.
      if (!reasons.some((r) => r.withholds === 'P1')) {
        reasons.push({
          check: 'provenance.statement',
          withholds: 'P1',
          message: sentence('Offline UOR-GPU-1 shim checks digests and ISA framing at P0; P1+ requires local UORTRST1 trust anchors.'),
        });
      }

      if (minimum !== 'P0') {
        reasons.push({ check: 'policy.level', withholds: null, message: sentence(`Assurance level P0 is below policy minimum ${minimum}.`) });
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
        throw shimErr(errorFromVerdict(verdict));
      }
      return verdict;
    }
    const err = validateHoloContainer(buf, true);
    if (err) throw shimErr(err);
    return { unsupported: 'Core-Wasm .holo verification is outside the omega-gpu runtime scope' };
  },

  load: async ({ bytes, input }) => {
    if (bytes === undefined) throw shimErr({ code: 'archive.input', message: sentence('Missing archive path.') });
    const buf = Buffer.from(bytes);
    if (isUorGpuBundle(buf)) {
      const parsed = parseUorGpuBundle(buf, false);
      if (parsed.error) throw shimErr(parsed.error);
      const intact = parsed.integrity.payloadOk && parsed.integrity.uorIdOk && parsed.integrity.holoOk;
      if (!intact && input.allowUnverified !== true) {
        throw shimErr({ code: 'digest_mismatch', check: 'holo.integrity', message: sentence('UOR-GPU-1 integrity check failed.') });
      }
      if (!parsed.integrity.isaStructOk) {
        throw shimErr({ code: 'world_mismatch', check: 'world.contract', message: sentence(parsed.integrity.isaStructError) });
      }
      return {
        kind: 'gpu-bundle',
        name: parsed.header.isa,
        verified: intact,
        fingerprint: parsed.header.holoBlake3,
        world: { contract: GPU_WORLD_CONTRACT, within: true, pure: true, effects: [] },
        capabilities: { set: null },
      };
    }
    const err = validateHoloContainer(buf, false);
    if (err) throw shimErr(err);
    return { unsupported: 'Core-Wasm .holo loading is outside the omega-gpu runtime scope' };
  },
};

async function answer(request) {
  const operation = OPERATIONS[request.op];
  if (!operation) return { ok: false, unsupported: `no operation ${request.op}` };
  try {
    let bytes;
    if (request.archive !== undefined) {
      try {
        bytes = new Uint8Array(await readFile(request.archive));
      } catch (err) {
        throw shimErr({ code: 'load.path', message: sentence(`Archive cannot be read: ${err.message}`) });
      }
    }
    const result = await operation({ bytes, archive: request.archive, input: request.input ?? {} });
    if (result && typeof result === 'object' && 'unsupported' in result && Object.keys(result).length === 1) {
      return { ok: false, unsupported: result.unsupported };
    }
    return { ok: true, result };
  } catch (error) {
    if (error instanceof ShimError) {
      return { ok: false, error: error.payload };
    }
    return { ok: false, error: { code: 'prism_error', message: sentence(error?.stack ?? error) } };
  }
}

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
process.stdout.write(`${JSON.stringify(await answer(request))}\n`);
