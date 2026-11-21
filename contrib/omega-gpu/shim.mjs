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

const VALID_SPIRV_CAPS = new Set([4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 21, 22, 33, 34, 35, 36, 37, 38, 39]);
const VALID_SPIRV_STORAGE_CLASSES = new Set([0, 1, 4, 5, 6, 7, 8]);
const SPIRV_BINOPS = new Set([128, 129, 130, 131, 132, 133, 134, 136, 137, 176, 186]);

/**
 * Parse a canonical SPIR-V 1.0 NUL-terminated, zero-padded UTF-8 literal string
 * starting at word `startWord` inside `[startWord, endWord)`. Returns the next
 * word index after the string, or `{ error }`.
 */
function parseSpirvLiteralString(payload, startWord, endWord, utf8, label) {
  const nameStart = startWord * 4;
  const instEnd = endWord * 4;
  let nulPos = -1;
  for (let bi = nameStart; bi < instEnd; bi++) {
    if (payload[bi] === 0) {
      nulPos = bi;
      break;
    }
  }
  if (nulPos <= nameStart) return { error: `${label} must be non-empty and NUL-terminated.` };
  const nameWordEnd = Math.floor((nulPos - nameStart) / 4) * 4 + nameStart + 4;
  for (let bi = nulPos + 1; bi < nameWordEnd; bi++) {
    if (payload[bi] !== 0) return { error: `${label} has non-zero padding after NUL.` };
  }
  try {
    utf8.decode(payload.subarray(nameStart, nulPos));
  } catch {
    return { error: `${label} is not valid UTF-8.` };
  }
  return { nextWord: nameWordEnd / 4 };
}

/**
 * Validate OpenCL SPIR-V 1.0 binary framing and closed OpenCL Kernel instruction
 * set matching `gpu/spirv/emit.om` and `protocol/uor-gpu/payload_vm.om`.
 * Fails closed on any unknown or malformed opcode.
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
  let memModelCount = 0;
  let stage = 0; // 0=capabilities/ext, 1=memory-model, 2=entry/decls, 3=functions
  const entryIds = new Set();
  const definedFns = new Set();
  const definedIds = new Set();
  let inFn = false;
  const utf8 = new TextDecoder('utf-8', { fatal: true });

  const checkId = (id, what) => (id === 0 || id >= bound ? `SPIR-V ${what} id ${id} is outside 1..${bound - 1}.` : null);
  const defineId = (id, what) => {
    const err = checkId(id, what);
    if (err) return err;
    if (definedIds.has(id)) return `SPIR-V duplicate result id ${id} in ${what}.`;
    definedIds.add(id);
    return null;
  };
  const checkMemAccess = (maskWord, wc, baseWc, label) => {
    if (wc === baseWc) return null;
    const mask = w(maskWord);
    if ((mask & ~7) !== 0) return `SPIR-V ${label} has invalid MemoryAccess mask 0x${mask.toString(16)}.`;
    const aligned = (mask & 2) !== 0;
    const expectedWc = aligned ? baseWc + 2 : baseWc + 1;
    if (wc !== expectedWc) return `SPIR-V ${label} MemoryAccess expects word count ${expectedWc}, got ${wc}.`;
    if (aligned) {
      const align = w(maskWord + 1);
      if (align === 0 || (align & (align - 1)) !== 0) return `SPIR-V ${label} alignment ${align} must be a non-zero power of two.`;
    }
    return null;
  };

  for (let p = 5; p < nw; ) {
    const hd = w(p);
    const wc = hd >>> 16;
    const op = hd & 0xffff;
    if (wc === 0 || p + wc > nw) {
      return `SPIR-V instruction at word ${p} has invalid word count ${wc}.`;
    }
    if (op === 17) {
      // OpCapability (section 1)
      if (inFn || stage > 0 || wc !== 2) return 'SPIR-V OpCapability must appear in module header before OpMemoryModel with word count 2.';
      const cap = w(p + 1);
      if (!VALID_SPIRV_CAPS.has(cap)) return `SPIR-V unsupported OpenCL capability ${cap}.`;
      if (cap === 4) capMask |= 1;
      if (cap === 6) capMask |= 2;
    } else if (op === 11) {
      // OpExtInstImport <ResultId> <LiteralString> (section 3)
      if (inFn || stage > 0 || wc < 3) return 'SPIR-V OpExtInstImport must appear before OpMemoryModel with word count >= 3.';
      const idErr = defineId(w(p + 1), 'OpExtInstImport');
      if (idErr) return idErr;
      const str = parseSpirvLiteralString(payload, p + 2, p + wc, utf8, 'SPIR-V OpExtInstImport name');
      if (str.error) return str.error;
      if (str.nextWord !== p + wc) return 'SPIR-V OpExtInstImport has trailing words after literal string.';
    } else if (op === 14) {
      // OpMemoryModel Physical64(2) OpenCL(2) (section 4)
      if (inFn || stage > 0 || wc !== 3) return 'SPIR-V OpMemoryModel must appear once before OpEntryPoint with word count 3.';
      if (memModelCount > 0) return 'SPIR-V module must declare exactly one OpMemoryModel.';
      if (w(p + 1) !== 2 || w(p + 2) !== 2) return 'SPIR-V OpMemoryModel must be Physical64 (2) OpenCL (2).';
      memModelCount += 1;
      stage = 1;
    } else if (op === 15) {
      // OpEntryPoint Kernel(6) <id> <name...> <interface...> (section 5)
      if (inFn || stage < 1 || stage > 2 || wc < 4 || w(p + 1) !== 6) {
        return 'SPIR-V OpEntryPoint must follow OpMemoryModel before functions and target OpenCL Kernel execution model (6).';
      }
      const eid = w(p + 2);
      const eidErr = checkId(eid, 'OpEntryPoint');
      if (eidErr) return eidErr;
      if (entryIds.has(eid)) return `SPIR-V duplicate OpEntryPoint for function id ${eid}.`;
      const str = parseSpirvLiteralString(payload, p + 3, p + wc, utf8, 'SPIR-V OpEntryPoint kernel name');
      if (str.error) return str.error;
      for (let wi = str.nextWord; wi < p + wc; wi++) {
        const ifaceErr = checkId(w(wi), 'OpEntryPoint interface');
        if (ifaceErr) return ifaceErr;
      }
      entryIds.add(eid);
      stage = 2;
    } else if (op === 16) {
      // OpExecutionMode <EntryPoint> <Mode> [literals...]
      if (inFn || stage !== 2 || wc < 3) return 'SPIR-V OpExecutionMode must follow OpEntryPoint before functions with word count >= 3.';
      const target = w(p + 1);
      if (!entryIds.has(target)) return `SPIR-V OpExecutionMode targets undeclared entry point ${target}.`;
    } else if (op === 71) {
      // OpDecorate <Target> <Decoration> [literals...]
      if (inFn || stage !== 2 || wc < 3) return 'SPIR-V OpDecorate must appear before functions with word count >= 3.';
      const targetErr = checkId(w(p + 1), 'OpDecorate target');
      if (targetErr) return targetErr;
      if (w(p + 2) === 11 && wc !== 4) return 'SPIR-V OpDecorate BuiltIn must have word count 4.';
    } else if (op === 19 || op === 20) {
      // OpTypeVoid / OpTypeBool <ResultId>
      if (inFn || stage !== 2 || wc !== 2) return `SPIR-V opcode ${op} must appear before functions with word count 2.`;
      const idErr = defineId(w(p + 1), `opcode ${op}`);
      if (idErr) return idErr;
    } else if (op === 21) {
      // OpTypeInt <ResultId> <Width> <Signedness>
      if (inFn || stage !== 2 || wc !== 4) return 'SPIR-V OpTypeInt must appear before functions with word count 4.';
      const idErr = defineId(w(p + 1), 'OpTypeInt');
      if (idErr) return idErr;
      const width = w(p + 2);
      const signed = w(p + 3);
      if (![8, 16, 32, 64].includes(width) || (signed !== 0 && signed !== 1)) {
        return `SPIR-V OpTypeInt has invalid width ${width} or signedness ${signed}.`;
      }
    } else if (op === 22) {
      // OpTypeFloat <ResultId> <Width>
      if (inFn || stage !== 2 || wc !== 3) return 'SPIR-V OpTypeFloat must appear before functions with word count 3.';
      const idErr = defineId(w(p + 1), 'OpTypeFloat');
      if (idErr) return idErr;
      const width = w(p + 2);
      if (![16, 32, 64].includes(width)) return `SPIR-V OpTypeFloat has invalid width ${width}.`;
    } else if (op === 23) {
      // OpTypeVector <ResultId> <ComponentType> <ComponentCount>
      if (inFn || stage !== 2 || wc !== 4) return 'SPIR-V OpTypeVector must appear before functions with word count 4.';
      const idErr = defineId(w(p + 1), 'OpTypeVector');
      if (idErr) return idErr;
      const compErr = checkId(w(p + 2), 'OpTypeVector component type');
      if (compErr) return compErr;
      const count = w(p + 3);
      if (count < 2 || count > 16) return `SPIR-V OpTypeVector component count ${count} is outside 2..16.`;
    } else if (op === 32) {
      // OpTypePointer <ResultId> <StorageClass> <Type>
      if (inFn || stage !== 2 || wc !== 4) return 'SPIR-V OpTypePointer must appear before functions with word count 4.';
      const idErr = defineId(w(p + 1), 'OpTypePointer');
      if (idErr) return idErr;
      if (!VALID_SPIRV_STORAGE_CLASSES.has(w(p + 2))) return `SPIR-V OpTypePointer unsupported storage class ${w(p + 2)}.`;
      const tyErr = checkId(w(p + 3), 'OpTypePointer pointee type');
      if (tyErr) return tyErr;
    } else if (op === 33) {
      // OpTypeFunction <ResultId> <ReturnType> [ParamType...]
      if (inFn || stage !== 2 || wc < 3) return 'SPIR-V OpTypeFunction must appear before functions with word count >= 3.';
      const idErr = defineId(w(p + 1), 'OpTypeFunction');
      if (idErr) return idErr;
      for (let wi = p + 2; wi < p + wc; wi++) {
        const tyErr = checkId(w(wi), 'OpTypeFunction signature type');
        if (tyErr) return tyErr;
      }
    } else if (op === 43) {
      // OpConstant <ResultType> <ResultId> <Literal...>
      if (inFn || stage !== 2 || wc < 4) return 'SPIR-V OpConstant must appear before functions with word count >= 4.';
      const tyErr = checkId(w(p + 1), 'OpConstant result type');
      if (tyErr) return tyErr;
      const idErr = defineId(w(p + 2), 'OpConstant');
      if (idErr) return idErr;
    } else if (op === 59) {
      // OpVariable <ResultType> <ResultId> <StorageClass> [Initializer]
      if ((inFn ? stage !== 3 : stage !== 2) || (wc !== 4 && wc !== 5)) return 'SPIR-V malformed or misplaced OpVariable.';
      const tyErr = checkId(w(p + 1), 'OpVariable result type');
      if (tyErr) return tyErr;
      const idErr = defineId(w(p + 2), 'OpVariable');
      if (idErr) return idErr;
      const sc = w(p + 3);
      if (!VALID_SPIRV_STORAGE_CLASSES.has(sc)) return `SPIR-V OpVariable unsupported storage class ${sc}.`;
      if (inFn && sc !== 7) return 'SPIR-V function-scope OpVariable must use Function storage class (7).';
      if (!inFn && sc === 7) return 'SPIR-V module-scope OpVariable cannot use Function storage class (7).';
      if (wc === 5) {
        const initErr = checkId(w(p + 4), 'OpVariable initializer');
        if (initErr) return initErr;
      }
    } else if (op === 54) {
      // OpFunction <ResultType> <ResultId> <FunctionControl> <FunctionType>
      if (inFn || stage < 2 || wc !== 5) return 'SPIR-V malformed, misplaced, or nested OpFunction.';
      const resType = w(p + 1);
      const fnId = w(p + 2);
      const fnCtrl = w(p + 3);
      const fnType = w(p + 4);
      const rtErr = checkId(resType, 'OpFunction result type');
      if (rtErr) return rtErr;
      const fnIdErr = defineId(fnId, 'OpFunction');
      if (fnIdErr) return fnIdErr;
      if ((fnCtrl & ~0xf) !== 0 || (fnCtrl & 3) === 3) return `SPIR-V OpFunction has invalid FunctionControl mask 0x${fnCtrl.toString(16)}.`;
      const ftErr = checkId(fnType, 'OpFunction type');
      if (ftErr) return ftErr;
      definedFns.add(fnId);
      inFn = true;
      stage = 3;
    } else if (op === 55) {
      // OpFunctionParameter <ResultType> <ResultId>
      if (!inFn || wc !== 3) return 'SPIR-V OpFunctionParameter must appear inside a function with word count 3.';
      const tyErr = checkId(w(p + 1), 'OpFunctionParameter result type');
      if (tyErr) return tyErr;
      const idErr = defineId(w(p + 2), 'OpFunctionParameter');
      if (idErr) return idErr;
    } else if (op === 56) {
      // OpFunctionEnd
      if (!inFn || wc !== 1) return 'SPIR-V malformed OpFunctionEnd.';
      inFn = false;
    } else if (op === 248) {
      // OpLabel <ResultId>
      if (!inFn || wc !== 2) return 'SPIR-V OpLabel must appear inside a function with word count 2.';
      const idErr = defineId(w(p + 1), 'OpLabel');
      if (idErr) return idErr;
    } else if (op === 247) {
      // OpSelectionMerge <MergeBlock> <SelectionControl>
      if (!inFn || wc !== 3) return 'SPIR-V OpSelectionMerge must appear inside a function with word count 3.';
      const blkErr = checkId(w(p + 1), 'OpSelectionMerge target');
      if (blkErr) return blkErr;
      if ((w(p + 2) & ~3) !== 0) return `SPIR-V OpSelectionMerge has invalid control mask 0x${w(p + 2).toString(16)}.`;
    } else if (op === 249) {
      // OpBranch <TargetLabel>
      if (!inFn || wc !== 2) return 'SPIR-V OpBranch must appear inside a function with word count 2.';
      const blkErr = checkId(w(p + 1), 'OpBranch target');
      if (blkErr) return blkErr;
    } else if (op === 250) {
      // OpBranchConditional <Condition> <TrueLabel> <FalseLabel> [Weight1 Weight2]
      if (!inFn || (wc !== 4 && wc !== 6)) return 'SPIR-V OpBranchConditional must appear inside a function with word count 4 or 6.';
      for (let wi = p + 1; wi <= p + 3; wi++) {
        const refErr = checkId(w(wi), 'OpBranchConditional operand');
        if (refErr) return refErr;
      }
    } else if (op === 253) {
      // OpReturn
      if (!inFn || wc !== 1) return 'SPIR-V OpReturn must appear inside a function with word count 1.';
    } else if (op === 61) {
      // OpLoad <ResultType> <ResultId> <Pointer> [MemoryAccess...]
      if (!inFn || wc < 4) return 'SPIR-V OpLoad must appear inside a function with word count >= 4.';
      const tyErr = checkId(w(p + 1), 'OpLoad result type');
      if (tyErr) return tyErr;
      const idErr = defineId(w(p + 2), 'OpLoad');
      if (idErr) return idErr;
      const ptrErr = checkId(w(p + 3), 'OpLoad pointer');
      if (ptrErr) return ptrErr;
      const maErr = checkMemAccess(p + 4, wc, 4, 'OpLoad');
      if (maErr) return maErr;
    } else if (op === 62) {
      // OpStore <Pointer> <Object> [MemoryAccess...]
      if (!inFn || wc < 3) return 'SPIR-V OpStore must appear inside a function with word count >= 3.';
      const ptrErr = checkId(w(p + 1), 'OpStore pointer');
      if (ptrErr) return ptrErr;
      const objErr = checkId(w(p + 2), 'OpStore object');
      if (objErr) return objErr;
      const maErr = checkMemAccess(p + 3, wc, 3, 'OpStore');
      if (maErr) return maErr;
    } else if (op === 70) {
      // OpInBoundsPtrAccessChain <ResultType> <ResultId> <Base> <Element> [Indexes...]
      if (!inFn || wc < 5) return 'SPIR-V OpInBoundsPtrAccessChain must appear inside a function with word count >= 5.';
      const tyErr = checkId(w(p + 1), 'OpInBoundsPtrAccessChain result type');
      if (tyErr) return tyErr;
      const idErr = defineId(w(p + 2), 'OpInBoundsPtrAccessChain');
      if (idErr) return idErr;
      for (let wi = p + 3; wi < p + wc; wi++) {
        const refErr = checkId(w(wi), 'OpInBoundsPtrAccessChain operand');
        if (refErr) return refErr;
      }
    } else if (op === 81) {
      // OpCompositeExtract <ResultType> <ResultId> <Composite> <Literal...>
      if (!inFn || wc < 5) return 'SPIR-V OpCompositeExtract must appear inside a function with word count >= 5.';
      const tyErr = checkId(w(p + 1), 'OpCompositeExtract result type');
      if (tyErr) return tyErr;
      const idErr = defineId(w(p + 2), 'OpCompositeExtract');
      if (idErr) return idErr;
      const cmpErr = checkId(w(p + 3), 'OpCompositeExtract composite');
      if (cmpErr) return cmpErr;
    } else if (op === 113) {
      // OpUConvert <ResultType> <ResultId> <UnsignedValue>
      if (!inFn || wc !== 4) return 'SPIR-V OpUConvert must appear inside a function with word count 4.';
      const tyErr = checkId(w(p + 1), 'OpUConvert result type');
      if (tyErr) return tyErr;
      const idErr = defineId(w(p + 2), 'OpUConvert');
      if (idErr) return idErr;
      const valErr = checkId(w(p + 3), 'OpUConvert operand');
      if (valErr) return valErr;
    } else if (op === 12) {
      // OpExtInst <ResultType> <ResultId> <Set> <Instruction> [Operands...]
      if (!inFn || wc < 5) return 'SPIR-V OpExtInst must appear inside a function with word count >= 5.';
      const tyErr = checkId(w(p + 1), 'OpExtInst result type');
      if (tyErr) return tyErr;
      const idErr = defineId(w(p + 2), 'OpExtInst');
      if (idErr) return idErr;
      const setErr = checkId(w(p + 3), 'OpExtInst set');
      if (setErr) return setErr;
      for (let wi = p + 5; wi < p + wc; wi++) {
        const opErr = checkId(w(wi), 'OpExtInst operand');
        if (opErr) return opErr;
      }
    } else if (op === 169) {
      // OpSelect <ResultType> <ResultId> <Condition> <Object1> <Object2>
      if (!inFn || wc !== 6) return 'SPIR-V OpSelect must appear inside a function with word count 6.';
      const tyErr = checkId(w(p + 1), 'OpSelect result type');
      if (tyErr) return tyErr;
      const idErr = defineId(w(p + 2), 'OpSelect');
      if (idErr) return idErr;
      for (let wi = p + 3; wi <= p + 5; wi++) {
        const refErr = checkId(w(wi), 'OpSelect operand');
        if (refErr) return refErr;
      }
    } else if (SPIRV_BINOPS.has(op)) {
      // Binary arithmetic / comparison <ResultType> <ResultId> <Op1> <Op2>
      if (!inFn || wc !== 5) return `SPIR-V opcode ${op} must appear inside a function with word count 5.`;
      const tyErr = checkId(w(p + 1), `opcode ${op} result type`);
      if (tyErr) return tyErr;
      const idErr = defineId(w(p + 2), `opcode ${op}`);
      if (idErr) return idErr;
      const aErr = checkId(w(p + 3), `opcode ${op} operand 1`);
      if (aErr) return aErr;
      const bErr = checkId(w(p + 4), `opcode ${op} operand 2`);
      if (bErr) return bErr;
    } else {
      return `SPIR-V unsupported or invalid opcode ${op} at word ${p}.`;
    }
    p += wc;
  }

  if (capMask !== 3) return 'SPIR-V OpenCL module must declare both Addresses and Kernel capabilities.';
  if (memModelCount !== 1) return 'SPIR-V OpenCL module must declare Physical64 OpenCL memory model.';
  if (entryIds.size === 0) return 'SPIR-V OpenCL module must declare at least one Kernel OpEntryPoint.';
  for (const eid of entryIds) {
    if (!definedFns.has(eid)) return `SPIR-V OpenCL module does not define Kernel OpEntryPoint function ${eid}.`;
  }
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
  } else if (attestSig === ZERO64_HEX) {
    return fail('archive.kind', 'holo.documents', 'Signed UOR-GPU-1 bundle carries an all-zero attest_sig.');
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
  const computedHoloBlake3 = blake3Hex(new Uint8Array(holoInput));
  const holoOk = computedHoloBlake3 === holoBlake3;
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
    computedHoloBlake3,
    digests: {
      archive: { sha256: sha256Hex(buf), blake3: blake3Hex(new Uint8Array(buf)) },
      payload: { sha256: actualPayloadSha, blake3: actualPayloadBlake3 },
      seal: { blake3: computedHoloBlake3 },
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
    // Match sdk/npm/prism-code/src/verify.mjs resolveOptions(): consult PRISM_MINIMUM_LEVEL
    // only when policy.minimum is omitted (undefined) and the env var is non-empty; an
    // explicit null falls back to the default P2 rather than weakening to the environment.
    const envMin = process.env.PRISM_MINIMUM_LEVEL;
    let minimum;
    if (input.policy?.minimum === undefined) {
      if (envMin !== undefined && envMin !== '') {
        if (!VALID_LEVELS.has(envMin)) {
          throw shimErr({
            code: 'verification_failed',
            check: 'policy.invalid',
            message: sentence(`Invalid PRISM_MINIMUM_LEVEL ${clipToken(envMin)}.`),
          });
        }
        minimum = envMin;
      } else {
        minimum = 'P2';
      }
    } else if (input.policy.minimum === null) {
      minimum = 'P2';
    } else {
      minimum = input.policy.minimum;
    }
    if (isUorGpuBundle(buf)) {
      const parsed = parseUorGpuBundle(buf, true);
      if (parsed.error) throw shimErr(parsed.error);
      const intact = parsed.integrity.payloadOk && parsed.integrity.uorIdOk && parsed.integrity.holoOk;
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
        holo: `blake3:${parsed.computedHoloBlake3}`,
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
        fingerprint: parsed.computedHoloBlake3,
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
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    return { ok: false, error: { code: 'prism_error', message: sentence('Shim request must be a JSON object.') } };
  }
  const operation = typeof request.op === 'string' && Object.hasOwn(OPERATIONS, request.op) ? OPERATIONS[request.op] : undefined;
  if (!operation) return { ok: false, unsupported: `no operation ${clipToken(request.op)}` };
  try {
    let bytes;
    if (request.archive !== undefined) {
      if (typeof request.archive !== 'string') {
        throw shimErr({ code: 'archive.input', message: sentence('Archive path must be a string.') });
      }
      try {
        bytes = new Uint8Array(await readFile(request.archive));
      } catch (err) {
        throw shimErr({ code: 'load.path', message: sentence(`Archive cannot be read: ${err.message}`) });
      }
    }
    if (request.input !== undefined && request.input !== null && (typeof request.input !== 'object' || Array.isArray(request.input))) {
      throw shimErr({ code: 'prism_error', message: sentence('Shim request input must be an object.') });
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
