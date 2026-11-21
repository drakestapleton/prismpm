// Two things taken from Hologram (github.com/Hologram-Technologies/hologram), as far as a browser page can take
// them today: its content-addressed store, and its rule that a pure function over a finite domain is computed once
// and kept as a table.
//
// The store. Hologram's browser KappaStore keeps one file for each blob in the origin's private file system, named
// by the blob's label with the colon written as an underscore, and returns bytes only when they re-derive to the
// label asked for (crates/hologram-store/src/opfs/js_api.rs at e8fcdc70: opfs_put, opfs_get, opfs_delete). The
// label is `blake3:` and the BLAKE3 of the bytes, the same label src/blake3.mjs makes. Hologram publishes no
// browser build of that store (no npm package, no release file), so this is the same layout written in
// JavaScript: a blob put here is one Hologram's store reads, and the other way round. When Hologram ships a build,
// `openStore` is the one function to replace.
//
// What a store keeps is only what this origin's own pages wrote, and nothing leaves the browser.

const LABEL = /^blake3:[0-9a-f]{64}$/;
const nameOf = (label) => label.replace(':', '_');
const dec = new TextDecoder();
const enc = new TextEncoder();

/**
 * The store. `kappa(bytes)` is src/blake3.mjs's. `root` is a directory handle; the origin's private file system when
 * none is given. Where the browser has no such file system, or refuses it (a private window), the store keeps
 * things for this tab only and `durable` is false. Every method resolves; none throws.
 */
export async function openStore({ kappa, root = null }) {
  let top = root;
  try { top ??= await navigator.storage.getDirectory(); } catch { top = null; }
  const memory = new Map();
  let durable = top !== null;
  const read = async (dir, name) => {
    try { return new Uint8Array(await (await (await dir.getFileHandle(name)).getFile()).arrayBuffer()); } catch { return null; }
  };
  const write = async (dir, name, bytes) => {
    try {
      const stream = await (await dir.getFileHandle(name, { create: true })).createWritable();
      await stream.write(bytes);
      // The file is replaced only on close, so a reader never sees half of it.
      await stream.close();
      return true;
    } catch { return false; }
  };
  const bindings = async (create) => { try { return await top.getDirectoryHandle('prism-terminal-bindings', { create }); } catch { return null; } };
  return {
    get durable() { return durable; },
    /** Keep bytes under their label. Bytes already held are not written again. */
    async put(bytes) {
      const label = kappa(bytes);
      if (durable && (await read(top, nameOf(label))) === null && !(await write(top, nameOf(label), bytes))) durable = false;
      if (!durable) memory.set(label, bytes.slice());
      return label;
    },
    /** The bytes under a label, or null: absent, or no longer what the label says. */
    async get(label) {
      if (!LABEL.test(label)) return null;
      const bytes = memory.get(label) ?? (top ? await read(top, nameOf(label)) : null);
      return bytes && kappa(bytes) === label ? bytes : null;
    },
    /** Say that a derivation key leads to a label. Hologram's layout has no place for this, so it has its own folder. */
    async bind(key, label) {
      const dir = durable ? await bindings(true) : null;
      if (!dir || !(await write(dir, nameOf(key), enc.encode(label)))) memory.set('bind ' + key, label);
    },
    async bound(key) {
      if (!LABEL.test(key)) return null;
      const dir = top ? await bindings(false) : null;
      const bytes = dir ? await read(dir, nameOf(key)) : null;
      const label = memory.get('bind ' + key) ?? (bytes ? dec.decode(bytes) : '');
      return LABEL.test(label) ? label : null;
    },
  };
}

const OUTPUT = 'prism/terminal-output/1';

/**
 * A program's outputs, kept in the store between visits, in the form session.mjs asks for. An entry is two blobs:
 * the output, and a small record naming the key, the program's label, the input's label and the output's label. The
 * key is bound to the record. What comes back is only what was read and re-derived; whether it may stand in for
 * running the program is `reuseAdmits`'s to say, in session.mjs.
 */
export function createKeptIn(store) {
  return {
    async get(key) {
      const named = await store.bound(key);
      const record = named ? await store.get(named) : null;
      if (!record) return null;
      let said;
      try { said = JSON.parse(dec.decode(record)); } catch { return null; }
      if (said?.schema !== OUTPUT || ![said.key, said.program, said.input, said.output].every((l) => typeof l === 'string')) return null;
      const bytes = await store.get(said.output);
      return bytes ? { key: said.key, program: said.program, input: said.input, output: said.output, bytes } : null;
    },
    async set(key, entry) {
      const output = await store.put(entry.bytes);
      const record = await store.put(enc.encode(JSON.stringify({ schema: OUTPUT, key: entry.key, program: entry.program, input: entry.input, output }) + '\n'));
      await store.bind(key, record);
    },
  };
}

/**
 * A rule table as a lookup table: every request's answer, computed once with the table's own judge and kept as one
 * byte each. A request's answer is then one read. Only for a table whose fields are all words (a finite domain);
 * a table with a number field resolves null and is judged rule by rule as before.
 * `judgeTable` is src/journey/rule-table.mjs's. Resolves { bytes, sizes, kappa }.
 */
export function materialize(table, judgeTable, kappa) {
  if (table.fields.some((f) => f.kind !== 'choice') || table.answers.length > 255) return null;
  const sizes = table.fields.map((f) => f.values.length);
  const total = sizes.reduce((n, s) => n * s, 1);
  if (total > 1 << 20) return null;
  const bytes = new Uint8Array(total);
  const request = new Array(sizes.length).fill(0);
  for (let i = 0; i < total; i++) {
    let rest = i;
    for (let f = sizes.length - 1; f >= 0; f--) { request[f] = rest % sizes[f]; rest = Math.floor(rest / sizes[f]); }
    bytes[i] = judgeTable(table, request).answer;
  }
  return { bytes, sizes, kappa: kappa(bytes) };
}

/** Where a request sits in a materialized table: its fields as the digits of one number, first field highest. */
export const indexOf = (sizes, request) => request.reduce((at, value, f) => at * sizes[f] + value, 0);
