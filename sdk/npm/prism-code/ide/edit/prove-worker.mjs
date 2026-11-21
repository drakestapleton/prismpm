// Lean's kernel, in a worker, judging a rule table's guarantees after an edit.
//
// It follows what the page of a built rule app does (src/journey/rule-app-site.mjs, `prove`), with the same pieces of
// prism-code: the proof term for each guarantee is produced by kernel-terms.mjs, the kernel judges it, and
// canonical-rules.mjs says whether that counts as proved, axioms included. The kernel, its loader and its library
// are used only when their bytes hash to what kernel/manifest.json names, and only when the manifest records that
// this kernel judged this library whole.
//
// Unlike the built page, nothing is kept between visits, and the kernel is put back to its just-loaded state before
// every batch, so an earlier edit's terms cannot stand in for this one's.
//
// Messages in:  { id, words, guarantees }
// Messages out: { ready: true, ms } once, or { failed: 'why' };  { id, results: [{ proved, accepted, axioms }], ms }.

import { HOLDS, KERNEL_AXIOMS, proofLines, readLibrary } from './prism-code/journey/kernel-terms.mjs';
import { guaranteeStatement } from './prism-code/journey/kappa-rules.mjs';
import { judgedFacts, proved } from './prism-code/journey/canonical-rules.mjs';

const enc = new TextEncoder();
const dec = new TextDecoder();
const sha256 = async (bytes) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map((b) => b.toString(16).padStart(2, '0')).join('');
const unpack = async (response) => new Uint8Array(await new Response(response.body.pipeThrough(new DecompressionStream('gzip'))).arrayBuffer());

async function open() {
  const started = performance.now();
  const base = new URL('./kernel/', import.meta.url).href;
  const manifest = await (await fetch(base + 'manifest.json', { cache: 'no-store' })).json();
  const [glue, wasm, library] = await Promise.all([manifest.glue, manifest.wasm, manifest.library].map(async (entry) => unpack(await fetch(base + entry.file))));
  const [g, w, l] = await Promise.all([glue, wasm, library].map(sha256));
  if (g !== manifest.glue.sha256 || w !== manifest.wasm.sha256 || l !== manifest.library.sha256) throw Object.assign(new Error('the kernel, its loader or its library is not the pinned one'), { reason: 'mismatch' });
  const b = manifest.binding;
  if (!b || b.kernel !== w || b.loader !== g || b.library !== l) throw new Error('there is no record that this kernel judged this library whole');

  const said = [];
  const url = URL.createObjectURL(new Blob([glue], { type: 'text/javascript' }));
  let module, memory;
  try {
    module = await (await import(url)).default({ instantiateWasm: (imports, done) => { WebAssembly.instantiate(wasm, imports).then((r) => { memory = r.instance.exports.memory; done(r.instance, r.module); }); return {}; }, print: (s) => said.push(s), printErr: (s) => said.push(s) });
  } finally { URL.revokeObjectURL(url); }
  const run = (entry, bytes) => {
    said.length = 0;
    module.FS.writeFile('/in.ndjson', bytes);
    let exit;
    try { exit = module.ccall(entry, 'number', ['string'], ['/in.ndjson']); } catch { exit = 3; }
    module.FS.unlink('/in.ndjson');
    const axioms = {};
    for (const line of said) { const a = /^axioms ([^:]+): ?(.*)$/.exec(line); if (a) axioms[a[1]] = a[2] ? a[2].split(', ') : []; }
    return { exit, axioms };
  };
  if (module.ccall('checker_ready', 'number', [], []) !== 0) throw new Error('the kernel did not start');
  if (run('load_library', library).exit !== 0) throw new Error('the kernel refused its library');
  // The kernel with this library and nothing else: every batch starts from here.
  const image = new Uint8Array(memory.buffer).slice();
  const reset = () => { const now = new Uint8Array(memory.buffer); now.set(image); now.fill(0, image.length); };
  postMessage({ ready: true, ms: Math.round(performance.now() - started), lean: manifest.lean?.version ?? null });
  return { lib: readLibrary(dec.decode(library)), run, reset, labels: { kernel: 'sha256:' + w, library: 'sha256:' + l } };
}

const kernel = open();
kernel.catch((e) => postMessage({ failed: String(e?.message ?? e), reason: e?.reason ?? 'absent' }));

onmessage = async ({ data }) => {
  try {
    const { lib, run, reset } = await kernel;
    const started = performance.now();
    reset();
    const results = [];
    for (const guarantee of data.guarantees) {
      const statement = guaranteeStatement(data.words, guarantee);
      const bytes = enc.encode(proofLines(lib, data.words, guarantee));
      const r = run('check_suffix', bytes);
      const axioms = r.axioms[HOLDS] || null;
      const derived = 'sha256:' + await sha256(bytes);
      // A term is proved only by what this kernel accepts now, within the axioms a rule table is allowed.
      const facts = judgedFacts({ hasTerm: true, termNamed: derived, termDerived: derived, termStatement: statement, statement, kernelRan: true, kernelAccepted: r.exit === 0 && axioms !== null, axioms, policy: KERNEL_AXIOMS, source: 0 });
      results.push({ proved: proved(facts), accepted: r.exit === 0, axioms });
    }
    postMessage({ id: data.id, results, ms: Math.round(performance.now() - started) });
  } catch (e) {
    postMessage({ id: data.id, error: String(e?.message ?? e) });
  }
};
