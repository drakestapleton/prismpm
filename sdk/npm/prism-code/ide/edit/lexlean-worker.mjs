// LexLean's front end, in a worker, checking a model as it is edited.
//
// The executable is the one prism-code pins (src/journey/lexlean-wasm.mjs): it is fetched once, inflated, and run
// only if its bytes hash to the pinned BLAKE3 label. It is the same `lexlean check` the SDK runs, on a read-only
// file system held in memory (src/journey/wasi-memory.mjs). Nothing leaves the tab.
//
// Messages in:  { id, files: { '/path': 'text', ... } }
// Messages out: { ready: true, ms, kappa } once, or { failed: 'why', reason: 'mismatch' | 'absent' };
//               { id, result, ms } with LexLean's command result, or { id, error }.

const base = new URL('./prism-code/', import.meta.url).href;
const enc = new TextEncoder();
const dec = new TextDecoder();

let modulePromise = null;
async function load(wasmUrl, want) {
  const started = performance.now();
  const [{ runWasi }, { kappa }] = await Promise.all([import(base + 'journey/wasi-memory.mjs'), import(base + 'blake3.mjs')]);
  const response = await fetch(wasmUrl);
  if (!response.ok) throw new Error(`the LexLean executable is not at ${wasmUrl} (${response.status})`);
  const stream = want.encoding === 'gzip' ? response.body.pipeThrough(new DecompressionStream('gzip')) : response.body;
  const bytes = new Uint8Array(await new Response(stream).arrayBuffer());
  const label = kappa(bytes);
  // The bytes run only if they are the pinned ones.
  if (label !== want.kappa) throw Object.assign(new Error(`the LexLean executable hashes to ${label}, not the pinned ${want.kappa}`), { reason: 'mismatch' });
  const module = await WebAssembly.compile(bytes);
  postMessage({ ready: true, ms: Math.round(performance.now() - started), kappa: label, bytes: bytes.length });
  return { module, runWasi };
}

onmessage = async ({ data }) => {
  if (data.start) {
    modulePromise = load(data.start.url, data.start.pin);
    modulePromise.catch((e) => postMessage({ failed: String(e?.message ?? e), reason: e?.reason ?? 'absent' }));
    return;
  }
  try {
    const { module, runWasi } = await modulePromise;
    const files = new Map(Object.entries(data.files).map(([path, text]) => [path, typeof text === 'string' ? enc.encode(text) : text]));
    const started = performance.now();
    if (data.snapshot) {
      // `lexlean snapshot --all`: what the model means, in the form the rule table and the kernel read.
      const taken = await runWasi(module, { files, args: ['snapshot', '--all'] });
      postMessage({ id: data.id, snapshot: taken.exit === 0 ? dec.decode(taken.stdout) : null, ms: Math.round(performance.now() - started) });
      return;
    }
    const run = await runWasi(module, { files, args: ['--diagnostic-format', 'json', 'check', '--all'] });
    let result;
    try { result = JSON.parse(dec.decode(run.stdout)); } catch { throw new Error(`LexLean gave no result (exit ${run.exit}): ${dec.decode(run.stderr).slice(0, 300)}`); }
    postMessage({ id: data.id, result, ms: Math.round(performance.now() - started) });
  } catch (e) {
    postMessage({ id: data.id, error: String(e?.message ?? e) });
  }
};
