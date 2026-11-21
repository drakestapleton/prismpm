// Serve the edit page with one LexLean project to edit, on one origin.
// Usage: node tools/serve-edit.mjs <project dir, holding lexlean.toml> [port]
// Then open http://localhost:<port>/edit/ , or /edit/ide/ for the workbench once it is built.
//
// The page is given: the project's files and a listing of them; this checkout's prism-code; the pin of the LexLean
// executable; and the executable itself, from where prism-code keeps it on this machine (fetched once if absent).
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { dirname, extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LEXLEAN_WASM, ensureLexleanWasm, lexleanWasmFile } from '../../src/journey/lexlean-wasm.mjs';
import { projectListing } from './edit-project.mjs';
import { ensureKernel, hasKernel, readKernelFile } from '../../src/journey/kernel-store.mjs';
import { terminalTables, vendorFiles } from './terminal-site.mjs';

const [projectArg, port = '4170'] = process.argv.slice(2);
if (!projectArg) { console.error('usage: node tools/serve-edit.mjs <project dir> [port]'); process.exit(64); }
const project = resolve(projectArg);
const editDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'edit');
const src = join(editDir, '..', '..', 'src');
const wasm = lexleanWasmFile() ?? await ensureLexleanWasm();
// Lean's kernel, its loader and its library, as a built rule app's page gets them: the manifest from the package,
// the three files from where prism-code keeps them on this machine (fetched once if absent).
if (!hasKernel()) await ensureKernel();
const KERNEL_FILES = new Set(['lean-kernel.mjs.gz', 'lean-kernel.wasm.gz', 'library.ndjson.gz']);

const { files, entry } = projectListing(project);
// The terminal's two published pieces: xterm.js, held to its pins, and the proved tables it asks.
const vendor = vendorFiles();
const tables = await terminalTables();
const json = (value) => ({ type: 'application/json', body: Buffer.from(JSON.stringify(value)) });
const fixed = {
  '/edit/project.json': json({ files, entry }),
  '/edit/pin.json': json({ commit: LEXLEAN_WASM.commit, kappa: LEXLEAN_WASM.kappa, encoding: LEXLEAN_WASM.encoding }),
  '/edit/terminal/tables.json': json(tables),
};
// Longest prefix first.
// The model editor on the full workbench, when it has been built (npx vite build -c vite.model.config.js): its
// files are served at /edit/ide/, as build-edit-site.mjs publishes them.
const roots = [['/edit/project/', project], ['/edit/prism-code/', resolve(src)], ['/edit/ide/', resolve(editDir, '..', 'dist-model')], ['/edit/', resolve(editDir)]];
const TYPES = { '.css': 'text/css', '.ttf': 'font/ttf', '.wasm': 'application/wasm', '.svg': 'image/svg+xml', '.html': 'text/html; charset=utf-8', '.mjs': 'text/javascript', '.js': 'text/javascript', '.json': 'application/json', '.toml': 'text/plain; charset=utf-8', '.tex': 'text/plain; charset=utf-8', '.lock': 'text/plain; charset=utf-8' };

createServer(async (request, response) => {
  const path = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
  const send = (status, type, body) => response.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' }).end(body);
  if (path === '/') { response.writeHead(302, { location: '/edit/' }).end(); return; }
  if (fixed[path]) { send(200, fixed[path].type, fixed[path].body); return; }
  if (path.startsWith('/edit/vendor/xterm/')) {
    const name = path.slice('/edit/vendor/xterm/'.length);
    if (!vendor.has(name)) { send(404, 'text/plain', 'not found'); return; }
    send(200, TYPES[extname(name)] ?? 'application/octet-stream', vendor.get(name));
    return;
  }
  try {
    if (path === '/edit/lexlean.wasm.gz') { send(200, 'application/gzip', await readFile(wasm)); return; }
    if (path === '/edit/kernel/manifest.json') { send(200, 'application/json', await readFile(join(src, 'journey', 'kernel', 'manifest.json'))); return; }
    if (path.startsWith('/edit/kernel/')) {
      const name = path.slice('/edit/kernel/'.length);
      if (!KERNEL_FILES.has(name)) { send(404, 'text/plain', 'not found'); return; }
      send(200, 'application/gzip', readKernelFile(name));
      return;
    }
    const root = roots.find(([prefix]) => path.startsWith(prefix));
    if (!root) { send(404, 'text/plain', 'not found'); return; }
    let rest = path.slice(root[0].length);
    if (rest === '' || rest.endsWith('/')) rest += root[0] === '/edit/ide/' ? 'model.html' : 'index.html';
    const file = normalize(join(root[1], rest));
    // Nothing outside the three folders is served.
    if (file !== root[1] && !file.startsWith(root[1] + sep)) { send(403, 'text/plain', 'forbidden'); return; }
    const body = await readFile(file);
    send(200, TYPES[extname(file)] ?? 'application/octet-stream', body);
  } catch { send(404, 'text/plain', 'not found'); }
}).listen(Number(port), '127.0.0.1', () => console.log(`edit page: http://localhost:${port}/edit/  (${files.length} project files, entry ${entry})`));
