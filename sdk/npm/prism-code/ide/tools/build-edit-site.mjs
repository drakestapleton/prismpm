// Add the edit page to a site of static files, beside the audit page build-audit-site.mjs put there.
// Usage: node tools/build-edit-site.mjs <out dir> <project dir, holding lexlean.toml> [commit]
//
//   <out>/edit/                      the page (ide/edit)
//   <out>/edit/prism-code/           prism-code's src, as the page and its workers import it
//   <out>/edit/pin.json              the pin of the LexLean executable, as src/journey/lexlean-wasm.mjs states it
//   <out>/edit/lexlean.wasm.gz       that executable
//   <out>/edit/kernel/               Lean's kernel, its loader and its library, with the manifest that names them
//   <out>/edit/project/              the model the page opens when it is given no other, and project.json listing it
//   <out>/edit/ide/                  the same loop in the VS Code workbench, when dist-model/ has been built
//   <out>/edit/vendor/xterm/         xterm.js and its addons, the files npm ships, each the one terminal/pins.json names
//   <out>/edit/terminal/tables.json  the proved tables the terminal asks, read from model/ide-terminal-* and model/ide-audit
//   <out>/edit/site.json             what was written, from which commit, each file with its BLAKE3 label and its SHA-256
//
// Two things are fetched, once, by prism-code itself: the LexLean executable and the kernel. Each is admitted only
// when its bytes decode to the BLAKE3 label prism-code pins, and the page's workers check them again before running
// them: LexLean by that label, the kernel by the SHA-256 its manifest names. They are published beside the page because a browser cannot fetch them from where
// prism-code does: those addresses do not allow another site to read them.
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LEXLEAN_WASM, ensureLexleanWasm, lexleanWasmFile } from '../../src/journey/lexlean-wasm.mjs';
import { ensureKernel, hasKernel, readKernelFile } from '../../src/journey/kernel-store.mjs';
import { projectListing } from './edit-project.mjs';
import { kappa } from '../../src/blake3.mjs';
import { terminalTables, vendorFiles } from './terminal-site.mjs';

const [outArg, projectArg, commit = 'unknown'] = process.argv.slice(2);
if (!outArg || !projectArg) { console.error('usage: node tools/build-edit-site.mjs <out dir> <project dir> [commit]'); process.exit(64); }
const ide = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = join(ide, '..');
const project = resolve(projectArg);
const site = join(resolve(outArg), 'edit');

rmSync(site, { recursive: true, force: true });
mkdirSync(site, { recursive: true });
cpSync(join(ide, 'edit'), site, { recursive: true, filter: (p) => !/README\.md$/.test(p) });
// Only code: the page imports modules, never the studio's pages or anything else under src.
cpSync(join(pkg, 'src'), join(site, 'prism-code'), { recursive: true, filter: (p) => statSync(p).isDirectory() || /\.(mjs|js)$/.test(p) });

writeFileSync(join(site, 'pin.json'), JSON.stringify({ commit: LEXLEAN_WASM.commit, kappa: LEXLEAN_WASM.kappa, encoding: LEXLEAN_WASM.encoding }) + '\n');
cpSync(lexleanWasmFile() ?? await ensureLexleanWasm(), join(site, 'lexlean.wasm.gz'));

if (!hasKernel()) await ensureKernel();
mkdirSync(join(site, 'kernel'));
const manifest = readFileSync(join(pkg, 'src', 'journey', 'kernel', 'manifest.json'));
writeFileSync(join(site, 'kernel', 'manifest.json'), manifest);
const named = JSON.parse(manifest);
for (const part of [named.glue, named.wasm, named.library]) writeFileSync(join(site, 'kernel', part.file), readKernelFile(part.file));

// The terminal: xterm.js, refused here when an installed file is not the pinned one, and its tables.
mkdirSync(join(site, 'vendor', 'xterm'), { recursive: true });
for (const [name, bytes] of vendorFiles()) writeFileSync(join(site, 'vendor', 'xterm', name), bytes);
writeFileSync(join(site, 'terminal', 'tables.json'), JSON.stringify(await terminalTables()) + '\n');

const listing = projectListing(project);
for (const path of listing.files) cpSync(join(project, path), join(site, 'project', path));
writeFileSync(join(site, 'project.json'), JSON.stringify(listing) + '\n');

// The workbench is built apart (npx vite build -c vite.model.config.js). Without that build the site has the plain page only.
const workbench = join(ide, 'dist-model');
const hasWorkbench = existsSync(join(workbench, 'model.html'));
if (hasWorkbench) {
  cpSync(workbench, join(site, 'ide'), { recursive: true });
  renameSync(join(site, 'ide', 'model.html'), join(site, 'ide', 'index.html'));
}

const files = [];
const walk = (dir) => { for (const name of readdirSync(dir).sort()) { const p = join(dir, name); if (statSync(p).isDirectory()) walk(p); else files.push(p); } };
walk(site);
// Each file is named by its BLAKE3 label; SHA-256 stays beside it for whoever reads the listing by that.
const written = files.map((p) => { const bytes = readFileSync(p); return { path: relative(site, p).split('\\').join('/'), bytes: bytes.length, kappa: kappa(bytes), sha256: createHash('sha256').update(bytes).digest('hex') }; });
const version = JSON.parse(readFileSync(join(pkg, 'package.json'), 'utf8')).version;
writeFileSync(join(site, 'site.json'), JSON.stringify({ schema: 'prism-ide/edit-site/1', prismCode: version, commit, lexlean: LEXLEAN_WASM.kappa, workbench: hasWorkbench, project: listing, files: written }, null, 1) + '\n');
const total = written.reduce((n, f) => n + f.bytes, 0);
console.log(`edit site: ${written.length} files, ${(total / 1048576).toFixed(1)} MiB, prism-code ${version}, workbench ${hasWorkbench ? 'included' : 'not built'}, commit ${commit}`);
