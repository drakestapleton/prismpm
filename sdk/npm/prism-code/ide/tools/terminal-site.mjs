// What the edit page's terminal is published with, beside its own code (ide/edit/terminal):
//
//   vendor/xterm/<file>     xterm.js and its addons, the files npm ships, each held to its BLAKE3 label in pins.json
//   terminal/tables.json    the proved tables the terminal asks, read from model/ide-terminal-* and model/ide-audit
//
// Usage: node tools/terminal-site.mjs pin      write ide/edit/terminal/pins.json from ide/node_modules
// build-edit-site.mjs and serve-edit.mjs import the rest.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { kappa } from '../../src/blake3.mjs';
import { ensureLexleanWasm, lexleanWasmFile, wasmSnapshot } from '../../src/journey/lexlean-wasm.mjs';
import { judgeTable, ruleTable } from '../../src/journey/rule-table.mjs';
import { materialize } from '../edit/terminal/kappa-space.mjs';

const ide = join(dirname(fileURLToPath(import.meta.url)), '..');
const PINS = join(ide, 'edit', 'terminal', 'pins.json');

/** The published name of each file, and where npm puts it. The versions are package.json's, exact. */
const VENDOR = {
  'xterm.mjs': ['@xterm/xterm', 'lib/xterm.mjs'],
  'xterm.css': ['@xterm/xterm', 'css/xterm.css'],
  'addon-fit.mjs': ['@xterm/addon-fit', 'lib/addon-fit.mjs'],
  'addon-webgl.mjs': ['@xterm/addon-webgl', 'lib/addon-webgl.mjs'],
  'addon-web-links.mjs': ['@xterm/addon-web-links', 'lib/addon-web-links.mjs'],
  'addon-search.mjs': ['@xterm/addon-search', 'lib/addon-search.mjs'],
  'addon-unicode11.mjs': ['@xterm/addon-unicode11', 'lib/addon-unicode11.mjs'],
};
/** The tables the terminal asks, by the name it asks them under. */
const MODELS = { commands: 'ide-terminal-commands', reach: 'ide-terminal-reach', effects: 'ide-terminal-effects', flow: 'ide-terminal-flow', audit: 'ide-audit' };

const installed = (pkg, file) => join(ide, 'node_modules', ...pkg.split('/'), file);
const versionOf = (pkg) => JSON.parse(readFileSync(installed(pkg, 'package.json'), 'utf8')).version;

/** What pins.json should say for what is installed. */
function pinsNow() {
  const packages = {};
  const files = {};
  for (const [name, [pkg, file]] of Object.entries(VENDOR)) {
    const bytes = readFileSync(installed(pkg, file));
    packages[pkg] = versionOf(pkg);
    files[name] = { package: pkg, path: file, bytes: bytes.length, kappa: kappa(bytes) };
  }
  return { schema: 'prism-ide/terminal-pins/1', license: 'MIT', packages, files };
}

/** Each published file's bytes, by name. Throws when an installed file is not the one pins.json names. */
export function vendorFiles() {
  const pins = JSON.parse(readFileSync(PINS, 'utf8'));
  const out = new Map();
  for (const [name, want] of Object.entries(pins.files)) {
    const from = installed(want.package, want.path);
    if (!existsSync(from)) throw new Error(`${want.package} is not installed: run npm ci in ide/`);
    const bytes = readFileSync(from);
    const label = kappa(bytes);
    if (label !== want.kappa) throw new Error(`${want.package}/${want.path} hashes to ${label}, not the pinned ${want.kappa}`);
    out.set(name, bytes);
  }
  return out;
}

/** tables.json: each model's table as rule-table.mjs reads it from LexLean's own snapshot, with the model's identity. */
export async function terminalTables() {
  if (!lexleanWasmFile()) await ensureLexleanWasm();
  const tables = {};
  for (const [name, model] of Object.entries(MODELS)) {
    const taken = await wasmSnapshot(join(ide, '..', 'model', model));
    if (!taken.ok) throw new Error(`model/${model} does not check`);
    tables[name] = ruleTable(taken.snapshot);
  }
  // A table over a finite set of requests is also named by the label of its lookup table: every answer, in order.
  const luts = {};
  for (const [name, table] of Object.entries(tables)) { const lut = materialize(table, judgeTable, kappa); if (lut) luts[name] = lut.kappa; }
  return { schema: 'prism-ide/terminal-tables/1', tables, luts };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1] && process.argv[2] === 'pin') {
  const pins = pinsNow();
  writeFileSync(PINS, JSON.stringify(pins, null, 1) + '\n');
  for (const [name, f] of Object.entries(pins.files)) console.log(`${f.kappa}  ${name}  ${f.bytes} bytes  ${f.package}@${pins.packages[f.package]}`);
}
