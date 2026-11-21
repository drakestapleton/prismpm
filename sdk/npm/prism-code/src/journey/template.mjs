/**
 * Every Prism app starts from one canonical template, UOR-Foundation/template, as `docker init` starts every project
 * the same way. The template is a whole Prism project: its LexLean model under `app/` (the app's one source of truth),
 * the workflows that build the app on GitHub Actions and serve it on GitHub Pages, its conformance and its locks.
 *
 * templates/canonical.json pins it at one commit: every file by path, with the SHA-256 of its bytes. `instantiate`
 * fetches each file from that commit through the serverless boundary and writes it only when its bytes have the
 * pinned digest, so every new app is the same bytes on every machine. It never writes over a file that holds other
 * bytes. `node scripts/pin-template.mjs <commit>` moves the pin.
 *
 * The app's model is then aligned to the LexLean this prism-code runs as WebAssembly (`alignToLexlean`), so the model
 * checks and proves here from the first call.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { PrismCodeError } from '../errors.mjs';
import { buildFetch } from './hosts.mjs';

const PIN_FILE = new URL('../../templates/canonical.json', import.meta.url);
const pin = JSON.parse(readFileSync(PIN_FILE, 'utf8'));

/** The canonical template: `{ repository, commit, files }`, every file `{ sha256, bytes }` by its path. */
export const TEMPLATE = Object.freeze({ repository: pin.repository, commit: pin.commit, files: Object.freeze(pin.files) });
/** Where the app lives in a project made from the template: its LexLean project, model under `src/`. */
export const APP_FOLDER = 'app';
/** Lean as this prism-code's LexLean names it, and LexLean's compiler identity for it (lexlean.lock `compiler_semantics`). */
export const LEXLEAN_TOOLCHAIN = 'leanprover/lean4:v4.32.2';
export const LEXLEAN_COMPILER_SEMANTICS = '4b3ed2378d6c43bb32a41d466cf140337e8b1cedc5e1f345aaf3395f488f63a9';

const RAW_URL = 'https://raw.githubusercontent.com';
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const urlOf = (template, path) => `${RAW_URL}/${template.repository}/${template.commit}/${path.split('/').map(encodeURIComponent).join('/')}`;

/** One file of the template at its pinned commit, admitted only when its bytes have the pinned SHA-256. */
async function fetchFile(template, path, get) {
  const url = urlOf(template, path);
  let response;
  try {
    response = await get(url);
  } catch (error) {
    if (error.code === 'build.host-not-allowed') throw error;
    throw new PrismCodeError('template.unavailable', `${url} did not answer (${error.cause?.code ?? error.message}); the template is fetched once per app, so try again with a network connection`);
  }
  if (!response.ok) throw new PrismCodeError('template.unavailable', `${url} answered HTTP ${response.status}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  const got = sha256(bytes);
  if (got !== template.files[path].sha256) throw new PrismCodeError('template.altered', `${path} of ${template.repository} at ${template.commit.slice(0, 8)} has SHA-256 ${got}, not the pinned ${template.files[path].sha256}: nothing was written`);
  return bytes;
}

/**
 * Write the canonical template into `root`: every file it pins, fetched and admitted first, then written, so an
 * altered or missing file writes nothing. A file already there with the same bytes is kept; one with other bytes
 * refuses the whole start (`template.exists`) before anything is written. Resolves `{ written, kept }`.
 */
export async function instantiate(root, { template = TEMPLATE, fetch = globalThis.fetch, log = () => {} } = {}) {
  const paths = Object.keys(template.files).sort();
  const clash = paths.filter((p) => existsSync(join(root, p)) && sha256(readFileSync(join(root, p))) !== template.files[p].sha256);
  if (clash.length) throw new PrismCodeError('template.exists', `${root} already holds other bytes at ${clash.slice(0, 3).join(', ')}${clash.length > 3 ? ` and ${clash.length - 3} more` : ''}: start the app in an empty folder`);
  const get = buildFetch({ fetch });
  const wanted = paths.filter((p) => !existsSync(join(root, p)));
  const bytes = new Map();
  log(`Fetching the canonical template, ${template.repository} at ${template.commit.slice(0, 8)}: ${wanted.length} files.`);
  for (let i = 0; i < wanted.length; i += 16) {
    const batch = wanted.slice(i, i + 16);
    const got = await Promise.all(batch.map((p) => fetchFile(template, p, get)));
    batch.forEach((p, k) => bytes.set(p, got[k]));
  }
  for (const [path, b] of bytes) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), b);
  }
  return { written: wanted, kept: paths.length - wanted.length };
}

/**
 * Align the app's LexLean project to the LexLean this prism-code runs: the Lean toolchain it names and the compiler
 * identity its lock records, then the lock's digests of the files that changed (restamp). A project already aligned
 * is left as it is. Resolves the files changed.
 */
export function alignToLexlean(appDir, { restamp }) {
  const changed = [];
  const edit = (file, fn) => {
    const path = join(appDir, file);
    if (!existsSync(path)) return;
    const before = readFileSync(path, 'utf8');
    const after = fn(before);
    if (after !== before) {
      writeFileSync(path, after);
      changed.push(file);
    }
  };
  edit('lean-toolchain', () => `${LEXLEAN_TOOLCHAIN}\n`);
  edit('lexlean.toml', (t) => t.replace(/^lean_toolchain = "[^"]*"$/m, `lean_toolchain = "${LEXLEAN_TOOLCHAIN}"`));
  edit('lexlean.lock', (t) => t.replace(/^compiler_semantics = "[0-9a-f]{64}"$/m, `compiler_semantics = "${LEXLEAN_COMPILER_SEMANTICS}"`).replace(/^lean_toolchain = "[^"]*"$/m, `lean_toolchain = "${LEXLEAN_TOOLCHAIN}"`));
  if (changed.length) restamp(appDir);
  return changed;
}
