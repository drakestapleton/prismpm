#!/usr/bin/env node
/**
 * Pin the canonical template, UOR-Foundation/template, at one commit: every file it holds, by path, with the SHA-256
 * of its bytes, written to templates/canonical.json. `prism_init` writes a new app from exactly these files, each
 * fetched from that commit and admitted only when its bytes have the pinned digest.
 *
 *   node scripts/pin-template.mjs <commit>            fetch the commit's tree from GitHub and write the pin
 *   node scripts/pin-template.mjs <commit> --check    exit 1 when templates/canonical.json is not that pin
 *
 * The tree is read with `gh api` (the user's own sign-in), and each file from raw.githubusercontent.com.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { TEMPLATE } from '../src/journey/template.mjs';

const [commit, flag] = process.argv.slice(2);
if (!/^[0-9a-f]{40}$/.test(commit ?? '')) {
  console.error('usage: node scripts/pin-template.mjs <40-hex commit> [--check]');
  process.exit(2);
}
const PIN = fileURLToPath(new URL('../templates/canonical.json', import.meta.url));
const gh = spawnSync('gh', ['api', `repos/${TEMPLATE.repository}/git/trees/${commit}?recursive=1`], { encoding: 'utf8', maxBuffer: 64 << 20 });
if (gh.status !== 0) throw new Error(`gh api failed: ${gh.stderr}`);
const tree = JSON.parse(gh.stdout);
if (tree.truncated) throw new Error('the tree is truncated: pin a smaller template');
const paths = tree.tree.filter((e) => e.type === 'blob').map((e) => e.path).sort();
const files = {};
for (let i = 0; i < paths.length; i += 16) {
  await Promise.all(paths.slice(i, i + 16).map(async (path) => {
    const response = await fetch(`https://raw.githubusercontent.com/${TEMPLATE.repository}/${commit}/${path.split('/').map(encodeURIComponent).join('/')}`);
    if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    files[path] = { sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
  }));
}
const pin = { schema: 'prism/template-pin/1', repository: TEMPLATE.repository, commit, files: Object.fromEntries(paths.map((p) => [p, files[p]])) };
const text = `${JSON.stringify(pin, null, 2)}\n`;
if (flag === '--check') {
  const same = readFileSync(PIN, 'utf8') === text;
  console.log(same ? `template pin ok: ${paths.length} files at ${commit}` : 'templates/canonical.json is not the pin of that commit');
  process.exit(same ? 0 : 1);
}
writeFileSync(PIN, text);
console.log(`pinned ${paths.length} files of ${TEMPLATE.repository} at ${commit}`);
