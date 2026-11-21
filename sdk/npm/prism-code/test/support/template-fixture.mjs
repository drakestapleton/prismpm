// A canonical template for tests, served with no network: this package's own text application (templates/text-request)
// as the template's app/ folder, beside a README and a workflow, pinned by SHA-256 the way templates/canonical.json
// pins UOR-Foundation/template. `fetch` answers the raw.githubusercontent.com URLs instantiate asks for.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const APP = fileURLToPath(new URL('../../templates/text-request/', import.meta.url));
const walk = (dir, rel = '') => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name), `${rel}${e.name}/`) : [`${rel}${e.name}`]));

/** `{ template, fetch, bytes }`: a pinned template of `extra` files plus app/, and a fetch that serves it (or `alter`s one). */
export function templateFixture({ extra = { 'README.md': '# A Prism app\n', '.github/workflows/build.yml': 'name: build\n' }, alter = null } = {}) {
  const bytes = new Map(Object.entries(extra).map(([p, t]) => [p, new TextEncoder().encode(t)]));
  for (const p of walk(APP)) bytes.set(`app/${p}`, new Uint8Array(readFileSync(join(APP, p))));
  const files = Object.fromEntries([...bytes].sort(([a], [b]) => (a < b ? -1 : 1)).map(([p, b]) => [p, { sha256: createHash('sha256').update(b).digest('hex'), bytes: b.length }]));
  const template = { repository: 'UOR-Foundation/template', commit: 'f'.repeat(40), files };
  const prefix = `https://raw.githubusercontent.com/${template.repository}/${template.commit}/`;
  const served = [];
  const fetch = async (url) => {
    const path = decodeURIComponent(String(url).slice(prefix.length));
    served.push(path);
    const b = path === alter ? new TextEncoder().encode('altered') : bytes.get(path);
    return b ? new Response(b, { status: 200 }) : new Response('missing', { status: 404 });
  };
  return { template, fetch, bytes, served };
}
