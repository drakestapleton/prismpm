// The build of the model editor alone (model.html). The spike's own page (index.html) needs files that are fetched,
// not committed, so it is built separately, by vite.config.js.
import { fileURLToPath } from 'node:url';
import { defineConfig, mergeConfig } from 'vite';
import base from './vite.config.js';

export default mergeConfig(base, defineConfig({
  // Relative addresses, so the build works in whatever folder it is published.
  base: './',
  publicDir: false,
  // The terminal panel's ligatures addon needs Node; see src/no-ligatures.js.
  resolve: { alias: [{ find: '@xterm/addon-ligatures', replacement: fileURLToPath(new URL('./src/no-ligatures.js', import.meta.url)) }] },
  build: { outDir: 'dist-model', emptyOutDir: true, rollupOptions: { input: 'model.html' } },
}));
