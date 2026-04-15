import { defineConfig } from 'vite';
import wasm from 'vite-plugin-wasm';

export default defineConfig({
  plugins: [wasm()],
  server: {
    port: 3001,
    cors: true,
    fs: {
      // pir-sdk-wasm/pkg and pir-core-wasm/pkg live outside web/.
      // `--target web` wasm bundles fetch their .wasm at runtime via
      // /@fs/<absolute-path>/..., which Vite 8 blocks by default.
      // Allow the repo root so dev can resolve sibling workspace packages.
      allow: ['..'],
    },
  },
  build: {
    outDir: 'dist-web',
    sourcemap: true,
  },
  define: {
    global: 'globalThis',
  },
  resolve: {
    alias: {
      buffer: 'buffer',
    },
  },
});
