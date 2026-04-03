import { defineConfig } from 'vite';
import wasm from 'vite-plugin-wasm';

export default defineConfig({
  plugins: [wasm()],
  server: {
    port: 3001,
    cors: true,
  },
  build: {
    outDir: 'dist-web',
    sourcemap: true,
    rollupOptions: {
      external: ['pir-core-wasm'],
    },
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
