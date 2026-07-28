import { defineConfig } from 'vite';
import wasm from 'vite-plugin-wasm';

export default defineConfig({
  plugins: [wasm()],
  server: {
    cors: false,
    fs: { allow: ['..'] },
  },
  define: { global: 'globalThis' },
  resolve: { alias: { buffer: 'buffer' } },
});
