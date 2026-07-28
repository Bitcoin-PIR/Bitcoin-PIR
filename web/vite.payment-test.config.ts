import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite';

const fakeSdk = fileURLToPath(new URL('./e2e/payment-sdk-fake.ts', import.meta.url));

/** Replace only service-acquisition's SDK import in this local test server. */
function paymentSdkTestAlias(): Plugin {
  return {
    name: 'bitcoinpir-payment-sdk-test-alias',
    enforce: 'pre',
    resolveId(source, importer) {
      if (source === './sdk-bridge.js' && importer?.endsWith('/src/service-acquisition.ts')) {
        return fakeSdk;
      }
      return null;
    },
  };
}

export default defineConfig({
  plugins: [paymentSdkTestAlias()],
  server: {
    cors: false,
  },
  define: { global: 'globalThis' },
});
