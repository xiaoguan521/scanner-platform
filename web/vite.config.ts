import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    // Only the shared antd vendor chunk comes close to this; page chunks stay small.
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        // Stable vendor chunks stay cached across application releases.
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          antd: ['antd', '@ant-design/icons', 'dayjs'],
        },
      },
    },
  },
  server: {
    host: '127.0.0.1',
    port: 3000,
    open: false,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: false },
      '/healthz': { target: 'http://127.0.0.1:8080', changeOrigin: false },
      '/readyz': { target: 'http://127.0.0.1:8080', changeOrigin: false },
    },
  },
});
