import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

const apiProxyTarget = process.env.INTRIQO_API_PROXY_TARGET || 'http://localhost:8000'
const wsProxyTarget = apiProxyTarget.replace(/^http/, 'ws')

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Proxy API calls to the FastAPI control plane during development
      '/api': {
        target: apiProxyTarget,
        changeOrigin: true,
      },
      '/ws': {
        target: wsProxyTarget,
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
})
