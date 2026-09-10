import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/proxy': 'http://localhost:8000',
      '/tools': 'http://localhost:8000',
      '/approvals': 'http://localhost:8000',
      '/audit': 'http://localhost:8000',
      '/api': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
    }
  }
});
