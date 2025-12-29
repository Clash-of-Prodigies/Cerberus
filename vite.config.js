import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import tailwindcss from '@tailwindcss/vite';

export default defineConfig(({mode}) => {
  var backendUrl = '';
  if (mode === 'development') backendUrl = 'http://localhost:5000';
  else backendUrl = 'https://sobbingly-hydrochloric-joel.ngrok-free.dev/auth';
  return {
    define: { 'import.meta.env.VITE_BACKEND_URL': JSON.stringify(backendUrl),},
    plugins: [react(), tailwindcss()],
  }});
