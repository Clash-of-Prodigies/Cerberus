import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import tailwindcss from '@tailwindcss/vite';

export default defineConfig(({mode}) => {
  var backendUrl = '';
  var terms_and_policy_base = new URL('/live', 'https://www.freeprivacypolicy.com/');
  var termsURL = new URL('/6fbb5983-935c-493b-80c0-0e863dbccd9a', terms_and_policy_base);
  var privacyURL = new URL('/8dd76e22-df05-4c81-b107-b09657a045ca', terms_and_policy_base);

  if (mode === 'development') backendUrl = 'http://localhost:5000';
  else backendUrl = new URL('/api/auth');
  return {
    define: { 
      'import.meta.env.VITE_BACKEND_URL': JSON.stringify(backendUrl.toString()),
      'import.meta.env.VITE_TERMS_URL': JSON.stringify(termsURL.toString()),
      'import.meta.env.VITE_PRIVACY_URL': JSON.stringify(privacyURL.toString()),
      'import.meta.env.VITE_APP_URL': JSON.stringify('https://app.clashofprodigies.org'),
    },
    plugins: [react(), tailwindcss()],
  }});
