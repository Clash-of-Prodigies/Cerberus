import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import tailwindcss from '@tailwindcss/vite';

export default defineConfig(({mode}) => {
  const backend_dev_url = 'http://Shadow:5000';
  const backend_prod_url = 'https://api.clashofprodigies.org';
  const app_page_dev_url = 'https://clash-of-prodigies.github.io/Kitsune/';
  const app_page_prod_url = 'https://app.clashofprodigies.org';

  const terms_and_policy_base = new URL('live/', 'https://www.freeprivacypolicy.com');
  const termsURL = new URL('6fbb5983-935c-493b-80c0-0e863dbccd9a', terms_and_policy_base);
  const privacyURL = new URL('8dd76e22-df05-4c81-b107-b09657a045ca', terms_and_policy_base);

  const backendUrl = new URL(mode==='development' ? backend_dev_url:backend_prod_url);
  const appPageUrl = new URL(mode==='development' ? app_page_dev_url : app_page_prod_url);
  return {
    define: { 
      'import.meta.env.VITE_API_URL': JSON.stringify(backendUrl.toString()),
      'import.meta.env.VITE_TERMS_URL': JSON.stringify(termsURL.toString()),
      'import.meta.env.VITE_PRIVACY_URL': JSON.stringify(privacyURL.toString()),
      'import.meta.env.VITE_APP_URL': JSON.stringify(appPageUrl.toString()),
    },
    plugins: [react(), tailwindcss()],
  }});
