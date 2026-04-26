import { defineConfig } from 'vite';
import { resolve } from 'path';
import { copyFileSync, existsSync, mkdirSync } from 'fs';

export default defineConfig({
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup.html'),
        background: resolve(__dirname, 'background.js'),
        'content-simple': resolve(__dirname, 'content-simple.js'),
        'ner-bert': resolve(__dirname, 'ner-bert.js'),
        'preprocess-focused': resolve(__dirname, 'preprocess-focused.js'),
        'response-interceptor': resolve(__dirname, 'response_interceptor.js'),
        'offscreen-bert': resolve(__dirname, 'offscreen-bert.js')
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: '[name].js',
        assetFileNames: '[name].[ext]'
      },
      external: id => id.includes('@xenova/transformers') // Keep transformers external
    },
    target: 'esnext',
    minify: false, // Keep readable for debugging
    copyPublicDir: false // Don't copy public dir, we'll handle files manually
  },
  plugins: [
    {
      name: 'copy-manifest',
      writeBundle() {
        // Copy manifest.json
        copyFileSync('manifest.json', 'dist/manifest.json');
        
        // Copy other required files
        const filesToCopy = [
          'offscreen.html',
          'style.css',
          'policy_config.json'
        ];
        
        filesToCopy.forEach(file => {
          if (existsSync(file)) {
            copyFileSync(file, `dist/${file}`);
          }
        });
        
        console.log('✅ Extension files copied to dist/');
      }
    }
  ],
  server: {
    port: 3000
  }
});
