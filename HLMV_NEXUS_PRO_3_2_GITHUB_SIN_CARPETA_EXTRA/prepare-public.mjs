// Prepara solo los archivos públicos del sistema HLMV 5.3 para Cloudflare Workers.
// La base D1, los archivos Python y los datos privados no se copian aquí.
import { copyFile, cp, mkdir, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const project = dirname(fileURLToPath(import.meta.url));
const app = join(project, 'app');
const publicDir = join(project, 'public');
const staticFiles = [
  'pro.js', 'customize.js', 'pro.css', 'customize.css',
  'minimal.css', 'institucional.css', 'compacto.css',
  'sw.js', 'manifest.webmanifest'
];

await rm(publicDir, { recursive: true, force: true });
await mkdir(publicDir, { recursive: true });
await copyFile(join(project, 'index.html'), join(publicDir, 'index.html'));
for (const file of staticFiles) {
  await copyFile(join(app, file), join(publicDir, file));
}
await cp(join(app, 'icons'), join(publicDir, 'icons'), { recursive: true });
console.log('HLMV 5.3: recursos publicos preparados para Cloudflare Workers.');
