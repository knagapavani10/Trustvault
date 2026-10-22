import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { initializeDatabase, PROJECT_ROOT } from './db/database.js';
import { handleApiRequest } from './routes/api.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(PROJECT_ROOT, 'public');

// Initialize database on boot
console.log('[TrustVault] Initializing database and security subsystem...');
initializeDatabase();
console.log('[TrustVault] SQLite database and tamper-evident audit ledger ready.');

// MIME map for static assets
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  // Global Hardened Security Headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // Handle CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Route API Requests
  if (url.pathname.startsWith('/api/')) {
    return handleApiRequest(req, res, url);
  }

  // Route Static Files
  let filePath = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
  // Prevent path traversal
  const safePath = path.normalize(filePath).replace(/^(\.\.[\/\\])+/, '');
  const absoluteStaticPath = path.join(PUBLIC_DIR, safePath);

  if (fs.existsSync(absoluteStaticPath) && fs.statSync(absoluteStaticPath).isFile()) {
    const ext = path.extname(absoluteStaticPath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': contentType });
    fs.createReadStream(absoluteStaticPath).pipe(res);
    return;
  }

  // Fallback to index.html for Single Page Application navigation
  const indexPath = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(indexPath)) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    fs.createReadStream(indexPath).pipe(res);
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

// Export server for testing and programmatic startup
export { server };

// Start listening if run directly
if (process.argv[1] === __filename) {
  server.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(` [TrustVault] Zero-Trust Secure Document Platform`);
    console.log(` Running on: http://localhost:${PORT}`);
    console.log(` Pre-seeded accounts ready:`);
    console.log(`   Admin:  admin@trustvault.local     (Pass: AdminPass123!)`);
    console.log(`   Owner:  alice.owner@trustvault.local (Pass: AlicePass123!)`);
    console.log(`   Owner:  bob.owner@trustvault.local   (Pass: BobPass123!)`);
    console.log(`   Viewer: charlie.viewer@trustvault.local (Pass: CharliePass123!)`);
    console.log(`   Viewer: dave.viewer@trustvault.local    (Pass: DavePass123!)`);
    console.log(`   Revoked: eve.revoked@trustvault.local   (Pass: EvePass123!)`);
    console.log(`=======================================================`);
  });
}
