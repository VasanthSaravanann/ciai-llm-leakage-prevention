import server from '../dist/server/index.js';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function contentTypeFor(ext) {
  switch (ext) {
    case '.js': return 'application/javascript; charset=utf-8';
    case '.css': return 'text/css; charset=utf-8';
    case '.png': return 'image/png';
    case '.svg': return 'image/svg+xml';
    case '.json': return 'application/json; charset=utf-8';
    case '.webp': return 'image/webp';
    default: return 'application/octet-stream';
  }
}

export default async function handler(req, res) {
  try {
    // Serve static assets directly from the built client folder
    const url = new URL(req.url, `https://${req.headers.host}`);
    if (url.pathname.startsWith('/assets/')) {
      const rel = url.pathname.replace(/^\/assets\//, '');
      const filePath = path.join(__dirname, '..', 'dist', 'client', 'assets', rel);
      try {
        const data = await fs.readFile(filePath);
        const ext = path.extname(filePath);
        res.status(200);
        res.setHeader('content-type', contentTypeFor(ext));
        return res.send(data);
      } catch (err) {
        // fallthrough to SSR for missing assets
        console.error('Asset read error', filePath, err && err.code);
      }
    }

    const request = new Request(url.toString(), {
      method: req.method,
      headers: req.headers,
      body: req.method === 'GET' || req.method === 'HEAD' ? undefined : req,
    });

    const response = await server.fetch(request);

    res.status(response.status || 200);
    for (const [k, v] of response.headers) {
      if (k.toLowerCase() === 'transfer-encoding') continue;
      res.setHeader(k, v);
    }

    const buffer = await response.arrayBuffer();
    res.send(Buffer.from(buffer));
  } catch (err) {
    console.error('SSR wrapper error:', err);
    res.status(500).send('Server error');
  }
}
