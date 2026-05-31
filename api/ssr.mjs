import server from '../Ldot/dist/server/index.js';

export default async function handler(req, res) {
  try {
    const url = new URL(req.url, `https://${req.headers.host}`);
    const request = new Request(url.toString(), {
      method: req.method,
      headers: req.headers,
      body: req.method === 'GET' || req.method === 'HEAD' ? undefined : req,
    });

    const response = await server.fetch(request);

    res.status(response.status || 200);
    for (const [k, v] of response.headers) {
      // Skip hop-by-hop headers
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
