import express from 'express';
import { createServer as createViteServer } from 'vite';
import { spawn, ChildProcess } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';

const PORT = 3000;
const PYTHON_PORT = Number(process.env.BAYORA_BACKEND_PORT || 8000);
const REMOTE_BACKEND = process.env.BAYORA_BACKEND_URL ? new URL(process.env.BAYORA_BACKEND_URL) : null;
const PYTHON_HOST = REMOTE_BACKEND ? REMOTE_BACKEND.hostname : '127.0.0.1';
const BACKEND_PORT = REMOTE_BACKEND ? Number(REMOTE_BACKEND.port || 80) : PYTHON_PORT;
const DEV_HEADER_AUTH = process.env.BAYORA_DEV_HEADER_AUTH === '1';

let pythonProc: ChildProcess | null = null;

function startPythonBackend(): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!REMOTE_BACKEND) pythonProc = spawn('python3', ['-m', 'backend.app.main'], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        BAYORA_BACKEND_HOST: PYTHON_HOST,
        BAYORA_BACKEND_PORT: String(PYTHON_PORT),
        BAYORA_DB_PATH: process.env.BAYORA_DB_PATH || path.join(process.cwd(), 'bayora.db'),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    pythonProc?.stdout?.on('data', (chunk) => {
      process.stdout.write(`[python-backend] ${chunk}`);
    });
    pythonProc?.stderr?.on('data', (chunk) => {
      process.stderr.write(`[python-backend] ${chunk}`);
    });

    let attempts = 0;
    const checkReady = () => {
      attempts++;
      const req = http.get(`http://${PYTHON_HOST}:${BACKEND_PORT}/api/health`, (res) => {
        if (res.statusCode === 200) {
          resolve();
        } else if (attempts < 30) {
          setTimeout(checkReady, 150);
        } else {
          reject(new Error(`Backend unhealthy after ${attempts} attempts (status ${res.statusCode})`));
        }
      });
      req.on('error', (err) => {
        if (attempts < 30) {
          setTimeout(checkReady, 150);
        } else {
          reject(new Error(`Backend unreachable after ${attempts} attempts: ${err.message}`));
        }
      });
      req.end();
    };

    setTimeout(checkReady, 120);
  });
}

const ROLE_CRED: Record<string, string | undefined> = {
  RED_TEAM: process.env.BAYORA_RED_WORKER_TOKEN,
  BLUE_TEAM: process.env.BAYORA_BLUE_WORKER_TOKEN,
  EVALUATOR: process.env.BAYORA_EVALUATOR_TOKEN,
};

// DEMO MODE ONLY (BAYORA_DEV_HEADER_AUTH=1): lets the demo UI's role switcher obtain a real signed token.
function devLogin(role: string, actor: string): Promise<string | null> {
  return new Promise((resolve) => {
    const body = JSON.stringify({ role, actor, credential: ROLE_CRED[role] || '' });
    const r = http.request(
      { hostname: PYTHON_HOST, port: BACKEND_PORT, path: '/api/auth/login', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
      (resp) => {
        let d = '';
        resp.on('data', (c) => (d += c));
        resp.on('end', () => { try { resolve(resp.statusCode === 200 ? JSON.parse(d).token : null); } catch { resolve(null); } });
      }
    );
    r.on('error', () => resolve(null));
    r.end(body);
  });
}

function proxyToPython(req: express.Request, res: express.Response, devToken: string | null = null): void {
  const bodyStr = req.body && Object.keys(req.body).length > 0 ? JSON.stringify(req.body) : '';
  const forwardHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  // Role headers from the browser are NEVER forwarded. Identity = signed bearer token only.
  if (req.headers['authorization']) {
    forwardHeaders['Authorization'] = String(req.headers['authorization']);
  } else if (devToken) {
    forwardHeaders['Authorization'] = `Bearer ${devToken}`;
  }
  if (bodyStr) {
    forwardHeaders['Content-Length'] = String(Buffer.byteLength(bodyStr));
  }

  const proxyReq = http.request(
    {
      hostname: PYTHON_HOST,
      port: BACKEND_PORT,
      path: req.originalUrl,
      method: req.method,
      headers: forwardHeaders,
    },
    (proxyRes) => {
      let rawData = '';
      proxyRes.setEncoding('utf8');
      proxyRes.on('data', (chunk) => {
        rawData += chunk;
      });
      proxyRes.on('end', () => {
        res.status(proxyRes.statusCode || 500);
        res.setHeader('Content-Type', 'application/json');
        res.send(rawData);
      });
    }
  );

  proxyReq.on('error', (err) => {
    res.status(502).json({
      error: 'CONTROL_PLANE_UNAVAILABLE',
      detail: `Failed to reach Python FastAPI/SQLite control plane: ${err.message}`,
    });
  });

  if (bodyStr) {
    proxyReq.write(bodyStr);
  }
  proxyReq.end();
}

async function startServer() {
  await startPythonBackend();

  const app = express();
  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (process.env.NODE_ENV === 'production') {
      res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
    }
    next();
  });
  app.use(express.json({ limit: '1mb' }));

  // Proxy all /api/* calls directly to the Python Control Plane backend
  app.all('/api/*splat', async (req, res) => {
    let devToken: string | null = null;
    const role = String(req.headers['x-bayora-role'] || '').toUpperCase();
    if (DEV_HEADER_AUTH && !req.headers['authorization'] && role) {
      devToken = await devLogin(role, String(req.headers['x-bayora-actor'] || ''));
    }
    proxyToPython(req, res, devToken);
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*splat', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Bayora Full-Stack Server] Listening on http://0.0.0.0:${PORT} (proxying /api/* -> Python :${PYTHON_PORT})`);
  });
}

process.on('SIGTERM', () => {
  if (pythonProc) pythonProc.kill();
  process.exit(0);
});

startServer().catch((err) => {
  console.error(`[Bayora] FATAL startup failure: ${err.message}`);
  if (pythonProc) pythonProc.kill();
  process.exit(1);
});
