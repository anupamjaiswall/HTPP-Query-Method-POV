'use strict';

/**
 * QUERY-method (RFC 10008) vulnerable API lab
 * - 5 QUERY endpoints, each demonstrating a distinct attack class
 * - a deliberately naive "WAF" that inspects only POST bodies
 * - a deliberately naive body-blind cache (cache-poisoning demo)
 */
const express = require('express');
const { exec } = require('child_process');
const ejs = require('ejs');
const { searchProducts, matchUser, getAllProducts } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
app.use(express.json({ type: ['application/json', 'application/query+json'], limit: '1mb' }));

// ---------------------------------------------------------------- logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

// ---------------------------------------------------------------- naive WAF
// Mimics ModSecurity-style deployments: REQUEST_BODY is inspected for
// POST/PUT/PATCH. QUERY bodies are never parsed -> differential bypass.
const WAF_PATTERNS = [
  /(\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b)\s+\d/i,
  /('|")\s*(\bor\b|\band\b)\s*('|")/i,
  /;\s*(cat|id|ls|rm|whoami|nc|bash|curl|wget)\b/i,
  /<%(=|-)?/,
  /\$\{/,
];

app.use((req, res, next) => {
  if (req.method === 'POST' && req.body && typeof req.body === 'object') {
    const blob = JSON.stringify(req.body);
    const hit = WAF_PATTERNS.find((re) => re.test(blob));
    if (hit) {
      console.log(`  [WAF] blocked POST body (rule ${hit})`);
      return res.status(403).json({ error: 'blocked by WAF', rule: String(hit) });
    }
  }
  // QUERY / GET / others: body (if any) is NOT inspected -> attacker path
  next();
});

// ---------------------------------------------------------------- router
// QUERY -> handler; OPTIONS -> 204 + Allow; anything else -> 405 + Allow
function queryRoute(path, handler) {
  app.use((req, res, next) => {
    if (req.path !== path) return next();
    if (req.method === 'QUERY') return handler(req, res, next);
    if (req.method === 'OPTIONS') {
      res.set('Allow', 'QUERY, OPTIONS');
      return res.sendStatus(204);
    }
    return res.status(405).set('Allow', 'QUERY, OPTIONS').json({ error: 'method not allowed' });
  });
}

const body = (req) => (req.body && typeof req.body === 'object' ? req.body : {});

// ------------------------------------------------- 1. SQLi (dual-registered:
// POST twin is WAF-guarded, QUERY twin is WAF-blind)
const searchProductsHandler = (req, res) => {
  const { q } = body(req);
  if (typeof q !== 'string' || !q.trim()) {
    return res.status(400).json({ error: 'missing string field "q"' });
  }
  try {
    const rows = searchProducts(q); // VULNERABLE
    res.json({ query: q, count: rows.length, results: rows });
  } catch (e) {
    res.status(500).json({ error: 'query failed', detail: e.message });
  }
};
app.post('/api/search/products', searchProductsHandler);   // guarded twin
queryRoute('/api/search/products', searchProductsHandler); // blind twin

// ------------------------------------------------- 2. NoSQLi login bypass
queryRoute('/api/auth/login', (req, res) => {
  const { username, password } = body(req);
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }
  const user = matchUser({ username, password }); // VULNERABLE
  if (user) return res.json({ ok: true, role: user.role, user: user.username });
  res.status(401).json({ ok: false, error: 'invalid credentials' });
});

// ------------------------------------------------- 3. SSTI -> RCE
queryRoute('/api/render/email', (req, res) => {
  const { template } = body(req);
  if (typeof template !== 'string' || !template.trim()) {
    return res.status(400).json({ error: 'missing string field "template"' });
  }
  const html = ejs.render(template); // VULNERABLE: user-controlled template
  res.type('html').send(html);
});

// ------------------------------------------------- 4. OS command injection
queryRoute('/api/export/report', (req, res) => {
  const { grep } = body(req);
  const term = typeof grep === 'string' ? grep : '';
  const cmd = `grep -i "${term}" /app/data/products.txt | head -20`; // VULNERABLE
  console.log(`  [export] executing: ${cmd}`);
  exec(cmd, { timeout: 5000 }, (err, stdout, stderr) => {
    res.json({ command: cmd, exit: err ? err.code : 0, output: stdout, stderr });
  });
});

// ------------------------------------------------- 5. catalog + body-blind cache
// RFC 10008: QUERY responses are cacheable but the key MUST include the body.
const cache = new Map();
const MAX_CACHE = 50;
const cacheKey = (req) => `${req.method}|${req.path}`; // BUG: body not keyed

queryRoute('/api/search/catalog', (req, res) => {
  const { q = '', page = 1, limit = 10 } = body(req);
  const key = cacheKey(req);
  if (cache.has(key)) return res.json({ cached: true, ...cache.get(key) });

  const all = getAllProducts();
  let rows = all.filter((p) => p.name.toLowerCase().includes(String(q).toLowerCase()));
  const start = (Number(page) - 1) * Number(limit);
  const result = { query: q, total: rows.length, results: rows.slice(start, start + Number(limit)) };

  cache.set(key, result);
  if (cache.size > MAX_CACHE) cache.delete(cache.keys().next().value);
  res.json({ cached: false, ...result });
});

// ---------------------------------------------------------------- errors
app.use((err, req, res, next) => {
  console.error('  [500]', err.message);
  res.status(500).json({ error: 'internal error', detail: err.message });
});

app.listen(PORT, () => console.log(`query-lab listening on :${PORT}`));