#!/usr/bin/env node
/**
 * MockAPI Inspector - Complete server using ONLY Node.js built-ins
 * No npm packages required.
 * 
 * Usage: node server.js [port]
 * Default port: 3000
 * 
 * How it works:
 *  - GET  /           → serves the dashboard HTML
 *  - ANY  /mock/:id/* → captures the request and broadcasts to WebSocket clients
 *  - WS   /ws         → WebSocket connection for real-time updates
 *  - GET  /api/endpoints        → list endpoints
 *  - POST /api/endpoints        → create endpoint
 *  - DELETE /api/endpoints/:id  → delete endpoint
 *  - GET  /api/requests/:endpointId → list requests
 *  - GET  /api/rules/:endpointId    → list rules
 *  - POST /api/rules/:endpointId    → add rule
 *  - DELETE /api/rules/:id          → delete rule
 */

const http = require('http');
const crypto = require('crypto');
const url = require('url');
const PORT = process.argv[2] || 3000;

// ── IN-MEMORY STORE ──────────────────────────────────────────────────────────
const store = {
  endpoints:  new Map(),  // id -> endpoint object
  requests:   new Map(),  // endpointId -> request[]
  rules:      new Map(),  // endpointId -> rule[]
  wsClients:  new Set(),  // WebSocket connections
  crudTables: new Map(),  // "epId:resourcePath" -> { idField, rows: Map(id->row) }
};

function genId(len = 6) {
  return crypto.randomBytes(len).toString('hex').toUpperCase().slice(0, len);
}

// ── WEBSOCKET IMPLEMENTATION (RFC 6455) ─────────────────────────────────────
function wsHandshake(req, socket) {
  const key = req.headers['sec-websocket-key'];
  const magic = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
  const accept = crypto.createHash('sha1').update(key + magic).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );
}

function wsFrame(data) {
  const json = JSON.stringify(data);
  const payload = Buffer.from(json, 'utf8');
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x81; // FIN + text frame
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}

function wsParse(buf) {
  if (buf.length < 2) return null;
  const fin  = (buf[0] & 0x80) !== 0;
  const op   = buf[0] & 0x0f;
  const mask = (buf[1] & 0x80) !== 0;
  let offset = 2;
  let len    = buf[1] & 0x7f;
  if (len === 126) { len = buf.readUInt16BE(2); offset = 4; }
  else if (len === 127) { len = Number(buf.readBigUInt64BE(2)); offset = 10; }
  if (buf.length < offset + (mask ? 4 : 0) + len) return null;
  const key = mask ? buf.slice(offset, offset + 4) : null;
  if (mask) offset += 4;
  const data = buf.slice(offset, offset + len);
  if (mask) for (let i = 0; i < data.length; i++) data[i] ^= key[i % 4];
  return { op, data: data.toString('utf8'), fin };
}

function broadcast(endpointId, event, payload) {
  const frame = wsFrame({ event, endpointId, payload });
  for (const client of store.wsClients) {
    try { client.socket.write(frame); } catch (_) {}
  }
}

// ── REQUEST BODY READER ───────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(''));
  });
}

// ── RULE MATCHING ENGINE ─────────────────────────────────────────────────────
function matchRule(rules, method, pathname) {
  if (!rules || rules.length === 0) return null;
  for (const rule of rules) {
    const methodMatch = rule.method === '*' || rule.method === method;
    if (!methodMatch) continue;
    // exact or wildcard
    const rp = rule.path || '';
    if (!rp || rp === '/*' || rp === '*') return rule;
    if (rp === pathname) return rule;
    if (rp.endsWith('*') && pathname.startsWith(rp.slice(0, -1))) return rule;
  }
  return null;
}

// ── CRUD ENGINE ──────────────────────────────────────────────────────────────
// Resolves subPath against registered CRUD tables for an endpoint.
// Supports deep paths like /api-teste-1/users and /api-teste-1/users/:id
function handleCrud(epId, method, subPath, rawBody, query) {
  const clean = subPath.replace(/\/$/, '') || '/';

  // Try to match against every registered table for this endpoint,
  // longest path first (most specific wins)
  let matchedKey = null;
  let matchedTbl = null;
  let itemId     = null;

  // Collect all tables for this endpoint, sorted by path length desc
  const candidates = [];
  for (const [key, tbl] of store.crudTables) {
    if (key.startsWith(epId + ':')) candidates.push({ key, tbl });
  }
  candidates.sort((a, b) => b.tbl.path.length - a.tbl.path.length);

  for (const { key, tbl } of candidates) {
    const tp = tbl.path; // e.g. /api-teste-1/users
    if (clean === tp) {
      // Exact match → collection operation (list / create / clear)
      matchedKey = key; matchedTbl = tbl; itemId = null; break;
    }
    if (clean.startsWith(tp + '/')) {
      // Sub-path → item operation, rest is the id
      const rest = clean.slice(tp.length + 1); // e.g. "42" or "42/sub"
      matchedKey = key; matchedTbl = tbl; itemId = rest; break;
    }
  }

  if (!matchedTbl) return null;

  const tbl     = matchedTbl;
  const idField = tbl.idField || 'id';

  // Parse body
  let data = {};
  if (rawBody) { try { data = JSON.parse(rawBody); } catch (_) {} }

  // ── GET /resource  → list all rows (with optional ?filter=field:value)
  if (method === 'GET' && !itemId) {
    let rows = [...tbl.rows.values()];
    // Simple filtering: ?name=John or ?status=active
    for (const [k, v] of Object.entries(query || {})) {
      rows = rows.filter(r => String(r[k] ?? '').toLowerCase() === String(v).toLowerCase());
    }
    // Pagination: ?_page=1&_limit=10
    const page  = parseInt(query._page) || null;
    const limit = parseInt(query._limit) || null;
    const total = rows.length;
    if (page && limit) rows = rows.slice((page - 1) * limit, page * limit);
    return { status: 200, body: { data: rows, total, page: page || 1, limit: limit || total } };
  }

  // ── GET /resource/:id  → find one
  if (method === 'GET' && itemId) {
    const row = tbl.rows.get(itemId);
    if (!row) return { status: 404, body: { error: 'Not found', [idField]: itemId } };
    return { status: 200, body: row };
  }

  // ── POST /resource  → create new row
  if (method === 'POST' && !itemId) {
    const newId = data[idField] != null ? String(data[idField]) : genId(8);
    const row   = { [idField]: newId, ...data, _createdAt: new Date().toISOString() };
    tbl.rows.set(newId, row);
    return { status: 201, body: row };
  }

  // ── PUT /resource/:id  → full replace
  if (method === 'PUT' && itemId) {
    if (!tbl.rows.has(itemId)) return { status: 404, body: { error: 'Not found', [idField]: itemId } };
    const row = { [idField]: itemId, ...data, _updatedAt: new Date().toISOString() };
    tbl.rows.set(itemId, row);
    return { status: 200, body: row };
  }

  // ── PATCH /resource/:id  → partial update
  if (method === 'PATCH' && itemId) {
    const existing = tbl.rows.get(itemId);
    if (!existing) return { status: 404, body: { error: 'Not found', [idField]: itemId } };
    const row = { ...existing, ...data, [idField]: itemId, _updatedAt: new Date().toISOString() };
    tbl.rows.set(itemId, row);
    return { status: 200, body: row };
  }

  // ── DELETE /resource/:id  → remove
  if (method === 'DELETE' && itemId) {
    if (!tbl.rows.has(itemId)) return { status: 404, body: { error: 'Not found', [idField]: itemId } };
    tbl.rows.delete(itemId);
    return { status: 200, body: { ok: true, deleted: itemId } };
  }

  // ── DELETE /resource  → clear all rows
  if (method === 'DELETE' && !itemId) {
    const count = tbl.rows.size;
    tbl.rows.clear();
    return { status: 200, body: { ok: true, deleted: count } };
  }

  return null;
}

// ── HTTP REQUEST HANDLER ─────────────────────────────────────────────────────
async function handleRequest(req, res) {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const method   = req.method;

  // CORS headers for all responses
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── STATIC DASHBOARD ──────────────────────────────────────────
  if (method === 'GET' && (pathname === '/' || pathname === '/dashboard')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(getDashboardHTML(PORT));
    return;
  }

  // ── REST API ────────────────────────────────────────────────────

  // List endpoints
  if (method === 'GET' && pathname === '/api/endpoints') {
    json(res, [...store.endpoints.values()]);
    return;
  }

  // Create endpoint
  if (method === 'POST' && pathname === '/api/endpoints') {
    const body = await readBody(req);
    let data = {};
    try { data = JSON.parse(body); } catch (_) {}
    const id = genId();
    const ep = {
      id,
      name: data.name || `Endpoint ${id}`,
      path: data.path || `/${id}`,
      url:  `localhost:${PORT}/mock/${id}`,
      corsEnabled: data.corsEnabled !== false,
      rateLimit: data.rateLimit || 100,
      requestCount: 0,
      createdAt: new Date().toISOString(),
    };
    store.endpoints.set(id, ep);
    store.requests.set(id, []);
    store.rules.set(id, []);
    broadcast(null, 'endpoint_created', ep);
    json(res, ep, 201);
    return;
  }

  // Delete endpoint
  const delEpMatch = pathname.match(/^\/api\/endpoints\/([A-Z0-9]+)$/);
  if (method === 'DELETE' && delEpMatch) {
    const id = delEpMatch[1];
    store.endpoints.delete(id);
    store.requests.delete(id);
    store.rules.delete(id);
    // Remove all CRUD tables for this endpoint
    for (const key of store.crudTables.keys()) {
      if (key.startsWith(id + ':')) store.crudTables.delete(key);
    }
    broadcast(null, 'endpoint_deleted', { id });
    json(res, { ok: true });
    return;
  }

  // List requests for endpoint
  const reqListMatch = pathname.match(/^\/api\/requests\/([A-Z0-9]+)$/);
  if (method === 'GET' && reqListMatch) {
    const id = reqListMatch[1];
    json(res, store.requests.get(id) || []);
    return;
  }

  // List rules
  const rulesListMatch = pathname.match(/^\/api\/rules\/([A-Z0-9]+)$/);
  if (method === 'GET' && rulesListMatch) {
    json(res, store.rules.get(rulesListMatch[1]) || []);
    return;
  }

  // Add rule
  if (method === 'POST' && rulesListMatch) {
    const body = await readBody(req);
    let data = {};
    try { data = JSON.parse(body); } catch (_) {}
    const epId = rulesListMatch[1];
    const rule = { id: genId(), ...data };
    const rules = store.rules.get(epId) || [];
    rules.unshift(rule);
    store.rules.set(epId, rules);
    broadcast(epId, 'rule_added', rule);
    json(res, rule, 201);
    return;
  }

  // Delete rule
  const delRuleMatch = pathname.match(/^\/api\/rules\/([A-Z0-9]+)\/([A-Z0-9]+)$/);
  if (method === 'DELETE' && delRuleMatch) {
    const [, epId, ruleId] = delRuleMatch;
    const rules = (store.rules.get(epId) || []).filter(r => r.id !== ruleId);
    store.rules.set(epId, rules);
    broadcast(epId, 'rule_deleted', { id: ruleId });
    json(res, { ok: true });
    return;
  }

  // Clear requests
  const clearMatch = pathname.match(/^\/api\/requests\/([A-Z0-9]+)\/clear$/);
  if (method === 'DELETE' && clearMatch) {
    store.requests.set(clearMatch[1], []);
    broadcast(clearMatch[1], 'requests_cleared', {});
    json(res, { ok: true });
    return;
  }

  // ── CRUD TABLE MANAGEMENT API ──────────────────────────────────
  // GET  /api/crud/:epId              → list all tables
  // POST /api/crud/:epId              → create/update a table { path, idField }
  // DELETE /api/crud/:epId/:tableKey  → drop a table
  // GET  /api/crud/:epId/:tableKey/rows → list rows in a table

  const crudMgmtMatch = pathname.match(/^\/api\/crud\/([A-Z0-9]+)$/);
  if (crudMgmtMatch) {
    const epId = crudMgmtMatch[1];
    if (method === 'GET') {
      const tables = [];
      for (const [key, tbl] of store.crudTables) {
        if (key.startsWith(epId + ':')) {
          tables.push({ key, path: tbl.path, idField: tbl.idField, count: tbl.rows.size });
        }
      }
      json(res, tables); return;
    }
    if (method === 'POST') {
      const body = await readBody(req);
      let data = {}; try { data = JSON.parse(body); } catch (_) {}
      const resourcePath = (data.path || '/items').replace(/\/$/, '') || '/items';
      const idField = data.idField || 'id';
      const key = epId + ':' + resourcePath;
      if (!store.crudTables.has(key)) {
        store.crudTables.set(key, { path: resourcePath, idField, rows: new Map() });
      } else {
        store.crudTables.get(key).idField = idField;
      }
      broadcast(epId, 'crud_table_updated', { key, path: resourcePath, idField });
      json(res, { ok: true, key, path: resourcePath, idField }, 201); return;
    }
  }

  const crudDropMatch = pathname.match(/^\/api\/crud\/([A-Z0-9]+)\/(.+)\/rows$/);
  if (method === 'GET' && crudDropMatch) {
    const [, epId, tableKey] = crudDropMatch;
    const key = decodeURIComponent(tableKey);
    const tbl = store.crudTables.get(key);
    if (!tbl) { json(res, []); return; }
    json(res, [...tbl.rows.values()]); return;
  }

  const crudDeleteMatch = pathname.match(/^\/api\/crud\/([A-Z0-9]+)\/(.+)$/);
  if (method === 'DELETE' && crudDeleteMatch) {
    const key = decodeURIComponent(crudDeleteMatch[2]);
    store.crudTables.delete(key);
    json(res, { ok: true }); return;
  }

  // ── MOCK ENDPOINT CAPTURE ──────────────────────────────────────
  // ANY method to /mock/:id/* or /mock/:id
  const mockMatch = pathname.match(/^\/mock\/([A-Z0-9]+)(\/.*)?$/);
  if (mockMatch) {
    const epId    = mockMatch[1];
    const subPath = mockMatch[2] || '/';
    const ep      = store.endpoints.get(epId);

    if (!ep) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Endpoint not found', id: epId }));
      return;
    }

    const body = await readBody(req);
    const rules = store.rules.get(epId) || [];
    const matchedRule = matchRule(rules, method, subPath);

    // ── CRUD ENGINE ─────────────────────────────────────────────────
    // Auto-register: if POST/PUT/PATCH to a path that looks like a collection
    // and no rule matches, auto-create a CRUD table for it
    if (!matchedRule && (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'GET' || method === 'DELETE')) {
      const cleanPath = subPath.replace(/\/$/, '');
      // Check if any existing table matches — if not, auto-create on POST to collection path
      const hasTable = [...store.crudTables.keys()].some(k => {
        if (!k.startsWith(epId + ':')) return false;
        const tp = store.crudTables.get(k).path;
        return cleanPath === tp || cleanPath.startsWith(tp + '/');
      });
      if (!hasTable && method === 'POST') {
        // Auto-register this path as a CRUD table
        const tableKey = epId + ':' + cleanPath;
        store.crudTables.set(tableKey, { path: cleanPath, idField: 'id', rows: new Map() });
        broadcast(epId, 'crud_table_updated', { key: tableKey, path: cleanPath, idField: 'id', count: 0 });
      }
    }

    let crudResponse = null;
    if (!matchedRule) {
      crudResponse = handleCrud(epId, method, subPath, body, parsed.query);
    }

    const statusCode = crudResponse ? crudResponse.status : (matchedRule ? matchedRule.status : 200);
    const delay      = matchedRule ? (matchedRule.delay || 0) : 0;
    let responseBody;
    if (crudResponse) {
      responseBody = JSON.stringify(crudResponse.body);
    } else if (matchedRule && matchedRule.body) {
      responseBody = matchedRule.body;
    } else {
      responseBody = JSON.stringify({ ok: true, endpoint: epId, path: subPath, timestamp: new Date().toISOString() });
    }

    // Build request record
    const record = {
      id:        genId(8),
      endpointId: epId,
      timestamp: new Date().toISOString(),
      method,
      path:      subPath,
      fullUrl:   req.url,
      status:    statusCode,
      latency:   delay,
      ip:        req.socket.remoteAddress || '127.0.0.1',
      headers:   req.headers,
      queryParams: parsed.query,
      requestBody: body || null,
      responseBody,
      matchedRule: matchedRule ? matchedRule.id : null,
    };

    // Update endpoint counter
    ep.requestCount = (ep.requestCount || 0) + 1;
    store.endpoints.set(epId, ep);

    // Store request (keep last 200)
    const reqs = store.requests.get(epId) || [];
    reqs.unshift(record);
    if (reqs.length > 200) reqs.pop();
    store.requests.set(epId, reqs);

    // Broadcast to WebSocket clients
    broadcast(epId, 'new_request', record);
    broadcast(epId, 'endpoint_updated', ep);

    // Broadcast updated CRUD table count if a CRUD operation happened
    if (crudResponse) {
      const cleanPath = subPath.replace(/\/$/, '');
      for (const [key, tbl] of store.crudTables) {
        if (!key.startsWith(epId + ':')) continue;
        if (cleanPath === tbl.path || cleanPath.startsWith(tbl.path + '/')) {
          broadcast(epId, 'crud_table_updated', { key, path: tbl.path, idField: tbl.idField, count: tbl.rows.size });
          break;
        }
      }
    }

    // CORS for mock responses
    if (ep.corsEnabled) {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', '*');
      res.setHeader('Access-Control-Allow-Headers', '*');
    }

    // Apply delay
    const sendResponse = () => {
      res.writeHead(statusCode, {
        'Content-Type': 'application/json',
        'X-MockAPI-Endpoint': epId,
        'X-MockAPI-Request-Id': record.id,
        'X-Response-Time': `${delay}ms`,
      });
      res.end(responseBody);
    };

    if (delay > 0) setTimeout(sendResponse, delay);
    else sendResponse();
    return;
  }

  // 404 fallback
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found', path: pathname }));
}

// ── JSON HELPER ───────────────────────────────────────────────────────────────
function json(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

// ── SERVER SETUP ──────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
    await handleRequest(req, res);
  } catch (err) {
    console.error('Handler error:', err);
    try { res.writeHead(500); res.end(JSON.stringify({ error: err.message })); } catch (_) {}
  }
});

server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/ws') { socket.destroy(); return; }
  wsHandshake(req, socket);
  const clientId = genId(8);
  const client   = { id: clientId, socket };
  store.wsClients.add(client);

  let buf = Buffer.alloc(0);
  socket.on('data', chunk => {
    buf = Buffer.concat([buf, chunk]);
    const frame = wsParse(buf);
    if (!frame) return;
    buf = Buffer.alloc(0);
    if (frame.op === 0x8) { // close
      store.wsClients.delete(client);
      socket.destroy();
    }
  });

  socket.on('close', () => store.wsClients.delete(client));
  socket.on('error', () => store.wsClients.delete(client));

  // Send current state
  const crudTablesList = [];
  for (const [key, tbl] of store.crudTables) {
    crudTablesList.push({ key, path: tbl.path, idField: tbl.idField, count: tbl.rows.size });
  }
  socket.write(wsFrame({
    event: 'connected',
    payload: { clientId, endpoints: [...store.endpoints.values()], crudTables: crudTablesList }
  }));
});

server.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════════════╗`);
  console.log(`  ║          MockAPI Inspector - Running!            ║`);
  console.log(`  ╠══════════════════════════════════════════════════╣`);
  console.log(`  ║  Dashboard:  http://localhost:${PORT}               ║`);
  console.log(`  ║  Mock URL:   http://localhost:${PORT}/mock/{ID}/... ║`);
  console.log(`  ║  WebSocket:  ws://localhost:${PORT}/ws              ║`);
  console.log(`  ╚══════════════════════════════════════════════════╝\n`);
});

// ── DASHBOARD HTML ────────────────────────────────────────────────────────────
function getDashboardHTML(port) {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>MockAPI Inspector</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080808;--bg2:#0A0A0A;--bg3:#111;--bg4:#161616;
  --border:#1a1a1a;--border2:#2a2a2a;
  --green:#00FF87;--green-dim:#00FF8722;--green-border:#00FF8744;
  --text:#e0e0e0;--text2:#888;--text3:#555;--text4:#333;
  --blue:#7DD3FC;--yellow:#FFD700;--red:#FF4444;--orange:#FF8C42;
}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:'Space Grotesk',sans-serif;overflow:hidden}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:#111}
::-webkit-scrollbar-thumb{background:#2a2a2a;border-radius:2px}
button{cursor:pointer;font-family:'Space Grotesk',sans-serif}
input,select,textarea{font-family:'Space Mono',monospace;font-size:13px}
.mono{font-family:'Space Mono',monospace}

/* LAYOUT */
#app{display:flex;height:100vh}
#sidebar{width:260px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0}
#main{flex:1;display:flex;flex-direction:column;overflow:hidden}

/* SIDEBAR */
.logo{padding:18px 20px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.logo-icon{width:34px;height:34px;background:var(--green);border-radius:8px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 16px #00FF8766;flex-shrink:0}
.logo-text{font-size:15px;font-weight:700;color:#fff;letter-spacing:-0.3px}
.logo-sub{font-size:9px;color:var(--text3);font-family:'Space Mono',monospace;letter-spacing:1px}
.new-ep-btn{margin:12px;background:var(--green-dim);border:1px dashed var(--green-border);border-radius:8px;padding:10px;color:var(--green);font-size:13px;font-weight:600;display:flex;align-items:center;justify-content:center;gap:8px;transition:all .2s;width:calc(100% - 24px)}
.new-ep-btn:hover{background:#00FF8733;border-style:solid}
.ep-section-label{font-size:9px;color:var(--text4);font-family:'Space Mono',monospace;padding:8px 16px 4px;letter-spacing:1px}
.ep-list{flex:1;overflow:auto;padding:0 8px}
.ep-item{padding:10px 12px;border-radius:8px;cursor:pointer;border:1px solid transparent;margin-bottom:4px;transition:all .15s;animation:slideIn .2s ease}
.ep-item:hover{background:var(--bg3)}
.ep-item.active{background:var(--bg4);border-color:var(--border2)}
.ep-name{font-size:13px;font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ep-meta{display:flex;justify-content:space-between;align-items:center;margin-top:6px}
.ep-id{font-size:10px;color:var(--text3);font-family:'Space Mono',monospace}
.ep-count{font-size:11px;color:var(--text3);font-family:'Space Mono',monospace}
.ep-del{background:none;border:none;color:var(--text4);padding:2px 4px;opacity:0;transition:all .2s}
.ep-item:hover .ep-del{opacity:1}
.ep-del:hover{color:var(--red)!important}
.sidebar-footer{padding:12px 16px;border-top:1px solid var(--border);display:flex;align-items:center;gap:8px}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);flex-shrink:0;animation:pulse 2s infinite}

/* HEADER BAR */
#header{padding:13px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:16px;background:var(--bg2);flex-shrink:0}
.ep-title{font-size:16px;font-weight:600;color:#fff}
.badge{padding:2px 8px;border-radius:4px;font-size:11px;font-family:'Space Mono',monospace;font-weight:700;letter-spacing:.5px}
.badge-gray{background:var(--bg4);border:1px solid var(--border2);color:var(--text3)}
.badge-green{background:var(--green-dim);border:1px solid var(--green-border);color:var(--green);font-size:10px}
.url-row{display:flex;align-items:center;gap:8px;margin-top:3px}
.ep-url{font-size:12px;color:var(--text3);font-family:'Space Mono',monospace}
.copy-btn{background:none;border:none;color:var(--text4);padding:2px;transition:color .2s}
.copy-btn:hover{color:var(--green)}
.stat-block{text-align:center;flex-shrink:0}
.stat-val{font-size:16px;font-weight:700;font-family:'Space Mono',monospace}
.stat-lbl{font-size:9px;color:var(--text4);letter-spacing:1px;margin-top:1px}
.ctrl-btn{background:var(--bg4);border:1px solid var(--border2);border-radius:8px;padding:8px 14px;font-size:12px;font-weight:600;display:flex;align-items:center;gap:6px;transition:all .2s;font-family:'Space Mono',monospace}
.ctrl-btn.live{background:var(--green-dim);border-color:var(--green-border);color:var(--green)}
.ctrl-btn:hover{border-color:#444;color:#fff}
.ctrl-btn.live:hover{background:#00FF8733}

/* TABS */
#tabs{display:flex;border-bottom:1px solid var(--border);background:var(--bg2);padding:0 24px;flex-shrink:0}
.tab-btn{background:none;border:none;border-bottom:2px solid transparent;padding:10px 16px;color:var(--text3);font-size:13px;font-weight:600;display:flex;align-items:center;gap:6px;transition:all .2s;margin-bottom:-1px}
.tab-btn.active{border-bottom-color:var(--green);color:var(--green)}
.tab-btn:hover:not(.active){color:var(--text)}

/* CONTENT */
#content{flex:1;display:flex;overflow:hidden}

/* FEED */
#feed{width:420px;flex-shrink:0;border-right:1px solid var(--border);overflow:auto}
.req-item{padding:12px 16px;border-bottom:1px solid #111;cursor:pointer;transition:background .15s;border-left:3px solid transparent}
.req-item:hover{background:#0F0F0F}
.req-item.selected{background:var(--bg4);border-left-color:var(--green)}
.req-item.new-req{animation:newReq 2s ease, slideInLeft .2s ease}
.req-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.req-path{font-size:12px;color:var(--text2);font-family:'Space Mono',monospace;margin-bottom:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.req-bottom{display:flex;justify-content:space-between}
.req-ip{font-size:10px;color:var(--text4)}
.req-time{font-size:10px;color:var(--text4)}
.req-latency{font-size:10px;color:var(--text4);font-family:'Space Mono',monospace}

/* INSPECTOR */
#inspector{flex:1;display:flex;flex-direction:column;overflow:hidden}
.insp-header{display:grid;grid-template-columns:1fr 1fr;border-bottom:1px solid var(--border);background:var(--bg2);flex-shrink:0}
.insp-side{padding:12px 20px;border-right:1px solid var(--border)}
.insp-side:last-child{border-right:none}
.insp-label{font-size:9px;color:var(--text4);font-family:'Space Mono',monospace;letter-spacing:1px;margin-bottom:4px}
.insp-tabs{display:flex;border-bottom:1px solid var(--border);background:var(--bg2);padding:0 20px;flex-shrink:0}
.insp-tab{background:none;border:none;border-bottom:2px solid transparent;padding:8px 12px;margin-bottom:-1px;color:var(--text3);font-size:12px;font-weight:600;transition:all .2s}
.insp-tab.active{border-bottom-color:var(--blue);color:var(--blue)}
.insp-body{flex:1;display:grid;grid-template-columns:1fr 1fr;overflow:hidden}
.insp-pane{overflow:auto;padding:16px 20px;border-right:1px solid var(--border)}
.insp-pane:last-child{border-right:none}
.insp-pane-label{font-size:9px;color:var(--text4);font-family:'Space Mono',monospace;letter-spacing:1px;margin-bottom:12px}

/* EMPTY STATES */
.empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;color:var(--text4);padding:40px;text-align:center}
.empty-icon{width:64px;height:64px;background:#00FF8710;border:1px solid #00FF8720;border-radius:16px;display:flex;align-items:center;justify-content:center;margin-bottom:8px}

/* STATUS & METHOD BADGES */
.method{font-family:'Space Mono',monospace;font-size:11px;font-weight:700;letter-spacing:1px;min-width:56px;display:inline-block}
.status{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;font-family:'Space Mono',monospace;letter-spacing:.5px}

/* RULES PANEL */
#rules-panel{flex:1;overflow:auto;padding:24px}
.rules-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px}
.rule-item{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 18px;margin-bottom:10px;display:flex;align-items:center;gap:14px;animation:slideIn .2s ease}
.rule-path{flex:1;color:var(--text2);font-family:'Space Mono',monospace;font-size:13px}
.rule-delay{font-size:11px;color:var(--yellow);font-family:'Space Mono',monospace}
.rule-del{background:none;border:none;color:var(--text4);padding:4px;transition:color .2s}
.rule-del:hover{color:var(--red)}

/* CODE VIEWER */
.json-viewer{font-family:'Space Mono',monospace;font-size:12px;line-height:1.7;white-space:pre-wrap;word-break:break-all}
.headers-viewer .hrow{display:flex;gap:8px;padding:4px 0;border-bottom:1px solid #1a1a1a}
.headers-viewer .hkey{color:var(--blue);min-width:180px;word-break:break-all}
.headers-viewer .hval{color:#d4d4d4;word-break:break-all}

/* MODAL */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.85);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;z-index:1000;animation:fadeIn .15s ease}
.modal{background:var(--bg);border:1px solid var(--border2);border-radius:12px;padding:32px;width:500px;max-height:90vh;overflow:auto;box-shadow:0 25px 80px rgba(0,0,0,.8)}
.modal-title{font-size:18px;font-weight:700;color:#fff;margin-bottom:24px}
.modal-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.form-group{margin-bottom:18px}
.form-label{display:block;color:var(--text2);font-size:11px;font-family:'Space Mono',monospace;letter-spacing:.5px;margin-bottom:6px}
.form-input{width:100%;background:var(--bg3);border:1px solid var(--border2);border-radius:8px;padding:10px 14px;color:#fff;font-size:13px;outline:none;transition:border-color .2s}
.form-input:focus{border-color:var(--green)}
.form-select{width:100%;background:var(--bg3);border:1px solid var(--border2);border-radius:8px;padding:10px 14px;color:#fff;font-size:13px;outline:none;-webkit-appearance:none}
.form-textarea{width:100%;background:var(--bg3);border:1px solid var(--border2);border-radius:8px;padding:12px;color:#86EFAC;font-size:12px;outline:none;resize:vertical;font-family:'Space Mono',monospace}
.toggle-btn{background:var(--bg3);border:1px solid var(--border2);border-radius:8px;padding:10px 20px;color:var(--text3);font-size:13px;font-weight:700;font-family:'Space Mono',monospace;transition:all .2s}
.toggle-btn.on{background:var(--green-dim);border-color:var(--green-border);color:var(--green)}
.btn-row{display:flex;gap:12px;margin-top:8px}
.btn-cancel{flex:1;background:none;border:1px solid var(--border2);border-radius:8px;padding:12px;color:var(--text2);font-size:14px}
.btn-cancel:hover{border-color:#444;color:#fff}
.btn-primary{flex:2;background:var(--green);border:none;border-radius:8px;padding:12px;color:#000;font-size:14px;font-weight:700;font-family:'Space Mono',monospace;box-shadow:0 0 20px #00FF8744;transition:all .2s}
.btn-primary:hover{background:#00CC6A}
.btn-icon{display:flex;align-items:center;justify-content:center;gap:8px}

/* TOAST */
#toasts{position:fixed;bottom:24px;right:24px;display:flex;flex-direction:column;gap:8px;z-index:9999}
.toast{padding:12px 16px;border-radius:8px;font-size:13px;font-weight:600;animation:toastIn .2s ease;display:flex;align-items:center;gap:8px;box-shadow:0 8px 24px rgba(0,0,0,.5);pointer-events:none}
.toast.success{background:var(--green-dim);border:1px solid var(--green-border);color:var(--green)}
.toast.error{background:#FF444422;border:1px solid #FF444455;color:#FF6B6B}
.toast.info{background:var(--bg4);border:1px solid var(--border2);color:var(--text2)}

/* URL BUILDER */
#url-builder{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 18px;margin:12px}
.url-builder-label{font-size:9px;color:var(--text3);font-family:'Space Mono',monospace;letter-spacing:1px;margin-bottom:8px}
.url-builder-row{display:flex;align-items:center;gap:0;background:var(--bg3);border:1px solid var(--border2);border-radius:8px;overflow:hidden}
.url-base{font-size:11px;color:var(--text3);font-family:'Space Mono',monospace;padding:8px 10px;white-space:nowrap;border-right:1px solid var(--border2);background:var(--bg4)}
.url-input{flex:1;background:none;border:none;padding:8px 10px;color:var(--green);font-size:11px;outline:none;font-family:'Space Mono',monospace}
.url-copy{background:none;border:none;border-left:1px solid var(--border2);padding:8px 12px;color:var(--text3);font-size:11px;transition:all .2s}
.url-copy:hover{color:var(--green);background:var(--green-dim)}
.url-test-btn{background:var(--green-dim);border:1px solid var(--green-border);border-radius:6px;padding:6px 12px;color:var(--green);font-size:11px;font-weight:700;font-family:'Space Mono',monospace;margin-top:8px;transition:all .2s;width:100%}
.url-test-btn:hover{background:#00FF8733}

/* ANIMATIONS */
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.6;transform:scale(1.3)}}
@keyframes slideIn{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:translateX(0)}}
@keyframes slideInLeft{from{opacity:0;transform:translateX(-12px)}to{opacity:1;transform:translateX(0)}}
@keyframes newReq{0%{background:#00FF8718}100%{background:transparent}}
@keyframes fadeIn{from{opacity:0;transform:scale(.96)}to{opacity:1;transform:scale(1)}}
@keyframes toastIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div id="app">
  <!-- SIDEBAR -->
  <div id="sidebar">
    <div class="logo">
      <div class="logo-icon">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
      </div>
      <div>
        <div class="logo-text">MockAPI</div>
        <div class="logo-sub">HTTP INSPECTOR</div>
      </div>
    </div>

    <button class="new-ep-btn" onclick="showCreateModal()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
      Novo Endpoint
    </button>

    <div class="ep-section-label" id="ep-label">ENDPOINTS (0)</div>
    <div class="ep-list" id="ep-list">
      <div class="empty-state" style="padding:24px 16px">
        <div style="font-size:13px;color:#333">Nenhum endpoint ainda</div>
      </div>
    </div>

    <div class="sidebar-footer">
      <div class="status-dot" id="ws-dot" style="background:#FF4444;box-shadow:0 0 6px #FF4444"></div>
      <span class="mono" style="font-size:10px;color:var(--text3)" id="ws-status">Conectando...</span>
    </div>
  </div>

  <!-- MAIN -->
  <div id="main">
    <!-- Empty state -->
    <div id="main-empty" class="empty-state" style="flex:1">
      <div class="empty-icon">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#00FF87" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
      </div>
      <div style="font-size:22px;font-weight:700;color:#fff">Selecione um Endpoint</div>
      <div style="font-size:14px;color:#555;max-width:320px">Escolha um endpoint ou crie um novo para começar a capturar requisições HTTP em tempo real.</div>
      <button class="btn-primary" style="padding:14px 32px;font-size:15px;flex:none;width:auto" onclick="showCreateModal()">+ Criar Primeiro Endpoint</button>
    </div>

    <!-- Endpoint view (hidden initially) -->
    <div id="main-view" style="display:none;flex:1;flex-direction:column;overflow:hidden;height:100%">
      <div id="header">
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <span class="ep-title" id="hdr-name">–</span>
            <span class="badge badge-gray mono" id="hdr-id">–</span>
            <span class="badge badge-green mono" id="hdr-cors" style="display:none">CORS</span>
          </div>
          <div class="url-row">
            <span class="ep-url" id="hdr-url">–</span>
            <button class="copy-btn" onclick="copyHeaderUrl()" title="Copiar URL">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
          </div>
        </div>
        <div style="display:flex;gap:20px;flex-shrink:0">
          <div class="stat-block"><div class="stat-val" id="stat-total" style="color:#fff">0</div><div class="stat-lbl">TOTAL</div></div>
          <div class="stat-block"><div class="stat-val" id="stat-errors" style="color:#555">0</div><div class="stat-lbl">ERROS</div></div>
          <div class="stat-block"><div class="stat-val" id="stat-latency" style="color:#FFD700">0ms</div><div class="stat-lbl">LATÊNCIA</div></div>
        </div>
        <div style="display:flex;gap:8px;flex-shrink:0">
          <button class="ctrl-btn live" id="live-btn" onclick="toggleLive()">
            <span class="status-dot" id="live-dot"></span>
            <span id="live-label">LIVE</span>
          </button>
          <button class="ctrl-btn" onclick="clearRequests()" title="Limpar requisições">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
            Limpar
          </button>
          <button class="ctrl-btn" onclick="showRuleModal()">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Mock Rule
          </button>
        </div>
      </div>

      <div id="tabs">
        <button class="tab-btn active" onclick="switchTab('requests')" id="tab-requests">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          Requisições
        </button>
        <button class="tab-btn" onclick="switchTab('rules')" id="tab-rules">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <span id="rules-tab-label">Regras (0)</span>
        </button>
        <button class="tab-btn" onclick="switchTab('crud')" id="tab-crud">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
          <span id="crud-tab-label">CRUD (0)</span>
        </button>
      </div>

      <div id="content">
        <!-- Requests tab -->
        <div id="tab-content-requests" style="display:flex;flex:1;overflow:hidden">
          <div id="feed">
            <div class="empty-state" id="feed-empty">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              <div style="font-size:14px">Aguardando requisições...</div>
              <div class="mono" id="feed-url-hint" style="font-size:11px;color:#333;text-align:center;line-height:1.6"></div>
            </div>
          </div>

          <div id="inspector" style="display:none">
            <div class="insp-header">
              <div class="insp-side">
                <div class="insp-label">REQUEST</div>
                <div style="display:flex;align-items:center;gap:8px">
                  <span class="method" id="insp-method"></span>
                  <span class="mono" style="font-size:12px;color:var(--text2)" id="insp-path"></span>
                </div>
              </div>
              <div class="insp-side">
                <div class="insp-label">RESPONSE</div>
                <div style="display:flex;align-items:center;gap:8px">
                  <span id="insp-status-badge"></span>
                  <span class="mono" style="font-size:12px;color:var(--text3)" id="insp-latency"></span>
                  <span class="mono" style="font-size:10px;color:#444" id="insp-rule-match"></span>
                </div>
              </div>
            </div>
            <div class="insp-tabs">
              <button class="insp-tab active" onclick="switchInspTab('headers')" id="itab-headers">Headers</button>
              <button class="insp-tab" onclick="switchInspTab('body')" id="itab-body">Body</button>
              <button class="insp-tab" onclick="switchInspTab('query')" id="itab-query">Query Params</button>
            </div>
            <div class="insp-body">
              <div class="insp-pane">
                <div class="insp-pane-label" id="insp-left-label">REQUEST HEADERS</div>
                <div id="insp-left"></div>
              </div>
              <div class="insp-pane">
                <div class="insp-pane-label" id="insp-right-label">RESPONSE HEADERS</div>
                <div id="insp-right"></div>
              </div>
            </div>
          </div>

          <div id="inspector-empty" style="flex:1;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:12px;color:#333">
            <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            <div style="font-size:14px">Selecione uma requisição</div>
          </div>
        </div>

        <!-- Rules tab -->
        <div id="tab-content-rules" style="display:none;flex:1;overflow:auto">
          <div id="rules-panel">
            <div class="rules-header">
              <div>
                <h3 style="color:#fff;font-size:16px;margin-bottom:4px">Mock Rules</h3>
                <p style="font-size:13px;color:var(--text3)">Respostas automáticas baseadas em método e caminho.</p>
              </div>
              <button class="btn-primary btn-icon" style="padding:10px 18px;font-size:13px;flex:none;width:auto" onclick="showRuleModal()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                Nova Regra
              </button>
            </div>
            <div id="rules-list"></div>
          </div>
        </div>

        <!-- CRUD tab -->
        <div id="tab-content-crud" style="display:none;flex:1;overflow:auto">
          <div style="padding:24px;max-width:900px">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px">
              <div>
                <h3 style="color:#fff;font-size:16px;margin-bottom:4px">Tabelas CRUD</h3>
                <p style="font-size:13px;color:var(--text3)">Defina um caminho e o sistema faz GET/POST/PUT/PATCH/DELETE automaticamente com persistência em memória.</p>
              </div>
              <button class="btn-primary btn-icon" style="padding:10px 18px;font-size:13px;flex:none;width:auto" onclick="showCrudModal()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                Nova Tabela
              </button>
            </div>

            <!-- How it works box -->
            <div style="background:#0D1A10;border:1px solid #00FF8722;border-radius:10px;padding:16px 20px;margin-bottom:20px;font-size:13px;color:var(--text2)">
              <div style="color:var(--green);font-weight:700;font-family:'Space Mono',monospace;font-size:11px;margin-bottom:8px">COMO FUNCIONA</div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-family:'Space Mono',monospace;font-size:11px">
                <div><span style="color:#00C8FF">GET</span> <span style="color:#888">/mock/{ID}/users</span> → lista todos</div>
                <div><span style="color:#00C8FF">GET</span> <span style="color:#888">/mock/{ID}/users/42</span> → busca por ID</div>
                <div><span style="color:#00FF87">POST</span> <span style="color:#888">/mock/{ID}/users</span> → cria novo registro</div>
                <div><span style="color:#FFD700">PUT</span> <span style="color:#888">/mock/{ID}/users/42</span> → substitui por ID</div>
                <div><span style="color:#FF8C42">PATCH</span> <span style="color:#888">/mock/{ID}/users/42</span> → atualiza campos</div>
                <div><span style="color:#FF4444">DELETE</span> <span style="color:#888">/mock/{ID}/users/42</span> → remove por ID</div>
              </div>
            </div>

            <div id="crud-tables-list"></div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- URL TESTER (floating) -->
<div id="url-tester" style="display:none;position:fixed;bottom:24px;left:272px;background:var(--bg2);border:1px solid var(--border2);border-radius:10px;padding:14px 18px;z-index:500;width:400px;box-shadow:0 8px 32px rgba(0,0,0,.6)">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
    <span style="font-size:11px;color:var(--text3);font-family:'Space Mono',monospace;letter-spacing:1px">TESTADOR DE URL</span>
    <button onclick="document.getElementById('url-tester').style.display='none'" style="background:none;border:none;color:var(--text4)">✕</button>
  </div>
  <div style="font-size:10px;color:var(--text3);font-family:'Space Mono',monospace;margin-bottom:6px">CAMINHO ADICIONAL</div>
  <div class="url-builder-row" style="margin-bottom:8px">
    <span class="url-base" id="tester-base"></span>
    <input class="url-input" id="tester-path" placeholder="/users/123" oninput="updateTesterUrl()"/>
  </div>
  <div style="font-size:10px;color:var(--text3);font-family:'Space Mono',monospace;margin-bottom:4px">URL COMPLETA</div>
  <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px">
    <code style="font-size:11px;color:var(--green);font-family:'Space Mono',monospace;word-break:break-all;flex:1" id="tester-full-url"></code>
    <button class="url-copy" onclick="copyTesterUrl()" style="border:1px solid var(--border2);border-radius:6px;flex-shrink:0">Copiar</button>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px">
    <button onclick="sendTestRequest('GET')" style="background:#00C8FF22;border:1px solid #00C8FF44;border-radius:6px;padding:7px;color:#00C8FF;font-size:11px;font-weight:700;font-family:'Space Mono',monospace">GET</button>
    <button onclick="sendTestRequest('POST')" style="background:#00FF8722;border:1px solid #00FF8744;border-radius:6px;padding:7px;color:#00FF87;font-size:11px;font-weight:700;font-family:'Space Mono',monospace">POST</button>
    <button onclick="sendTestRequest('DELETE')" style="background:#FF444422;border:1px solid #FF444444;border-radius:6px;padding:7px;color:#FF6B6B;font-size:11px;font-weight:700;font-family:'Space Mono',monospace">DELETE</button>
  </div>
</div>

<!-- TOASTS -->
<div id="toasts"></div>

<!-- CREATE ENDPOINT MODAL -->
<div id="create-modal" style="display:none" class="modal-overlay">
  <div class="modal">
    <div class="modal-row">
      <h2 class="modal-title" style="margin:0">Novo Endpoint</h2>
      <button onclick="hideCreateModal()" style="background:none;border:none;color:var(--text3)">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div class="form-group">
      <label class="form-label">NOME DO ENDPOINT</label>
      <input class="form-input" id="ep-name-input" placeholder="Ex: Webhook de Pagamentos"/>
    </div>
    <div class="form-group">
      <label class="form-label">CAMINHO BASE (opcional)</label>
      <input class="form-input" id="ep-path-input" placeholder="/api/meu-endpoint"/>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px">
      <div class="form-group" style="margin:0">
        <label class="form-label">RATE LIMIT (req/min)</label>
        <input class="form-input" type="number" id="ep-ratelimit-input" value="100"/>
      </div>
      <div class="form-group" style="margin:0">
        <label class="form-label">CORS</label>
        <button class="toggle-btn on" id="cors-toggle" onclick="toggleCors()">ON</button>
      </div>
    </div>
    <div class="btn-row">
      <button class="btn-cancel" onclick="hideCreateModal()">Cancelar</button>
      <button class="btn-primary" onclick="createEndpoint()">Criar Endpoint</button>
    </div>
  </div>
</div>

<!-- RULE MODAL -->
<div id="rule-modal" style="display:none" class="modal-overlay">
  <div class="modal">
    <div class="modal-row">
      <h2 class="modal-title" style="margin:0">Nova Mock Rule</h2>
      <button onclick="hideRuleModal()" style="background:none;border:none;color:var(--text3)">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px">
      <div class="form-group" style="margin:0">
        <label class="form-label">METHOD</label>
        <select class="form-select" id="rule-method">
          <option>*</option><option>GET</option><option>POST</option>
          <option>PUT</option><option>DELETE</option><option>PATCH</option>
        </select>
      </div>
      <div class="form-group" style="margin:0">
        <label class="form-label">STATUS CODE</label>
        <select class="form-select" id="rule-status">
          <option>200</option><option>201</option><option>204</option>
          <option>400</option><option>401</option><option>403</option>
          <option>404</option><option>429</option><option>500</option><option>503</option>
        </select>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">PATH PATTERN</label>
      <input class="form-input" id="rule-path" placeholder="/api/users/* ou /api/users/123"/>
    </div>
    <div class="form-group">
      <label class="form-label">LATÊNCIA SIMULADA: <span id="delay-val">0</span>ms</label>
      <input type="range" id="rule-delay" min="0" max="5000" step="100" value="0" style="width:100%;accent-color:var(--green)" oninput="document.getElementById('delay-val').textContent=this.value"/>
    </div>
    <div class="form-group">
      <label class="form-label">RESPONSE BODY (JSON)</label>
      <textarea class="form-textarea" id="rule-body" rows="6">{\n  "message": "Mock response"\n}</textarea>
    </div>
    <div class="btn-row">
      <button class="btn-cancel" onclick="hideRuleModal()">Cancelar</button>
      <button class="btn-primary" onclick="createRule()">Salvar Regra</button>
    </div>
  </div>
</div>

<!-- CRUD TABLE MODAL -->
<div id="crud-modal" style="display:none" class="modal-overlay">
  <div class="modal" style="width:540px">
    <div class="modal-row">
      <h2 class="modal-title" style="margin:0">Nova Tabela CRUD</h2>
      <button onclick="hideCrudModal()" style="background:none;border:none;color:var(--text3)">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div class="form-group">
      <label class="form-label">CAMINHO DA COLEÇÃO</label>
      <input class="form-input" id="crud-path" placeholder="/users  ou  /api/products"/>
      <div style="font-size:11px;color:var(--text3);margin-top:5px;font-family:'Space Mono',monospace">
        Será acessível em: <span id="crud-path-preview" style="color:var(--green)">...</span>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">CAMPO IDENTIFICADOR</label>
      <input class="form-input" id="crud-idfield" value="id" placeholder="id"/>
      <div style="font-size:11px;color:var(--text3);margin-top:5px">Campo usado como chave única. Gerado automaticamente se não enviado no POST.</div>
    </div>
    <div style="background:#0A1A0A;border:1px solid #1a2a1a;border-radius:8px;padding:14px;margin-bottom:18px">
      <div style="font-size:10px;color:var(--text3);font-family:'Space Mono',monospace;margin-bottom:8px">ROTAS GERADAS AUTOMATICAMENTE</div>
      <div id="crud-routes-preview" style="font-size:11px;font-family:'Space Mono',monospace;color:#666;line-height:2"></div>
    </div>
    <div class="btn-row">
      <button class="btn-cancel" onclick="hideCrudModal()">Cancelar</button>
      <button class="btn-primary" onclick="createCrudTable()">Criar Tabela</button>
    </div>
  </div>
</div>

<!-- CRUD DATA MODAL (view/edit rows) -->
<div id="crud-data-modal" style="display:none" class="modal-overlay">
  <div class="modal" style="width:700px;max-height:85vh">
    <div class="modal-row" style="margin-bottom:16px">
      <div>
        <h2 style="margin:0;color:#fff;font-size:16px" id="crud-data-title">Dados</h2>
        <div style="font-size:11px;color:var(--text3);font-family:'Space Mono',monospace;margin-top:2px" id="crud-data-subtitle"></div>
      </div>
      <div style="display:flex;gap:8px">
        <button onclick="showAddRowModal()" style="background:var(--green-dim);border:1px solid var(--green-border);border-radius:6px;padding:7px 14px;color:var(--green);font-size:12px;font-weight:700;font-family:'Space Mono',monospace">+ Linha</button>
        <button onclick="hideCrudDataModal()" style="background:none;border:none;color:var(--text3)">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>
    </div>
    <div id="crud-data-table" style="overflow:auto;max-height:60vh"></div>
  </div>
</div>

<!-- ADD ROW MODAL -->
<div id="add-row-modal" style="display:none" class="modal-overlay">
  <div class="modal" style="width:480px">
    <div class="modal-row">
      <h2 class="modal-title" style="margin:0">Inserir Registro</h2>
      <button onclick="document.getElementById('add-row-modal').style.display='none'" style="background:none;border:none;color:var(--text3)">✕</button>
    </div>
    <div class="form-group">
      <label class="form-label">JSON DO REGISTRO</label>
      <textarea class="form-textarea" id="add-row-body" rows="8" placeholder='{"name":"João","email":"joao@email.com","age":30}'></textarea>
    </div>
    <div class="btn-row">
      <button class="btn-cancel" onclick="document.getElementById('add-row-modal').style.display='none'">Cancelar</button>
      <button class="btn-primary" onclick="insertRow()">Inserir</button>
    </div>
  </div>
</div>

<script>
// ── STATE ────────────────────────────────────────────────────────────────────
const state = {
  endpoints: {},
  requests: {},      // endpointId -> []
  rules: {},         // endpointId -> []
  crudTables: {},    // key -> { path, idField, count }
  activeCrudKey: null,
  selectedEp: null,
  selectedReq: null,
  isLive: true,
  currentTab: 'requests',
  currentInspTab: 'headers',
  corsOn: true,
  ws: null,
  wsReady: false,
};

// Status/method colors
const STATUS_COLORS = {
  200:{bg:'#00FF87',t:'#000'},201:{bg:'#00FF87',t:'#000'},204:{bg:'#7EFF6B',t:'#000'},
  301:{bg:'#FFD700',t:'#000'},302:{bg:'#FFD700',t:'#000'},
  400:{bg:'#FF6B6B',t:'#fff'},401:{bg:'#FF6B6B',t:'#fff'},403:{bg:'#FF4444',t:'#fff'},
  404:{bg:'#FF8C42',t:'#000'},429:{bg:'#FF4444',t:'#fff'},500:{bg:'#CC0000',t:'#fff'},503:{bg:'#CC0000',t:'#fff'},
};
const METHOD_COLORS = {GET:'#00C8FF',POST:'#00FF87',PUT:'#FFD700',PATCH:'#FF8C42',DELETE:'#FF4444',OPTIONS:'#A855F7',HEAD:'#888'};

// ── WEBSOCKET ────────────────────────────────────────────────────────────────
function connectWS() {
  const wsUrl = 'ws://' + location.host + '/ws';
  setWsStatus('connecting');
  let ws;
  try {
    ws = new WebSocket(wsUrl);
  } catch(e) {
    setWsStatus(false);
    setTimeout(connectWS, 3000);
    return;
  }
  state.ws = ws;

  const timeout = setTimeout(() => {
    if (ws.readyState !== 1) { ws.close(); }
  }, 5000);

  ws.onopen = () => {
    clearTimeout(timeout);
    state.wsReady = true;
    setWsStatus(true);
  };

  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      handleWsEvent(msg);
    } catch(_) {}
  };

  ws.onclose = () => {
    clearTimeout(timeout);
    state.wsReady = false;
    setWsStatus(false);
    setTimeout(connectWS, 3000);
  };

  ws.onerror = () => { clearTimeout(timeout); ws.close(); };
}

function setWsStatus(status) {
  const dot = document.getElementById('ws-dot');
  const lbl = document.getElementById('ws-status');
  if (status === true) {
    dot.style.background = '#00FF87'; dot.style.boxShadow = '0 0 6px #00FF87';
    lbl.textContent = 'CONECTADO';
  } else if (status === 'connecting') {
    dot.style.background = '#FFD700'; dot.style.boxShadow = '0 0 6px #FFD700';
    lbl.textContent = 'CONECTANDO...';
  } else {
    dot.style.background = '#FF4444'; dot.style.boxShadow = '0 0 6px #FF4444';
    lbl.textContent = 'RECONECTANDO...';
  }
}

function handleWsEvent(msg) {
  const { event, endpointId, payload } = msg;
  switch (event) {
    case 'connected':
      // Load all existing endpoints
      if (payload.endpoints) {
        payload.endpoints.forEach(ep => {
          state.endpoints[ep.id] = ep;
          if (!state.requests[ep.id]) state.requests[ep.id] = [];
          if (!state.rules[ep.id]) state.rules[ep.id] = [];
        });
        renderEndpointList();
      }
      if (payload.crudTables) {
        payload.crudTables.forEach(t => { state.crudTables[t.key] = t; });
        if (state.selectedEp) renderCrudTables();
      }
      break;
    case 'endpoint_created':
      state.endpoints[payload.id] = payload;
      state.requests[payload.id] = [];
      state.rules[payload.id] = [];
      renderEndpointList();
      break;
    case 'endpoint_deleted':
      delete state.endpoints[payload.id];
      delete state.requests[payload.id];
      delete state.rules[payload.id];
      if (state.selectedEp === payload.id) { state.selectedEp = null; showEmptyMain(); }
      renderEndpointList();
      break;
    case 'endpoint_updated':
      state.endpoints[payload.id] = payload;
      if (state.selectedEp === payload.id) updateHeaderStats();
      renderEndpointList();
      break;
    case 'new_request':
      if (!state.isLive) break;
      if (!state.requests[endpointId]) state.requests[endpointId] = [];
      state.requests[endpointId].unshift(payload);
      if (state.requests[endpointId].length > 200) state.requests[endpointId].pop();
      if (state.selectedEp === endpointId) {
        prependRequestRow(payload, true);
        updateHeaderStats();
      }
      break;
    case 'requests_cleared':
      state.requests[endpointId] = [];
      if (state.selectedEp === endpointId) renderFeed();
      break;
    case 'rule_added':
      if (!state.rules[endpointId]) state.rules[endpointId] = [];
      state.rules[endpointId].unshift(payload);
      if (state.selectedEp === endpointId) renderRules();
      break;
    case 'rule_deleted':
      if (state.rules[endpointId]) {
        state.rules[endpointId] = state.rules[endpointId].filter(r => r.id !== payload.id);
        if (state.selectedEp === endpointId) renderRules();
      }
      break;
    case 'crud_table_updated':
      state.crudTables[payload.key] = { ...payload };
      if (state.selectedEp) renderCrudTables();
      break;
  }
}

// ── API CALLS ────────────────────────────────────────────────────────────────
async function api(method, path, body) {
  const opts = { method, headers: {'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  return r.json();
}

// ── ENDPOINT MANAGEMENT ───────────────────────────────────────────────────────
function showCreateModal() {
  document.getElementById('ep-name-input').value = '';
  document.getElementById('ep-path-input').value = '';
  document.getElementById('ep-ratelimit-input').value = '100';
  document.getElementById('create-modal').style.display = 'flex';
  setTimeout(() => document.getElementById('ep-name-input').focus(), 50);
}
function hideCreateModal() { document.getElementById('create-modal').style.display = 'none'; }

function toggleCors() {
  state.corsOn = !state.corsOn;
  const btn = document.getElementById('cors-toggle');
  btn.textContent = state.corsOn ? 'ON' : 'OFF';
  btn.className = 'toggle-btn' + (state.corsOn ? ' on' : '');
}

async function createEndpoint() {
  const name = document.getElementById('ep-name-input').value.trim();
  if (!name) { toast('Digite um nome para o endpoint.', 'error'); return; }
  try {
    const ep = await api('POST', '/api/endpoints', {
      name,
      path: document.getElementById('ep-path-input').value.trim(),
      corsEnabled: state.corsOn,
      rateLimit: parseInt(document.getElementById('ep-ratelimit-input').value) || 100,
    });
    // Update state immediately (WS may also fire, that's fine)
    state.endpoints[ep.id] = ep;
    state.requests[ep.id] = [];
    state.rules[ep.id] = [];
    renderEndpointList();
    hideCreateModal();
    selectEndpoint(ep.id);
    toast('Endpoint criado! URL pronta para uso.', 'success');
  } catch(e) {
    toast('Erro ao criar endpoint: ' + e.message, 'error');
  }
}

async function deleteEndpoint(id, e) {
  e.stopPropagation();
  await api('DELETE', '/api/endpoints/' + id);
  toast('Endpoint removido.', 'error');
}

function renderEndpointList() {
  const list = document.getElementById('ep-list');
  const eps = Object.values(state.endpoints);
  document.getElementById('ep-label').textContent = \`ENDPOINTS (\${eps.length})\`;
  if (eps.length === 0) {
    list.innerHTML = '<div class="empty-state" style="padding:24px 16px"><div style="font-size:13px;color:#333">Nenhum endpoint ainda</div></div>';
    return;
  }
  list.innerHTML = eps.map(ep => \`
    <div class="ep-item \${state.selectedEp === ep.id ? 'active' : ''}" onclick="selectEndpoint('\${ep.id}')">
      <div class="ep-name">\${esc(ep.name)}</div>
      <div class="ep-meta">
        <span class="ep-id">\${ep.id}</span>
        <div style="display:flex;align-items:center;gap:8px">
          <span class="ep-count">\${ep.requestCount || 0} req</span>
          <button class="ep-del" onclick="deleteEndpoint('\${ep.id}',event)">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
          </button>
        </div>
      </div>
    </div>
  \`).join('');
}

async function selectEndpoint(id) {
  state.selectedEp = id;
  state.selectedReq = null;
  renderEndpointList();

  // Load requests and rules if not loaded
  if (!state.requests[id] || state.requests[id].length === 0) {
    const reqs = await api('GET', '/api/requests/' + id);
    state.requests[id] = reqs;
  }
  if (!state.rules[id] || state.rules[id].length === 0) {
    const rules = await api('GET', '/api/rules/' + id);
    state.rules[id] = rules;
  }
  // Load CRUD tables
  const tables = await api('GET', '/api/crud/' + id);
  tables.forEach(t => { state.crudTables[t.key] = t; });

  showEndpointView();
  updateHeader();
  renderFeed();
  renderRules();

  // Show URL tester
  const ep = state.endpoints[id];
  document.getElementById('url-tester').style.display = 'block';
  document.getElementById('tester-base').textContent = 'http://localhost:${port}/mock/' + id;
  document.getElementById('tester-path').value = '';
  updateTesterUrl();
}

function showEmptyMain() {
  document.getElementById('main-empty').style.display = 'flex';
  document.getElementById('main-view').style.display = 'none';
  document.getElementById('url-tester').style.display = 'none';
}

function showEndpointView() {
  document.getElementById('main-empty').style.display = 'none';
  document.getElementById('main-view').style.display = 'flex';
}

function updateHeader() {
  const ep = state.endpoints[state.selectedEp];
  if (!ep) return;
  document.getElementById('hdr-name').textContent = ep.name;
  document.getElementById('hdr-id').textContent = ep.id;
  document.getElementById('hdr-url').textContent = 'http://localhost:${port}/mock/' + ep.id;
  const corsEl = document.getElementById('hdr-cors');
  corsEl.style.display = ep.corsEnabled ? 'inline-block' : 'none';
  updateHeaderStats();
}

function updateHeaderStats() {
  const reqs = state.requests[state.selectedEp] || [];
  const errors = reqs.filter(r => r.status >= 400).length;
  const avgLatency = reqs.length ? Math.round(reqs.reduce((a, r) => a + (r.latency||0), 0) / reqs.length) : 0;
  document.getElementById('stat-total').textContent = reqs.length;
  const errEl = document.getElementById('stat-errors');
  errEl.textContent = errors;
  errEl.style.color = errors > 0 ? '#FF6B6B' : '#555';
  document.getElementById('stat-latency').textContent = avgLatency + 'ms';
}

function copyHeaderUrl() {
  const url = 'http://localhost:${port}/mock/' + state.selectedEp;
  navigator.clipboard.writeText(url).catch(() => {});
  toast('URL copiada!', 'success');
}

// ── LIVE TOGGLE ───────────────────────────────────────────────────────────────
function toggleLive() {
  state.isLive = !state.isLive;
  const btn = document.getElementById('live-btn');
  const dot = document.getElementById('live-dot');
  const lbl = document.getElementById('live-label');
  if (state.isLive) {
    btn.className = 'ctrl-btn live';
    dot.style.display = 'block';
    lbl.textContent = 'LIVE';
  } else {
    btn.className = 'ctrl-btn';
    dot.style.display = 'none';
    lbl.textContent = 'PAUSADO';
  }
}

// ── FEED ──────────────────────────────────────────────────────────────────────
function renderFeed() {
  const feed = document.getElementById('feed');
  const reqs = (state.requests[state.selectedEp] || []);
  const ep = state.endpoints[state.selectedEp];
  if (reqs.length === 0) {
    const hint = ep ? \`http://localhost:${port}/mock/\${ep.id}/\\n...adicione qualquer caminho\` : '';
    feed.innerHTML = \`<div class="empty-state" id="feed-empty">
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      <div style="font-size:14px">Aguardando requisições...</div>
      <div class="mono" style="font-size:11px;color:#333;text-align:center;line-height:1.7">\${hint}</div>
    </div>\`;
    return;
  }
  feed.innerHTML = reqs.map((r, i) => reqRowHTML(r, i === 0)).join('');
}

function reqRowHTML(r, isNew) {
  const sc = STATUS_COLORS[r.status] || {bg:'#555',t:'#fff'};
  const mc = METHOD_COLORS[r.method] || '#aaa';
  const ts = new Date(r.timestamp).toLocaleTimeString('pt-BR');
  return \`<div class="req-item \${isNew?'new-req':''} \${state.selectedReq?.id===r.id?'selected':''}" onclick="selectRequest('\${r.id}')">
    <div class="req-top">
      <div style="display:flex;align-items:center;gap:10px">
        <span class="method" style="color:\${mc}">\${r.method}</span>
        <span class="status" style="background:\${sc.bg};color:\${sc.t};box-shadow:0 0 8px \${sc.bg}55">\${r.status}</span>
      </div>
      <span class="req-latency">\${r.latency||0}ms</span>
    </div>
    <div class="req-path">\${esc(r.path)}</div>
    <div class="req-bottom">
      <span class="req-ip">\${r.ip}</span>
      <span class="req-time">\${ts}</span>
    </div>
  </div>\`;
}

function prependRequestRow(r, isNew) {
  const feed = document.getElementById('feed');
  const empty = document.getElementById('feed-empty');
  if (empty) empty.remove();
  const div = document.createElement('div');
  div.innerHTML = reqRowHTML(r, isNew);
  feed.insertBefore(div.firstElementChild, feed.firstChild);
  updateHeaderStats();
}

function selectRequest(id) {
  const reqs = state.requests[state.selectedEp] || [];
  const req = reqs.find(r => r.id === id);
  if (!req) return;
  state.selectedReq = req;

  // Update feed selection
  document.querySelectorAll('.req-item').forEach(el => el.classList.remove('selected'));
  event.currentTarget.classList.add('selected');

  showInspector(req);
}

function showInspector(req) {
  document.getElementById('inspector-empty').style.display = 'none';
  document.getElementById('inspector').style.display = 'flex';

  const mc = METHOD_COLORS[req.method] || '#aaa';
  const sc = STATUS_COLORS[req.status] || {bg:'#555',t:'#fff'};

  document.getElementById('insp-method').textContent = req.method;
  document.getElementById('insp-method').style.color = mc;
  document.getElementById('insp-path').textContent = req.path;
  document.getElementById('insp-status-badge').innerHTML =
    \`<span class="status" style="background:\${sc.bg};color:\${sc.t}">\${req.status}</span>\`;
  document.getElementById('insp-latency').textContent = (req.latency || 0) + 'ms';
  document.getElementById('insp-rule-match').textContent = req.matchedRule ? '⚡ Mock Rule' : '';

  renderInspectorContent();
}

function renderInspectorContent() {
  const req = state.selectedReq;
  if (!req) return;
  const tab = state.currentInspTab;
  const ep = state.endpoints[state.selectedEp];

  let leftLabel, rightLabel, leftContent, rightContent;

  if (tab === 'headers') {
    leftLabel = 'REQUEST HEADERS'; rightLabel = 'RESPONSE HEADERS';
    leftContent = headersHTML(req.headers || {});
    rightContent = headersHTML({
      'content-type': 'application/json',
      'x-mockapi-endpoint': req.endpointId,
      'x-mockapi-request-id': req.id,
      'access-control-allow-origin': ep?.corsEnabled ? '*' : undefined,
      'x-response-time': (req.latency||0) + 'ms',
    });
  } else if (tab === 'body') {
    leftLabel = 'REQUEST BODY'; rightLabel = 'RESPONSE BODY';
    leftContent = jsonHTML(req.requestBody);
    rightContent = jsonHTML(req.responseBody);
  } else {
    leftLabel = 'QUERY PARAMS'; rightLabel = 'DETALHES';
    leftContent = headersHTML(req.queryParams || {}, 'Sem query params');
    rightContent = \`<div class="mono" style="font-size:12px;line-height:1.8">
      <div><span style="color:var(--blue)">status: </span><span class="status" style="background:\${(STATUS_COLORS[req.status]||{bg:'#555'}).bg};color:\${(STATUS_COLORS[req.status]||{t:'#fff'}).t}">\${req.status}</span></div>
      <div style="margin-top:6px"><span style="color:var(--blue)">latency: </span><span style="color:var(--yellow)">\${req.latency||0}ms</span></div>
      <div style="margin-top:6px"><span style="color:var(--blue)">ip: </span><span style="color:#d4d4d4">\${req.ip}</span></div>
      <div style="margin-top:6px"><span style="color:var(--blue)">timestamp: </span><span style="color:#86EFAC">\${new Date(req.timestamp).toISOString()}</span></div>
      <div style="margin-top:6px"><span style="color:var(--blue)">method: </span><span style="color:\${METHOD_COLORS[req.method]||'#aaa'}">\${req.method}</span></div>
      \${req.matchedRule ? '<div style="margin-top:6px"><span style="color:var(--blue)">rule: </span><span style="color:#C084FC">⚡ ' + req.matchedRule + '</span></div>' : ''}
    </div>\`;
  }

  document.getElementById('insp-left-label').textContent = leftLabel;
  document.getElementById('insp-right-label').textContent = rightLabel;
  document.getElementById('insp-left').innerHTML = leftContent;
  document.getElementById('insp-right').innerHTML = rightContent;
}

// ── RULES ─────────────────────────────────────────────────────────────────────
function showRuleModal() {
  document.getElementById('rule-path').value = '';
  document.getElementById('rule-method').value = '*';
  document.getElementById('rule-status').value = '200';
  document.getElementById('rule-delay').value = '0';
  document.getElementById('delay-val').textContent = '0';
  document.getElementById('rule-body').value = '{\\n  "message": "Mock response"\\n}';
  document.getElementById('rule-modal').style.display = 'flex';
}
function hideRuleModal() { document.getElementById('rule-modal').style.display = 'none'; }

async function createRule() {
  const epId = state.selectedEp;
  const rule = {
    path:   document.getElementById('rule-path').value.trim(),
    method: document.getElementById('rule-method').value,
    status: parseInt(document.getElementById('rule-status').value),
    delay:  parseInt(document.getElementById('rule-delay').value) || 0,
    body:   document.getElementById('rule-body').value,
  };
  await api('POST', '/api/rules/' + epId, rule);
  hideRuleModal();
  toast('Regra salva!', 'success');
}

async function deleteRule(epId, ruleId) {
  await api('DELETE', \`/api/rules/\${epId}/\${ruleId}\`);
  toast('Regra removida.', 'info');
}

function renderRules() {
  const rules = state.rules[state.selectedEp] || [];
  const tabLabel = document.getElementById('rules-tab-label');
  if (tabLabel) tabLabel.textContent = \`Regras (\${rules.length})\`;

  const list = document.getElementById('rules-list');
  if (!list) return;
  if (rules.length === 0) {
    list.innerHTML = \`<div style="background:#0D0D0D;border:1px dashed var(--border2);border-radius:12px;padding:48px;text-align:center;color:#333">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <div style="margin-top:12px;font-size:14px">Nenhuma regra configurada</div>
      <div style="font-size:12px;color:#2a2a2a;margin-top:4px">Todas as requisições retornam 200 OK por padrão</div>
    </div>\`;
    return;
  }
  const epId = state.selectedEp;
  list.innerHTML = rules.map(r => {
    const sc = STATUS_COLORS[r.status] || {bg:'#555',t:'#fff'};
    const mc = METHOD_COLORS[r.method] || '#aaa';
    return \`<div class="rule-item">
      <span class="method" style="color:\${mc}">\${r.method}</span>
      <code class="rule-path">\${esc(r.path || '/*')}</code>
      <span class="status" style="background:\${sc.bg};color:\${sc.t}">\${r.status}</span>
      \${r.delay ? \`<span class="rule-delay">+\${r.delay}ms</span>\` : ''}
      <button class="rule-del" onclick="deleteRule('\${epId}','\${r.id}')">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
      </button>
    </div>\`;
  }).join('');
}

// ── CLEAR ─────────────────────────────────────────────────────────────────────
async function clearRequests() {
  if (!state.selectedEp) return;
  await api('DELETE', '/api/requests/' + state.selectedEp + '/clear');
  state.selectedReq = null;
  document.getElementById('inspector').style.display = 'none';
  document.getElementById('inspector-empty').style.display = 'flex';
  toast('Requisições limpas.', 'info');
}

// ── TAB SWITCHING ─────────────────────────────────────────────────────────────
function switchTab(tab) {
  state.currentTab = tab;
  ['requests','rules','crud'].forEach(t => {
    document.getElementById('tab-' + t).className = 'tab-btn' + (t === tab ? ' active' : '');
    document.getElementById('tab-content-' + t).style.display = t === tab ? 'flex' : 'none';
  });
  if (tab === 'crud') renderCrudTables();
}

// ── CRUD MANAGEMENT ───────────────────────────────────────────────────────────
function showCrudModal() {
  document.getElementById('crud-path').value = '';
  document.getElementById('crud-idfield').value = 'id';
  document.getElementById('crud-path-preview').textContent = '...';
  document.getElementById('crud-routes-preview').innerHTML = '';
  document.getElementById('crud-modal').style.display = 'flex';
  setTimeout(() => document.getElementById('crud-path').focus(), 50);
}
function hideCrudModal() {
  document.getElementById('crud-modal').style.display = 'none';
  state._editingCrudKey = null;
  const title = document.querySelector('#crud-modal .modal-title');
  if (title) title.textContent = 'Nova Tabela CRUD';
}

document.addEventListener('input', e => {
  if (e.target.id === 'crud-path' || e.target.id === 'crud-idfield') updateCrudPreview();
});

function updateCrudPreview() {
  const ep = state.selectedEp;
  const rawPath = document.getElementById('crud-path').value.trim();
  const path = rawPath.startsWith('/') ? rawPath : '/' + rawPath;
  const preview = \`http://localhost:${port}/mock/\${ep}\${path}\`;
  document.getElementById('crud-path-preview').textContent = preview;
  const MC = {GET:'#00C8FF',POST:'#00FF87',PUT:'#FFD700',PATCH:'#FF8C42',DELETE:'#FF4444'};
  const routes = [
    {m:'GET', p: path + ' → lista todos os registros'},
    {m:'GET', p: path + '/:id → busca por ID'},
    {m:'POST', p: path + ' → cria novo registro'},
    {m:'PUT', p: path + '/:id → substitui registro'},
    {m:'PATCH', p: path + '/:id → atualiza campos'},
    {m:'DELETE', p: path + '/:id → remove por ID'},
  ];
  document.getElementById('crud-routes-preview').innerHTML = routes
    .map(r => \`<div><span style="color:\${MC[r.m]};min-width:56px;display:inline-block">\${r.m}</span><span style="color:#555">\${esc(r.p)}</span></div>\`)
    .join('');
}

async function createCrudTable() {
  let path = document.getElementById('crud-path').value.trim();
  if (!path) { toast('Digite o caminho da coleção.', 'error'); return; }
  // Auto-fix: ensure starts with /
  if (!path.startsWith('/')) path = '/' + path;
  const idField = document.getElementById('crud-idfield').value.trim() || 'id';

  if (state._editingCrudKey) {
    // EDIT MODE: delete old, create new
    const oldKey = state._editingCrudKey;
    const oldTbl = state.crudTables[oldKey];
    if (oldTbl && oldTbl.path !== path) {
      // Migrate rows to new path
      const rows = await api('GET', '/api/crud/' + state.selectedEp + '/' + encodeURIComponent(oldKey) + '/rows');
      await api('DELETE', '/api/crud/' + state.selectedEp + '/' + encodeURIComponent(oldKey));
      delete state.crudTables[oldKey];
      const result = await api('POST', '/api/crud/' + state.selectedEp, { path, idField });
      // Re-insert rows
      const mockBase = 'http://localhost:' + location.port + '/mock/' + state.selectedEp;
      for (const row of rows) {
        await fetch(mockBase + path, {
          method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(row)
        });
      }
      toast('Tabela renomeada para "' + path + '" · ' + rows.length + ' registros migrados.', 'success');
    } else {
      // Just update idField
      await api('POST', '/api/crud/' + state.selectedEp, { path, idField });
      toast('Tabela atualizada.', 'success');
    }
    state._editingCrudKey = null;
  } else {
    await api('POST', '/api/crud/' + state.selectedEp, { path, idField });
    toast('Tabela "' + path + '" criada! CRUD ativo.', 'success');
  }

  hideCrudModal();
  const tables = await api('GET', '/api/crud/' + state.selectedEp);
  tables.forEach(t => { state.crudTables[t.key] = t; });
  renderCrudTables();
}

async function deleteCrudTable(key) {
  await api('DELETE', '/api/crud/' + state.selectedEp + '/' + encodeURIComponent(key));
  delete state.crudTables[key];
  renderCrudTables();
  toast('Tabela removida.', 'info');
}

function copyCurlIdx(idx, key) {
  const curls = window._crudCurls && window._crudCurls[idx];
  if (!curls || !curls[key]) return;
  const text = curls[key];
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => toast('cURL copiado! ✓', 'success')).catch(() => fallbackCopy(text));
  } else { fallbackCopy(text); }
}

function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.focus(); ta.select();
  try { document.execCommand('copy'); toast('cURL copiado!', 'success'); } catch(_) { toast('Erro ao copiar.', 'error'); }
  document.body.removeChild(ta);
}

function toggleCurlPanel(idx) {
  const el = document.getElementById('curl-panel-' + idx);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

function editCrudTable(key) {
  const tbl = state.crudTables[key];
  if (!tbl) return;
  document.getElementById('crud-path').value = tbl.path;
  document.getElementById('crud-idfield').value = tbl.idField || 'id';
  state._editingCrudKey = key;
  const title = document.querySelector('#crud-modal .modal-title');
  if (title) title.textContent = 'Editar Tabela CRUD';
  updateCrudPreview();
  document.getElementById('crud-modal').style.display = 'flex';
}

function renderCrudTables() {
  const ep = state.selectedEp;
  const list = document.getElementById('crud-tables-list');
  if (!list) return;

  const tables = Object.values(state.crudTables).filter(t => t.key && t.key.startsWith(ep + ':'));
  const tabLabel = document.getElementById('crud-tab-label');
  if (tabLabel) tabLabel.textContent = \`CRUD (\${tables.length})\`;

  if (tables.length === 0) {
    list.innerHTML = \`<div style="background:#0D0D0D;border:1px dashed var(--border2);border-radius:12px;padding:48px;text-align:center;color:#333">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
      <div style="margin-top:12px;font-size:14px">Nenhuma tabela ainda</div>
      <div style="font-size:12px;color:#2a2a2a;margin-top:4px">Faça um POST em qualquer caminho — a tabela é criada automaticamente</div>
    </div>\`;
    return;
  }

  window._crudCurls = {};

  list.innerHTML = tables.map((t, idx) => {
    const base = \`http://localhost:${port}/mock/\${ep}\${t.path}\`;
    const idField = t.idField || 'id';
    window._crudCurls[idx] = {
      get:    \`curl "\${base}"\`,
      getid:  \`curl "\${base}/{id}"\`,
      post:   \`curl -X POST "\${base}" -H "Content-Type: application/json" -d '{"nome":"Exemplo","valor":123}'\`,
      patch:  \`curl -X PATCH "\${base}/{id}" -H "Content-Type: application/json" -d '{"campo":"novoValor"}'\`,
      put:    \`curl -X PUT "\${base}/{id}" -H "Content-Type: application/json" -d '{"nome":"Exemplo","valor":123}'\`,
      del:    \`curl -X DELETE "\${base}/{id}"\`,
    };

    const MC = {GET:'#00C8FF',POST:'#00FF87',PATCH:'#FF8C42',PUT:'#FFD700',DELETE:'#FF4444'};
    const miniRow = (m, url, ck) => \`<div onclick="copyCurlIdx(\${idx},'\${ck}')"
      style="background:#111;border-radius:5px;padding:7px 10px;display:flex;align-items:center;justify-content:space-between;gap:8px;cursor:pointer;transition:background .15s"
      onmouseover="this.style.background='#1a1a1a'" onmouseout="this.style.background='#111'" title="Clique para copiar cURL">
      <div style="display:flex;align-items:center;gap:10px;min-width:0">
        <span style="color:\${MC[m]||'#aaa'};min-width:60px;font-weight:700;font-size:11px">\${m}</span>
        <span style="color:#555;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px">\${esc(url)}</span>
      </div>
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2" style="flex-shrink:0"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
    </div>\`;

    return \`<div style="background:#0D0D0D;border:1px solid var(--border);border-radius:12px;padding:18px 20px;margin-bottom:12px;animation:slideIn .2s ease">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <div style="display:flex;align-items:center;gap:12px">
          <div style="background:#00FF8715;border:1px solid #00FF8733;border-radius:8px;width:36px;height:36px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00FF87" stroke-width="1.5"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
          </div>
          <div>
            <div style="font-size:15px;font-weight:700;color:#fff;font-family:'Space Mono',monospace">\${esc(t.path)}</div>
            <div style="font-size:11px;color:#555;margin-top:2px">
              id: <span style="color:#7DD3FC">\${esc(idField)}</span>
              <span style="margin:0 6px;color:#2a2a2a">·</span>
              <span id="crud-count-\${idx}" style="color:var(--green)">\${t.count||0} registros</span>
            </div>
          </div>
        </div>
        <div style="display:flex;gap:6px;flex-shrink:0">
          <button onclick="editCrudTable('\${esc(t.key)}')"
            style="background:#161616;border:1px solid #2a2a2a;border-radius:7px;padding:6px 12px;color:#888;font-size:11px;cursor:pointer;display:flex;align-items:center;gap:5px;transition:all .2s"
            onmouseover="this.style.color='#fff'" onmouseout="this.style.color='#888'">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            Editar
          </button>
          <button onclick="toggleCurlPanel(\${idx})"
            style="background:#161616;border:1px solid #2a2a2a;border-radius:7px;padding:6px 12px;color:#888;font-size:11px;cursor:pointer;font-family:'Space Mono',monospace;display:flex;align-items:center;gap:5px;transition:all .2s"
            onmouseover="this.style.color='#fff'" onmouseout="this.style.color='#888'">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            cURL
          </button>
          <button onclick="openCrudData('\${esc(t.key)}')"
            style="background:#161616;border:1px solid #2a2a2a;border-radius:7px;padding:6px 12px;color:#888;font-size:12px;cursor:pointer;transition:all .2s"
            onmouseover="this.style.color='#fff'" onmouseout="this.style.color='#888'">
            Ver Dados
          </button>
          <button onclick="deleteCrudTable('\${esc(t.key)}')"
            style="background:none;border:none;color:#333;cursor:pointer;padding:6px;transition:color .2s"
            onmouseover="this.style.color='#FF4444'" onmouseout="this.style.color='#333'">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
          </button>
        </div>
      </div>
      <div id="curl-panel-\${idx}" style="display:none;background:#060606;border:1px solid #1a1a1a;border-radius:8px;padding:12px 14px;margin-bottom:10px">
        <div style="font-size:10px;color:#444;font-family:'Space Mono',monospace;letter-spacing:1px;margin-bottom:8px">CLIQUE PARA COPIAR cURL</div>
        <div style="display:flex;flex-direction:column;gap:4px">
          \${miniRow('GET',    base,         'get')}
          \${miniRow('GET',    base+'/{id}', 'getid')}
          \${miniRow('POST',   base,         'post')}
          \${miniRow('PATCH',  base+'/{id}', 'patch')}
          \${miniRow('PUT',    base+'/{id}', 'put')}
          \${miniRow('DELETE', base+'/{id}', 'del')}
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px">
        \${miniRow('GET',    base,         'get')}
        \${miniRow('POST',   base,         'post')}
        \${miniRow('PATCH',  base+'/{id}', 'patch')}
        \${miniRow('DELETE', base+'/{id}', 'del')}
      </div>
    </div>\`;
  }).join('');
}

async function openCrudData(key) {
  state.activeCrudKey = key;
  const tbl = state.crudTables[key];
  document.getElementById('crud-data-title').textContent = 'Dados: ' + (tbl?.path || key);
  document.getElementById('crud-data-subtitle').textContent = (tbl?.count || 0) + ' registros · id field: ' + (tbl?.idField || 'id');
  // Fetch rows
  const rows = await api('GET', '/api/crud/' + state.selectedEp + '/' + encodeURIComponent(key) + '/rows');
  renderCrudDataTable(rows, tbl?.idField || 'id');
  document.getElementById('crud-data-modal').style.display = 'flex';
}

function hideCrudDataModal() { document.getElementById('crud-data-modal').style.display = 'none'; state.activeCrudKey = null; }

function renderCrudDataTable(rows, idField) {
  const container = document.getElementById('crud-data-table');
  if (!rows || rows.length === 0) {
    container.innerHTML = '<div style="padding:32px;text-align:center;color:#333;font-size:14px">Nenhum dado ainda. Faça um POST para inserir registros.</div>';
    return;
  }
  // Collect all columns
  const cols = [...new Set(rows.flatMap(r => Object.keys(r)))];
  container.innerHTML = \`<table style="width:100%;border-collapse:collapse;font-family:'Space Mono',monospace;font-size:12px">
    <thead>
      <tr style="border-bottom:2px solid #2a2a2a">
        \${cols.map(c => \`<th style="padding:8px 12px;text-align:left;color:#7DD3FC;font-weight:700;white-space:nowrap">\${esc(c)}</th>\`).join('')}
        <th style="padding:8px 12px;color:#555">Ações</th>
      </tr>
    </thead>
    <tbody>
      \${rows.map(row => \`<tr style="border-bottom:1px solid #1a1a1a" onmouseover="this.style.background='#111'" onmouseout="this.style.background='transparent'">
        \${cols.map(c => \`<td style="padding:8px 12px;color:\${c === idField ? '#00FF87' : '#d4d4d4'};max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${esc(row[c] != null ? String(row[c]) : '—')}</td>\`).join('')}
        <td style="padding:8px 12px">
          <button onclick="deleteRowFromTable('\${esc(String(row[idField]))}','\${idField}')" style="background:none;border:none;color:#333;cursor:pointer" onmouseover="this.style.color='#FF4444'" onmouseout="this.style.color='#333'">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
          </button>
        </td>
      </tr>\`).join('')}
    </tbody>
  </table>\`;
}

async function deleteRowFromTable(rowId, idField) {
  const key = state.activeCrudKey;
  const tbl = state.crudTables[key];
  if (!tbl) return;
  await fetch(\`http://localhost:${port}/mock/\${state.selectedEp}\${tbl.path}/\${rowId}\`, { method: 'DELETE' });
  const rows = await api('GET', '/api/crud/' + state.selectedEp + '/' + encodeURIComponent(key) + '/rows');
  renderCrudDataTable(rows, idField);
  toast('Registro removido.', 'info');
}

function showAddRowModal() {
  document.getElementById('add-row-body').value = '';
  document.getElementById('add-row-modal').style.display = 'flex';
}

async function insertRow() {
  const key = state.activeCrudKey;
  const tbl = state.crudTables[key];
  if (!tbl) return;
  let body = {};
  try { body = JSON.parse(document.getElementById('add-row-body').value); } catch(_) { toast('JSON inválido.', 'error'); return; }
  await fetch(\`http://localhost:${port}/mock/\${state.selectedEp}\${tbl.path}\`, {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)
  });
  document.getElementById('add-row-modal').style.display = 'none';
  const rows = await api('GET', '/api/crud/' + state.selectedEp + '/' + encodeURIComponent(key) + '/rows');
  renderCrudDataTable(rows, tbl.idField || 'id');
  // Update count
  state.crudTables[key].count = rows.length;
  renderCrudTables();
  toast('Registro inserido!', 'success');
}

function switchInspTab(tab) {
  state.currentInspTab = tab;
  ['headers','body','query'].forEach(t => {
    document.getElementById('itab-' + t).className = 'insp-tab' + (t === tab ? ' active' : '');
  });
  renderInspectorContent();
}

// ── URL TESTER ────────────────────────────────────────────────────────────────
function updateTesterUrl() {
  const base = 'http://localhost:${port}/mock/' + state.selectedEp;
  const extra = document.getElementById('tester-path').value;
  const full = base + (extra.startsWith('/') ? extra : (extra ? '/' + extra : ''));
  document.getElementById('tester-full-url').textContent = full;
}

function copyTesterUrl() {
  const url = document.getElementById('tester-full-url').textContent;
  navigator.clipboard.writeText(url).catch(() => {});
  toast('URL copiada!', 'success');
}

async function sendTestRequest(method) {
  const url = document.getElementById('tester-full-url').textContent;
  try {
    const opts = { method };
    if (method === 'POST') {
      opts.headers = {'Content-Type':'application/json'};
      opts.body = JSON.stringify({test: true, from: 'MockAPI Inspector', ts: Date.now()});
    }
    const r = await fetch(url, opts);
    toast(\`\${method} → \${r.status} ✓\`, r.status < 400 ? 'success' : 'error');
  } catch(e) {
    toast('Erro ao enviar requisição: ' + e.message, 'error');
  }
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function jsonHTML(data) {
  if (!data) return '<span style="color:#555;font-style:italic">— vazio —</span>';
  try {
    const parsed = typeof data === 'string' ? JSON.parse(data) : data;
    const fmt = JSON.stringify(parsed, null, 2)
      .replace(/("[\w\-]+")\s*:/g, '<span style="color:#7DD3FC">$1</span>:')
      .replace(/:\s*(".*?")/g, ': <span style="color:#86EFAC">$1</span>')
      .replace(/:\s*(\d+\.?\d*)/g, ': <span style="color:#FCA5A5">$1</span>')
      .replace(/:\s*(true|false|null)/g, ': <span style="color:#C084FC">$1</span>');
    return \`<pre class="json-viewer">\${fmt}</pre>\`;
  } catch {
    return \`<pre class="json-viewer" style="color:#ccc">\${esc(String(data))}</pre>\`;
  }
}

function headersHTML(headers, emptyMsg = 'Sem dados') {
  const entries = Object.entries(headers || {}).filter(([,v]) => v !== undefined);
  if (!entries.length) return \`<span style="color:#555;font-style:italic">\${emptyMsg}</span>\`;
  return \`<div class="headers-viewer">\${
    entries.map(([k,v]) => \`<div class="hrow"><span class="hkey">\${esc(k)}</span><span class="hval">\${esc(String(v))}</span></div>\`).join('')
  }</div>\`;
}

function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  const icons = { success: '✓', error: '✕', info: 'ℹ' };
  el.innerHTML = \`<span>\${icons[type]||'ℹ'}</span> \${esc(msg)}\`;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// ── BOOT ──────────────────────────────────────────────────────────────────────
async function init() {
  // Enable buttons immediately - don't wait for WS
  try {
    const eps = await api('GET', '/api/endpoints');
    eps.forEach(ep => {
      state.endpoints[ep.id] = ep;
      state.requests[ep.id] = [];
      state.rules[ep.id] = [];
    });
    renderEndpointList();
  } catch(e) {
    console.warn('Could not load endpoints, retrying...', e);
    setTimeout(init, 2000);
    return;
  }
  connectWS();
}

init();

// Keyboard shortcuts
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    hideCreateModal(); hideRuleModal(); hideCrudModal(); hideCrudDataModal();
    document.getElementById('add-row-modal').style.display = 'none';
    document.getElementById('url-tester').style.display = 'none';
  }
});
</script>
</body>
</html>`;
}