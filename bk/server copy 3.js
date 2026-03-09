#!/usr/bin/env node
/**
 * MockAPI Inspector v2 — SQLite + Faker + OpenAPI
 * Usage: node server.js [port]
 */

const http   = require('http');
const crypto = require('crypto');
const url    = require('url');
const fs     = require('fs');
const path   = require('path');

const PORT = parseInt(process.env.PORT) || parseInt(process.argv[2]) || 3000;

// Detecta a URL base real (funciona em localhost, Render, Railway, etc.)
function getBaseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || 'http';
  const host  = req.headers['x-forwarded-host'] || req.headers.host || ('localhost:' + PORT);
  return proto + '://' + host;
}

// Suppress experimental warning for node:sqlite
const origEmit = process.emit;
process.emit = function(name, data) {
  if (name === 'warning' && data?.name === 'ExperimentalWarning' && data?.message?.includes('SQLite')) return false;
  return origEmit.apply(process, arguments);
};

const db     = require('../db.js');
const faker  = require('../faker.js');
const { parseOpenAPI } = require('../openapi.js');

function genId(len = 6) {
  return crypto.randomBytes(len).toString('hex').toUpperCase().slice(0, len);
}

// ── WEBSOCKET (RFC 6455) ──────────────────────────────────────────────────────
const wsClients = new Set();

function wsHandshake(req, socket) {
  const key    = req.headers['sec-websocket-key'];
  const magic  = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
  const accept = crypto.createHash('sha1').update(key + magic).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );
}

function wsFrame(data) {
  const payload = Buffer.from(typeof data === 'string' ? data : JSON.stringify(data), 'utf8');
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x81, len]);
  } else if (len < 65536) {
    header = Buffer.from([0x81, 126, (len >> 8) & 0xff, len & 0xff]);
  } else {
    header = Buffer.from([0x81, 127, 0, 0, 0, 0,
      (len >> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff]);
  }
  return Buffer.concat([header, payload]);
}

function wsParse(buf) {
  if (buf.length < 2) return null;
  const masked = (buf[1] & 0x80) !== 0;
  let len = buf[1] & 0x7f, offset = 2;
  if (len === 126) { len = (buf[2] << 8) | buf[3]; offset = 4; }
  else if (len === 127) { offset = 10; }
  if (masked) {
    const mask = buf.slice(offset, offset + 4); offset += 4;
    const data = buf.slice(offset, offset + len);
    for (let i = 0; i < data.length; i++) data[i] ^= mask[i % 4];
    return data.toString('utf8');
  }
  return buf.slice(offset, offset + len).toString('utf8');
}

function broadcast(endpointId, event, payload) {
  const msg = JSON.stringify({ endpointId, event, payload });
  const frame = wsFrame(msg);
  for (const client of wsClients) {
    try { if (client.writable) client.write(frame); }
    catch(_) { wsClients.delete(client); }
  }
}

// ── BODY READER ───────────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(''));
  });
}

// ── RULE MATCHING ─────────────────────────────────────────────────────────────
function matchRule(rules, method, pathname) {
  for (const rule of rules) {
    const mOk = rule.method === '*' || rule.method === method;
    if (!mOk) continue;
    const rp = rule.path || '/*';
    if (rp === '/*' || rp === '*') return rule;
    if (rp === pathname) return rule;
    if (rp.endsWith('/*') && pathname.startsWith(rp.slice(0, -2))) return rule;
    if (rp.endsWith('*') && pathname.startsWith(rp.slice(0, -1))) return rule;
    const re = new RegExp('^' + rp.replace(/\{[^}]+\}/g, '[^/]+') + '$');
    if (re.test(pathname)) return rule;
  }
  return null;
}

// ── CRUD ENGINE (SQLite-backed) ───────────────────────────────────────────────
function handleCrud(epId, method, subPath, rawBody, query) {
  const clean = subPath.replace(/\/$/, '') || '/';
  const tables = db.getCrudTablesForEndpoint(epId);
  tables.sort((a, b) => b.path.length - a.path.length);

  let matchedTbl = null, itemId = null;
  for (const tbl of tables) {
    const tp = tbl.path;
    if (clean === tp) { matchedTbl = tbl; itemId = null; break; }
    if (clean.startsWith(tp + '/')) { matchedTbl = tbl; itemId = clean.slice(tp.length + 1); break; }
  }
  if (!matchedTbl) return null;

  const { key, idField } = matchedTbl;
  let data = {};
  if (rawBody) try { data = JSON.parse(rawBody); } catch(_) {}

  // GET list
  if (method === 'GET' && !itemId) {
    let rows = db.getCrudRows(key);
    // Filter
    for (const [k, v] of Object.entries(query || {})) {
      if (k.startsWith('_')) continue;
      rows = rows.filter(r => String(r[k] ?? '').toLowerCase() === String(v).toLowerCase());
    }
    const total = rows.length;
    const page  = parseInt(query?._page) || 1;
    const limit = parseInt(query?._limit) || null;
    if (limit) rows = rows.slice((page - 1) * limit, page * limit);
    return { status: 200, body: { data: rows, total, page, limit: limit || total } };
  }

  // GET one
  if (method === 'GET' && itemId) {
    const row = db.getCrudRow(key, itemId);
    if (!row) return { status: 404, body: { error: 'Not found', [idField]: itemId } };
    return { status: 200, body: row };
  }

  // POST — create (supports faker templates)
  if (method === 'POST' && !itemId) {
    const processed = faker.processTemplate(data);
    const newId = processed[idField] != null ? String(processed[idField]) : genId(8);
    const row = { [idField]: newId, ...processed, _createdAt: new Date().toISOString() };
    db.saveCrudRow(key, newId, row);
    broadcast(epId, 'crud_table_updated', { key, path: matchedTbl.path, idField, count: db.countCrudRows(key) });
    return { status: 201, body: row };
  }

  // PUT — full replace
  if (method === 'PUT' && itemId) {
    if (!db.getCrudRow(key, itemId)) return { status: 404, body: { error: 'Not found', [idField]: itemId } };
    const row = { [idField]: itemId, ...data, _updatedAt: new Date().toISOString() };
    db.saveCrudRow(key, itemId, row);
    return { status: 200, body: row };
  }

  // PATCH — partial update
  if (method === 'PATCH' && itemId) {
    const existing = db.getCrudRow(key, itemId);
    if (!existing) return { status: 404, body: { error: 'Not found', [idField]: itemId } };
    const row = { ...existing, ...data, [idField]: itemId, _updatedAt: new Date().toISOString() };
    db.saveCrudRow(key, itemId, row);
    return { status: 200, body: row };
  }

  // DELETE one
  if (method === 'DELETE' && itemId) {
    if (!db.getCrudRow(key, itemId)) return { status: 404, body: { error: 'Not found', [idField]: itemId } };
    db.deleteCrudRow(key, itemId);
    broadcast(epId, 'crud_table_updated', { key, path: matchedTbl.path, idField, count: db.countCrudRows(key) });
    return { status: 200, body: { ok: true, deleted: itemId } };
  }

  // DELETE collection
  if (method === 'DELETE' && !itemId) {
    const count = db.countCrudRows(key);
    db.clearCrudRows(key);
    return { status: 200, body: { ok: true, deleted: count } };
  }

  return null;
}

// ── HTTP HANDLER ──────────────────────────────────────────────────────────────
async function handleRequest(req, res) {
  const parsed   = url.parse(req.url, true);
  const pathname = decodeURIComponent(parsed.pathname);
  const method   = req.method.toUpperCase();

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── DASHBOARD
  if (method === 'GET' && (pathname === '/' || pathname === '/dashboard')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(getDashboardHTML(PORT, getBaseUrl(req))); return;
  }

  // ── HEALTH CHECK
  if (method === 'GET' && pathname === '/health') {
    return json(res, { ok: true, version: '2.0.0', uptime: Math.floor(process.uptime()), ts: new Date().toISOString() });
  }

  // ── ENDPOINTS
  if (method === 'GET' && pathname === '/api/endpoints') {
    return json(res, db.getAllEndpoints());
  }
  if (method === 'POST' && pathname === '/api/endpoints') {
    const body = await readBody(req);
    let data = {}; try { data = JSON.parse(body); } catch(_) {}
    const id = genId();
    const ep = { id, name: data.name || `Endpoint ${id}`, path: data.path || `/${id}`,
                 corsEnabled: data.corsEnabled !== false, globalDelay: parseInt(data.globalDelay)||0,
                 rateLimit: parseInt(data.rateLimit)||100, requestCount: 0, createdAt: new Date().toISOString() };
    db.saveEndpoint(ep);
    broadcast(null, 'endpoint_created', ep);
    return json(res, ep, 201);
  }
  // Update endpoint (PATCH)
  const epPatchMatch = pathname.match(/^\/api\/endpoints\/([A-Z0-9]+)$/);
  if (method === 'PATCH' && epPatchMatch) {
    const id = epPatchMatch[1];
    const ep = db.getEndpoint(id);
    if (!ep) return json(res, { error: 'Not found' }, 404);
    const body = await readBody(req);
    let data = {}; try { data = JSON.parse(body); } catch(_) {}
    const updated = { ...ep, ...data, id };
    db.updateEndpoint(updated);
    broadcast(null, 'endpoint_updated', updated);
    return json(res, updated);
  }
  if (method === 'DELETE' && epPatchMatch) {
    const id = epPatchMatch[1];
    db.deleteEndpoint(id);
    broadcast(null, 'endpoint_deleted', { id });
    return json(res, { ok: true });
  }

  // ── REQUESTS
  const reqListMatch = pathname.match(/^\/api\/requests\/([A-Z0-9]+)$/);
  if (method === 'GET' && reqListMatch) return json(res, db.getRequests(reqListMatch[1]));
  const clearMatch = pathname.match(/^\/api\/requests\/([A-Z0-9]+)\/clear$/);
  if (method === 'DELETE' && clearMatch) {
    db.clearRequests(clearMatch[1]);
    broadcast(clearMatch[1], 'requests_cleared', {});
    return json(res, { ok: true });
  }

  // ── RULES
  const rulesMatch = pathname.match(/^\/api\/rules\/([A-Z0-9]+)$/);
  if (method === 'GET' && rulesMatch) return json(res, db.getRules(rulesMatch[1]));
  if (method === 'POST' && rulesMatch) {
    const body = await readBody(req);
    let data = {}; try { data = JSON.parse(body); } catch(_) {}
    const rule = { id: genId(), endpointId: rulesMatch[1], ...data, createdAt: new Date().toISOString() };
    db.saveRule(rule);
    broadcast(rulesMatch[1], 'rule_added', rule);
    return json(res, rule, 201);
  }
  const delRuleMatch = pathname.match(/^\/api\/rules\/([A-Z0-9]+)\/([A-Z0-9]+)$/);
  if (method === 'DELETE' && delRuleMatch) {
    db.deleteRule(delRuleMatch[2]);
    broadcast(delRuleMatch[1], 'rule_deleted', { id: delRuleMatch[2] });
    return json(res, { ok: true });
  }

  // ── CRUD TABLE MANAGEMENT
  const crudMgmtMatch = pathname.match(/^\/api\/crud\/([A-Z0-9]+)$/);
  if (crudMgmtMatch) {
    const epId = crudMgmtMatch[1];
    if (method === 'GET') return json(res, db.getCrudTablesForEndpoint(epId));
    if (method === 'POST') {
      const body = await readBody(req);
      let data = {}; try { data = JSON.parse(body); } catch(_) {}
      const p = data.path?.startsWith('/') ? data.path : '/' + (data.path || 'items');
      const key = epId + ':' + p;
      db.saveCrudTable(key, epId, p, data.idField || 'id');
      const tbl = db.getCrudTable(key);
      broadcast(epId, 'crud_table_updated', tbl);
      return json(res, { ok: true, key, path: p, idField: data.idField || 'id' }, 201);
    }
  }
  // CRUD table rows (for dashboard "Ver Dados")
  const crudRowsMatch = pathname.match(/^\/api\/crud\/([A-Z0-9]+)\/(.+)\/rows$/);
  if (method === 'GET' && crudRowsMatch) {
    const key = decodeURIComponent(crudRowsMatch[2]);
    return json(res, db.getCrudRows(key));
  }
  const crudDeleteMatch = pathname.match(/^\/api\/crud\/([A-Z0-9]+)\/(.+)$/);
  if (method === 'DELETE' && crudDeleteMatch) {
    const key = decodeURIComponent(crudDeleteMatch[2]);
    db.deleteCrudTable(key);
    return json(res, { ok: true });
  }

  // ── EXPORT / IMPORT JSON
  // GET  /api/export/:epId/:tableKey
  const exportMatch = pathname.match(/^\/api\/export\/([A-Z0-9]+)\/(.+)$/);
  if (method === 'GET' && exportMatch) {
    const key = decodeURIComponent(exportMatch[2]);
    const data = db.exportTable(key);
    if (!data) return json(res, { error: 'Table not found' }, 404);
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="${key.replace(/[^a-z0-9]/gi,'_')}.json"`
    });
    res.end(JSON.stringify(data, null, 2)); return;
  }
  // POST /api/import/:epId  (body: { path, idField, rows: [...] })
  const importMatch = pathname.match(/^\/api\/import\/([A-Z0-9]+)$/);
  if (method === 'POST' && importMatch) {
    const epId = importMatch[1];
    const body = await readBody(req);
    let data = {}; try { data = JSON.parse(body); } catch(_) {}
    const p = data.path || data.meta?.path || '/imported';
    const idField = data.idField || data.meta?.idField || 'id';
    const rows = data.rows || data;
    if (!Array.isArray(rows)) return json(res, { error: 'rows must be an array' }, 400);
    const key = epId + ':' + p;
    const count = db.importTable(key, epId, p, idField, rows);
    broadcast(epId, 'crud_table_updated', db.getCrudTable(key));
    return json(res, { ok: true, imported: count, path: p, key });
  }

  // ── FAKER GENERATE (bulk seeding)
  // POST /api/faker/:epId/:tableKey  body: { template:{...}, count:10 }
  const fakerMatch = pathname.match(/^\/api\/faker\/([A-Z0-9]+)\/(.+)$/);
  if (method === 'POST' && fakerMatch) {
    const epId = fakerMatch[1];
    const key = decodeURIComponent(fakerMatch[2]);
    const body = await readBody(req);
    let data = {}; try { data = JSON.parse(body); } catch(_) {}
    const tbl = db.getCrudTable(key);
    if (!tbl) return json(res, { error: 'Table not found' }, 404);
    const count = Math.min(parseInt(data.count)||10, 500);
    const template = data.template || {};
    const generated = [];
    for (let i = 0; i < count; i++) {
      const row = faker.processTemplate(JSON.parse(JSON.stringify(template)));
      const rowId = row[tbl.idField] != null ? String(row[tbl.idField]) : genId(8);
      const full = { [tbl.idField]: rowId, ...row, _createdAt: new Date().toISOString() };
      db.saveCrudRow(key, rowId, full);
      generated.push(full);
    }
    broadcast(epId, 'crud_table_updated', { ...tbl, count: db.countCrudRows(key) });
    return json(res, { ok: true, generated: generated.length, rows: generated });
  }

  // ── OPENAPI IMPORT
  // POST /api/openapi/:epId  body: { spec: "yaml or json string" }
  const openApiMatch = pathname.match(/^\/api\/openapi\/([A-Z0-9]+)$/);
  if (method === 'POST' && openApiMatch) {
    const epId = openApiMatch[1];
    const body = await readBody(req);
    let data = {}; try { data = JSON.parse(body); } catch(_) {}
    const specText = data.spec || body;
    try {
      const parsed = parseOpenAPI(typeof specText === 'string' ? specText : JSON.stringify(specText));
      // Create mock rules for each route
      let rulesCreated = 0;
      for (const route of parsed.routes) {
        const rule = {
          id: genId(), endpointId: epId,
          method: route.method, path: route.path,
          status: route.status || 200, delay: 0,
          body: route.responseBody || JSON.stringify({ ok: true, message: route.summary }),
          createdAt: new Date().toISOString()
        };
        db.saveRule(rule);
        broadcast(epId, 'rule_added', rule);
        rulesCreated++;
      }
      // Create CRUD tables for detected CRUD paths
      let tablesCreated = 0;
      for (const crudPath of parsed.crudPaths) {
        const key = epId + ':' + crudPath;
        db.saveCrudTable(key, epId, crudPath, 'id');
        broadcast(epId, 'crud_table_updated', db.getCrudTable(key));
        tablesCreated++;
      }
      return json(res, { ok: true, title: parsed.title, rulesCreated, tablesCreated, crudPaths: parsed.crudPaths });
    } catch(e) {
      return json(res, { error: e.message }, 400);
    }
  }

  // ── MOCK ENDPOINT CAPTURE ─────────────────────────────────────────────────
  const mockMatch = pathname.match(/^\/mock\/([A-Z0-9]+)(\/.*)?$/);
  if (mockMatch) {
    const epId    = mockMatch[1];
    const subPath = mockMatch[2] || '/';
    const ep      = db.getEndpoint(epId);

    if (!ep) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Endpoint not found', id: epId })); return;
    }

    const body = await readBody(req);
    const rules = db.getRules(epId);
    const matchedRule = matchRule(rules, method, subPath);

    // Auto-register CRUD table on first POST to unknown path
    // Only auto-register if path has at least one segment (not root '/')
    if (!matchedRule && method === 'POST') {
      const cleanPath = subPath.replace(/\/$/, '');
      if (cleanPath && cleanPath !== '/') {
        // Only register the first segment (e.g. /users/foo -> /users)
        const segments = cleanPath.split('/').filter(Boolean);
        const tablePath = '/' + segments[0];
        const tables = db.getCrudTablesForEndpoint(epId);
        const hasTable = tables.some(t => t.path === tablePath || cleanPath.startsWith(t.path + '/'));
        if (!hasTable) {
          const key = epId + ':' + tablePath;
          db.saveCrudTable(key, epId, tablePath, 'id');
          broadcast(epId, 'crud_table_updated', db.getCrudTable(key));
        }
      }
    }

    let crudResponse = null;
    if (!matchedRule) {
      crudResponse = handleCrud(epId, method, subPath, body, parsed.query);
    }

    const globalDelay = ep.globalDelay || 0;
    const ruleDelay   = matchedRule ? (matchedRule.delay || 0) : 0;
    const totalDelay  = globalDelay + ruleDelay;

    // Determine status and body
    let statusCode, responseBody;
    if (crudResponse) {
      statusCode   = crudResponse.status;
      responseBody = JSON.stringify(crudResponse.body);
    } else if (matchedRule) {
      statusCode = matchedRule.status;
      try {
        const parsed_body = JSON.parse(matchedRule.body);
        responseBody = JSON.stringify(faker.processTemplate(parsed_body));
      } catch(_) { responseBody = matchedRule.body; }
    } else {
      // No CRUD table and no rule matched — helpful 404
      const tables = db.getCrudTablesForEndpoint(epId);
      statusCode = 404;
      responseBody = JSON.stringify({
        error: 'No route matched',
        path: subPath,
        hint: tables.length
          ? 'Available paths: ' + tables.map(t => t.path).join(', ')
          : 'No CRUD tables created yet. Create one in the dashboard under the CRUD tab.',
        docs: 'Create a Mock Rule or CRUD table in the dashboard to handle this path.'
      });
    }

    const record = {
      id: genId(8), endpointId: epId, timestamp: new Date().toISOString(),
      method, path: subPath, fullUrl: req.url, status: statusCode,
      latency: totalDelay, ip: req.socket.remoteAddress || '127.0.0.1',
      headers: req.headers, queryParams: parsed.query,
      requestBody: body || null, responseBody,
      matchedRule: matchedRule ? matchedRule.id : null,
    };

    db.saveRequest(record);
    db.incrementCount(epId);
    const updatedEp = db.getEndpoint(epId);
    broadcast(epId, 'new_request', record);
    broadcast(epId, 'endpoint_updated', updatedEp);

    // Broadcast CRUD count update
    if (crudResponse) {
      const cleanPath = subPath.replace(/\/$/, '');
      const tables = db.getCrudTablesForEndpoint(epId);
      for (const tbl of tables) {
        if (cleanPath === tbl.path || cleanPath.startsWith(tbl.path + '/')) {
          broadcast(epId, 'crud_table_updated', { ...tbl, count: db.countCrudRows(tbl.key) });
          break;
        }
      }
    }

    if (ep.corsEnabled) {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', '*');
      res.setHeader('Access-Control-Allow-Headers', '*');
    }
    res.setHeader('X-MockAPI-Endpoint', epId);
    res.setHeader('X-MockAPI-Request-Id', record.id);

    const sendResponse = () => {
      res.writeHead(statusCode, { 'Content-Type': 'application/json', 'X-Response-Time': `${totalDelay}ms` });
      res.end(responseBody);
    };
    if (totalDelay > 0) setTimeout(sendResponse, totalDelay); else sendResponse();
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
}

function json(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

// ── SERVER SETUP ──────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try { await handleRequest(req, res); }
  catch(e) { console.error('Handler error:', e); try { res.writeHead(500); res.end('{}'); } catch(_){} }
});

server.on('upgrade', (req, socket, head) => {
  if (req.url === '/ws') {
    wsHandshake(req, socket);
    const clientId = genId();
    wsClients.add(socket);

    const crudTables = db.getAllCrudTables();
    socket.write(wsFrame({ event: 'connected', payload: { clientId, endpoints: db.getAllEndpoints(), crudTables } }));

    socket.on('data', buf => { try { wsParse(buf); } catch(_){} });
    socket.on('close', () => wsClients.delete(socket));
    socket.on('error', () => wsClients.delete(socket));
  }
});

server.listen(PORT, () => {
  const line = '═'.repeat(50);
  console.log(`\n  ╔${line}╗`);
  console.log(`  ║          MockAPI Inspector v2 - Running!        ║`);
  console.log(`  ╠${line}╣`);
  console.log(`  ║  Dashboard:  http://localhost:${PORT}${' '.repeat(19 - String(PORT).length)}║`);
  console.log(`  ║  Mock URL:   http://localhost:${PORT}/mock/{ID}/...  ║`);
  console.log(`  ║  WebSocket:  ws://localhost:${PORT}/ws${' '.repeat(21 - String(PORT).length)}║`);
  console.log(`  ║  Database:   ${process.env.DB_FILE || path.join(__dirname,'mockapi.db')}  ║`);
  console.log(`  ╚${line}╝\n`);
});

function getDashboardHTML(port, baseUrl) {
  baseUrl = baseUrl || 'http://localhost:' + port;
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
              <div style="display:flex;gap:8px">
                <button style="background:#7C3AED15;border:1px solid #7C3AED44;border-radius:8px;padding:10px 16px;color:#A78BFA;font-size:12px;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:6px;transition:all .2s" onclick="showOpenApiModal()" onmouseover="this.style.background='#7C3AED25'" onmouseout="this.style.background='#7C3AED15'">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                  OpenAPI
                </button>
                <button class="btn-primary btn-icon" style="padding:10px 18px;font-size:13px;flex:none;width:auto" onclick="showCrudModal()">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                  Nova Tabela
                </button>
              </div>
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
        <button onclick="exportTableJSON(state.activeCrudKey)"
          style="background:#161616;border:1px solid #2a2a2a;border-radius:6px;padding:6px 11px;color:#888;font-size:11px;cursor:pointer;font-family:'Space Mono',monospace;transition:all .2s;display:flex;align-items:center;gap:5px"
          onmouseover="this.style.color='#fff'" onmouseout="this.style.color='#888'" title="Exportar como JSON">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Export
        </button>
        <button onclick="importTableJSON(state.activeCrudKey)"
          style="background:#161616;border:1px solid #2a2a2a;border-radius:6px;padding:6px 11px;color:#888;font-size:11px;cursor:pointer;font-family:'Space Mono',monospace;transition:all .2s;display:flex;align-items:center;gap:5px"
          onmouseover="this.style.color='#fff'" onmouseout="this.style.color='#888'" title="Importar JSON">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
          Import
        </button>
        <button onclick="showFakerModal(state.activeCrudKey)"
          style="background:#00FF8712;border:1px solid #00FF8733;border-radius:6px;padding:6px 11px;color:var(--green);font-size:11px;cursor:pointer;font-family:'Space Mono',monospace;font-weight:700;transition:all .2s"
          onmouseover="this.style.background='#00FF8720'" onmouseout="this.style.background='#00FF8712'" title="Gerar dados fake">
          ✦ Faker
        </button>
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
const baseUrl = '${baseUrl}';  // injected by server — works on localhost and production
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
  const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = wsProto + '//' + location.host + '/ws';
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
  document.getElementById('tester-base').textContent = '${baseUrl}/mock/' + id;
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
  document.getElementById('hdr-url').textContent = '${baseUrl}/mock/' + ep.id;
  const corsEl = document.getElementById('hdr-cors');
  corsEl.style.display = ep.corsEnabled ? 'inline-block' : 'none';
  // Update delay button
  const d = ep.globalDelay || 0;
  const lbl = document.getElementById('delay-btn-label');
  if (lbl) { lbl.textContent = d + 'ms'; lbl.style.color = d > 0 ? 'var(--green)' : ''; }
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
  const url = '${baseUrl}/mock/' + state.selectedEp;
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
    const hint = ep ? \`${baseUrl}/mock/\${ep.id}/\\n...adicione qualquer caminho\` : '';
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
  const preview = \`${baseUrl}/mock/\${ep}\${path}\`;
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
    const base = \`${baseUrl}/mock/\${ep}\${t.path}\`;
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
          <button onclick="showFakerModal('\${esc(t.key)}')"
            style="background:#00FF8712;border:1px solid #00FF8733;border-radius:7px;padding:6px 12px;color:var(--green);font-size:11px;cursor:pointer;font-weight:700;transition:all .2s"
            onmouseover="this.style.background='#00FF8720'" onmouseout="this.style.background='#00FF8712'" title="Gerar dados fake">
            ✦ Faker
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
  await fetch(\`${baseUrl}/mock/\${state.selectedEp}\${tbl.path}/\${rowId}\`, { method: 'DELETE' });
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
  await fetch(\`${baseUrl}/mock/\${state.selectedEp}\${tbl.path}\`, {
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
  const base = '${baseUrl}/mock/' + state.selectedEp;
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
// ── GLOBAL DELAY ─────────────────────────────────────────────────────────────
function showDelayModal() {
  const ep = state.endpoints[state.selectedEp];
  const d = ep?.globalDelay || 0;
  document.getElementById('delay-slider').value = d;
  document.getElementById('delay-display').textContent = d;
  document.getElementById('delay-modal').style.display = 'flex';
}
function setDelayPreset(v) {
  document.getElementById('delay-slider').value = v;
  document.getElementById('delay-display').textContent = v;
}
async function saveGlobalDelay() {
  const delay = parseInt(document.getElementById('delay-slider').value) || 0;
  await api('PATCH', '/api/endpoints/' + state.selectedEp, { globalDelay: delay });
  state.endpoints[state.selectedEp].globalDelay = delay;
  const lbl = document.getElementById('delay-btn-label');
  if (lbl) { lbl.textContent = delay + 'ms'; lbl.style.color = delay > 0 ? 'var(--green)' : ''; }
  document.getElementById('delay-modal').style.display = 'none';
  toast(delay > 0 ? 'Delay global: ' + delay + 'ms ativo ⏱' : 'Delay removido', delay > 0 ? 'success' : 'info');
}

// ── EXPORT / IMPORT JSON ──────────────────────────────────────────────────────
function exportTableJSON(key) {
  if (!key) { toast('Nenhuma tabela selecionada.', 'error'); return; }
  const a = document.createElement('a');
  a.href = '/api/export/' + state.selectedEp + '/' + encodeURIComponent(key);
  a.download = (key.split(':')[1] || key).split('/').join('_').replace(/^_+/, '') + '.json';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  toast('Exportando JSON...', 'info');
}
function importTableJSON(key) {
  if (!key) { toast('Nenhuma tabela selecionada.', 'error'); return; }
  const inp = document.createElement('input'); inp.type = 'file'; inp.accept = '.json';
  inp.onchange = async e => {
    const file = e.target.files[0]; if (!file) return;
    const text = await file.text();
    let data; try { data = JSON.parse(text); } catch (_) { toast('JSON inválido.', 'error'); return; }
    const tbl = state.crudTables[key];
    const rows = Array.isArray(data) ? data : (data.rows || [data]);
    const res = await api('POST', '/api/import/' + state.selectedEp,
      { path: tbl?.path || '/imported', idField: tbl?.idField || 'id', rows });
    if (res.error) { toast('Erro: ' + res.error, 'error'); return; }
    toast(res.imported + ' registros importados! ✓', 'success');
    if (document.getElementById('crud-data-modal').style.display === 'flex' && state.activeCrudKey === key) {
      const freshRows = await api('GET', '/api/crud/' + state.selectedEp + '/' + encodeURIComponent(key) + '/rows');
      const t = state.crudTables[key];
      renderCrudDataTable(freshRows, t?.idField || 'id');
    }
    renderCrudTables();
  };
  inp.click();
}

// ── FAKER SEED ────────────────────────────────────────────────────────────────
function buildFakerChips() {
  const chips = document.getElementById('faker-chips');
  if (!chips) return;
  const keys = ['faker.name','faker.firstName','faker.email','faker.phone','faker.username',
    'faker.uuid','faker.id','faker.age','faker.price','faker.rating','faker.quantity',
    'faker.date','faker.datetime','faker.city','faker.street','faker.cep',
    'faker.company','faker.status','faker.color','faker.url','faker.boolean',
    'faker.lorem','faker.cpf','faker.cnpj'];
  chips.innerHTML = '';
  keys.forEach(k => {
    const span = document.createElement('span');
    span.textContent = k.replace('faker.', '');
    span.title = '{{' + k + '}}';
    span.style.cssText = 'background:#111;border:1px solid #222;border-radius:4px;padding:3px 7px;font-size:10px;font-family:var(--mono);color:#00FF87;cursor:pointer;transition:all .15s;white-space:nowrap;display:inline-block';
    span.addEventListener('mouseover', () => { span.style.background = '#1a1a1a'; span.style.borderColor = '#00FF8744'; });
    span.addEventListener('mouseout',  () => { span.style.background = '#111';    span.style.borderColor = '#222'; });
    span.addEventListener('click', () => insertFakerKey('{{' + k + '}}'));
    chips.appendChild(span);
  });
}
function showFakerModal(key) {
  state.activeCrudKey = key || state.activeCrudKey;
  buildFakerChips();
  document.getElementById('faker-modal').style.display = 'flex';
}
function insertFakerKey(token) {
  const ta = document.getElementById('faker-tpl');
  const s = ta.selectionStart, e2 = ta.selectionEnd, v = ta.value;
  ta.value = v.slice(0, s) + '"' + token + '"' + v.slice(e2);
  ta.focus(); ta.setSelectionRange(s + token.length + 2, s + token.length + 2);
}
async function runFakerSeed() {
  const key = state.activeCrudKey;
  if (!key) { toast('Nenhuma tabela selecionada.', 'error'); return; }
  const count = parseInt(document.getElementById('faker-count').value) || 10;
  let tpl;
  try { tpl = JSON.parse(document.getElementById('faker-tpl').value); }
  catch (_) { toast('Template JSON inválido.', 'error'); return; }
  const result = await api('POST', '/api/faker/' + state.selectedEp + '/' + encodeURIComponent(key), { template: tpl, count });
  if (result.error) { toast('Erro: ' + result.error, 'error'); return; }
  document.getElementById('faker-modal').style.display = 'none';
  toast(result.generated + ' registros gerados! ✦', 'success');
  if (state.activeCrudKey === key && document.getElementById('crud-data-modal').style.display === 'flex') {
    const rows = await api('GET', '/api/crud/' + state.selectedEp + '/' + encodeURIComponent(key) + '/rows');
    const t = state.crudTables[key];
    renderCrudDataTable(rows, t?.idField || 'id');
    document.getElementById('crud-data-subtitle').textContent = rows.length + ' registros · id field: ' + (t?.idField || 'id');
  }
  renderCrudTables();
}

// ── OPENAPI IMPORT ────────────────────────────────────────────────────────────
function showOpenApiModal() {
  document.getElementById('openapi-result').style.display = 'none';
  document.getElementById('openapi-modal').style.display = 'flex';
}
async function importOpenAPI() {
  const spec = document.getElementById('openapi-spec').value.trim();
  if (!spec) { toast('Cole o YAML ou JSON.', 'error'); return; }
  const result = await api('POST', '/api/openapi/' + state.selectedEp, { spec });
  const resEl = document.getElementById('openapi-result');
  resEl.style.display = 'block';
  if (result.error) {
    resEl.style.color = '#FF6B6B'; resEl.style.borderColor = '#FF444433';
    resEl.textContent = '✗ Erro: ' + result.error; return;
  }
  resEl.style.color = 'var(--green)'; resEl.style.borderColor = '#00FF8733';
  resEl.innerHTML = '✓ <strong>' + esc(result.title || 'API') + '</strong> importado!<br>' +
    result.rulesCreated + ' mock rules criadas &nbsp;·&nbsp; ' +
    result.tablesCreated + ' tabelas CRUD' +
    (result.crudPaths?.length ? ' (' + result.crudPaths.join(', ') + ')' : '');
  const [rules, tables] = await Promise.all([
    api('GET', '/api/rules/' + state.selectedEp),
    api('GET', '/api/crud/' + state.selectedEp),
  ]);
  state.rules[state.selectedEp] = rules; renderRules();
  tables.forEach(t => { state.crudTables[t.key] = t; }); renderCrudTables();
  toast('Importado: ' + result.rulesCreated + ' regras + ' + result.tablesCreated + ' tabelas', 'success');
}

// ── VERSIONING (via Mock Rules) ───────────────────────────────────────────────
// API versioning is done with Mock Rules. /v1/users and /v2/users = two different rules.
// createVersionedRule() pre-fills the rule modal to make it easy.
function createVersionedRule(fromPath, version) {
  const vpath = '/v' + version + fromPath;
  showRuleModal();
  setTimeout(() => {
    document.getElementById('rule-path').value = vpath;
    document.getElementById('rule-status').value = '200';
    document.getElementById('rule-body').value = JSON.stringify({
      _version: 'v' + version, _source: fromPath,
      data: [], meta: { version: 'v' + version, deprecated: version < 2 }
    }, null, 2);
    if (document.getElementById('rule-delay')) document.getElementById('rule-delay').value = '0';
    toast('Defina o body para ' + vpath, 'info');
  }, 50);
}


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
    ['add-row-modal','delay-modal','openapi-modal','faker-modal'].forEach(id => {
      const el = document.getElementById(id); if (el) el.style.display = 'none';
    });
  }
});
</script>

<!-- ── GLOBAL DELAY MODAL ─────────────────────────────────────────────────── -->
<div id="delay-modal" class="modal-overlay" style="display:none">
  <div class="modal" style="width:420px">
    <div class="modal-row">
      <h2 class="modal-title" style="margin:0">⏱ Delay Global</h2>
      <button onclick="document.getElementById('delay-modal').style.display='none'" style="background:none;border:none;color:var(--text3);font-size:20px;cursor:pointer">✕</button>
    </div>
    <p style="font-size:12px;color:var(--text3);margin:0 0 16px">Adiciona latência a TODAS as respostas deste endpoint — simula rede lenta.</p>
    <div class="form-group">
      <label class="form-label">DELAY: <span id="delay-display">0</span>ms</label>
      <input type="range" id="delay-slider" min="0" max="5000" step="100" value="0"
        style="width:100%;accent-color:var(--green);margin-top:8px"
        oninput="document.getElementById('delay-display').textContent=this.value">
    </div>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-bottom:18px">
      ${[0,200,500,1000,2000,3000,4000,5000].map(v =>
        `<button onclick="setDelayPreset(${v})" style="background:#111;border:1px solid #222;border-radius:6px;padding:7px 4px;color:#666;font-size:11px;font-family:var(--mono);cursor:pointer;transition:all .2s" onmouseover="this.style.color='#fff';this.style.borderColor='#444'" onmouseout="this.style.color='#666';this.style.borderColor='#222'">${v}ms</button>`
      ).join('')}
    </div>
    <div class="btn-row">
      <button class="btn-cancel" onclick="document.getElementById('delay-modal').style.display='none'">Cancelar</button>
      <button class="btn-primary" onclick="saveGlobalDelay()">Aplicar</button>
    </div>
  </div>
</div>

<!-- ── OPENAPI IMPORT MODAL ──────────────────────────────────────────────── -->
<div id="openapi-modal" class="modal-overlay" style="display:none">
  <div class="modal" style="width:680px">
    <div class="modal-row">
      <h2 class="modal-title" style="margin:0">OpenAPI / Swagger Import</h2>
      <button onclick="document.getElementById('openapi-modal').style.display='none'" style="background:none;border:none;color:var(--text3);font-size:20px;cursor:pointer">✕</button>
    </div>
    <p style="font-size:12px;color:var(--text3);margin:0 0 12px">Cole seu YAML ou JSON (OpenAPI 2.x / 3.x). Serão criadas <strong style="color:var(--text1)">Mock Rules</strong> e <strong style="color:var(--text1)">tabelas CRUD</strong> automaticamente.</p>
    <div class="form-group">
      <label class="form-label">SPEC YAML / JSON</label>
      <textarea class="form-textarea" id="openapi-spec" rows="13" style="font-size:11px" placeholder="openapi: '3.0.0'
info:
  title: Minha API
  version: '1.0.0'
paths:
  /users:
    get:
      summary: Listar usuários
    post:
      summary: Criar usuário
  /users/{id}:
    get:
      summary: Buscar por ID
    patch:
      summary: Atualizar
    delete:
      summary: Remover"></textarea>
    </div>
    <div id="openapi-result" style="display:none;background:#0A1A0A;border:1px solid #00FF8733;border-radius:8px;padding:12px;margin-bottom:12px;font-size:13px;color:var(--green);font-family:var(--mono)"></div>
    <div class="btn-row">
      <button class="btn-cancel" onclick="document.getElementById('openapi-modal').style.display='none'">Cancelar</button>
      <button class="btn-primary" onclick="importOpenAPI()">Importar Spec</button>
    </div>
  </div>
</div>

<!-- ── FAKER SEED MODAL ───────────────────────────────────────────────────── -->
<div id="faker-modal" class="modal-overlay" style="display:none">
  <div class="modal" style="width:600px">
    <div class="modal-row">
      <h2 class="modal-title" style="margin:0">✦ Gerar Dados Fake</h2>
      <button onclick="document.getElementById('faker-modal').style.display='none'" style="background:none;border:none;color:var(--text3);font-size:20px;cursor:pointer">✕</button>
    </div>
    <p style="font-size:12px;color:var(--text3);margin:0 0 10px">Clique num chip para inserir no template. Use <code style="color:var(--green)">{{faker.xxx}}</code> como valores.</p>
    <div id="faker-chips" style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:14px;background:#060606;border:1px solid #1a1a1a;border-radius:8px;padding:10px"></div>
    <div class="form-group">
      <label class="form-label">TEMPLATE JSON</label>
      <textarea class="form-textarea" id="faker-tpl" rows="8" style="font-size:11px">{
  "nome": "{{faker.name}}",
  "email": "{{faker.email}}",
  "idade": "{{faker.age}}",
  "cidade": "{{faker.city}}",
  "empresa": "{{faker.company}}",
  "status": "{{faker.status}}"
}</textarea>
    </div>
    <div class="form-group">
      <label class="form-label">QUANTIDADE: <span id="faker-count-lbl">10</span> registros</label>
      <input type="range" id="faker-count" min="1" max="200" value="10"
        style="width:100%;margin-top:6px;accent-color:var(--green)"
        oninput="document.getElementById('faker-count-lbl').textContent=this.value">
    </div>
    <div class="btn-row">
      <button class="btn-cancel" onclick="document.getElementById('faker-modal').style.display='none'">Cancelar</button>
      <button class="btn-primary" onclick="runFakerSeed()">✦ Gerar e Inserir</button>
    </div>
  </div>
</div>
</body>
</html>`;
}
