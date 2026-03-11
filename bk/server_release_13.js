#!/usr/bin/env node
/**
 * MockAPI Inspector v2 — SQLite + Faker + OpenAPI + Auth
 * Usage: node server.js [port]
 */

// Prevent crashes from unhandled errors
process.on('uncaughtException',  err => console.error('[crash] uncaughtException:', err));
process.on('unhandledRejection', err => console.error('[crash] unhandledRejection:', err));

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

// ── POSTMAN COLLECTION PARSER ─────────────────────────────────────────────────
function parsePostmanCollection(col, user, existingEpId) {
  // Support both wrapped { collection: {...} } and raw collection object
  const c = col.info ? col : col.collection || col;
  if (!c || !c.info) throw new Error('Formato de collection inválido. Export como Collection v2.0 ou v2.1.');

  const colName = c.info.name || 'Postman Import';
  const endpoints = [];

  // Flatten items (supports nested folders)
  function flattenItems(items, prefix = '') {
    const rules = [];
    for (const item of (items || [])) {
      if (item.item) {
        // Folder — recurse
        const folderName = item.name ? `${prefix}/${item.name}`.replace(/\/+/g,'/') : prefix;
        rules.push(...flattenItems(item.item, folderName));
      } else if (item.request) {
        // Request item
        const req = item.request;
        const method = (typeof req === 'string' ? 'GET' : req.method || 'GET').toUpperCase();
        // Extract path — strip host/protocol/variables
        let rawUrl = '';
        if (req.url) {
          rawUrl = typeof req.url === 'string' ? req.url
                  : (req.url.raw || (req.url.path || []).join('/'));
        }
        // Remove protocol + host, keep path only
        rawUrl = rawUrl.replace(/^https?:\/\/[^\/]+/, '').replace(/\{\{[^}]+\}\}/g, '').replace(/^\/+/, '/') || '/';
        // Remove query string
        const path = rawUrl.split('?')[0] || '/';
        // Extract example response body
        let status = 200;
        let body = '{"ok":true}';
        // 1. Try example response first
        if (item.response && item.response.length > 0) {
          const ex = item.response[0];
          status = parseInt(ex.status || ex.code || 200) || 200;
          if (ex.body) {
            try { JSON.parse(ex.body); body = ex.body; } catch(_) { body = JSON.stringify({ message: ex.body }); }
          }
        }
        // 2. If no example response body, use request body as template
        if (body === '{"ok":true}' && req.body) {
          let reqBody = '';
          if (req.body.mode === 'raw' && req.body.raw) {
            reqBody = req.body.raw;
          } else if (req.body.mode === 'formdata' && req.body.formdata) {
            const obj = {};
            (req.body.formdata || []).forEach(f => { if (f.key) obj[f.key] = f.value || ''; });
            reqBody = JSON.stringify(obj, null, 2);
          }
          if (reqBody) {
            try { JSON.parse(reqBody); body = reqBody; } catch(_) { body = JSON.stringify({ raw: reqBody }); }
          }
        }
        rules.push({ method, path, status, body, name: item.name || `${method} ${path}` });
      }
    }
    return rules;
  }

  const allRules = flattenItems(c.item);
  if (allRules.length === 0) throw new Error('Nenhum request encontrado na collection.');

  // Group rules into a single endpoint (or use existing)
  const epId = existingEpId || genId();
  const ep = {
    id: epId,
    userId: user ? user.id : null,
    name: colName,
    path: `/${epId}`,
    corsEnabled: true,
    globalDelay: 0,
    rateLimit: 100,
    requestCount: 0,
    createdAt: new Date().toISOString(),
    _rules: allRules.map(r => ({
      id: genId(),
      endpointId: epId,
      method: r.method,
      path: r.path,
      status: r.status,
      delay: 0,
      body: r.body,
      createdAt: new Date().toISOString(),
    }))
  };
  endpoints.push(ep);

  return { name: colName, endpoints };
}


const GITHUB_CLIENT_ID     = process.env.GITHUB_CLIENT_ID     || '';
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || '';
const SESSION_SECRET       = process.env.SESSION_SECRET       || 'dev_secret_change_me';
const ADMIN_GITHUB_ID      = process.env.ADMIN_GITHUB_ID      || '';
const AUTH_ENABLED         = !!GITHUB_CLIENT_ID;

// ── PLAN LIMITS (DB-driven, admin-configurable) ──────────────────────────────
function getPlanLimits(plan) {
  const cfg = db.getPlanConfig(plan || 'free');
  return {
    endpoints: cfg.ep_limit    >= 999999 ? Infinity : cfg.ep_limit,
    reqPerDay: cfg.req_per_day >= 999999999 ? Infinity : cfg.req_per_day,
    label: cfg.label,
    enabled: !!cfg.enabled,
    priceBrl: cfg.price_brl || 0,
  };
}
function checkEndpointLimit(user) {
  if (!user) return null; // no auth = no limit
  const limits = getPlanLimits(user.plan);
  const count = db.countUserEndpoints(user.id);
  if (count >= limits.endpoints) return { error: 'endpoint_limit', plan: user.plan, limit: limits.endpoints, count };
  return null;
}
function checkDailyLimit(user) {
  if (!user) return null;
  const limits = getPlanLimits(user.plan);
  if (limits.reqPerDay === Infinity) return null;
  const count = db.countUserReqsToday(user.id);
  if (count >= limits.reqPerDay) return { error: 'daily_limit', plan: user.plan, limit: limits.reqPerDay, count };
  return null;
}

function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) rc.split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    list[k.trim()] = decodeURIComponent(v.join('='));
  });
  return list;
}

function getSessionUser(req) {
  if (!AUTH_ENABLED) return null;
  const cookies = parseCookies(req);
  const token = cookies['mockapi_session'];
  if (!token) return null;
  const session = db.getSession(token);
  if (!session) return null;
  return db.getUserById(session.userId);
}

function getTokenUser(req) {
  const auth = req.headers['authorization'] || '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const row = db.getApiToken(match[1]);
  if (!row) return null;
  return db.getUserById(row.user_id);
}

function requireAuth(req, res) {
  const user = getSessionUser(req) || getTokenUser(req);
  if (!user) { res.writeHead(401, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Unauthorized'})); return null; }
  if (user.banned) { res.writeHead(403, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Account banned'})); return null; }
  return user;
}

function requireAdmin(req, res) {
  const user = requireAuth(req, res);
  if (!user) return null;
  if (!user.isAdmin) { res.writeHead(403, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Admin only'})); return null; }
  return user;
}

setInterval(() => db.cleanExpiredSessions(), 60 * 60 * 1000);

// ── KEEP-ALIVE (Render free tier sleeps after 15min) ─────────────────────────
if (process.env.RENDER_EXTERNAL_URL) {
  const pingUrl = process.env.RENDER_EXTERNAL_URL + '/health';
  setInterval(() => {
    require('https').get(pingUrl, () => {}).on('error', () => {});
  }, 10 * 60 * 1000); // every 10 min
  console.log('[keep-alive] Pinging', pingUrl, 'every 10min');
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
    try {
      const dashUser = getSessionUser(req);

      // 1. Não logado — landing page (ou redirect se AUTH_ENABLED)
      if (!dashUser) {
        if (AUTH_ENABLED) {
          // Mostra landing page pública em vez de redirecionar direto pro login
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          return res.end(getLandingHTML(getBaseUrl(req)));
        }
        // Auth desabilitado: entra direto
      }

      // 2. Logado — dashboard
      const html = getDashboardHTML(PORT, getBaseUrl(req), dashUser);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);

    } catch(e) {
      console.error('[dashboard] Error:', e.message, e.stack);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Dashboard error: ' + e.message);
      }
    }
    return;
  }

  // ── DOCS
  if (method === 'GET' && pathname === '/docs') {
    try {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(getDocsHTML(getBaseUrl(req)));
    } catch(e) { res.writeHead(500); res.end('Docs error: ' + e.message); }
    return;
  }

  // ── SDK LANDING PAGE
  if (method === 'GET' && pathname === '/sdk') {
    try {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(getSdkLandingHTML(getBaseUrl(req)));
    } catch(e) { res.writeHead(500); res.end('SDK page error: ' + e.message); }
    return;
  }

  // ── UPGRADE PAGE
  if (method === 'GET' && pathname === '/upgrade') {
    const user = getSessionUser(req);
    const userPlan = user ? user.plan : 'free';
    const userLimits = getPlanLimits(userPlan);
    const userEpUsed  = user ? db.countUserEndpoints(user.id) : 0;
    const userReqUsed = user ? db.countUserReqsToday(user.id) : 0;
    // Get all enabled plans from DB (excluding current if free, show all paid ones)
    const allPlans = db.getAllPlanConfigs().filter(p => p.enabled || p.plan === userPlan);
    const planDescs = {
      free: 'Para explorar e testar a ferramenta.',
      pro: 'Para devs e times pequenos que precisam de mais.',
      team: 'Para equipes e projetos de maior escala.',
      enterprise: 'Para empresas com demanda ilimitada.'
    };
    const planColors = { free:'#00FF87', pro:'#00FF87', team:'#4dabf7', enterprise:'#da77f2' };
    const planOrder  = ['free','pro','team','enterprise'];
    const sorted = allPlans.sort((a,b) => (planOrder.indexOf(a.plan)||99) - (planOrder.indexOf(b.plan)||99));
    const cols = Math.min(sorted.length, 4);
    const plansHtml = sorted.map(p => {
      const isCurrent = p.plan === userPlan;
      const isPopular = p.plan === 'pro';
      const color = planColors[p.plan] || '#00FF87';
      const inf = 999999;
      const epLabel  = p.ep_limit  >= inf ? 'Ilimitado' : p.ep_limit.toLocaleString('pt-BR');
      const reqLabel = p.req_per_day >= 999999999 ? 'Ilimitado' : p.req_per_day.toLocaleString('pt-BR');
      const price    = p.price_brl || 0;
      return `<div class="plan${isPopular ? ' popular' : ''}" style="${isCurrent ? 'opacity:.7' : ''}">
        ${isPopular ? '<div class="plan-badge">MAIS POPULAR</div>' : ''}
        <div class="plan-name">${p.label}</div>
        <div class="plan-price"><sup>R$</sup>${price}<span>/mês</span></div>
        <div class="plan-desc">${planDescs[p.plan] || ''}</div>
        <ul class="plan-features">
          <li><span class="check">✓</span> <strong>${epLabel} endpoints</strong></li>
          <li><span class="check">✓</span> <strong>${reqLabel} req/dia</strong></li>
          <li><span class="check">✓</span> CRUD + Faker + OpenAPI</li>
          ${p.plan !== 'free' ? '<li><span class="check">✓</span> Suporte prioritário</li>' : ''}
          ${p.plan === 'team' || p.plan === 'enterprise' ? '<li><span class="check">✓</span> SLA e onboarding</li>' : ''}
        </ul>
        ${isCurrent
          ? '<div class="btn btn-outline" style="cursor:default;text-align:center">Plano atual</div>'
          : `<a href="mailto:anderson@mockapi.dev?subject=Upgrade ${p.label}&body=Olá Anderson, gostaria de assinar o plano ${p.label} (R$${price}/mês). Meu login: ${user ? user.login : '?'}" class="btn btn-primary" style="background:${color};color:#000;text-align:center">Assinar ${p.label} →</a>`
        }
      </div>`;
    }).join('');

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Upgrade — MockAPI Inspector</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--green:#00FF87;--bg:#0a0a0a;--bg2:#111;--border:#1a1a1a;--blue:#4dabf7}
body{background:var(--bg);color:#e0e0e0;font-family:'Inter',system-ui,sans-serif;min-height:100vh;display:flex;flex-direction:column}
header{border-bottom:1px solid var(--border);padding:0 32px;height:56px;display:flex;align-items:center;justify-content:space-between;background:var(--bg2)}
.logo{font-size:15px;font-weight:700;color:#fff}.logo span{color:var(--green)}
a{color:var(--green);text-decoration:none}
nav{display:flex;gap:20px;align-items:center}
nav a{font-size:13px;color:#666}nav a:hover{color:#fff}
.container{max-width:1040px;margin:0 auto;padding:60px 32px;flex:1;text-align:center}
h1{font-size:36px;font-weight:700;color:#fff;margin-bottom:12px}
.sub{font-size:16px;color:#666;margin-bottom:8px}
.usage-bar-wrap{max-width:400px;margin:0 auto 40px;text-align:left}
.usage-row{display:flex;justify-content:space-between;font-size:12px;color:#555;margin-bottom:3px}
.usage-bar{background:#1a1a1a;border-radius:4px;height:4px;margin-bottom:10px}
.usage-fill{height:4px;border-radius:4px;transition:width .5s}
.plans{display:grid;grid-template-columns:repeat(${cols},1fr);gap:20px;text-align:left}
@media(max-width:700px){.plans{grid-template-columns:1fr}}
.plan{background:var(--bg2);border:1px solid #1e1e1e;border-radius:16px;padding:28px;position:relative}
.plan.popular{border-color:var(--green)}
.plan-badge{position:absolute;top:-12px;left:50%;transform:translateX(-50%);background:var(--green);color:#000;font-size:11px;font-weight:700;padding:3px 12px;border-radius:100px}
.plan-name{font-size:13px;font-weight:600;color:#888;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.plan-price{font-size:40px;font-weight:800;color:#fff;margin-bottom:4px}
.plan-price sup{font-size:18px;vertical-align:top;margin-top:8px;color:#888}
.plan-price span{font-size:14px;color:#555;font-weight:400}
.plan-desc{font-size:13px;color:#555;margin-bottom:20px;line-height:1.5}
.plan-features{list-style:none;margin-bottom:24px}
.plan-features li{font-size:13px;color:#888;padding:6px 0;border-bottom:1px solid #111;display:flex;align-items:center;gap:8px}
.plan-features li:last-child{border-bottom:none}
.plan-features .check{color:var(--green);font-size:14px}
.btn{display:block;text-align:center;padding:12px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:all .2s;text-decoration:none}
.btn-outline{border:1px solid #333;color:#888}
</style>
</head>
<body>
<header>
  <div class="logo">⚡ <span>MockAPI</span></div>
  <nav>
    <a href="/docs">Documentação</a>
    <a href="/" style="color:#666">← Dashboard</a>
  </nav>
</header>
<div class="container">
  <h1>Faça Upgrade do seu Plano</h1>
  <p class="sub">Você está no plano <strong style="color:var(--green)">${userPlan.toUpperCase()}</strong> — usando ${userEpUsed} endpoints e ${userReqUsed.toLocaleString()} req hoje</p>
  <div class="usage-bar-wrap">
    <div class="usage-row"><span>Endpoints</span><span>${userEpUsed} / ${userLimits.endpoints >= 999999 ? '∞' : userLimits.endpoints}</span></div>
    <div class="usage-bar"><div class="usage-fill" style="width:${Math.min((userEpUsed/(userLimits.endpoints||1))*100,100)}%;background:${userEpUsed >= (userLimits.endpoints||3) ? '#ff4444' : '#00FF87'}"></div></div>
    <div class="usage-row"><span>Requisições hoje</span><span>${userReqUsed.toLocaleString()} / ${userLimits.reqPerDay >= 999999999 ? '∞' : userLimits.reqPerDay.toLocaleString()}</span></div>
    <div class="usage-bar"><div class="usage-fill" style="width:${Math.min((userReqUsed/(userLimits.reqPerDay||1000))*100,100)}%;background:${userReqUsed >= (userLimits.reqPerDay||1000) ? '#ff4444' : '#00FF87'}"></div></div>
  </div>
  <div class="plans">${plansHtml}</div>
  <p style="margin-top:40px;font-size:13px;color:#333">Pagamento via Pix ou cartão. Ativação manual em até 24h. Dúvidas: <a href="mailto:anderson@mockapi.dev">anderson@mockapi.dev</a></p>
</div>
</body></html>`);
    return;
  }

  // ── HEALTH CHECK
  if (method === 'GET' && pathname === '/health') {
    return json(res, { ok: true, version: '2.0.0', uptime: Math.floor(process.uptime()), ts: new Date().toISOString() });
  }

  // ── AUTH: Login page
  if (method === 'GET' && pathname === '/login') {
    try {
      const user = getSessionUser(req);
      if (user) { res.writeHead(302, { Location: '/' }); res.end(); return; }
      const html = getLoginHTML(getBaseUrl(req));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch(e) {
      console.error('[login] Error rendering login page:', e.message, e.stack);
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Login page error: ' + e.message);
    }
    return;
  }

  // ── AUTH: GitHub OAuth start
  if (method === 'GET' && pathname === '/auth/github') {
    if (!AUTH_ENABLED) { res.writeHead(302, { Location: '/' }); res.end(); return; }
    const state = crypto.randomBytes(16).toString('hex');
    const ghUrl = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&scope=read:user,user:email&state=${state}`;
    res.writeHead(302, { Location: ghUrl });
    res.end(); return;
  }

  // ── AUTH: GitHub OAuth callback
  if (method === 'GET' && pathname === '/auth/github/callback') {
    const code  = parsed.query.code;
    if (!code) { res.writeHead(302, { Location: '/login' }); res.end(); return; }
    try {
      // Exchange code for access token
      const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ client_id: GITHUB_CLIENT_ID, client_secret: GITHUB_CLIENT_SECRET, code })
      });
      const tokenData = await tokenRes.json();
      const accessToken = tokenData.access_token;
      if (!accessToken) throw new Error('No access token');

      // Get GitHub user info
      const userRes = await fetch('https://api.github.com/user', {
        headers: { Authorization: `token ${accessToken}`, 'User-Agent': 'MockAPI-Inspector' }
      });
      const ghUser = await userRes.json();

      // Get email if not public
      let email = ghUser.email;
      if (!email) {
        const emailRes = await fetch('https://api.github.com/user/emails', {
          headers: { Authorization: `token ${accessToken}`, 'User-Agent': 'MockAPI-Inspector' }
        });
        const emails = await emailRes.json();
        const primary = Array.isArray(emails) ? emails.find(e => e.primary) : null;
        email = primary ? primary.email : null;
      }

      // Upsert user — first user or matching ADMIN_GITHUB_ID gets admin
      const isAdmin = String(ghUser.id) === String(ADMIN_GITHUB_ID) || db.countUsers() === 0;
      const user = db.upsertUser({
        id: 'U' + String(ghUser.id),
        githubId: ghUser.id,
        login: ghUser.login,
        name: ghUser.name || ghUser.login,
        email, avatar: ghUser.avatar_url,
        plan: 'free', isAdmin
      });

      // Create session (30 days)
      const token = crypto.randomBytes(32).toString('hex');
      const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
      db.createSession(token, user.id, expires);

      res.writeHead(302, {
        Location: '/',
        'Set-Cookie': `mockapi_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${30*24*3600}`
      });
      res.end();
    } catch(e) {
      console.error('[auth] GitHub callback error:', e.message, e.stack);
      try {
        if (!res.headersSent) {
          res.writeHead(302, { Location: '/login?error=1' });
          res.end();
        }
      } catch(_) {}
    }
    return;
  }

  // ── AUTH: Logout
  if (method === 'GET' && pathname === '/auth/logout') {
    const cookies = parseCookies(req);
    if (cookies['mockapi_session']) db.deleteSession(cookies['mockapi_session']);
    res.writeHead(302, {
      Location: '/login',
      'Set-Cookie': 'mockapi_session=; Path=/; HttpOnly; Max-Age=0'
    });
    res.end(); return;
  }

  // ── API TOKENS ────────────────────────────────────────────────────────────────
  if (method === 'GET' && pathname === '/api/tokens') {
    const user = requireAuth(req, res);
    if (!user) return;
    return json(res, db.listApiTokens(user.id));
  }
  if (method === 'POST' && pathname === '/api/tokens') {
    const user = requireAuth(req, res);
    if (!user) return;
    const body = await readBody(req);
    let data = {}; try { data = JSON.parse(body); } catch(_) {}
    const name = (data.name || 'Token ' + Date.now()).slice(0, 60);
    const crypto = require('crypto');
    const token = 'mapi_' + crypto.randomBytes(24).toString('hex');
    const row = db.createApiToken(user.id, name, token);
    return json(res, { ...row, token });
  }
  const tokenDelMatch = pathname.match(/^\/api\/tokens\/([A-F0-9]+)$/);
  if (method === 'DELETE' && tokenDelMatch) {
    const user = requireAuth(req, res);
    if (!user) return;
    db.deleteApiToken(tokenDelMatch[1], user.id);
    return json(res, { ok: true });
  }

  // ── AUTH: Current user info
  if (method === 'GET' && pathname === '/api/me') {
    const user = getSessionUser(req);
    if (!user) return json(res, { loggedIn: false, authEnabled: AUTH_ENABLED });
    const limits = getPlanLimits(user.plan);
    const epCount  = db.countUserEndpoints(user.id);
    const reqToday = db.countUserReqsToday(user.id);
    return json(res, { loggedIn: true, authEnabled: AUTH_ENABLED, user: {
      id: user.id, login: user.login, name: user.name,
      avatar: user.avatar, plan: user.plan, isAdmin: user.isAdmin,
      limits: {
        endpoints:    { used: epCount,  max: limits.endpoints,  pct: limits.endpoints === Infinity ? 0 : Math.round(epCount/limits.endpoints*100) },
        reqPerDay:    { used: reqToday, max: limits.reqPerDay,  pct: limits.reqPerDay === Infinity  ? 0 : Math.round(reqToday/limits.reqPerDay*100) },
      }
    }});
  }

  // ── ADMIN PANEL
  if (method === 'GET' && pathname === '/admin') {
    const user = requireAdmin(req, res);
    if (!user) return;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(getAdminHTML(getBaseUrl(req), user)); return;
  }

  // ── ADMIN API: Stats
  if (method === 'GET' && pathname === '/api/admin/stats') {
    if (!requireAdmin(req, res)) return;
    return json(res, db.getAdminStats());
  }

  // ── ADMIN API: Users list
  if (method === 'GET' && pathname === '/api/admin/users') {
    if (!requireAdmin(req, res)) return;
    return json(res, db.getAllUsers());
  }

  // ── ADMIN API: Plan config
  if (method === 'GET' && pathname === '/api/admin/plans') {
    if (!requireAdmin(req, res)) return;
    return json(res, db.getAllPlanConfigs());
  }
  const planPatchMatch = pathname.match(/^\/api\/admin\/plans\/([a-z]+)$/);
  if (method === 'PATCH' && planPatchMatch) {
    if (!requireAdmin(req, res)) return;
    const plan = planPatchMatch[1];
    const body = await readBody(req);
    let data = {}; try { data = JSON.parse(body); } catch(_) {}
    const updated = db.updatePlanConfig(plan, data);
    return json(res, updated);
  }

  // ── ADMIN API: All endpoints
  if (method === 'GET' && pathname === '/api/admin/endpoints') {
    if (!requireAdmin(req, res)) return;
    return json(res, db.getAllEndpoints());
  }

  // ── ADMIN API: Ban/unban user
  const adminUserMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)\/(ban|unban|promote|demote)$/);
  if (method === 'POST' && adminUserMatch) {
    if (!requireAdmin(req, res)) return;
    const [, userId, action] = adminUserMatch;
    if (action === 'ban')     db.banUser(userId, true);
    if (action === 'unban')   db.banUser(userId, false);
    if (action === 'promote') db.setAdmin(userId, true);
    if (action === 'demote')  db.setAdmin(userId, false);
    return json(res, { ok: true, action, userId });
  }
  // Set user plan directly
  const setPlanMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)\/set_plan$/);
  if (method === 'POST' && setPlanMatch) {
    if (!requireAdmin(req, res)) return;
    const userId = setPlanMatch[1];
    const body = await readBody(req);
    let data = {}; try { data = JSON.parse(body); } catch(_) {}
    if (!data.plan) return json(res, { error: 'plan required' }, 400);
    db.upgradeUserPlan(userId, data.plan);
    const user = db.getUserById(userId);
    return json(res, { ok: true, userId, plan: user?.plan });
  }

  // ── ENDPOINTS (with auth filter)
  if (method === 'GET' && pathname === '/api/endpoints') {
    const user = getSessionUser(req) || getTokenUser(req);
    return json(res, db.getAllEndpoints(user ? user.id : null));
  }
  if (method === 'POST' && pathname === '/api/endpoints') {
    const user = AUTH_ENABLED ? requireAuth(req, res) : null;
    if (AUTH_ENABLED && !user) return;
    // Check endpoint limit (admins bypass)
    if (!user?.isAdmin) {
      const epLimitErr = checkEndpointLimit(user);
      if (epLimitErr) return json(res, epLimitErr, 403);
    }
    const body = await readBody(req);
    let data = {}; try { data = JSON.parse(body); } catch(_) {}
    const id = genId();
    const ep = { id, userId: user ? user.id : null,
                 name: data.name || `Endpoint ${id}`, path: data.path || `/${id}`,
                 corsEnabled: data.corsEnabled !== false, globalDelay: parseInt(data.globalDelay)||0,
                 rateLimit: parseInt(data.rateLimit)||100, requestCount: 0, createdAt: new Date().toISOString() };
    db.saveEndpoint(ep);
    // Auto-init CRUD table when crud:true (SDK usage)
    if (data.crud !== false) {
      const crudPath = '/' + (data.name || id).toLowerCase().replace(/\s+/g, '-');
      const tableKey = id + crudPath;
      db.saveCrudTable(tableKey, id, crudPath, data.idField || 'id');
      ep.crudPath = crudPath;
      ep.tableKey = tableKey;
    }
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
  if (method === 'PATCH' && delRuleMatch) {
    const body = await readBody(req);
    let data = {}; try { data = JSON.parse(body); } catch(_) {}
    const existing = db.getRule(delRuleMatch[2]);
    if (!existing) return json(res, { error: 'Rule not found' }, 404);
    const updated = { ...existing, ...data, id: existing.id, endpointId: existing.endpointId };
    db.saveRule(updated);
    broadcast(delRuleMatch[1], 'rule_updated', updated);
    return json(res, updated);
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

  // ── POSTMAN COLLECTION IMPORT ────────────────────────────────────────────
  // POST /api/postman  body: { collection: {...} }
  // POST /api/postman/:epId  body: { collection: {...} } — import into existing endpoint
  const postmanMatch = pathname.match(/^\/api\/postman(?:\/([A-Z0-9]+))?$/);
  if (method === 'POST' && postmanMatch) {
    const user = requireAuth(req, res);
    if (!user) return;
    const body = await readBody(req);
    let data = {}; try { data = JSON.parse(body); } catch(_) {}
    const col = data.collection;
    if (!col) return json(res, { error: 'collection required' }, 400);
    try {
      const result = parsePostmanCollection(col, user, postmanMatch[1]);
      // Create endpoints + rules from parsed collection
      const created = [];
      for (const ep of result.endpoints) {
        db.saveEndpoint(ep);
        broadcast(null, 'endpoint_created', ep);
        for (const rule of ep._rules || []) {
          db.saveRule(rule);
          broadcast(ep.id, 'rule_added', rule);
        }
        created.push({ id: ep.id, name: ep.name, rules: (ep._rules||[]).length });
      }
      return json(res, { ok: true, endpoints: created.length, details: created });
    } catch(e) {
      return json(res, { error: e.message }, 400);
    }
  }

  // POST /api/postman/preview — returns what would be imported without saving
  if (method === 'POST' && pathname === '/api/postman/preview') {
    const user = requireAuth(req, res);
    if (!user) return;
    const body = await readBody(req);
    let data = {}; try { data = JSON.parse(body); } catch(_) {}
    const col = data.collection;
    if (!col) return json(res, { error: 'collection required' }, 400);
    try {
      const result = parsePostmanCollection(col, user, null);
      return json(res, {
        ok: true,
        name: result.name,
        endpoints: result.endpoints.map(ep => ({
          name: ep.name,
          rules: (ep._rules||[]).map(r => ({ method: r.method, path: r.path, status: r.status }))
        }))
      });
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

    // Check daily request limit for endpoint owner (admins bypass)
    if (ep.userId) {
      const owner = db.getUserById(ep.userId);
      if (owner && !owner.isAdmin) {
        const limitErr = checkDailyLimit(owner);
        if (limitErr) {
          res.writeHead(429, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Daily request limit reached',
            plan: limitErr.plan,
            limit: limitErr.limit,
            upgrade_url: '/upgrade'
          })); return;
        }
      }
    }

    const body = await readBody(req);
    const rules = db.getRules(epId);
    const matchedRule = matchRule(rules, method, subPath);

    // Auto-register CRUD table on first POST to unknown path
    // Uses full path up to the last segment (e.g. /users/123 -> /users, /v1/products -> /v1/products)
    if (!matchedRule && method === 'POST') {
      const cleanPath = subPath.replace(/\/$/, '');
      if (cleanPath && cleanPath !== '/') {
        const segments = cleanPath.split('/').filter(Boolean);
        const tables = db.getCrudTablesForEndpoint(epId);
        // Check if this path (or a parent path) already has a table
        const existingTable = tables.find(t => {
          const tSegs = t.path.split('/').filter(Boolean);
          // exact match or path starts with table path and next char is /
          return cleanPath === t.path || cleanPath.startsWith(t.path + '/');
        });
        if (!existingTable) {
          // If last segment looks like an ID (short alphanumeric), use parent path
          const lastSeg = segments[segments.length - 1];
          const looksLikeId = /^[0-9a-f-]{1,36}$/i.test(lastSeg) && segments.length > 1;
          const tablePath = looksLikeId
            ? '/' + segments.slice(0, -1).join('/')
            : '/' + segments.join('/');
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


// ── LOGIN PAGE ────────────────────────────────────────────────────────────────
function getLoginHTML(baseUrl) {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Login — MockAPI Inspector</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#0a0a0a;color:#fff;font-family:'Inter',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{background:#111;border:1px solid #1a1a1a;border-radius:16px;padding:48px 40px;width:100%;max-width:400px;text-align:center}
  .logo{font-size:32px;margin-bottom:8px}
  h1{font-size:22px;font-weight:700;margin-bottom:6px}
  p{color:#666;font-size:14px;margin-bottom:32px;line-height:1.5}
  .btn-github{display:flex;align-items:center;justify-content:center;gap:10px;background:#fff;color:#000;border:none;border-radius:8px;padding:14px 24px;font-size:15px;font-weight:600;cursor:pointer;text-decoration:none;transition:all .2s;width:100%}
  .btn-github:hover{background:#f0f0f0;transform:translateY(-1px)}
  .btn-github svg{width:20px;height:20px}
  .features{display:grid;gap:10px;margin-top:32px;text-align:left}
  .feature{display:flex;gap:10px;align-items:flex-start;font-size:13px;color:#555}
  .feature .icon{color:#00FF87;font-size:16px;flex-shrink:0}
  .divider{border:none;border-top:1px solid #1a1a1a;margin:24px 0}
  .footer{font-size:12px;color:#333;margin-top:24px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">⚡</div>
  <h1>MockAPI Inspector</h1>
  <p>Mock server com CRUD real, Faker integrado e import OpenAPI. Sem cartão de crédito.</p>
  <a href="/auth/github" class="btn-github">
    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
    Entrar com GitHub
  </a>
  <hr class="divider"/>
  <div class="features">
    <div class="feature"><span class="icon">✦</span><span>CRUD com estado real — GET, POST, PUT, DELETE automáticos</span></div>
    <div class="feature"><span class="icon">✦</span><span>Faker integrado — seed de dados realistas em 1 clique</span></div>
    <div class="feature"><span class="icon">✦</span><span>Import OpenAPI/Swagger — gera mocks do seu spec automaticamente</span></div>
    <div class="feature"><span class="icon">✦</span><span>Histórico de requisições em tempo real</span></div>
  </div>
  <p class="footer">Ao entrar, você concorda com os termos de uso.</p>
</div>
</body></html>`;
}

// ── ADMIN PANEL ───────────────────────────────────────────────────────────────
function getAdminHTML(baseUrl, adminUser) {
  const av = adminUser.avatar || '';
  const lg = adminUser.login  || '';
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin — MockAPI</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a0a;--bg2:#111;--bg3:#161616;--border:#1e1e1e;--text:#e0e0e0;--text2:#888;--text3:#444;--green:#00FF87;--gold:#FFD700;--red:#ff4444;--blue:#4dabf7}
body{background:var(--bg);color:var(--text);font-family:'Inter',system-ui,sans-serif;min-height:100vh;display:flex;flex-direction:column}
a{color:var(--green);text-decoration:none}
a:hover{text-decoration:underline}
header{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 32px;height:56px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
.logo{font-size:15px;font-weight:700;color:#fff;display:flex;align-items:center;gap:8px}
.logo span{color:var(--green)}
nav{display:flex;gap:4px}
nav a{padding:6px 12px;border-radius:6px;font-size:13px;color:var(--text2);transition:all .15s}
nav a:hover,nav a.active{background:var(--bg3);color:#fff;text-decoration:none}
.user-info{display:flex;align-items:center;gap:10px;font-size:13px;color:var(--text2)}
.user-info img{width:28px;height:28px;border-radius:50%}
.container{max-width:1280px;margin:0 auto;padding:28px 32px;flex:1}
.page{display:none}.page.active{display:block}
h2.section-title{font-size:12px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:16px}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:28px}
@media(max-width:900px){.stats-grid{grid-template-columns:repeat(2,1fr)}}
.stat{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:20px 24px;position:relative;overflow:hidden}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--green);opacity:.3}
.stat.highlight::before{opacity:1}
.stat-label{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}
.stat-value{font-size:32px;font-weight:700;color:#fff;line-height:1;margin-bottom:4px}
.stat.highlight .stat-value{color:var(--green)}
.stat-sub{font-size:12px;color:var(--text3)}
.stat-delta{font-size:11px;padding:2px 6px;border-radius:4px;margin-left:6px}
.stat-delta.up{background:#0a2a0a;color:var(--green)}
.stat-delta.down{background:#2a0a0a;color:var(--red)}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:20px}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.card-title{font-size:13px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.06em}
.refresh{background:none;border:none;color:var(--text3);font-size:12px;cursor:pointer;padding:4px 8px;border-radius:4px;transition:all .15s}
.refresh:hover{background:var(--bg3);color:var(--green)}
.chart-wrap{position:relative;height:140px}
.chart-bars{display:flex;align-items:flex-end;gap:3px;height:120px;padding:0 4px}
.bar{background:var(--green);opacity:.25;border-radius:3px 3px 0 0;flex:1;min-height:2px;transition:all .2s;cursor:pointer}
.bar:hover{opacity:1}
.chart-labels{display:flex;justify-content:space-between;margin-top:6px;padding:0 4px}
.chart-labels span{font-size:10px;color:var(--text3)}
.tooltip{position:absolute;background:#222;border:1px solid #333;border-radius:6px;padding:6px 10px;font-size:12px;color:#fff;pointer-events:none;opacity:0;transition:opacity .15s;white-space:nowrap;z-index:10}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{text-align:left;color:var(--text3);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.05em;padding:8px 12px;border-bottom:1px solid var(--border)}
tbody td{padding:11px 12px;border-bottom:1px solid #0d0d0d;vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:#0e0e0e}
.avatar{width:30px;height:30px;border-radius:50%;vertical-align:middle;margin-right:8px}
.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:100px;font-size:11px;font-weight:600}
.badge.admin{background:#2a2a00;color:var(--gold);border:1px solid #3a3a00}
.badge.pro{background:#00132a;color:var(--blue);border:1px solid #003a6a}
.badge.free{background:#001a0a;color:var(--green);border:1px solid #003318}
.badge.banned{background:#2a0000;color:var(--red);border:1px solid #4a0000}
.action-btn{padding:3px 10px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--text2);font-size:11px;cursor:pointer;transition:all .15s;margin-right:4px}
.action-btn:hover{background:var(--bg3);color:#fff;border-color:#333}
.action-btn.danger{color:var(--red);border-color:#330000}
.action-btn.danger:hover{background:#1a0000}
.action-btn.success{color:var(--green);border-color:#003300}
.action-btn.success:hover{background:#001a00}
.empty{color:var(--text3);text-align:center;padding:32px;font-size:13px}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:800px){.two-col{grid-template-columns:1fr}}
.activity-item{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #0d0d0d}
.activity-item:last-child{border-bottom:none}
.activity-dot{width:8px;height:8px;border-radius:50%;background:var(--green);flex-shrink:0}
.activity-text{font-size:13px;color:var(--text2);flex:1}
.activity-time{font-size:11px;color:var(--text3)}
.search-input{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:6px 12px;font-size:13px;color:#fff;width:220px;outline:none}
.search-input:focus{border-color:#333}
.plan-bar{display:flex;height:8px;border-radius:4px;overflow:hidden;gap:2px;margin-top:8px}
.plan-bar div{border-radius:4px;transition:width .5s}
</style>
</head>
<body>
<header>
  <div style="display:flex;align-items:center;gap:24px">
    <a href="/" style="text-decoration:none" class="logo">⚡ <span>MockAPI</span> <span style="color:var(--text3);font-size:11px;font-weight:400">Admin</span></a>
    <nav>
      <a href="#" class="active" onclick="showPage('overview',this)">Overview</a>
      <a href="#" onclick="showPage('users',this)">Usuários</a>
      <a href="#" onclick="showPage('endpoints',this)">Endpoints</a>
      <a href="#" onclick="showPage('plans',this)">⚙ Planos</a>
    </nav>
  </div>
  <div class="user-info">
    <img src="${av}"/>
    <span>${lg}</span>
    <a href="/" style="color:var(--text3);font-size:12px">Dashboard</a>
    <a href="/auth/logout" style="color:var(--text3);font-size:12px">Sair</a>
  </div>
</header>

<div class="container">

  <!-- OVERVIEW PAGE -->
  <div class="page active" id="page-overview">
    <div class="stats-grid" id="stats-grid">
      <div class="stat highlight">
        <div class="stat-label">Usuários</div>
        <div class="stat-value" id="s-users">—</div>
        <div class="stat-sub" id="s-users-sub">carregando...</div>
      </div>
      <div class="stat">
        <div class="stat-label">Endpoints</div>
        <div class="stat-value" id="s-ep">—</div>
        <div class="stat-sub" id="s-ep-sub">&nbsp;</div>
      </div>
      <div class="stat">
        <div class="stat-label">Requisições totais</div>
        <div class="stat-value" id="s-req">—</div>
        <div class="stat-sub" id="s-req-sub">carregando...</div>
      </div>
      <div class="stat">
        <div class="stat-label">Rules criadas</div>
        <div class="stat-value" id="s-rules">—</div>
        <div class="stat-sub">&nbsp;</div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">Requisições — últimos 30 dias</span>
        <button class="refresh" onclick="loadStats()">↻ Atualizar</button>
      </div>
      <div class="chart-wrap">
        <div class="chart-bars" id="chart-bars"></div>
        <div class="chart-labels" id="chart-labels"></div>
        <div class="tooltip" id="tooltip"></div>
      </div>
    </div>

    <div class="two-col">
      <div class="card">
        <div class="card-header"><span class="card-title">Top Endpoints</span></div>
        <table>
          <thead><tr><th>Endpoint</th><th>Owner</th><th style="text-align:right">Reqs</th></tr></thead>
          <tbody id="top-ep-body"><tr><td colspan="3" class="empty">Carregando...</td></tr></tbody>
        </table>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Distribuição de Planos</span></div>
        <div id="plans-content"><div class="empty">Carregando...</div></div>
      </div>
    </div>
  </div>

  <!-- USERS PAGE -->
  <div class="page" id="page-users">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
      <h2 class="section-title" style="margin:0">Usuários <span id="users-count" style="color:var(--text3)"></span></h2>
      <input class="search-input" placeholder="Buscar por login..." id="user-search" oninput="filterUsers()"/>
    </div>
    <div class="card" style="padding:0">
      <table>
        <thead><tr><th>Usuário</th><th>Plano</th><th>Endpoints</th><th>Requisições</th><th>Membro desde</th><th>Ações</th></tr></thead>
        <tbody id="users-tbody"><tr><td colspan="6" class="empty">Carregando...</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- ENDPOINTS PAGE -->
  <div class="page" id="page-endpoints">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
      <h2 class="section-title" style="margin:0">Todos os Endpoints</h2>
      <button class="refresh" onclick="loadAllEndpoints()">↻ Atualizar</button>
    </div>
    <div class="card" style="padding:0">
      <table>
        <thead><tr><th>ID</th><th>Nome</th><th>Owner</th><th style="text-align:right">Requisições</th><th>Criado em</th></tr></thead>
        <tbody id="ep-tbody"><tr><td colspan="5" class="empty">Carregando...</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- PLANS PAGE -->
  <div class="page" id="page-plans">
    <div style="margin-bottom:20px">
      <h2 class="section-title" style="margin:0 0 4px">Configuração de Planos</h2>
      <p style="font-size:12px;color:var(--text3)">Altere limites e visibilidade de cada plano. Alterações têm efeito imediato.</p>
    </div>
    <div id="plans-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px"></div>
  </div>

</div>

<script>
let allUsers = [];

function showPage(name, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  el.classList.add('active');
  if (name === 'users' && allUsers.length === 0) loadUsers();
  if (name === 'endpoints') loadAllEndpoints();
  if (name === 'plans') loadPlans();
}

async function loadStats() {
  try {
    const r = await fetch('/api/admin/stats');
    if (r.status === 401 || r.status === 403) { window.location.href = '/login'; return; }
    if (!r.ok) { console.error('Stats fetch failed:', r.status); return; }
    const d = await r.json();
    if (d.error) { console.error('Stats error:', d.error); return; }
    document.getElementById('s-users').textContent  = (d.totalUsers||0).toLocaleString();
    document.getElementById('s-ep').textContent     = (d.totalEndpoints||0).toLocaleString();
    document.getElementById('s-req').textContent    = (d.totalRequests||0).toLocaleString();
    document.getElementById('s-rules').textContent  = (d.totalRules||0).toLocaleString();
    document.getElementById('s-users-sub').textContent = '+' + (d.newUsersWeek||0) + ' esta semana';
    document.getElementById('s-req-sub').textContent   = (d.reqToday||0).toLocaleString() + ' hoje';

    // SVG-style bar chart
    const bars   = document.getElementById('chart-bars');
    const labels = document.getElementById('chart-labels');
    const tip    = document.getElementById('tooltip');
    bars.innerHTML = ''; labels.innerHTML = '';
    const chart = d.chart || [];
    const max = Math.max(...chart.map(c => c.n), 1);
    chart.forEach((c, i) => {
      const bar = document.createElement('div');
      bar.className = 'bar';
      bar.style.height = Math.max((c.n / max) * 110, 2) + 'px';
      bar.addEventListener('mousemove', e => {
        tip.style.opacity = '1';
        tip.style.left = (e.offsetX + bar.offsetLeft - 40) + 'px';
        tip.style.top  = (bar.parentElement.offsetTop - 36) + 'px';
        tip.textContent = c.day.slice(5) + ': ' + c.n + ' req';
      });
      bar.addEventListener('mouseleave', () => tip.style.opacity = '0');
      bars.appendChild(bar);
    });
    if (chart.length > 0) {
      const idxs = [0, Math.floor(chart.length/3), Math.floor(2*chart.length/3), chart.length-1];
      idxs.forEach(i => {
        const sp = document.createElement('span');
        sp.textContent = (chart[i]||{day:''}).day.slice(5);
        labels.appendChild(sp);
      });
    }

    // Top endpoints
    const tbody = document.getElementById('top-ep-body');
    const topEps = d.topEndpoints || [];
    tbody.innerHTML = topEps.length === 0
      ? '<tr><td colspan="3" class="empty">Nenhum endpoint</td></tr>'
      : topEps.map(e =>
          '<tr><td><code style="color:var(--green);font-size:11px">' + e.id + '</code><span style="color:#666;margin-left:6px">' + e.name + '</span></td>'
          + '<td style="color:var(--text2)">' + (e.owner||'—') + '</td>'
          + '<td style="text-align:right;font-variant-numeric:tabular-nums">' + e.req_count + '</td></tr>'
        ).join('');

    // Plans distribution
    const pc = document.getElementById('plans-content');
    const byPlan = d.usersByPlan || [];
    if (byPlan.length > 0) {
      const total = byPlan.reduce((s,p) => s + p.n, 0) || 1;
      const colors = {free:'var(--green)',pro:'var(--blue)',team:'var(--gold)',enterprise:'#da77f2'};
      pc.innerHTML = byPlan.map(p =>
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">'
        + '<div style="display:flex;align-items:center;gap:8px"><div style="width:10px;height:10px;border-radius:2px;background:'+(colors[p.plan]||'#666')+'"></div>'
        + '<span style="font-size:13px">' + p.plan + '</span></div>'
        + '<span style="font-size:13px;color:var(--text2)">' + p.n + ' (' + Math.round(p.n/total*100) + '%)</span></div>'
      ).join('')
      + '<div class="plan-bar">' + byPlan.map(p =>
        '<div style="flex:' + p.n + ';background:' + (colors[p.plan]||'#666') + ';opacity:.7"></div>'
      ).join('') + '</div>';
    } else {
      pc.innerHTML = '<div class="empty">Nenhum usuário ainda</div>';
    }
  } catch(e) {
    console.error('[loadStats] Error:', e.message);
  }
}

async function loadUsers() {
  try {
    const r = await fetch('/api/admin/users');
    if (r.status === 401 || r.status === 403) { window.location.href = '/login'; return; }
    const users = await r.json();
    if (!Array.isArray(users)) return;
    allUsers = users;
    document.getElementById('users-count').textContent = '(' + users.length + ')';
    renderUsers(users);
  } catch(e) { console.error('[loadUsers]', e.message); }
}

function filterUsers() {
  const q = document.getElementById('user-search').value.toLowerCase();
  renderUsers(allUsers.filter(u => u.login.toLowerCase().includes(q) || (u.name||'').toLowerCase().includes(q)));
}

function renderUsers(users) {
  const tbody = document.getElementById('users-tbody');
  if (users.length === 0) { tbody.innerHTML = '<tr><td colspan="6" class="empty">Nenhum usuário</td></tr>'; return; }
  const planColors = {free:'#00FF87',pro:'#4dabf7',team:'#FFD700',enterprise:'#da77f2'};
  tbody.innerHTML = users.map(u => {
    const badges = [];
    if (u.isAdmin) badges.push('<span class="badge admin">👑 admin</span>');
    if (u.banned)  badges.push('<span class="badge banned">🚫 banido</span>');
    const planColor = planColors[u.plan] || '#00FF87';
    const planSelect =
      '<select data-uid="'+u.id+'" onchange="setPlanFromSelect(this)" style="background:#111;border:1px solid '+planColor+'44;color:'+planColor+';border-radius:5px;padding:3px 6px;font-size:11px;font-weight:700;cursor:pointer;outline:none">'
      + ['free','pro','team','enterprise'].map(p =>
          '<option value="'+p+'"'+(u.plan===p?' selected':'')+'>'+p.toUpperCase()+'</option>'
        ).join('')
      + '</select>';
    const actions = [];
    if (!u.isAdmin) actions.push('<button class="action-btn success" data-id="'+u.id+'" data-action="promote" onclick="actBtn(this)" title="Tornar admin">👑</button>');
    else            actions.push('<button class="action-btn" data-id="'+u.id+'" data-action="demote" onclick="actBtn(this)" title="Remover admin">−👑</button>');
    if (!u.banned)  actions.push('<button class="action-btn danger" data-id="'+u.id+'" data-action="ban" onclick="actBtn(this)" title="Banir">🚫</button>');
    else            actions.push('<button class="action-btn" data-id="'+u.id+'" data-action="unban" onclick="actBtn(this)" title="Desbanir">✓</button>');
    return '<tr>'
      + '<td style="max-width:200px">'
        + '<div style="display:flex;align-items:center;gap:8px;min-width:0">'
        + '<img src="'+(u.avatar||'')+'" class="avatar" style="flex-shrink:0"/>'
        + '<div style="min-width:0">'
        + '<div style="font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+u.login+'</div>'
        + (u.name ? '<div style="font-size:11px;color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+u.name+'</div>' : '')
        + '</div>'
        + (badges.length ? '<div style="display:flex;gap:4px;flex-shrink:0">'+badges.join('')+'</div>' : '')
        + '</div>'
      + '</td>'
      + '<td>'+planSelect+'</td>'
      + '<td style="text-align:right;font-family:monospace;font-size:12px">'+u.epCount+'</td>'
      + '<td style="text-align:right;font-family:monospace;font-size:12px">'+u.reqCount+'</td>'
      + '<td style="color:var(--text3);font-size:11px">'+(u.createdAt||'').slice(0,10)+'</td>'
      + '<td style="white-space:nowrap">'+actions.join(' ')+'</td>'
      + '</tr>';
  }).join('');
}

async function loadAllEndpoints() {
  try {
    const r = await fetch('/api/admin/endpoints');
    if (!r.ok) return;
    const eps = await r.json();
    const tbody = document.getElementById('ep-tbody');
    if (!eps.length) { tbody.innerHTML = '<tr><td colspan="5" class="empty">Nenhum endpoint</td></tr>'; return; }
    tbody.innerHTML = eps.map(e =>
      '<tr>'
      + '<td><code style="color:var(--green);font-size:11px">'+e.id+'</code></td>'
      + '<td>'+e.name+'</td>'
      + '<td style="color:var(--text2)">'+(e.userId||'—')+'</td>'
      + '<td style="text-align:right">'+e.requestCount+'</td>'
      + '<td style="color:var(--text3);font-size:12px">'+(e.createdAt||'').slice(0,10)+'</td>'
      + '</tr>'
    ).join('');
  } catch(e) { console.error('[loadAllEndpoints]', e.message); }
}

async function loadPlans() {
  try {
    const r = await fetch('/api/admin/plans');
    if (!r.ok) return;
    const plans = await r.json();
    const grid = document.getElementById('plans-grid');
    const colors = {free:'var(--green)',pro:'var(--blue)',team:'var(--gold)',enterprise:'#da77f2'};
    grid.innerHTML = plans.map(p => {
      const color = colors[p.plan] || 'var(--green)';
      const inf = 999999;
      return '<div class="card" style="border-top:3px solid '+color+'">'
        + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">'
        + '<strong style="font-size:15px;color:#fff">'+p.label+'</strong>'
        + '<label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:12px;color:var(--text2)">'
        + '<span>Visível</span>'
        + '<input type="checkbox" data-plan="'+p.plan+'" data-field="enabled" onchange="patchPlan(this)" '+(p.enabled?'checked':'')+'>'
        + '</label></div>'
        + '<div style="display:grid;gap:10px">'
        + '<label style="font-size:12px;color:var(--text3)">Endpoints</label>'
        + '<input class="search-input" style="width:100%" type="number" value="'+(p.ep_limit>=inf?'':p.ep_limit)+'" placeholder="999999 = ilimitado" data-plan="'+p.plan+'" data-field="ep_limit" onchange="patchPlan(this)">'
        + '<label style="font-size:12px;color:var(--text3)">Req/dia</label>'
        + '<input class="search-input" style="width:100%" type="number" value="'+(p.req_per_day>=999999999?'':p.req_per_day)+'" placeholder="999999999 = ilimitado" data-plan="'+p.plan+'" data-field="req_per_day" onchange="patchPlan(this)">'
        + '<label style="font-size:12px;color:var(--text3)">Preço (R$)</label>'
        + '<input class="search-input" style="width:100%" type="number" value="'+p.price_brl+'" data-plan="'+p.plan+'" data-field="price_brl" onchange="patchPlan(this)">'
        + '</div></div>';
    }).join('');
  } catch(e) { console.error('[loadPlans]', e.message); }
}

async function patchPlan(input) {
  const plan  = input.dataset.plan;
  const field = input.dataset.field;
  const value = input.type === 'checkbox' ? (input.checked ? 1 : 0) : parseInt(input.value) || 0;
  await fetch('/api/admin/plans/' + plan, {
    method: 'PATCH',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ [field]: value })
  });
}

async function act(id, action) {
  await fetch('/api/admin/users/' + id + '/' + action, { method: 'POST' });
  loadUsers();
}
function actBtn(btn) { act(btn.dataset.id, btn.dataset.action); }
function setPlanFromSelect(sel) { setPlan(sel.dataset.uid, sel); }

async function setPlan(id, select) {
  const plan = select.value;
  const planColors = {free:'#00FF87',pro:'#4dabf7',team:'#FFD700',enterprise:'#da77f2'};
  select.style.borderColor = (planColors[plan]||'#00FF87') + '44';
  select.style.color = planColors[plan]||'#00FF87';
  const res = await fetch('/api/admin/users/' + id + '/set_plan', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ plan })
  });
  const data = await res.json();
  // Flash green border to confirm
  select.style.boxShadow = '0 0 0 2px ' + (planColors[plan]||'#00FF87') + '66';
  setTimeout(() => { select.style.boxShadow = ''; }, 1200);
}

loadStats();
setInterval(loadStats, 30000);
</script>
</body></html>`;
}


// ── SDK LANDING PAGE ──────────────────────────────────────────────────────────
function getSdkLandingHTML(baseUrl) {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>MockAPI SDK — Mock APIs em segundos, direto no seu código</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,300;0,400;0,600;0,800;1,400&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}

:root {
  --bg:       #060608;
  --bg2:      #0d0d12;
  --bg3:      #12121a;
  --border:   #1c1c28;
  --border2:  #252535;
  --green:    #00FF87;
  --green-dim:#00FF8722;
  --blue:     #7DD3FC;
  --purple:   #C084FC;
  --orange:   #FB923C;
  --text:     #E2E8F0;
  --text2:    #94A3B8;
  --text3:    #475569;
  --text4:    #1E293B;
}

html { scroll-behavior: smooth; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Syne', system-ui, sans-serif;
  min-height: 100vh;
  overflow-x: hidden;
}

/* ── GRAIN OVERLAY ── */
body::before {
  content: '';
  position: fixed; inset: 0;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.04'/%3E%3C/svg%3E");
  pointer-events: none;
  z-index: 1000;
  opacity: .4;
}

/* ── GRID BACKGROUND ── */
.grid-bg {
  position: fixed; inset: 0;
  background-image:
    linear-gradient(var(--border) 1px, transparent 1px),
    linear-gradient(90deg, var(--border) 1px, transparent 1px);
  background-size: 40px 40px;
  opacity: .35;
  pointer-events: none;
}

/* ── GLOW ── */
.glow-orb {
  position: fixed;
  border-radius: 50%;
  filter: blur(120px);
  pointer-events: none;
  opacity: .12;
}
.glow-1 { width: 600px; height: 600px; background: var(--green); top: -200px; left: -100px; }
.glow-2 { width: 500px; height: 500px; background: var(--blue); bottom: 0; right: -100px; }
.glow-3 { width: 300px; height: 300px; background: var(--purple); top: 40%; left: 50%; }

/* ── NAV ── */
nav {
  position: fixed; top: 0; left: 0; right: 0;
  z-index: 100;
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 48px; height: 64px;
  background: rgba(6,6,8,.8);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
}

.nav-logo {
  display: flex; align-items: center; gap: 10px;
  font-family: 'JetBrains Mono', monospace;
  font-weight: 800; font-size: 15px; color: #fff;
}
.nav-logo .badge {
  background: var(--green); color: #000;
  font-size: 9px; font-weight: 800; letter-spacing: .08em;
  padding: 2px 6px; border-radius: 4px; text-transform: uppercase;
}
.nav-links { display: flex; gap: 32px; align-items: center; }
.nav-links a {
  font-size: 13px; color: var(--text3); text-decoration: none;
  font-family: 'JetBrains Mono', monospace;
  transition: color .2s;
}
.nav-links a:hover { color: var(--text); }
.btn-nav {
  background: var(--green-dim); border: 1px solid #00FF8744;
  color: var(--green); padding: 8px 20px; border-radius: 8px;
  font-size: 13px; font-family: 'JetBrains Mono', monospace; font-weight: 600;
  cursor: pointer; text-decoration: none; transition: all .2s;
}
.btn-nav:hover { background: var(--green); color: #000; }

/* ── HERO ── */
.hero {
  padding: 160px 48px 100px;
  max-width: 1200px; margin: 0 auto;
  position: relative; z-index: 2;
}

.hero-eyebrow {
  display: inline-flex; align-items: center; gap: 8px;
  background: var(--bg3); border: 1px solid var(--border2);
  padding: 6px 14px; border-radius: 100px;
  font-family: 'JetBrains Mono', monospace; font-size: 11px;
  color: var(--green); letter-spacing: .08em; margin-bottom: 32px;
  animation: fadeUp .6s ease both;
}
.hero-eyebrow span { opacity: .5; }

.hero h1 {
  font-size: clamp(48px, 7vw, 88px);
  font-weight: 800; line-height: 1.0;
  letter-spacing: -.03em; margin-bottom: 24px;
  animation: fadeUp .6s .1s ease both;
}

.hero h1 .accent-green { color: var(--green); }
.hero h1 .accent-dim   { color: var(--text3); }

.hero-sub {
  font-size: 18px; color: var(--text2); max-width: 560px;
  line-height: 1.7; margin-bottom: 48px;
  font-family: 'JetBrains Mono', monospace; font-weight: 300;
  animation: fadeUp .6s .2s ease both;
}

.hero-cta {
  display: flex; gap: 12px; flex-wrap: wrap;
  animation: fadeUp .6s .3s ease both;
}

.btn-primary {
  display: inline-flex; align-items: center; gap: 8px;
  background: var(--green); color: #000;
  padding: 14px 28px; border-radius: 10px;
  font-size: 15px; font-family: 'JetBrains Mono', monospace; font-weight: 700;
  text-decoration: none; transition: all .2s;
  border: none; cursor: pointer;
}
.btn-primary:hover { transform: translateY(-2px); box-shadow: 0 12px 40px #00FF8740; }

.btn-secondary {
  display: inline-flex; align-items: center; gap: 8px;
  background: transparent; color: var(--text2);
  padding: 14px 28px; border-radius: 10px;
  font-size: 15px; font-family: 'JetBrains Mono', monospace; font-weight: 400;
  text-decoration: none; border: 1px solid var(--border2);
  transition: all .2s; cursor: pointer;
}
.btn-secondary:hover { border-color: var(--text3); color: var(--text); }

/* ── CODE WINDOW ── */
.code-hero {
  margin-top: 80px;
  animation: fadeUp .6s .4s ease both;
}

.code-window {
  background: var(--bg2);
  border: 1px solid var(--border2);
  border-radius: 14px;
  overflow: hidden;
  box-shadow: 0 32px 80px rgba(0,0,0,.6), 0 0 0 1px rgba(255,255,255,.03);
}

.code-titlebar {
  background: var(--bg3);
  padding: 12px 20px;
  display: flex; align-items: center; gap: 10px;
  border-bottom: 1px solid var(--border);
}
.code-dot { width: 12px; height: 12px; border-radius: 50%; }
.code-dot.r { background: #FF5F57; }
.code-dot.y { background: #FFBD2E; }
.code-dot.g { background: #28CA41; }
.code-filename {
  font-family: 'JetBrains Mono', monospace; font-size: 12px;
  color: var(--text3); margin-left: 8px; flex: 1;
}
.code-tabs {
  display: flex; gap: 0;
}
.code-tab {
  font-family: 'JetBrains Mono', monospace; font-size: 11px;
  color: var(--text3); padding: 4px 14px; cursor: pointer;
  border-right: 1px solid var(--border); transition: all .15s;
}
.code-tab.active { color: var(--green); background: var(--bg2); }
.code-tab:hover:not(.active) { color: var(--text2); }

.code-body {
  padding: 28px 32px;
  font-family: 'JetBrains Mono', monospace; font-size: 13px;
  line-height: 1.8; overflow-x: auto;
}
.code-body pre { white-space: pre; }

.tok-comment  { color: #3D5566; }
.tok-keyword  { color: var(--purple); }
.tok-fn       { color: var(--blue); }
.tok-string   { color: var(--orange); }
.tok-number   { color: #F9A825; }
.tok-operator { color: var(--text3); }
.tok-var      { color: var(--text); }
.tok-green    { color: var(--green); }
.tok-type     { color: #67E8F9; }

/* ── SECTIONS ── */
section {
  padding: 100px 48px;
  max-width: 1200px; margin: 0 auto;
  position: relative; z-index: 2;
}

.section-label {
  font-family: 'JetBrains Mono', monospace; font-size: 11px;
  color: var(--green); letter-spacing: .12em; text-transform: uppercase;
  margin-bottom: 16px;
}
.section-title {
  font-size: clamp(32px, 4vw, 52px); font-weight: 800;
  letter-spacing: -.02em; margin-bottom: 16px; line-height: 1.1;
}
.section-sub {
  font-size: 16px; color: var(--text2); max-width: 500px;
  font-family: 'JetBrains Mono', monospace; font-weight: 300; line-height: 1.7;
}

/* ── FEATURES GRID ── */
.features-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1px;
  background: var(--border);
  border: 1px solid var(--border);
  border-radius: 16px;
  overflow: hidden;
  margin-top: 64px;
}

.feature-card {
  background: var(--bg);
  padding: 40px 36px;
  transition: background .2s;
}
.feature-card:hover { background: var(--bg2); }

.feature-icon {
  width: 44px; height: 44px;
  background: var(--bg3); border: 1px solid var(--border2);
  border-radius: 12px;
  display: flex; align-items: center; justify-content: center;
  margin-bottom: 20px; font-size: 20px;
}
.feature-card h3 {
  font-size: 18px; font-weight: 700; margin-bottom: 10px;
  letter-spacing: -.01em;
}
.feature-card p {
  font-size: 13px; color: var(--text2);
  font-family: 'JetBrains Mono', monospace; font-weight: 300;
  line-height: 1.7;
}

/* ── COMPARISON TABLE ── */
.compare-wrap {
  margin-top: 64px;
  border: 1px solid var(--border2);
  border-radius: 16px; overflow: hidden;
}
table { width: 100%; border-collapse: collapse; }
thead { background: var(--bg3); }
th {
  padding: 16px 24px; text-align: left;
  font-size: 12px; font-family: 'JetBrains Mono', monospace;
  color: var(--text3); letter-spacing: .06em; text-transform: uppercase;
  border-bottom: 1px solid var(--border2);
}
th:first-child { color: var(--text2); }
td {
  padding: 14px 24px; font-size: 14px;
  border-bottom: 1px solid var(--border);
}
tr:last-child td { border-bottom: none; }
td:first-child { font-family: 'JetBrains Mono', monospace; font-size: 13px; color: var(--text2); }
.check-green { color: var(--green); font-size: 16px; }
.check-red   { color: #475569; font-size: 16px; }
.check-mid   { color: var(--orange); font-size: 16px; }
.highlight-col { background: #00FF8706; }

/* ── INSTALL BLOCK ── */
.install-block {
  display: flex; align-items: center; gap: 12px;
  background: var(--bg2); border: 1px solid var(--border2);
  border-radius: 10px; padding: 14px 20px;
  font-family: 'JetBrains Mono', monospace; font-size: 14px;
  color: var(--green); margin-top: 32px; max-width: 460px;
  cursor: pointer; transition: border-color .2s;
}
.install-block:hover { border-color: var(--green); }
.install-block .prompt { color: var(--text3); margin-right: 4px; }
.install-copy {
  margin-left: auto; background: none; border: none; color: var(--text3);
  cursor: pointer; font-size: 12px; font-family: 'JetBrains Mono', monospace;
  transition: color .2s;
}
.install-copy:hover { color: var(--green); }

/* ── STEPS ── */
.steps {
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 0;
  margin-top: 64px; position: relative;
}
.steps::before {
  content: '';
  position: absolute; top: 28px; left: 28px; right: 28px; height: 1px;
  background: linear-gradient(90deg, var(--green), var(--blue), var(--purple), transparent);
  opacity: .4;
}
.step { padding: 0 24px 0 0; position: relative; }
.step-num {
  width: 56px; height: 56px;
  background: var(--bg2); border: 1px solid var(--border2);
  border-radius: 50%; display: flex; align-items: center; justify-content: center;
  font-family: 'JetBrains Mono', monospace; font-size: 13px; font-weight: 700;
  color: var(--green); margin-bottom: 20px;
  position: relative; z-index: 1;
}
.step h4 { font-size: 16px; font-weight: 700; margin-bottom: 8px; }
.step p { font-size: 12px; color: var(--text3); font-family: 'JetBrains Mono', monospace; line-height: 1.6; }

/* ── PRICING ── */
.pricing-grid {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px;
  margin-top: 64px;
}
.pricing-card {
  background: var(--bg2); border: 1px solid var(--border2);
  border-radius: 16px; padding: 32px; position: relative;
  transition: transform .2s, border-color .2s;
}
.pricing-card:hover { transform: translateY(-4px); }
.pricing-card.featured {
  border-color: var(--green);
  background: linear-gradient(135deg, #060608 0%, #0a1a0a 100%);
}
.pricing-card.featured::before {
  content: 'MAIS POPULAR';
  position: absolute; top: -12px; left: 50%; transform: translateX(-50%);
  background: var(--green); color: #000; font-size: 10px; font-weight: 800;
  padding: 3px 14px; border-radius: 100px; letter-spacing: .08em;
  font-family: 'JetBrains Mono', monospace;
}
.price-label { font-size: 11px; color: var(--text3); letter-spacing: .08em; margin-bottom: 12px; font-family: 'JetBrains Mono', monospace; }
.price-value { font-size: 48px; font-weight: 800; letter-spacing: -.03em; margin-bottom: 4px; }
.price-value sup { font-size: 20px; vertical-align: top; margin-top: 12px; color: var(--text3); font-weight: 400; }
.price-value span { font-size: 14px; color: var(--text3); font-weight: 400; }
.price-desc { font-size: 13px; color: var(--text2); margin-bottom: 28px; font-family: 'JetBrains Mono', monospace; line-height: 1.5; }
.price-features { list-style: none; margin-bottom: 28px; }
.price-features li {
  font-size: 13px; color: var(--text2); padding: 7px 0;
  border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 8px;
  font-family: 'JetBrains Mono', monospace;
}
.price-features li:last-child { border-bottom: none; }
.price-features .ck { color: var(--green); }

/* ── WAITLIST ── */
.waitlist-section {
  padding: 100px 48px;
  text-align: center;
  position: relative; z-index: 2;
}
.waitlist-card {
  max-width: 620px; margin: 0 auto;
  background: var(--bg2); border: 1px solid var(--border2);
  border-radius: 24px; padding: 64px 48px;
  position: relative; overflow: hidden;
}
.waitlist-card::before {
  content: '';
  position: absolute; inset: 0;
  background: radial-gradient(ellipse at 50% 0%, #00FF8712, transparent 60%);
  pointer-events: none;
}
.waitlist-card h2 { font-size: 40px; font-weight: 800; letter-spacing: -.02em; margin-bottom: 16px; }
.waitlist-card p { font-size: 15px; color: var(--text2); font-family: 'JetBrains Mono', monospace; margin-bottom: 32px; line-height: 1.7; }

.waitlist-form {
  display: flex; gap: 0;
  background: var(--bg3); border: 1px solid var(--border2);
  border-radius: 10px; overflow: hidden; max-width: 480px; margin: 0 auto 16px;
  transition: border-color .2s;
}
.waitlist-form:focus-within { border-color: var(--green); }
.waitlist-form input {
  flex: 1; background: none; border: none; outline: none;
  padding: 14px 20px; font-size: 14px; color: var(--text);
  font-family: 'JetBrains Mono', monospace;
}
.waitlist-form input::placeholder { color: var(--text4); }
.waitlist-form button {
  background: var(--green); color: #000; border: none;
  padding: 14px 24px; font-size: 13px; font-weight: 700;
  font-family: 'JetBrains Mono', monospace; cursor: pointer;
  transition: background .2s; white-space: nowrap;
}
.waitlist-form button:hover { background: #00e87a; }

.waitlist-note { font-size: 11px; color: var(--text4); font-family: 'JetBrains Mono', monospace; }
.waitlist-count {
  display: inline-flex; align-items: center; gap: 6px;
  font-size: 12px; color: var(--text3); font-family: 'JetBrains Mono', monospace;
  margin-top: 20px;
}
.waitlist-count .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--green); animation: pulse 2s infinite; }

/* ── FOOTER ── */
footer {
  border-top: 1px solid var(--border);
  padding: 40px 48px;
  display: flex; align-items: center; justify-content: space-between;
  position: relative; z-index: 2;
}
footer .logo { font-family: 'JetBrains Mono', monospace; font-size: 14px; font-weight: 700; color: #fff; }
footer .copy { font-size: 12px; color: var(--text3); font-family: 'JetBrains Mono', monospace; }
footer .links { display: flex; gap: 24px; }
footer .links a { font-size: 12px; color: var(--text3); text-decoration: none; font-family: 'JetBrains Mono', monospace; transition: color .2s; }
footer .links a:hover { color: var(--text); }

/* ── SCROLL REVEAL ── */
.reveal { opacity: 0; transform: translateY(24px); transition: opacity .6s ease, transform .6s ease; }
.reveal.visible { opacity: 1; transform: none; }

/* ── ANIMATIONS ── */
@keyframes fadeUp {
  from { opacity: 0; transform: translateY(20px); }
  to   { opacity: 1; transform: none; }
}
@keyframes pulse {
  0%,100% { opacity: 1; } 50% { opacity: .3; }
}
@keyframes blink {
  0%,100% { opacity: 1; } 50% { opacity: 0; }
}
@keyframes typewriter {
  from { width: 0; } to { width: 100%; }
}

.cursor {
  display: inline-block; width: 2px; height: 1em;
  background: var(--green); vertical-align: middle;
  animation: blink 1s step-end infinite;
  margin-left: 2px;
}

/* ── RESPONSIVE ── */
@media(max-width:768px) {
  nav { padding: 0 20px; }
  .nav-links { display: none; }
  .hero { padding: 120px 24px 60px; }
  section { padding: 60px 24px; }
  .features-grid { grid-template-columns: 1fr; }
  .pricing-grid { grid-template-columns: 1fr; }
  .steps { grid-template-columns: 1fr 1fr; gap: 32px; }
  .steps::before { display: none; }
  footer { flex-direction: column; gap: 16px; text-align: center; }
  .waitlist-section { padding: 60px 24px; }
  .waitlist-card { padding: 40px 24px; }
}
</style>
</head>
<body>

<div class="grid-bg"></div>
<div class="glow-orb glow-1"></div>
<div class="glow-orb glow-2"></div>
<div class="glow-orb glow-3"></div>

<!-- NAV -->
<nav>
  <div class="nav-logo">
    ⚡ MockAPI
    <span class="badge">SDK</span>
  </div>
  <div class="nav-links">
    <a href="#features">Features</a>
    <a href="#como-funciona">Como funciona</a>
    <a href="#comparacao">vs concorrentes</a>
    <a href="#precos">Preços</a>
    <a href="${baseUrl}/docs" target="_blank">Docs</a>
  </div>
  <a href="#waitlist" class="btn-nav">Entrar na lista →</a>
</nav>

<!-- HERO -->
<div class="hero">
  <div class="hero-eyebrow">
    <span>●</span> EM DESENVOLVIMENTO · Lista de espera aberta
  </div>

  <h1>
    Mock APIs<br/>
    <span class="accent-green">em segundos.</span><br/>
    <span class="accent-dim">No seu código.</span>
  </h1>

  <p class="hero-sub">
    O SDK do MockAPI traz a infraestrutura de mock direto para o seu projeto.
    Sem configuração. Sem Service Workers. Funciona em qualquer ambiente.
  </p>

  <div class="hero-cta">
    <a href="#waitlist" class="btn-primary">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
      Entrar na lista de espera
    </a>
    <a href="${baseUrl}" target="_blank" class="btn-secondary">
      Ver plataforma →
    </a>
  </div>

  <!-- INSTALL BLOCK -->
  <div class="install-block" onclick="copyInstall(this)">
    <span class="prompt">$</span>
    <span>npm install @mockapi/js</span>
    <button class="install-copy">copiar</button>
  </div>

  <!-- CODE WINDOW -->
  <div class="code-hero">
    <div class="code-window">
      <div class="code-titlebar">
        <div class="code-dot r"></div>
        <div class="code-dot y"></div>
        <div class="code-dot g"></div>
        <div class="code-tabs">
          <div class="code-tab active" onclick="switchTab('js', this)">JavaScript</div>
          <div class="code-tab" onclick="switchTab('ts', this)">TypeScript</div>
          <div class="code-tab" onclick="switchTab('py', this)">Python</div>
        </div>
        <span class="code-filename" style="text-align:right">setup.test.js</span>
      </div>
      <div class="code-body">
        <pre id="code-js"><span class="tok-comment">// 1. Instale e importe</span>
<span class="tok-keyword">import</span> <span class="tok-type">{ MockAPI }</span> <span class="tok-keyword">from</span> <span class="tok-string">'@mockapi/js'</span>

<span class="tok-comment">// 2. Conecte com seu token</span>
<span class="tok-keyword">const</span> <span class="tok-var">mock</span> = <span class="tok-keyword">new</span> <span class="tok-fn">MockAPI</span>(<span class="tok-string">'mapi_seu_token_aqui'</span>)

<span class="tok-comment">// 3. Defina seus mocks</span>
<span class="tok-keyword">await</span> mock.<span class="tok-fn">intercept</span>(<span class="tok-string">'GET /users'</span>, {
  status: <span class="tok-number">200</span>,
  data: mock.<span class="tok-fn">faker</span>(<span class="tok-string">'user'</span>, <span class="tok-number">10</span>)   <span class="tok-comment">// gera 10 users fake</span>
})

<span class="tok-keyword">await</span> mock.<span class="tok-fn">intercept</span>(<span class="tok-string">'POST /login'</span>, {
  status: <span class="tok-number">200</span>,
  body: { token: <span class="tok-string">'jwt-simulado-123'</span>, expiresIn: <span class="tok-number">3600</span> }
})

<span class="tok-comment">// 4. Use normalmente — sem mudar seu código de produção</span>
<span class="tok-keyword">const</span> <span class="tok-var">res</span> = <span class="tok-keyword">await</span> <span class="tok-fn">fetch</span>(mock.<span class="tok-fn">url</span>(<span class="tok-string">'/users'</span>))
<span class="tok-keyword">const</span> <span class="tok-var">users</span> = <span class="tok-keyword">await</span> res.<span class="tok-fn">json</span>()  <span class="tok-comment">// → [{id, name, email, ...}]</span>

<span class="tok-comment">// 5. Limpe após os testes</span>
<span class="tok-keyword">await</span> mock.<span class="tok-fn">reset</span>()</pre>

        <pre id="code-ts" style="display:none"><span class="tok-keyword">import</span> <span class="tok-type">{ MockAPI, MockConfig }</span> <span class="tok-keyword">from</span> <span class="tok-string">'@mockapi/js'</span>

<span class="tok-keyword">const</span> <span class="tok-var">mock</span> = <span class="tok-keyword">new</span> <span class="tok-fn">MockAPI</span>(<span class="tok-string">'mapi_seu_token'</span>)

<span class="tok-comment">// Tipagem completa com generics</span>
<span class="tok-keyword">interface</span> <span class="tok-type">User</span> {
  id: <span class="tok-type">number</span>; name: <span class="tok-type">string</span>; email: <span class="tok-type">string</span>
}

<span class="tok-keyword">await</span> mock.<span class="tok-fn">intercept</span>&lt;<span class="tok-type">User[]</span>&gt;(<span class="tok-string">'GET /users'</span>, {
  data: mock.<span class="tok-fn">faker</span>&lt;<span class="tok-type">User</span>&gt;(<span class="tok-string">'user'</span>, <span class="tok-number">10</span>)
})

<span class="tok-comment">// CRUD automático com tipagem</span>
<span class="tok-keyword">const</span> <span class="tok-var">users</span> = mock.<span class="tok-fn">crud</span>&lt;<span class="tok-type">User</span>&gt;(<span class="tok-string">'/api/users'</span>)
<span class="tok-keyword">await</span> users.<span class="tok-fn">seed</span>([
  { id: <span class="tok-number">1</span>, name: <span class="tok-string">'Ana'</span>, email: <span class="tok-string">'ana@teste.com'</span> }
])</pre>

        <pre id="code-py" style="display:none"><span class="tok-keyword">from</span> mockapi <span class="tok-keyword">import</span> <span class="tok-type">MockAPI</span>
<span class="tok-keyword">import</span> pytest

<span class="tok-comment"># Inicializa com seu token</span>
mock = <span class="tok-fn">MockAPI</span>(<span class="tok-string">"mapi_seu_token_aqui"</span>)

<span class="tok-comment"># Define o mock</span>
mock.<span class="tok-fn">intercept</span>(<span class="tok-string">"GET /users"</span>, {
    <span class="tok-string">"status"</span>: <span class="tok-number">200</span>,
    <span class="tok-string">"data"</span>: mock.<span class="tok-fn">faker</span>(<span class="tok-string">"user"</span>, count=<span class="tok-number">5</span>)
})

<span class="tok-comment"># Use no pytest</span>
<span class="tok-keyword">def</span> <span class="tok-fn">test_lista_usuarios</span>():
    res = requests.<span class="tok-fn">get</span>(mock.<span class="tok-fn">url</span>(<span class="tok-string">"/users"</span>))
    <span class="tok-keyword">assert</span> res.status_code == <span class="tok-number">200</span>
    <span class="tok-keyword">assert</span> <span class="tok-fn">len</span>(res.<span class="tok-fn">json</span>()) == <span class="tok-number">5</span></pre>
      </div>
    </div>
  </div>
</div>

<!-- FEATURES -->
<section id="features">
  <div class="reveal">
    <div class="section-label">// features</div>
    <h2 class="section-title">Tudo que você precisa.<br/>Nada que você não precisa.</h2>
    <p class="section-sub">Construído sobre a infraestrutura do MockAPI — battle-tested, zero config.</p>
  </div>

  <div class="features-grid reveal">
    <div class="feature-card">
      <div class="feature-icon">⚡</div>
      <h3>Zero Service Worker</h3>
      <p>Diferente do MSW, funciona em Node.js, CI/CD, Bun, Deno e qualquer ambiente sem instalar nada extra.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">🎲</div>
      <h3>Faker integrado</h3>
      <p>Gere dados realistas com <code style="color:var(--green);font-size:11px">mock.faker('user', 50)</code> — nomes, emails, CPFs, endereços brasileiros.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">📦</div>
      <h3>CRUD automático</h3>
      <p>Uma linha para criar uma API REST completa com GET, POST, PATCH, DELETE e persistência real.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">🔁</div>
      <h3>WebSocket em tempo real</h3>
      <p>Veja cada request no dashboard em tempo real enquanto seus testes rodam. Debug instantâneo.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">🔀</div>
      <h3>Mock Rules</h3>
      <p>Simule erros, latência, status codes diferentes por rota. Teste cenários de falha sem complicação.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">📋</div>
      <h3>OpenAPI / Swagger</h3>
      <p>Importe sua spec e o SDK gera todos os mocks automaticamente. De spec a mock em 3 segundos.</p>
    </div>
  </div>
</section>

<!-- COMO FUNCIONA -->
<section id="como-funciona">
  <div class="reveal">
    <div class="section-label">// como funciona</div>
    <h2 class="section-title">Do npm install<br/>ao primeiro mock.</h2>
  </div>

  <div class="steps reveal">
    <div class="step">
      <div class="step-num">01</div>
      <h4>Instale</h4>
      <p>npm install @mockapi/js<br/>ou pip install mockapi</p>
    </div>
    <div class="step">
      <div class="step-num">02</div>
      <h4>Gere um token</h4>
      <p>No painel MockAPI, clique em 🔑 Tokens e gere um token de API.</p>
    </div>
    <div class="step">
      <div class="step-num">03</div>
      <h4>Defina seus mocks</h4>
      <p>Use mock.intercept() ou mock.crud() direto no seu código de teste.</p>
    </div>
    <div class="step">
      <div class="step-num">04</div>
      <h4>Rode e observe</h4>
      <p>Seus testes rodam. Veja cada request ao vivo no dashboard MockAPI.</p>
    </div>
  </div>
</section>

<!-- COMPARAÇÃO -->
<section id="comparacao">
  <div class="reveal">
    <div class="section-label">// comparação</div>
    <h2 class="section-title">Por que não MSW<br/>ou Mockoon?</h2>
  </div>

  <div class="compare-wrap reveal">
    <table>
      <thead>
        <tr>
          <th>Feature</th>
          <th class="highlight-col" style="color:var(--green)">MockAPI SDK</th>
          <th>MSW</th>
          <th>Mockoon</th>
          <th>WireMock</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Funciona em Node.js / CI</td>
          <td class="highlight-col"><span class="check-green">✓</span></td>
          <td><span class="check-mid">~</span></td>
          <td><span class="check-red">✗</span></td>
          <td><span class="check-green">✓</span></td>
        </tr>
        <tr>
          <td>Zero instalação de deps extras</td>
          <td class="highlight-col"><span class="check-green">✓</span></td>
          <td><span class="check-red">✗</span></td>
          <td><span class="check-red">✗</span></td>
          <td><span class="check-red">✗</span></td>
        </tr>
        <tr>
          <td>CRUD persistente com 1 linha</td>
          <td class="highlight-col"><span class="check-green">✓</span></td>
          <td><span class="check-red">✗</span></td>
          <td><span class="check-mid">~</span></td>
          <td><span class="check-red">✗</span></td>
        </tr>
        <tr>
          <td>Faker integrado</td>
          <td class="highlight-col"><span class="check-green">✓</span></td>
          <td><span class="check-red">✗</span></td>
          <td><span class="check-green">✓</span></td>
          <td><span class="check-red">✗</span></td>
        </tr>
        <tr>
          <td>Dashboard em tempo real</td>
          <td class="highlight-col"><span class="check-green">✓</span></td>
          <td><span class="check-red">✗</span></td>
          <td><span class="check-green">✓</span></td>
          <td><span class="check-mid">~</span></td>
        </tr>
        <tr>
          <td>Multi-linguagem (JS, TS, Python)</td>
          <td class="highlight-col"><span class="check-green">✓</span></td>
          <td><span class="check-mid">~</span></td>
          <td><span class="check-red">✗</span></td>
          <td><span class="check-green">✓</span></td>
        </tr>
        <tr>
          <td>Preço</td>
          <td class="highlight-col" style="color:var(--green);font-family:monospace;font-size:13px">Grátis</td>
          <td style="font-family:monospace;font-size:13px">Grátis</td>
          <td style="font-family:monospace;font-size:13px">Grátis</td>
          <td style="font-family:monospace;font-size:13px">$$$</td>
        </tr>
      </tbody>
    </table>
  </div>
</section>

<!-- PREÇOS -->
<section id="precos">
  <div class="reveal">
    <div class="section-label">// preços</div>
    <h2 class="section-title">Simples. Sem surpresas.</h2>
    <p class="section-sub">O SDK é gratuito no plano Free. Cresce com você.</p>
  </div>

  <div class="pricing-grid reveal">
    <div class="pricing-card">
      <div class="price-label">FREE</div>
      <div class="price-value"><sup>R$</sup>0<span>/mês</span></div>
      <div class="price-desc">Para explorar e testar.</div>
      <ul class="price-features">
        <li><span class="ck">✓</span> SDK JS + Python</li>
        <li><span class="ck">✓</span> 3 endpoints</li>
        <li><span class="ck">✓</span> 1.000 req/dia</li>
        <li><span class="ck">✓</span> Dashboard em tempo real</li>
      </ul>
      <a href="${baseUrl}" class="btn-secondary" style="display:block;text-align:center;padding:12px">Começar grátis</a>
    </div>

    <div class="pricing-card featured">
      <div class="price-label">PRO</div>
      <div class="price-value"><sup>R$</sup>59<span>/mês</span></div>
      <div class="price-desc">Para devs e times que precisam de mais.</div>
      <ul class="price-features">
        <li><span class="ck">✓</span> Tudo do Free</li>
        <li><span class="ck">✓</span> 50 endpoints</li>
        <li><span class="ck">✓</span> 100.000 req/dia</li>
        <li><span class="ck">✓</span> Tokens ilimitados</li>
        <li><span class="ck">✓</span> Suporte prioritário</li>
      </ul>
      <a href="#waitlist" class="btn-primary" style="display:block;text-align:center;justify-content:center">Assinar Pro →</a>
    </div>

    <div class="pricing-card">
      <div class="price-label">TEAM</div>
      <div class="price-value"><sup>R$</sup>199<span>/mês</span></div>
      <div class="price-desc">Para equipes e projetos de escala.</div>
      <ul class="price-features">
        <li><span class="ck">✓</span> Tudo do Pro</li>
        <li><span class="ck">✓</span> 200 endpoints</li>
        <li><span class="ck">✓</span> 1.000.000 req/dia</li>
        <li><span class="ck">✓</span> SLA e onboarding</li>
      </ul>
      <a href="mailto:anderson@mockapi.dev?subject=Plano Team" class="btn-secondary" style="display:block;text-align:center;padding:12px">Falar com time →</a>
    </div>
  </div>
</section>

<!-- WAITLIST -->
<div class="waitlist-section" id="waitlist">
  <div class="waitlist-card reveal">
    <div class="section-label">// lista de espera</div>
    <h2>Seja o primeiro<br/>a usar o SDK.</h2>
    <p>O SDK está em desenvolvimento. Entre na lista e ganhe acesso antecipado + plano Pro grátis por 3 meses.</p>

    <div class="waitlist-form">
      <input type="email" id="waitlist-email" placeholder="seu@email.com" onkeydown="if(event.key==='Enter')joinWaitlist()"/>
      <button onclick="joinWaitlist()">Quero acesso →</button>
    </div>
    <div class="waitlist-note">Sem spam. Apenas quando o SDK estiver pronto.</div>

    <div class="waitlist-count">
      <div class="dot"></div>
      <span id="waitlist-num">47 devs</span> já na lista
    </div>

    <div id="waitlist-success" style="display:none;margin-top:20px;background:#0a1a0a;border:1px solid #00FF8733;border-radius:8px;padding:16px">
      <div style="color:var(--green);font-family:monospace;font-size:13px">✓ Você está na lista! Avisaremos quando o SDK estiver pronto.</div>
    </div>
  </div>
</div>

<!-- FOOTER -->
<footer>
  <div class="logo">⚡ MockAPI SDK</div>
  <div class="links">
    <a href="${baseUrl}">Plataforma</a>
    <a href="${baseUrl}/docs">Docs</a>
    <a href="mailto:anderson@mockapi.dev">Contato</a>
  </div>
  <div class="copy">© 2025 MockAPI · Feito no Brasil 🇧🇷</div>
</footer>

<script>
// Tab switcher
function switchTab(lang, el) {
  document.querySelectorAll('.code-tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  ['js','ts','py'].forEach(l => {
    const el2 = document.getElementById('code-' + l);
    if (el2) el2.style.display = l === lang ? 'block' : 'none';
  });
}

// Copy install
function copyInstall(el) {
  navigator.clipboard.writeText('npm install @mockapi/js').then(() => {
    const btn = el.querySelector('.install-copy');
    btn.textContent = '✓ copiado';
    btn.style.color = 'var(--green)';
    setTimeout(() => { btn.textContent = 'copiar'; btn.style.color = ''; }, 2000);
  });
}

// Waitlist
function joinWaitlist() {
  const email = document.getElementById('waitlist-email').value.trim();
  if (!email || !email.includes('@')) {
    document.getElementById('waitlist-email').style.borderColor = '#ff4444';
    return;
  }
  document.getElementById('waitlist-success').style.display = 'block';
  document.querySelector('.waitlist-form').style.opacity = '.4';
  document.querySelector('.waitlist-form').style.pointerEvents = 'none';
  // Animate counter up
  const num = document.getElementById('waitlist-num');
  let count = 47;
  const interval = setInterval(() => {
    count++;
    num.textContent = count + ' devs';
    if (count >= 48) clearInterval(interval);
  }, 100);
}

// Scroll reveal
const observer = new IntersectionObserver(entries => {
  entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); });
}, { threshold: 0.1 });
document.querySelectorAll('.reveal').forEach(el => observer.observe(el));

// Animated counter in hero
let heroStarted = false;
function animateHero() {
  if (heroStarted) return;
  heroStarted = true;
}
setTimeout(animateHero, 500);
</script>
</body>
</html>
`;
}

// ── LANDING PAGE ─────────────────────────────────────────────────────────────
function getLandingHTML(baseUrl) {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>MockAPI Inspector — Mock Server com CRUD Real</title>
<meta name="description" content="Crie mocks de API com CRUD persistente, Faker integrado e import OpenAPI. Mais poderoso que o Beeceptor."/>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--green:#00FF87;--bg:#0a0a0a;--bg2:#111;--border:#1a1a1a}
body{background:var(--bg);color:#e0e0e0;font-family:'Inter',system-ui,sans-serif}
a{color:var(--green);text-decoration:none}
header{border-bottom:1px solid var(--border);padding:0 48px;height:60px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:rgba(10,10,10,.9);backdrop-filter:blur(12px);z-index:10}
.logo{font-size:16px;font-weight:700;color:#fff}
.logo span{color:var(--green)}
.nav-links{display:flex;gap:24px;align-items:center;font-size:14px}
.nav-links a{color:#888;transition:color .15s}
.nav-links a:hover{color:#fff}
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 20px;border-radius:8px;font-size:14px;font-weight:600;transition:all .2s;cursor:pointer;text-decoration:none}
.btn-primary{background:var(--green);color:#000}
.btn-primary:hover{background:#00e87a;transform:translateY(-1px)}
.btn-outline{border:1px solid #333;color:#888;background:transparent}
.btn-outline:hover{border-color:#555;color:#fff}
.hero{text-align:center;padding:100px 48px 80px;max-width:900px;margin:0 auto}
.hero-badge{display:inline-flex;align-items:center;gap:6px;background:#001a0a;border:1px solid #003318;border-radius:100px;padding:6px 14px;font-size:12px;color:var(--green);margin-bottom:24px}
h1{font-size:56px;font-weight:800;line-height:1.1;color:#fff;margin-bottom:20px;letter-spacing:-.02em}
h1 span{color:var(--green)}
.hero-sub{font-size:18px;color:#666;margin-bottom:40px;line-height:1.6;max-width:600px;margin-left:auto;margin-right:auto}
.hero-btns{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.features-section{padding:80px 48px;max-width:1100px;margin:0 auto}
.features-title{text-align:center;font-size:13px;color:#444;text-transform:uppercase;letter-spacing:.1em;margin-bottom:48px}
.features-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}
@media(max-width:768px){.features-grid{grid-template-columns:1fr}h1{font-size:36px}}
.feature-card{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:28px}
.feature-icon{font-size:24px;margin-bottom:14px}
.feature-title{font-size:15px;font-weight:700;color:#fff;margin-bottom:8px}
.feature-desc{font-size:13px;color:#555;line-height:1.6}
.compare-section{padding:80px 48px;background:var(--bg2);border-top:1px solid var(--border);border-bottom:1px solid var(--border)}
.compare-inner{max-width:900px;margin:0 auto}
.compare-title{text-align:center;font-size:28px;font-weight:700;color:#fff;margin-bottom:48px}
.compare-table{width:100%;border-collapse:collapse;font-size:14px}
.compare-table th{text-align:left;padding:12px 16px;color:#555;font-weight:500;border-bottom:1px solid var(--border)}
.compare-table td{padding:14px 16px;border-bottom:1px solid #0f0f0f}
.compare-table td:first-child{color:#888}
.check{color:var(--green);font-size:16px}
.cross{color:#444}
.highlight-col{background:#001408}
.cta-section{text-align:center;padding:100px 48px}
.cta-section h2{font-size:36px;font-weight:700;color:#fff;margin-bottom:16px}
.cta-section p{color:#555;margin-bottom:32px;font-size:16px}
footer{border-top:1px solid var(--border);padding:32px 48px;display:flex;justify-content:space-between;align-items:center;font-size:13px;color:#333}
.terminal{background:#0d0d0d;border:1px solid #1e1e1e;border-radius:10px;padding:20px 24px;text-align:left;margin-top:48px;max-width:560px;margin-left:auto;margin-right:auto}
.terminal-bar{display:flex;gap:6px;margin-bottom:16px}
.dot{width:10px;height:10px;border-radius:50%}
.terminal code{font-family:'Space Mono',monospace;font-size:13px;line-height:2;display:block}
.terminal .cmd{color:var(--green)}
.terminal .out{color:#666}
</style>
</head>
<body>
<header>
  <div class="logo">⚡ <span>MockAPI</span> Inspector</div>
  <div class="nav-links">
    <a href="/docs">Docs</a>
    <a href="/sdk">SDK</a>
    <a href="https://github.com/andersonrolim/mockapi" target="_blank">GitHub</a>
    <a href="/login" class="btn btn-primary" style="padding:8px 16px;font-size:13px">Começar grátis →</a>
  </div>
</header>

<section class="hero">
  <div class="hero-badge">✦ Mock server com estado persistente</div>
  <h1>Simule um <span>backend real</span> em segundos</h1>
  <p class="hero-sub">CRUD completo, Faker integrado, import OpenAPI e histórico de requisições em tempo real. Mais poderoso que o Beeceptor.</p>
  <div class="hero-btns">
    <a href="/login" class="btn btn-primary">Entrar com GitHub — é grátis</a>
    <a href="/docs" class="btn btn-outline">Ver documentação</a>
  </div>
  <div class="terminal">
    <div class="terminal-bar"><div class="dot" style="background:#ff5f57"></div><div class="dot" style="background:#febc2e"></div><div class="dot" style="background:#28c840"></div></div>
    <code><span class="cmd"># Cria um mock de users em 10 segundos</span></code>
    <code><span class="cmd">POST</span> <span style="color:#fff">https://mockapi.dev/mock/ABC123/users</span></code>
    <code><span class="out">→ {"id": "x9K2","nome": "Maria Silva","email": "maria@email.com"}</span></code>
    <code>&nbsp;</code>
    <code><span class="cmd">GET</span> <span style="color:#fff">https://mockapi.dev/mock/ABC123/users</span></code>
    <code><span class="out">→ {"data": [...], "total": 1, "page": 1}</span></code>
  </div>
</section>

<section class="features-section">
  <div class="features-title">Tudo que você precisa para mockar uma API</div>
  <div class="features-grid">
    <div class="feature-card">
      <div class="feature-icon">🗄️</div>
      <div class="feature-title">CRUD com estado real</div>
      <div class="feature-desc">GET, POST, PUT, PATCH, DELETE automáticos com persistência. Os dados ficam salvos entre requisições — diferente de mocks que resetam a cada request.</div>
    </div>
    <div class="feature-card">
      <div class="feature-icon">✦</div>
      <div class="feature-title">Faker integrado</div>
      <div class="feature-desc">Popule sua tabela com dados realistas em 1 clique. 30+ geradores: nomes, CPF, CNPJ, emails, endereços, preços, datas e muito mais.</div>
    </div>
    <div class="feature-card">
      <div class="feature-icon">📋</div>
      <div class="feature-title">Import OpenAPI</div>
      <div class="feature-desc">Cole seu spec YAML ou JSON e o sistema gera as tabelas CRUD e Mock Rules automaticamente. Suporta OpenAPI 2.x e 3.x.</div>
    </div>
    <div class="feature-card">
      <div class="feature-icon">⚡</div>
      <div class="feature-title">Histórico em tempo real</div>
      <div class="feature-desc">Veja cada requisição chegando ao vivo via WebSocket — método, status, headers, body, latência. Perfeito para debug.</div>
    </div>
    <div class="feature-card">
      <div class="feature-icon">⏱️</div>
      <div class="feature-title">Delay e Mock Rules</div>
      <div class="feature-desc">Simule latência de rede (0–5000ms), erros específicos por rota, respostas customizadas por método. Teste cenários de falha com facilidade.</div>
    </div>
    <div class="feature-card">
      <div class="feature-icon">🔒</div>
      <div class="feature-title">Login com GitHub</div>
      <div class="feature-desc">Seus endpoints são privados e isolados. Login em 1 clique via OAuth do GitHub — sem senha, sem formulário chato.</div>
    </div>
  </div>
</section>

<section class="compare-section">
  <div class="compare-inner">
    <div class="compare-title">Por que não o Beeceptor?</div>
    <table class="compare-table">
      <thead><tr><th>Feature</th><th>Beeceptor</th><th class="highlight-col" style="color:var(--green)">MockAPI Inspector</th></tr></thead>
      <tbody>
        <tr><td>Mock rules estáticas</td><td class="check">✓</td><td class="check highlight-col">✓</td></tr>
        <tr><td>CRUD com estado persistente</td><td class="cross">✗</td><td class="check highlight-col">✓</td></tr>
        <tr><td>Faker / seed de dados</td><td class="cross">✗</td><td class="check highlight-col">✓</td></tr>
        <tr><td>Import OpenAPI/Swagger</td><td class="cross">✗</td><td class="check highlight-col">✓</td></tr>
        <tr><td>Export/Import JSON</td><td class="cross">✗</td><td class="check highlight-col">✓</td></tr>
        <tr><td>Histórico em tempo real (WS)</td><td class="cross">✗</td><td class="check highlight-col">✓</td></tr>
        <tr><td>Self-hosted</td><td class="cross">✗</td><td class="check highlight-col">✓ (open source)</td></tr>
        <tr><td>Grátis para começar</td><td class="check">✓</td><td class="check highlight-col">✓</td></tr>
      </tbody>
    </table>
  </div>
</section>

<section class="cta-section">
  <h2>Pronto para usar?</h2>
  <p>Crie sua conta em 1 clique. Sem cartão de crédito.</p>
  <a href="/login" class="btn btn-primary" style="font-size:16px;padding:14px 28px">Entrar com GitHub →</a>
</section>

<footer>
  <div>⚡ MockAPI Inspector — Mock server para devs</div>
  <div style="display:flex;gap:20px"><a href="/docs" style="color:#333">Docs</a><a href="/sdk" style="color:#333">SDK</a><a href="/login" style="color:#333">Login</a></div>
</footer>
</body></html>`;
}

// ── DOCS PAGE ─────────────────────────────────────────────────────────────────
function getDocsHTML(baseUrl) {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Documentação — MockAPI Inspector</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--green:#00FF87;--bg:#0a0a0a;--bg2:#111;--bg3:#161616;--border:#1a1a1a;--text:#e0e0e0;--text2:#888;--text3:#444}
body{background:var(--bg);color:var(--text);font-family:'Inter',system-ui,sans-serif;display:flex;flex-direction:column;min-height:100vh}
a{color:var(--green);text-decoration:none}
header{border-bottom:1px solid var(--border);padding:0 32px;height:56px;display:flex;align-items:center;justify-content:space-between;background:var(--bg2);position:sticky;top:0;z-index:10}
.logo{font-size:15px;font-weight:700;color:#fff}
.logo span{color:var(--green)}
.layout{display:flex;flex:1}
.sidebar{width:240px;border-right:1px solid var(--border);padding:24px 0;position:sticky;top:56px;height:calc(100vh - 56px);overflow-y:auto;flex-shrink:0}
.sidebar-group{margin-bottom:24px}
.sidebar-group-title{font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.1em;padding:0 20px;margin-bottom:8px}
.sidebar a{display:block;padding:6px 20px;font-size:13px;color:var(--text2);transition:all .15s;border-left:2px solid transparent}
.sidebar a:hover{color:#fff;background:var(--bg3)}
.sidebar a.active{color:var(--green);border-left-color:var(--green);background:var(--bg3)}
.content{flex:1;max-width:800px;padding:40px 48px}
h1{font-size:30px;font-weight:700;color:#fff;margin-bottom:12px}
h2{font-size:20px;font-weight:700;color:#fff;margin:40px 0 12px;padding-top:40px;border-top:1px solid var(--border)}
h3{font-size:15px;font-weight:600;color:#ccc;margin:24px 0 8px}
p{color:var(--text2);line-height:1.7;margin-bottom:16px;font-size:14px}
.lead{font-size:16px;color:#aaa;line-height:1.6;margin-bottom:32px}
pre{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:20px;overflow-x:auto;margin:16px 0}
code{font-family:'Space Mono',monospace;font-size:12px;line-height:1.6}
.inline-code{background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:1px 6px;font-size:12px;color:var(--green)}
.method{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;margin-right:6px;font-family:'Space Mono',monospace}
.get{background:#001a3a;color:#4dabf7}
.post{background:#001a0a;color:var(--green)}
.put{background:#2a1a00;color:#ffa94d}
.patch{background:#1a0a2a;color:#da77f2}
.delete{background:#2a0000;color:#ff6b6b}
.endpoint-row{display:flex;align-items:center;gap:10px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px 16px;margin-bottom:10px;font-size:13px}
.endpoint-path{font-family:'Space Mono',monospace;color:#fff}
.endpoint-desc{color:var(--text2);margin-left:auto;font-size:12px}
.note{background:#001408;border:1px solid #003318;border-radius:8px;padding:14px 16px;margin:16px 0;font-size:13px;color:#aaa}
.note strong{color:var(--green)}
table{width:100%;border-collapse:collapse;font-size:13px;margin:16px 0}
th{text-align:left;color:var(--text3);font-size:11px;text-transform:uppercase;letter-spacing:.05em;padding:8px 12px;border-bottom:1px solid var(--border)}
td{padding:10px 12px;border-bottom:1px solid #0d0d0d;vertical-align:top}
td:first-child{font-family:'Space Mono',monospace;color:var(--green);font-size:12px}
td:nth-child(2){color:#888;font-size:12px}
</style>
</head>
<body>
<header>
  <div class="logo">⚡ <span>MockAPI</span> Inspector</div>
  <div style="display:flex;gap:16px;font-size:13px">
    <a href="/" style="color:#666">Home</a>
    <a href="/login" style="color:#666">Login</a>
  </div>
</header>
<div class="layout">
  <nav class="sidebar">
    <div class="sidebar-group">
      <div class="sidebar-group-title">Introdução</div>
      <a href="#intro" class="active">O que é</a>
      <a href="#quickstart">Quickstart</a>
      <a href="#concepts">Conceitos</a>
    </div>
    <div class="sidebar-group">
      <div class="sidebar-group-title">CRUD</div>
      <a href="#crud-create">Criar tabela</a>
      <a href="#crud-ops">Operações</a>
      <a href="#crud-faker">Faker</a>
    </div>
    <div class="sidebar-group">
      <div class="sidebar-group-title">Mock Rules</div>
      <a href="#rules">Regras</a>
      <a href="#delay">Delay</a>
    </div>
    <div class="sidebar-group">
      <div class="sidebar-group-title">API Reference</div>
      <a href="#api-endpoints">Endpoints</a>
      <a href="#api-crud">CRUD</a>
      <a href="#api-rules">Rules</a>
      <a href="#api-faker">Faker</a>
    </div>
  </nav>

  <div class="content">
    <h1 id="intro">MockAPI Inspector</h1>
    <p class="lead">Mock server com CRUD persistente, Faker integrado e import OpenAPI. Simule um backend completo sem escrever uma linha de código.</p>

    <h2 id="quickstart">Quickstart</h2>
    <p>Crie um endpoint e comece a receber requisições em 30 segundos:</p>
    <pre><code><span style="color:#666"># 1. Crie um endpoint no dashboard</span>
<span style="color:var(--green)">POST</span> /api/endpoints
{ "name": "Minha API" }

<span style="color:#666"># 2. Use o ID retornado para fazer requisições</span>
<span style="color:var(--green)">POST</span> ${baseUrl}/mock/{ID}/users
{ "nome": "João", "email": "joao@email.com" }

<span style="color:#666"># 3. Liste os dados salvos</span>
<span style="color:#4dabf7">GET</span>  ${baseUrl}/mock/{ID}/users
<span style="color:#666">→ { "data": [...], "total": 1, "page": 1 }</span></code></pre>

    <h2 id="concepts">Conceitos</h2>
    <h3>Endpoint</h3>
    <p>Um endpoint é um namespace isolado para sua API. Cada endpoint tem um ID único (ex: <span class="inline-code">ABC123</span>) e pode ter múltiplas tabelas CRUD e Mock Rules.</p>
    <h3>CRUD Table</h3>
    <p>Uma tabela CRUD é criada com um path (ex: <span class="inline-code">/users</span>) e automaticamente responde a GET, POST, PUT, PATCH e DELETE. Os dados ficam persistidos no banco.</p>
    <h3>Mock Rule</h3>
    <p>Uma regra que intercepta requisições para um path específico e retorna uma resposta customizada — status HTTP, delay, body fixo.</p>

    <h2 id="crud-create">Criar Tabela CRUD</h2>
    <p>No dashboard, vá em <strong>CRUD → Nova Tabela</strong> e informe o path (ex: <span class="inline-code">/produtos</span>). O sistema cria automaticamente:</p>
    <div class="endpoint-row"><span class="method get">GET</span><span class="endpoint-path">/mock/{ID}/produtos</span><span class="endpoint-desc">Lista todos com paginação</span></div>
    <div class="endpoint-row"><span class="method get">GET</span><span class="endpoint-path">/mock/{ID}/produtos/{id}</span><span class="endpoint-desc">Busca por ID</span></div>
    <div class="endpoint-row"><span class="method post">POST</span><span class="endpoint-path">/mock/{ID}/produtos</span><span class="endpoint-desc">Cria novo registro</span></div>
    <div class="endpoint-row"><span class="method put">PUT</span><span class="endpoint-path">/mock/{ID}/produtos/{id}</span><span class="endpoint-desc">Substitui registro</span></div>
    <div class="endpoint-row"><span class="method patch">PATCH</span><span class="endpoint-path">/mock/{ID}/produtos/{id}</span><span class="endpoint-desc">Atualiza campos</span></div>
    <div class="endpoint-row"><span class="method delete">DELETE</span><span class="endpoint-path">/mock/{ID}/produtos/{id}</span><span class="endpoint-desc">Remove registro</span></div>

    <h2 id="crud-ops">Paginação e Filtros</h2>
    <p>O GET de lista suporta parâmetros de query:</p>
    <table>
      <thead><tr><th>Parâmetro</th><th>Tipo</th><th>Descrição</th></tr></thead>
      <tbody>
        <tr><td>_page</td><td>number</td><td>Página (padrão: 1)</td></tr>
        <tr><td>_limit</td><td>number</td><td>Itens por página (padrão: todos)</td></tr>
      </tbody>
    </table>
    <pre><code><span style="color:#4dabf7">GET</span> /mock/{ID}/users?_page=2&_limit=10
<span style="color:#666">→ { "data": [...], "total": 47, "page": 2, "limit": 10 }</span></code></pre>

    <h2 id="crud-faker">Faker</h2>
    <p>Use templates <span class="inline-code">{"{"}{"{"}faker.field{"}"}{"}"}</span> no body do POST para gerar dados dinâmicos:</p>
    <pre><code><span style="color:var(--green)">POST</span> /mock/{ID}/users
{
  "nome":    "{{faker.name}}",
  "email":   "{{faker.email}}",
  "cidade":  "{{faker.city}}",
  "empresa": "{{faker.company}}"
}</code></pre>
    <p>Geradores disponíveis:</p>
    <table>
      <thead><tr><th>Token</th><th>Exemplo</th></tr></thead>
      <tbody>
        <tr><td>{{faker.name}}</td><td>João Silva</td></tr>
        <tr><td>{{faker.email}}</td><td>joao@email.com</td></tr>
        <tr><td>{{faker.cpf}}</td><td>123.456.789-00</td></tr>
        <tr><td>{{faker.cnpj}}</td><td>12.345.678/0001-90</td></tr>
        <tr><td>{{faker.phone}}</td><td>(11) 99999-0000</td></tr>
        <tr><td>{{faker.city}}</td><td>São Paulo</td></tr>
        <tr><td>{{faker.company}}</td><td>TechCorp Ltda</td></tr>
        <tr><td>{{faker.price}}</td><td>149.90</td></tr>
        <tr><td>{{faker.uuid}}</td><td>a1b2c3d4-...</td></tr>
        <tr><td>{{faker.date}}</td><td>2024-03-15</td></tr>
        <tr><td>{{faker.boolean}}</td><td>true</td></tr>
        <tr><td>{{faker.status}}</td><td>active</td></tr>
      </tbody>
    </table>

    <h2 id="rules">Mock Rules</h2>
    <p>Crie regras para interceptar requisições e retornar respostas customizadas. Útil para simular erros, autenticação e cenários específicos.</p>
    <pre><code><span style="color:var(--green)">POST</span> /api/rules/{epId}
{
  "method": "POST",
  "path":   "/auth/login",
  "status": 401,
  "delay":  500,
  "body":   "{\\"error\\": \\"Invalid credentials\\"}"
}</code></pre>
    <div class="note"><strong>Prioridade:</strong> Mock Rules têm prioridade sobre tabelas CRUD. Se uma requisição bate em uma Rule e também em uma tabela, a Rule vence.</div>

    <h2 id="delay">Delay Global</h2>
    <p>Configure um delay em ms para simular latência de rede em todas as requisições do endpoint. Acesse via botão <span class="inline-code">⏱ Xms</span> no dashboard.</p>
    <pre><code><span style="color:#da77f2">PATCH</span> /api/endpoints/{id}
{ "globalDelay": 1000 }  <span style="color:#666">// 1 segundo de delay em todas as resps</span></code></pre>

    <h2 id="api-endpoints">API Reference — Endpoints</h2>
    <div class="endpoint-row"><span class="method get">GET</span><span class="endpoint-path">/api/endpoints</span><span class="endpoint-desc">Lista seus endpoints</span></div>
    <div class="endpoint-row"><span class="method post">POST</span><span class="endpoint-path">/api/endpoints</span><span class="endpoint-desc">Cria endpoint</span></div>
    <div class="endpoint-row"><span class="method patch">PATCH</span><span class="endpoint-path">/api/endpoints/{id}</span><span class="endpoint-desc">Atualiza nome/delay</span></div>
    <div class="endpoint-row"><span class="method delete">DELETE</span><span class="endpoint-path">/api/endpoints/{id}</span><span class="endpoint-desc">Remove endpoint</span></div>

    <h2 id="api-crud">API Reference — CRUD</h2>
    <div class="endpoint-row"><span class="method get">GET</span><span class="endpoint-path">/api/crud/{epId}</span><span class="endpoint-desc">Lista tabelas do endpoint</span></div>
    <div class="endpoint-row"><span class="method post">POST</span><span class="endpoint-path">/api/crud/{epId}</span><span class="endpoint-desc">Cria nova tabela CRUD</span></div>
    <div class="endpoint-row"><span class="method delete">DELETE</span><span class="endpoint-path">/api/crud/{epId}/{key}</span><span class="endpoint-desc">Remove tabela</span></div>
    <div class="endpoint-row"><span class="method get">GET</span><span class="endpoint-path">/api/export/{epId}/{key}</span><span class="endpoint-desc">Exporta dados como JSON</span></div>
    <div class="endpoint-row"><span class="method post">POST</span><span class="endpoint-path">/api/import/{epId}</span><span class="endpoint-desc">Importa dados JSON</span></div>

    <h2 id="api-rules">API Reference — Rules</h2>
    <div class="endpoint-row"><span class="method get">GET</span><span class="endpoint-path">/api/rules/{epId}</span><span class="endpoint-desc">Lista regras</span></div>
    <div class="endpoint-row"><span class="method post">POST</span><span class="endpoint-path">/api/rules/{epId}</span><span class="endpoint-desc">Cria regra</span></div>
    <div class="endpoint-row"><span class="method delete">DELETE</span><span class="endpoint-path">/api/rules/{epId}/{ruleId}</span><span class="endpoint-desc">Remove regra</span></div>

    <h2 id="api-faker">API Reference — Faker</h2>
    <div class="endpoint-row"><span class="method post">POST</span><span class="endpoint-path">/api/faker/{epId}/{key}</span><span class="endpoint-desc">Seed em massa</span></div>
    <pre><code><span style="color:var(--green)">POST</span> /api/faker/{epId}/users
{
  "template": { "nome": "{{faker.name}}", "email": "{{faker.email}}" },
  "count": 50
}</code></pre>

    <div style="margin-top:60px;padding-top:32px;border-top:1px solid var(--border);color:var(--text3);font-size:13px">
      MockAPI Inspector — <a href="/">Home</a> · <a href="/login">Login</a>
    </div>
  </div>
</div>
</body></html>`;
}

function getDashboardHTML(port, baseUrl, currentUser) {
  baseUrl = baseUrl || 'http://localhost:' + port;
  // Pre-build user bar HTML (avoids nested template literal escaping issues)
  let userBarHtml = '';
  if (currentUser) {
    const adminLink = currentUser.isAdmin
      ? '<a href="/admin" style="font-size:10px;color:#FFD700;text-decoration:none;white-space:nowrap">Admin</a>'
      : '';
    userBarHtml = '<div style="display:flex;align-items:center;gap:8px;width:100%;padding-top:4px;border-top:1px solid #1a1a1a">'
      + '<img src="' + (currentUser.avatar||'') + '" style="width:24px;height:24px;border-radius:50%;flex-shrink:0"/>'
      + '<span style="font-size:12px;color:#aaa;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + (currentUser.login||'') + '</span>'
      + adminLink
      + '<a href="/auth/logout" style="font-size:10px;color:#555;text-decoration:none">Sair</a>'
      + '</div>';
  }
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
.ep-item{padding:10px 12px;border-radius:8px;cursor:pointer;border:1px solid transparent;margin-bottom:4px;transition:all .15s;animation:slideIn .2s ease;min-width:0}
.ep-item:hover{background:var(--bg3)}
.ep-item.active{background:var(--bg4);border-color:var(--border2)}
.ep-name{font-size:13px;font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;display:block}
.ep-meta{display:flex;justify-content:space-between;align-items:center;margin-top:4px;gap:4px;min-width:0}
.ep-id{font-size:10px;color:var(--text3);font-family:'Space Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;min-width:0}
.ep-count{font-size:11px;color:var(--text3);font-family:'Space Mono',monospace;white-space:nowrap;flex-shrink:0}
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
.revoke-btn{background:none;border:1px solid #2a2a2a;color:#555;border-radius:6px;padding:4px 10px;font-size:11px;cursor:pointer;transition:all .2s;flex-shrink:0}
.revoke-btn:hover{color:#ff4444;border-color:#ff444433}
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
@keyframes slideDown{from{transform:translateY(-100%);opacity:0}to{transform:translateY(0);opacity:1}}
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

    <div class="sidebar-footer" style="flex-direction:column;align-items:flex-start;gap:10px">
      <div style="display:flex;align-items:center;gap:8px;width:100%">
        <div class="status-dot" id="ws-dot" style="background:#FF4444;box-shadow:0 0 6px #FF4444"></div>
        <span class="mono" style="font-size:10px;color:var(--text3);flex:1" id="ws-status">Conectando...</span>
      </div>
      <div id="plan-usage" style="width:100%;padding-top:4px;border-top:1px solid #1a1a1a"></div>
      <div style="display:flex;gap:6px;width:100%;padding-top:4px;border-top:1px solid #131313">
        <a href="/docs" target="_blank" style="font-size:10px;color:#333;text-decoration:none;flex:1;text-align:center;padding:4px 0;border-radius:4px;border:1px solid #1a1a1a;transition:all .2s" onmouseover="this.style.color='#00FF87';this.style.borderColor='#00FF8733'" onmouseout="this.style.color='#333';this.style.borderColor='#1a1a1a'">📄 Docs</a>
        <button onclick="showTokenModal()" style="font-size:10px;color:#333;background:none;cursor:pointer;flex:1;text-align:center;padding:4px 0;border-radius:4px;border:1px solid #1a1a1a;transition:all .2s" onmouseover="this.style.color='#7DD3FC';this.style.borderColor='#7DD3FC33'" onmouseout="this.style.color='#333';this.style.borderColor='#1a1a1a'">🔑 Tokens</button>
        <a href="/upgrade" style="font-size:10px;color:#333;text-decoration:none;flex:1;text-align:center;padding:4px 0;border-radius:4px;border:1px solid #1a1a1a;transition:all .2s" id="upgrade-sidebar-link" onmouseover="this.style.color='#ff8c00';this.style.borderColor='#ff8c0033'" onmouseout="this.style.color='#333';this.style.borderColor='#1a1a1a'">⚡ Planos</a>
      </div>
      ${userBarHtml}
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
      <button id="empty-cta-btn" class="btn-primary" style="padding:14px 32px;font-size:15px;flex:none;width:auto" onclick="emptyCtaClick()">+ Criar Primeiro Endpoint</button>
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
            <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap">
              <div style="display:flex;align-items:center;gap:10px;min-width:0">
                <span style="font-size:22px;flex-shrink:0">🗄️</span>
                <div>
                  <h3 style="color:#fff;font-size:16px;margin-bottom:2px">Tabelas CRUD</h3>
                  <p style="font-size:12px;color:var(--text3)">GET · POST · PUT · PATCH · DELETE automáticos com persistência</p>
                </div>
              </div>
              <div style="display:flex;gap:8px;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end">
                <button style="background:#F9731615;border:1px solid #F9731644;border-radius:8px;padding:9px 14px;color:#FB923C;font-size:12px;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:6px;transition:all .2s;white-space:nowrap" onclick="showPostmanModal()" onmouseover="this.style.background='#F9731625'" onmouseout="this.style.background='#F9731615'">
                  📦 Postman
                </button>
                <button style="background:#7C3AED15;border:1px solid #7C3AED44;border-radius:8px;padding:9px 14px;color:#A78BFA;font-size:12px;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:6px;transition:all .2s;white-space:nowrap" onclick="showOpenApiModal()" onmouseover="this.style.background='#7C3AED25'" onmouseout="this.style.background='#7C3AED15'">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                  OpenAPI
                </button>
                <button class="btn-primary btn-icon" style="padding:9px 16px;font-size:13px;flex:none;width:auto;white-space:nowrap" onclick="showCrudModal()">
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
<div id="url-tester" style="display:none;position:fixed;bottom:24px;left:50%;transform:translateX(-50%);width:calc(100% - 280px);max-width:620px;background:var(--bg2);border:1px solid var(--border2);border-radius:10px;padding:14px 18px;z-index:500;box-shadow:0 8px 32px rgba(0,0,0,.6)">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
    <span style="font-size:11px;color:var(--text3);font-family:'Space Mono',monospace;letter-spacing:1px">TESTADOR DE URL</span>
    <button onclick="document.getElementById('url-tester').style.display='none'" style="background:none;border:none;color:var(--text4);cursor:pointer;font-size:16px;padding:0 2px">✕</button>
  </div>
  <div style="font-size:10px;color:var(--text3);font-family:'Space Mono',monospace;margin-bottom:6px">CAMINHO ADICIONAL</div>
  <div class="url-builder-row" style="margin-bottom:8px">
    <span class="url-base" id="tester-base" style="font-size:10px;padding:0 8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:260px;flex-shrink:0"></span>
    <input class="url-input" id="tester-path" placeholder="/users/123" oninput="updateTesterUrl()" style="flex:1;min-width:0"/>
  </div>
  <div style="font-size:10px;color:var(--text3);font-family:'Space Mono',monospace;margin-bottom:4px">URL COMPLETA</div>
  <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;background:#0d0d0d;border-radius:6px;padding:6px 10px;border:1px solid #1a1a1a">
    <code style="font-size:11px;color:var(--green);font-family:'Space Mono',monospace;word-break:break-all;flex:1;min-width:0" id="tester-full-url"></code>
    <button class="url-copy" onclick="copyTesterUrl()" style="border:1px solid var(--border2);border-radius:6px;flex-shrink:0;padding:4px 10px;font-size:11px">Copiar</button>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px">
    <button onclick="sendTestRequest('GET')" style="background:#00C8FF22;border:1px solid #00C8FF44;border-radius:6px;padding:7px;color:#00C8FF;font-size:11px;font-weight:700;font-family:'Space Mono',monospace;cursor:pointer">GET</button>
    <button onclick="sendTestRequest('POST')" style="background:#00FF8722;border:1px solid #00FF8744;border-radius:6px;padding:7px;color:#00FF87;font-size:11px;font-weight:700;font-family:'Space Mono',monospace;cursor:pointer">POST</button>
    <button onclick="sendTestRequest('DELETE')" style="background:#FF444422;border:1px solid #FF444444;border-radius:6px;padding:7px;color:#FF6B6B;font-size:11px;font-weight:700;font-family:'Space Mono',monospace;cursor:pointer">DELETE</button>
  </div>
</div>

<!-- API TOKENS MODAL -->
<div id="token-modal" style="display:none" class="modal-overlay">
  <div class="modal" style="max-width:520px">
    <div class="modal-row">
      <h2 class="modal-title" style="margin:0">🔑 API Tokens</h2>
      <button onclick="hideTokenModal()" style="background:none;border:none;color:var(--text3);cursor:pointer">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <p style="font-size:12px;color:#555;margin-bottom:16px">Use tokens para autenticar o SDK ou chamadas diretas à API sem precisar de login.</p>

    <div style="display:flex;gap:8px;margin-bottom:16px">
      <input id="token-name-input" class="form-input" placeholder="Nome do token (ex: CI/CD, projeto-x)" style="flex:1"/>
      <button class="btn-primary" style="flex:none;width:auto;padding:0 16px;font-size:13px" onclick="createToken()">Gerar</button>
    </div>

    <div id="token-new-reveal" style="display:none;background:#0a1a0a;border:1px solid #00FF8733;border-radius:8px;padding:12px;margin-bottom:16px">
      <div style="font-size:10px;color:#00FF87;letter-spacing:1px;margin-bottom:6px;font-family:monospace">✓ TOKEN GERADO — COPIE AGORA, NÃO SERÁ MOSTRADO NOVAMENTE</div>
      <div style="display:flex;gap:8px;align-items:center">
        <code id="token-new-value" style="font-family:monospace;font-size:12px;color:#00FF87;flex:1;word-break:break-all"></code>
        <button onclick="copyNewToken()" style="background:#00FF8722;border:1px solid #00FF8744;border-radius:6px;padding:6px 12px;color:#00FF87;font-size:11px;cursor:pointer;flex-shrink:0">Copiar</button>
      </div>
    </div>

    <div style="font-size:11px;color:#333;margin-bottom:8px;text-transform:uppercase;letter-spacing:.06em">Tokens ativos</div>
    <div id="token-list" style="display:flex;flex-direction:column;gap:6px;max-height:240px;overflow-y:auto">
      <div style="color:#333;font-size:12px;padding:16px;text-align:center">Carregando...</div>
    </div>
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
    case 'rule_updated':
      if (state.rules[endpointId]) {
        const idx = state.rules[endpointId].findIndex(r => r.id === payload.id);
        if (idx >= 0) state.rules[endpointId][idx] = payload;
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
    const res = await fetch('/api/endpoints', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name,
        path: document.getElementById('ep-path-input').value.trim(),
        corsEnabled: state.corsOn,
        rateLimit: parseInt(document.getElementById('ep-ratelimit-input').value) || 100,
      })
    });
    if (res.status === 403) {
      const err = await res.json();
      hideCreateModal();
      showUpgradeBanner(err.limit);
      return;
    }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const ep = await res.json();
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

function showUpgradeBanner(limit) {
  const existing = document.getElementById('upgrade-banner');
  if (existing) existing.remove();

  const banner = document.createElement('div');
  banner.id = 'upgrade-banner';
  banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;background:linear-gradient(135deg,#1a0a00,#2a1200);border-bottom:1px solid #ff8c00;padding:14px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px;animation:slideDown .3s ease';

  const left = document.createElement('div');
  left.style.cssText = 'display:flex;align-items:center;gap:12px';
  left.innerHTML = '<span style="font-size:20px">⚡</span>'
    + '<div><strong style="color:#ff8c00;font-size:14px">Limite do plano Free atingido</strong>'
    + '<div style="font-size:12px;color:#888;margin-top:2px">Você usou ' + limit + '/' + limit + ' endpoints. Faça upgrade para criar mais.</div></div>';

  const right = document.createElement('div');
  right.style.cssText = 'display:flex;gap:8px;flex-shrink:0';

  const upgradeLink = document.createElement('a');
  upgradeLink.href = '/upgrade';
  upgradeLink.style.cssText = 'background:#ff8c00;color:#000;padding:8px 16px;border-radius:6px;font-size:13px;font-weight:700;text-decoration:none';
  upgradeLink.textContent = 'Fazer Upgrade →';

  const closeBtn = document.createElement('button');
  closeBtn.style.cssText = 'background:none;border:1px solid #333;color:#666;padding:8px 12px;border-radius:6px;font-size:13px;cursor:pointer';
  closeBtn.textContent = '✕';
  closeBtn.addEventListener('click', function() { banner.remove(); });

  right.appendChild(upgradeLink);
  right.appendChild(closeBtn);
  banner.appendChild(left);
  banner.appendChild(right);
  document.body.prepend(banner);
}

async function deleteEndpoint(id, e) {
  e.stopPropagation();
  await api('DELETE', '/api/endpoints/' + id);
  toast('Endpoint removido.', 'error');
}

// ── API TOKEN MODAL ────────────────────────────────────────────────────────────
async function showTokenModal() {
  document.getElementById('token-modal').style.display = 'flex';
  document.getElementById('token-new-reveal').style.display = 'none';
  document.getElementById('token-name-input').value = '';
  await loadTokenList();
}

function hideTokenModal() {
  document.getElementById('token-modal').style.display = 'none';
}

async function loadTokenList() {
  const list = document.getElementById('token-list');
  list.innerHTML = '<div style="color:#333;font-size:12px;padding:16px;text-align:center">Carregando...</div>';
  try {
    const tokens = await api('GET', '/api/tokens');
    if (!tokens || tokens.length === 0) {
      list.innerHTML = '<div style="color:#333;font-size:12px;padding:16px;text-align:center">Nenhum token ainda. Gere um acima.</div>';
      return;
    }
    list.innerHTML = tokens.map(t => {
      const lastUsed = t.last_used ? new Date(t.last_used).toLocaleDateString('pt-BR') : 'nunca';
      const created  = (t.created_at||'').slice(0,10);
      return '<div style="background:#0d0d0d;border:1px solid #1a1a1a;border-radius:8px;padding:10px 14px;display:flex;align-items:center;gap:10px">'
        + '<div style="flex:1;min-width:0">'
        + '<div style="font-size:13px;color:#ccc;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(t.name) + '</div>'
        + '<div style="font-size:10px;color:#444;font-family:monospace;margin-top:2px">' + t.token_preview + ' · criado ' + created + ' · usado ' + lastUsed + '</div>'
        + '</div>'
        + '<button data-tid="'+t.id+'" onclick="deleteToken(this)" class="revoke-btn">Revogar</button>'
        + '</div>';
    }).join('');
  } catch(e) {
    list.innerHTML = '<div style="color:#555;font-size:12px;padding:16px;text-align:center">Erro ao carregar tokens.</div>';
  }
}

async function createToken() {
  const nameInput = document.getElementById('token-name-input');
  const name = nameInput.value.trim() || ('Token ' + new Date().toLocaleDateString('pt-BR'));
  try {
    const data = await api('POST', '/api/tokens', { name });
    if (!data || !data.token) { toast('Erro ao gerar token', 'error'); return; }
    document.getElementById('token-new-value').textContent = data.token;
    document.getElementById('token-new-reveal').style.display = 'block';
    nameInput.value = '';
    await loadTokenList();
    toast('Token gerado! Copie agora — não será exibido novamente.', 'success');
  } catch(e) {
    toast('Erro ao gerar token', 'error');
  }
}

function copyNewToken() {
  const val = document.getElementById('token-new-value').textContent;
  navigator.clipboard.writeText(val).then(() => toast('Token copiado!', 'success'));
}

async function deleteToken(btn) {
  const id = btn.dataset.tid;
  if (!confirm('Revogar este token? Aplicações que o usam perderão acesso.')) return;
  await api('DELETE', '/api/tokens/' + id);
  toast('Token revogado.', 'error');
  await loadTokenList();
}

function emptyCtaClick() {
  if (window._atEpLimit) { window.location.href = '/upgrade'; }
  else { showCreateModal(); }
}

function updatePlanUsage() {
  fetch('/api/me').then(r => r.json()).then(d => {
    if (!d.loggedIn || !d.user || !d.user.limits) return;
    const lim  = d.user.limits;
    const plan = d.user.plan;
    const epPct  = lim.endpoints.pct;
    const reqPct = lim.reqPerDay.pct;
    const el = document.getElementById('plan-usage');
    if (!el) return;
    const epColor  = epPct  >= 100 ? '#ff4444' : epPct  >= 80 ? '#ff8c00' : '#00FF87';
    const reqColor = reqPct >= 100 ? '#ff4444' : reqPct >= 80 ? '#ff8c00' : '#00FF87';
    const epMax  = lim.endpoints.max >= 1e9 ? '\u221e' : lim.endpoints.max;
    const reqMax = lim.reqPerDay.max >= 1e9 ? '\u221e' : lim.reqPerDay.max.toLocaleString();
    el.innerHTML =
      '<div style="margin-bottom:6px">'
      + '<div style="display:flex;justify-content:space-between;margin-bottom:3px">'
      + '<span style="font-size:10px;color:#555;text-transform:uppercase;letter-spacing:.06em">' + plan.toUpperCase() + ' · Endpoints</span>'
      + '<span style="font-size:10px;color:#555">' + lim.endpoints.used + '/' + epMax + '</span>'
      + '</div>'
      + '<div style="background:#1a1a1a;border-radius:4px;height:3px">'
      + '<div style="background:' + epColor + ';height:3px;width:' + Math.min(epPct,100) + '%;border-radius:4px;transition:width .5s"></div>'
      + '</div></div>'
      + '<div>'
      + '<div style="display:flex;justify-content:space-between;margin-bottom:3px">'
      + '<span style="font-size:10px;color:#555">Requisições hoje</span>'
      + '<span style="font-size:10px;color:#555">' + lim.reqPerDay.used.toLocaleString() + '/' + reqMax + '</span>'
      + '</div>'
      + '<div style="background:#1a1a1a;border-radius:4px;height:3px">'
      + '<div style="background:' + reqColor + ';height:3px;width:' + Math.min(reqPct,100) + '%;border-radius:4px;transition:width .5s"></div>'
      + '</div></div>';
    // Update state flag
    window._atEpLimit = epPct >= 100;
    // Update sidebar "Novo Endpoint" button
    const newEpBtn = document.querySelector('.new-ep-btn');
    if (newEpBtn) {
      if (epPct >= 100) {
        newEpBtn.style.cssText += ';background:linear-gradient(135deg,#ff8c00,#ff6600);border-color:#ff8c00;color:#000';
        newEpBtn.onclick = () => window.location.href = '/upgrade';
        newEpBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Upgrade ⚡';
      } else {
        newEpBtn.style.cssText = '';
        newEpBtn.onclick = () => showCreateModal();
        newEpBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Novo Endpoint';
      }
    }
    // Update empty-state CTA button
    const ctaBtn = document.getElementById('empty-cta-btn');
    if (ctaBtn) {
      if (epPct >= 100) {
        ctaBtn.style.background = 'linear-gradient(135deg,#ff8c00,#ff6600)';
        ctaBtn.style.color = '#000';
        ctaBtn.style.boxShadow = '0 0 20px #ff8c0066';
        ctaBtn.textContent = '⚡ Fazer Upgrade';
      } else {
        ctaBtn.style.background = '';
        ctaBtn.style.color = '';
        ctaBtn.style.boxShadow = '';
        ctaBtn.textContent = '+ Criar Primeiro Endpoint';
      }
    }
  }).catch(() => {});
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
  state._editingRuleId = null;
  document.getElementById('rule-path').value = '';
  document.getElementById('rule-method').value = '*';
  document.getElementById('rule-status').value = '200';
  document.getElementById('rule-delay').value = '0';
  document.getElementById('delay-val').textContent = '0';
  document.getElementById('rule-body').value = '{\\n  "message": "Mock response"\\n}';
  const title = document.querySelector('#rule-modal .modal-title');
  if (title) title.textContent = 'Nova Mock Rule';
  const btn = document.querySelector('#rule-modal .btn-primary');
  if (btn) btn.textContent = 'Salvar Regra';
  document.getElementById('rule-modal').style.display = 'flex';
}
function hideRuleModal() {
  state._editingRuleId = null;
  document.getElementById('rule-modal').style.display = 'none';
}
function editRule(epId, ruleId) {
  const rules = state.rules[epId] || [];
  const r = rules.find(x => x.id === ruleId);
  if (!r) return;
  state._editingRuleId = ruleId;
  document.getElementById('rule-path').value   = r.path   || '';
  document.getElementById('rule-method').value = r.method || '*';
  document.getElementById('rule-status').value = r.status || 200;
  document.getElementById('rule-delay').value  = r.delay  || 0;
  document.getElementById('delay-val').textContent = r.delay || 0;
  // Pretty-print JSON body if possible
  let body = r.body || '';
  try { body = JSON.stringify(JSON.parse(body), null, 2); } catch(_) {}
  document.getElementById('rule-body').value = body;
  const title = document.querySelector('#rule-modal .modal-title');
  if (title) title.textContent = 'Editar Mock Rule';
  const btn = document.querySelector('#rule-modal .btn-primary');
  if (btn) btn.textContent = 'Atualizar Regra';
  document.getElementById('rule-modal').style.display = 'flex';
}

async function createRule() {
  const epId = state.selectedEp;
  const rule = {
    path:   document.getElementById('rule-path').value.trim(),
    method: document.getElementById('rule-method').value,
    status: parseInt(document.getElementById('rule-status').value),
    delay:  parseInt(document.getElementById('rule-delay').value) || 0,
    body:   document.getElementById('rule-body').value,
  };
  if (state._editingRuleId) {
    await api('PATCH', '/api/rules/' + epId + '/' + state._editingRuleId, rule);
    toast('Regra atualizada!', 'success');
  } else {
    await api('POST', '/api/rules/' + epId, rule);
    toast('Regra salva!', 'success');
  }
  hideRuleModal();
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
    return \`<div class="rule-item" onclick="editRule('\${epId}','\${r.id}')" style="cursor:pointer" title="Clique para editar">
      <span class="method" style="color:\${mc}">\${r.method}</span>
      <code class="rule-path">\${esc(r.path || '/*')}</code>
      <span class="status" style="background:\${sc.bg};color:\${sc.t}">\${r.status}</span>
      \${r.delay ? \`<span class="rule-delay">+\${r.delay}ms</span>\` : ''}
      <button class="rule-del" onclick="event.stopPropagation();deleteRule('\${epId}','\${r.id}')">
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
      style="background:#111;border-radius:5px;padding:6px 10px;display:flex;align-items:center;gap:8px;cursor:pointer;transition:background .15s;min-width:0;overflow:hidden"
      onmouseover="this.style.background='#1a1a1a'" onmouseout="this.style.background='#111'" title="\${esc(url)}">
      <span style="color:\${MC[m]||'#aaa'};width:54px;flex-shrink:0;font-weight:700;font-size:10px;letter-spacing:.04em">\${m}</span>
      <span style="color:#444;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:10px;flex:1;min-width:0">\${esc(url)}</span>
      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#2a2a2a" stroke-width="2" style="flex-shrink:0"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
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
      <div style="display:flex;flex-direction:column;gap:3px">
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

// ── POSTMAN IMPORT ────────────────────────────────────────────────────────────
function showPostmanModal() {
  document.getElementById('postman-json').value = '';
  document.getElementById('postman-preview').style.display = 'none';
  document.getElementById('postman-result').style.display = 'none';
  document.getElementById('postman-import-btn').disabled = true;
  document.getElementById('postman-import-btn').style.opacity = '.5';
  document.getElementById('postman-modal').style.display = 'flex';
}
function closePostmanModal() {
  document.getElementById('postman-modal').style.display = 'none';
}
function handlePostmanDrop(e) {
  e.preventDefault();
  const dz = document.getElementById('postman-drop-zone');
  dz.style.borderColor = 'var(--border2)'; dz.style.background = '';
  const file = e.dataTransfer.files[0];
  if (!file) return;
  readPostmanFile(file);
}
function handlePostmanFile(input) {
  if (!input.files[0]) return;
  readPostmanFile(input.files[0]);
}
function readPostmanFile(file) {
  const reader = new FileReader();
  reader.onload = e => {
    document.getElementById('postman-json').value = e.target.result;
    previewPostman();
  };
  reader.readAsText(file);
}
async function previewPostman() {
  const raw = document.getElementById('postman-json').value.trim();
  if (!raw) { toast('Cole o JSON da collection.', 'error'); return; }
  let collection;
  try { collection = JSON.parse(raw); } catch(_) { toast('JSON inválido.', 'error'); return; }
  const btn = document.getElementById('postman-preview-btn');
  btn.textContent = '⏳ Analisando...'; btn.disabled = true;
  const result = await api('POST', '/api/postman/preview', { collection });
  btn.textContent = '👁 Preview'; btn.disabled = false;
  if (result.error) { toast(result.error, 'error'); return; }
  // Render preview
  const list = document.getElementById('postman-preview-list');
  list.innerHTML = renderPostmanPreview(result.endpoints);
  const total = result.endpoints.reduce((s,e)=>s+e.rules.length,0);
  document.getElementById('postman-preview').style.display = 'block';
  document.getElementById('postman-import-btn').disabled = false;
  document.getElementById('postman-import-btn').style.opacity = '1';
  toast('Preview: ' + result.endpoints.length + ' endpoint(s), ' + total + ' requests', 'success');
}
async function importPostman() {
  const raw = document.getElementById('postman-json').value.trim();
  if (!raw) return;
  let collection;
  try { collection = JSON.parse(raw); } catch(_) { toast('JSON inválido.', 'error'); return; }
  const btn = document.getElementById('postman-import-btn');
  btn.textContent = '⏳ Importando...'; btn.disabled = true;
  const result = await api('POST', '/api/postman', { collection });
  btn.textContent = 'Importar'; btn.disabled = false;
  if (result.error) { toast(result.error, 'error'); return; }
  const resEl = document.getElementById('postman-result');
  resEl.style.display = 'block';
  const total = result.details.reduce((s,e)=>s+e.rules,0);
  resEl.innerHTML = '✓ <strong>' + esc(result.details[0]?.name || 'Collection') + '</strong> importada!<br>'
    + result.endpoints + ' endpoint(s) criado(s) · ' + total + ' mock rules';
  // Reload endpoints list
  const eps = await api('GET', '/api/endpoints');
  if (eps && !eps.error) {
    state.endpoints = eps;
    renderEndpointList();
    if (eps.length > 0 && !state.selectedEp) selectEndpoint(eps[eps.length-1].id);
  }
  toast('Collection importada: ' + total + ' regras criadas!', 'success');
}
function methodColor(m) {
  return { GET:'#00C8FF', POST:'#00FF87', PUT:'#FFD23F', PATCH:'#FB923C', DELETE:'#FF4D6D' }[m] || '#94A3B8';
}
function renderPostmanPreview(endpoints) {
  return endpoints.map(function(ep) {
    var rows = ep.rules.map(function(r) {
      var c = methodColor(r.method);
      return '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--border)">'
        + '<span style="font-size:10px;font-weight:700;color:' + c + ';background:' + c + '18;padding:2px 7px;border-radius:4px;min-width:46px;text-align:center">' + esc(r.method) + '</span>'
        + '<span style="font-size:12px;color:var(--text2);font-family:var(--mono)">' + esc(r.path) + '</span>'
        + '<span style="margin-left:auto;font-size:11px;color:var(--text3)">' + r.status + '</span>'
        + '</div>';
    }).join('');
    return '<div style="margin-bottom:12px">'
      + '<div style="font-size:12px;font-weight:700;color:var(--text);margin-bottom:6px">📁 ' + esc(ep.name) + '</div>'
      + rows
      + '</div>';
  }).join('');
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
  updatePlanUsage();
}

init();

// Keyboard shortcuts
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    hideCreateModal(); hideRuleModal(); hideCrudModal(); hideCrudDataModal();
    ['add-row-modal','delay-modal','openapi-modal','faker-modal','postman-modal'].forEach(id => {
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
<div id="postman-modal" class="modal-overlay" style="display:none">
  <div class="modal" style="width:640px;max-height:85vh;overflow:auto">
    <div class="modal-row">
      <h2 class="modal-title" style="margin:0">📦 Import Postman Collection</h2>
      <button onclick="closePostmanModal()" style="background:none;border:none;color:var(--text3);font-size:20px;cursor:pointer">✕</button>
    </div>
    <p style="font-size:12px;color:var(--text3);margin:0 0 16px">No Postman: <strong style="color:var(--text)">Export → Collection v2.1</strong> → cole o JSON abaixo.<br/>Serão criadas <strong style="color:var(--text)">Mock Rules</strong> para cada request da collection.</p>

    <div id="postman-drop-zone" style="border:2px dashed var(--border2);border-radius:10px;padding:32px;text-align:center;cursor:pointer;transition:all .2s;margin-bottom:16px"
      onclick="document.getElementById('postman-file-input').click()"
      ondragover="event.preventDefault();this.style.borderColor='var(--green)';this.style.background='#00FF8708'"
      ondragleave="this.style.borderColor='var(--border2)';this.style.background=''"
      ondrop="handlePostmanDrop(event)">
      <div style="font-size:28px;margin-bottom:8px">📂</div>
      <div style="font-size:13px;color:var(--text2)">Arraste o arquivo <code style="color:var(--green)">.json</code> aqui</div>
      <div style="font-size:11px;color:var(--text3);margin-top:4px">ou clique para selecionar</div>
      <input type="file" id="postman-file-input" accept=".json" style="display:none" onchange="handlePostmanFile(this)"/>
    </div>

    <div style="text-align:center;font-size:11px;color:var(--text3);margin-bottom:12px">— ou cole o JSON diretamente —</div>

    <textarea class="form-textarea" id="postman-json" rows="8" style="font-size:11px" placeholder='{"info":{"name":"Minha API",...},"item":[...]}'></textarea>

    <!-- Preview area -->
    <div id="postman-preview" style="display:none;margin-top:12px;background:var(--bg3);border:1px solid var(--border2);border-radius:8px;padding:16px;max-height:240px;overflow-y:auto">
      <div style="font-size:11px;color:var(--text3);letter-spacing:.06em;text-transform:uppercase;margin-bottom:10px">Preview — o que será importado</div>
      <div id="postman-preview-list"></div>
    </div>

    <div id="postman-result" style="display:none;background:#0A1A0A;border:1px solid #00FF8733;border-radius:8px;padding:12px;margin-top:12px;font-size:13px;color:var(--green);font-family:var(--mono)"></div>

    <div class="btn-row" style="margin-top:16px">
      <button class="btn-cancel" onclick="closePostmanModal()">Cancelar</button>
      <button id="postman-preview-btn" class="btn-secondary" onclick="previewPostman()" style="width:auto;padding:0 16px">👁 Preview</button>
      <button id="postman-import-btn" class="btn-primary" onclick="importPostman()" disabled style="opacity:.5">Importar</button>
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
