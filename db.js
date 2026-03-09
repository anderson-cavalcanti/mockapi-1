/**
 * db.js — SQLite persistence layer
 * Usa better-sqlite3 (compatível com Node.js 18, 20, 22+)
 *
 * Instalação: npm install better-sqlite3
 */
const Database = require('better-sqlite3');
const path     = require('path');

const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'mockapi.db');

let db;
try {
  db = new Database(DB_FILE);
} catch(e) {
  console.warn('[db] Erro ao abrir arquivo, usando in-memory:', e.message);
  db = new Database(':memory:');
}

// ── SCHEMA ───────────────────────────────────────────────────────────────────
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS endpoints (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    path         TEXT,
    cors         INTEGER DEFAULT 1,
    global_delay INTEGER DEFAULT 0,
    rate_limit   INTEGER DEFAULT 100,
    req_count    INTEGER DEFAULT 0,
    created_at   TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS requests (
    id            TEXT PRIMARY KEY,
    endpoint_id   TEXT NOT NULL,
    method        TEXT,
    path          TEXT,
    full_url      TEXT,
    status        INTEGER,
    latency       INTEGER DEFAULT 0,
    ip            TEXT,
    headers       TEXT,
    query_params  TEXT,
    request_body  TEXT,
    response_body TEXT,
    matched_rule  TEXT,
    ts            TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    method      TEXT DEFAULT '*',
    path        TEXT DEFAULT '/*',
    status      INTEGER DEFAULT 200,
    delay       INTEGER DEFAULT 0,
    body        TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS crud_tables (
    key         TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    path        TEXT NOT NULL,
    id_field    TEXT DEFAULT 'id',
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS crud_rows (
    row_id     TEXT NOT NULL,
    table_key  TEXT NOT NULL,
    data       TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (row_id, table_key),
    FOREIGN KEY (table_key) REFERENCES crud_tables(key) ON DELETE CASCADE
  );
`);

// ── PREPARED STATEMENTS ───────────────────────────────────────────────────────
const stmts = {
  // Endpoints
  epInsert:    db.prepare(`INSERT OR REPLACE INTO endpoints VALUES (?,?,?,?,?,?,?,?)`),
  epUpdate:    db.prepare(`UPDATE endpoints SET name=?,path=?,cors=?,global_delay=?,rate_limit=? WHERE id=?`),
  epIncCount:  db.prepare(`UPDATE endpoints SET req_count = req_count + 1 WHERE id=?`),
  epDelete:    db.prepare(`DELETE FROM endpoints WHERE id=?`),
  epAll:       db.prepare(`SELECT * FROM endpoints ORDER BY created_at DESC`),
  epGet:       db.prepare(`SELECT * FROM endpoints WHERE id=?`),

  // Requests
  reqInsert:   db.prepare(`INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`),
  reqByEp:     db.prepare(`SELECT * FROM requests WHERE endpoint_id=? ORDER BY ts DESC LIMIT 200`),
  reqClear:    db.prepare(`DELETE FROM requests WHERE endpoint_id=?`),
  reqDelOld:   db.prepare(`DELETE FROM requests WHERE id=?`),

  // Rules
  ruleInsert:  db.prepare(`INSERT INTO rules VALUES (?,?,?,?,?,?,?,?)`),
  ruleDelete:  db.prepare(`DELETE FROM rules WHERE id=?`),
  rulesByEp:   db.prepare(`SELECT * FROM rules WHERE endpoint_id=? ORDER BY created_at DESC`),

  // CRUD tables
  crudInsert:  db.prepare(`INSERT OR REPLACE INTO crud_tables VALUES (?,?,?,?,?)`),
  crudDelete:  db.prepare(`DELETE FROM crud_tables WHERE key=?`),
  crudByEp:    db.prepare(`SELECT * FROM crud_tables WHERE endpoint_id=?`),
  crudGet:     db.prepare(`SELECT * FROM crud_tables WHERE key=?`),
  crudAll:     db.prepare(`SELECT * FROM crud_tables`),

  // CRUD rows
  rowInsert:   db.prepare(`INSERT OR REPLACE INTO crud_rows VALUES (?,?,?,?,?)`),
  rowUpdate:   db.prepare(`UPDATE crud_rows SET data=?, updated_at=datetime('now') WHERE row_id=? AND table_key=?`),
  rowDelete:   db.prepare(`DELETE FROM crud_rows WHERE row_id=? AND table_key=?`),
  rowGet:      db.prepare(`SELECT * FROM crud_rows WHERE row_id=? AND table_key=?`),
  rowsByTable: db.prepare(`SELECT * FROM crud_rows WHERE table_key=? ORDER BY created_at ASC`),
  rowCount:    db.prepare(`SELECT COUNT(*) as n FROM crud_rows WHERE table_key=?`),
  rowsClear:   db.prepare(`DELETE FROM crud_rows WHERE table_key=?`),
};

// ── HELPERS ───────────────────────────────────────────────────────────────────
// better-sqlite3 retorna `undefined` quando não encontra registro — normalizamos para null
function maybe(v) { return v === undefined ? null : v; }

function rowToEndpoint(r) {
  if (!r) return null;
  return {
    id: r.id, name: r.name, path: r.path,
    corsEnabled:  r.cors === 1 || r.cors === true,
    globalDelay:  r.global_delay  || 0,
    rateLimit:    r.rate_limit    || 100,
    requestCount: r.req_count     || 0,
    createdAt:    r.created_at,
  };
}

function rowToRequest(r) {
  if (!r) return null;
  return {
    id: r.id, endpointId: r.endpoint_id,
    method: r.method, path: r.path, fullUrl: r.full_url,
    status: r.status, latency: r.latency, ip: r.ip,
    headers:      safeJSON(r.headers),
    queryParams:  safeJSON(r.query_params),
    requestBody:  r.request_body,
    responseBody: r.response_body,
    matchedRule:  r.matched_rule,
    timestamp:    r.ts,
  };
}

function rowToRule(r) {
  if (!r) return null;
  return {
    id: r.id, endpointId: r.endpoint_id,
    method: r.method, path: r.path,
    status: r.status, delay: r.delay, body: r.body,
  };
}

function rowToCrudTable(r) {
  if (!r) return null;
  const count = maybe(stmts.rowCount.get(r.key))?.n || 0;
  return { key: r.key, endpointId: r.endpoint_id, path: r.path, idField: r.id_field, count };
}

function safeJSON(s) { try { return JSON.parse(s); } catch(_) { return s || null; } }
function safeStr(v)  { return typeof v === 'string' ? v : (JSON.stringify(v) ?? null); }

// ── PUBLIC API ────────────────────────────────────────────────────────────────
module.exports = {

  // ── Endpoints ──────────────────────────────────────────────────────────────
  getAllEndpoints() { return stmts.epAll.all().map(rowToEndpoint); },
  getEndpoint(id)  { return rowToEndpoint(maybe(stmts.epGet.get(id))); },
  saveEndpoint(ep) {
    stmts.epInsert.run(
      ep.id, ep.name, ep.path || null,
      ep.corsEnabled ? 1 : 0,
      ep.globalDelay  || 0,
      ep.rateLimit    || 100,
      ep.requestCount || 0,
      ep.createdAt    || new Date().toISOString()
    );
  },
  updateEndpoint(ep) {
    stmts.epUpdate.run(
      ep.name, ep.path || null,
      ep.corsEnabled ? 1 : 0,
      ep.globalDelay || 0,
      ep.rateLimit   || 100,
      ep.id
    );
  },
  deleteEndpoint(id) { stmts.epDelete.run(id); },
  incrementCount(id) { stmts.epIncCount.run(id); },

  // ── Requests ───────────────────────────────────────────────────────────────
  getRequests(epId) { return stmts.reqByEp.all(epId).map(rowToRequest); },
  saveRequest(r) {
    const existing = stmts.reqByEp.all(r.endpointId);
    if (existing.length >= 200) stmts.reqDelOld.run(existing[existing.length - 1].id);
    stmts.reqInsert.run(
      r.id, r.endpointId, r.method, r.path, r.fullUrl,
      r.status, r.latency || 0, r.ip || null,
      safeStr(r.headers), safeStr(r.queryParams),
      r.requestBody  || null,
      r.responseBody || null,
      r.matchedRule  || null,
      r.timestamp    || new Date().toISOString()
    );
  },
  clearRequests(epId) { stmts.reqClear.run(epId); },

  // ── Rules ──────────────────────────────────────────────────────────────────
  getRules(epId) { return stmts.rulesByEp.all(epId).map(rowToRule); },
  saveRule(r) {
    stmts.ruleInsert.run(
      r.id, r.endpointId,
      r.method    || '*',
      r.path      || '/*',
      r.status    || 200,
      r.delay     || 0,
      r.body      || null,
      r.createdAt || new Date().toISOString()
    );
  },
  deleteRule(id) { stmts.ruleDelete.run(id); },

  // ── CRUD Tables ────────────────────────────────────────────────────────────
  getCrudTablesForEndpoint(epId) { return stmts.crudByEp.all(epId).map(rowToCrudTable); },
  getAllCrudTables()              { return stmts.crudAll.all().map(rowToCrudTable); },
  getCrudTable(key)              { return rowToCrudTable(maybe(stmts.crudGet.get(key))); },
  saveCrudTable(key, epId, path, idField) {
    stmts.crudInsert.run(key, epId, path, idField || 'id', new Date().toISOString());
  },
  deleteCrudTable(key) { stmts.crudDelete.run(key); },

  // ── CRUD Rows ──────────────────────────────────────────────────────────────
  getCrudRows(tableKey)       { return stmts.rowsByTable.all(tableKey).map(r => safeJSON(r.data)); },
  getCrudRow(tableKey, rowId) {
    const r = maybe(stmts.rowGet.get(rowId, tableKey));
    return r ? safeJSON(r.data) : null;
  },
  saveCrudRow(tableKey, rowId, data) {
    const existing = maybe(stmts.rowGet.get(rowId, tableKey));
    const dataStr  = safeStr(data);
    if (existing) {
      stmts.rowUpdate.run(dataStr, rowId, tableKey);
    } else {
      stmts.rowInsert.run(rowId, tableKey, dataStr, new Date().toISOString(), new Date().toISOString());
    }
  },
  deleteCrudRow(tableKey, rowId) { stmts.rowDelete.run(rowId, tableKey); },
  clearCrudRows(tableKey)        { stmts.rowsClear.run(tableKey); },
  countCrudRows(tableKey)        { return maybe(stmts.rowCount.get(tableKey))?.n || 0; },

  // ── Export / Import ────────────────────────────────────────────────────────
  exportTable(tableKey) {
    const tbl = maybe(stmts.crudGet.get(tableKey));
    if (!tbl) return null;
    return { meta: rowToCrudTable(tbl), rows: module.exports.getCrudRows(tableKey) };
  },
  importTable(tableKey, epId, path, idField, rows) {
    module.exports.saveCrudTable(tableKey, epId, path, idField);
    module.exports.clearCrudRows(tableKey);
    for (const row of rows) {
      const rowId = String(
        row[idField] || row.id ||
        require('crypto').randomBytes(4).toString('hex').toUpperCase()
      );
      module.exports.saveCrudRow(tableKey, rowId, row);
    }
    return rows.length;
  },

  // Raw db para queries avançadas
  raw: db,
};
