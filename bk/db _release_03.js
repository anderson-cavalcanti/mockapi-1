/**
 * db.js — SQLite persistence layer (better-sqlite3)
 * Supports users, multi-tenancy, admin metrics
 */
const Database = require('better-sqlite3');
const path = require('path');
const fs   = require('fs');

// Priority: 1) DB_FILE env var (Render disk at /data/mockapi.db)
//           2) ./data/mockapi.db  (local dev or ephemeral disk)
//           3) :memory:           (last resort — data lost on restart)
let DB_FILE = process.env.DB_FILE;
if (!DB_FILE) {
  const localDir = path.join(__dirname, 'data');
  try { fs.mkdirSync(localDir, { recursive: true }); } catch(_) {}
  DB_FILE = path.join(localDir, 'mockapi.db');
}

let db;
try {
  db = new Database(DB_FILE);
  console.log('[db] SQLite opened:', DB_FILE);
} catch(e) {
  console.warn('[db] Erro ao abrir arquivo, usando in-memory:', e.message);
  db = new Database(':memory:');
}

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    github_id   TEXT UNIQUE NOT NULL,
    login       TEXT NOT NULL,
    name        TEXT,
    email       TEXT,
    avatar      TEXT,
    plan        TEXT DEFAULT 'free',
    is_admin    INTEGER DEFAULT 0,
    banned      INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now')),
    last_login  TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    created_at  TEXT DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS endpoints (
    id           TEXT PRIMARY KEY,
    user_id      TEXT,
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
    row_id      TEXT NOT NULL,
    table_key   TEXT NOT NULL,
    data        TEXT NOT NULL,
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (row_id, table_key),
    FOREIGN KEY (table_key) REFERENCES crud_tables(key) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_endpoints_user ON endpoints(user_id);
  CREATE INDEX IF NOT EXISTS idx_requests_ep    ON requests(endpoint_id);
  CREATE INDEX IF NOT EXISTS idx_requests_ts    ON requests(ts);
  CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
`);

try { db.exec(`ALTER TABLE endpoints ADD COLUMN user_id TEXT`); } catch(_) {}

function safeJSON(s) { try { return JSON.parse(s); } catch(_) { return s||null; } }
function safeStr(v)  { return typeof v==='string'?v:JSON.stringify(v)||null; }

function rowToUser(r) {
  if (!r) return null;
  return { id:r.id, githubId:r.github_id, login:r.login, name:r.name,
           email:r.email, avatar:r.avatar, plan:r.plan,
           isAdmin:!!r.is_admin, banned:!!r.banned,
           createdAt:r.created_at, lastLogin:r.last_login };
}
function rowToEndpoint(r) {
  if (!r) return null;
  return { id:r.id, userId:r.user_id||null, name:r.name, path:r.path,
           corsEnabled:!!r.cors, globalDelay:r.global_delay||0,
           rateLimit:r.rate_limit||100, requestCount:r.req_count||0, createdAt:r.created_at };
}
function rowToRequest(r) {
  if (!r) return null;
  return { id:r.id, endpointId:r.endpoint_id, method:r.method, path:r.path,
           fullUrl:r.full_url, status:r.status, latency:r.latency, ip:r.ip,
           headers:safeJSON(r.headers), queryParams:safeJSON(r.query_params),
           requestBody:r.request_body, responseBody:r.response_body,
           matchedRule:r.matched_rule, timestamp:r.ts };
}
function rowToRule(r) {
  if (!r) return null;
  return { id:r.id, endpointId:r.endpoint_id, method:r.method, path:r.path,
           status:r.status, delay:r.delay, body:r.body };
}
function rowToCrudTable(r) {
  if (!r) return null;
  const count = db.prepare(`SELECT COUNT(*) as n FROM crud_rows WHERE table_key=?`).get(r.key)?.n||0;
  return { key:r.key, endpointId:r.endpoint_id, path:r.path, idField:r.id_field, count };
}

module.exports = {
  // USERS
  getUserById(id)         { return rowToUser(db.prepare(`SELECT * FROM users WHERE id=?`).get(id)); },
  getUserByGithubId(gid)  { return rowToUser(db.prepare(`SELECT * FROM users WHERE github_id=?`).get(String(gid))); },
  upsertUser(u) {
    db.prepare(`INSERT INTO users (id,github_id,login,name,email,avatar,plan,is_admin,last_login)
      VALUES (?,?,?,?,?,?,?,?,datetime('now'))
      ON CONFLICT(github_id) DO UPDATE SET
        login=excluded.login,name=excluded.name,email=excluded.email,
        avatar=excluded.avatar,last_login=datetime('now')`
    ).run(u.id,String(u.githubId),u.login,u.name||null,u.email||null,u.avatar||null,u.plan||'free',u.isAdmin?1:0);
    return module.exports.getUserByGithubId(u.githubId);
  },
  getAllUsers() {
    return db.prepare(`
      SELECT u.*,
        (SELECT COUNT(*) FROM endpoints e WHERE e.user_id=u.id) as ep_count,
        (SELECT COUNT(*) FROM requests r JOIN endpoints e ON r.endpoint_id=e.id WHERE e.user_id=u.id) as req_count
      FROM users u ORDER BY u.created_at DESC`).all().map(r=>({...rowToUser(r),epCount:r.ep_count,reqCount:r.req_count}));
  },
  banUser(id,banned)   { db.prepare(`UPDATE users SET banned=? WHERE id=?`).run(banned?1:0,id); },
  setAdmin(id,isAdmin) { db.prepare(`UPDATE users SET is_admin=? WHERE id=?`).run(isAdmin?1:0,id); },
  countUsers()         { return db.prepare(`SELECT COUNT(*) as n FROM users`).get()?.n||0; },

  // SESSIONS
  createSession(token,userId,expiresAt) {
    db.prepare(`INSERT OR REPLACE INTO sessions VALUES (?,?,datetime('now'),?)`).run(token,userId,expiresAt);
  },
  getSession(token) {
    const r = db.prepare(`SELECT * FROM sessions WHERE token=? AND expires_at>datetime('now')`).get(token);
    return r ? {token:r.token,userId:r.user_id,expiresAt:r.expires_at} : null;
  },
  deleteSession(token) { db.prepare(`DELETE FROM sessions WHERE token=?`).run(token); },
  cleanExpiredSessions() { db.prepare(`DELETE FROM sessions WHERE expires_at<=datetime('now')`).run(); },

  // ENDPOINTS
  getAllEndpoints(userId) {
    if (userId) return db.prepare(`SELECT * FROM endpoints WHERE user_id=? ORDER BY created_at DESC`).all(userId).map(rowToEndpoint);
    return db.prepare(`SELECT * FROM endpoints ORDER BY created_at DESC`).all().map(rowToEndpoint);
  },
  getEndpoint(id)  { return rowToEndpoint(db.prepare(`SELECT * FROM endpoints WHERE id=?`).get(id)); },
  saveEndpoint(ep) {
    db.prepare(`INSERT OR REPLACE INTO endpoints (id,user_id,name,path,cors,global_delay,rate_limit,req_count,created_at) VALUES (?,?,?,?,?,?,?,?,?)`
    ).run(ep.id,ep.userId||null,ep.name,ep.path||null,ep.corsEnabled?1:0,ep.globalDelay||0,ep.rateLimit||100,ep.requestCount||0,ep.createdAt||new Date().toISOString());
  },
  patchEndpoint(id,fields) {
    const sets=[],vals=[];
    if (fields.globalDelay!==undefined){sets.push('global_delay=?');vals.push(fields.globalDelay);}
    if (fields.name!==undefined)       {sets.push('name=?');        vals.push(fields.name);}
    if (sets.length){vals.push(id);db.prepare(`UPDATE endpoints SET ${sets.join(',')} WHERE id=?`).run(...vals);}
  },
  deleteEndpoint(id) { db.prepare(`DELETE FROM endpoints WHERE id=?`).run(id); },
  incrementCount(id) { db.prepare(`UPDATE endpoints SET req_count=req_count+1 WHERE id=?`).run(id); },
  countEndpoints()   { return db.prepare(`SELECT COUNT(*) as n FROM endpoints`).get()?.n||0; },

  // REQUESTS
  getRequests(epId) {
    return db.prepare(`SELECT * FROM requests WHERE endpoint_id=? ORDER BY ts DESC LIMIT 200`).all(epId).map(rowToRequest);
  },
  saveRequest(r) {
    const existing = db.prepare(`SELECT id FROM requests WHERE endpoint_id=? ORDER BY ts DESC LIMIT 200`).all(r.endpointId);
    if (existing.length>=200) db.prepare(`DELETE FROM requests WHERE id=?`).run(existing[existing.length-1].id);
    db.prepare(`INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).run(r.id,r.endpointId,r.method,r.path,r.fullUrl,r.status,r.latency||0,r.ip||null,
          safeStr(r.headers),safeStr(r.queryParams),r.requestBody||null,r.responseBody||null,
          r.matchedRule||null,r.timestamp||new Date().toISOString());
  },
  clearRequests(epId) { db.prepare(`DELETE FROM requests WHERE endpoint_id=?`).run(epId); },
  countRequests()     { return db.prepare(`SELECT COUNT(*) as n FROM requests`).get()?.n||0; },
  reqPerDay(days=30)  {
    return db.prepare(`SELECT date(ts) as day,COUNT(*) as n FROM requests WHERE ts>=datetime('now','-${days} days') GROUP BY day ORDER BY day`).all();
  },

  // RULES
  getRules(epId) { return db.prepare(`SELECT * FROM rules WHERE endpoint_id=? ORDER BY created_at DESC`).all(epId).map(rowToRule); },
  saveRule(r) {
    db.prepare(`INSERT INTO rules VALUES (?,?,?,?,?,?,?,?)`
    ).run(r.id,r.endpointId,r.method||'*',r.path||'/*',r.status||200,r.delay||0,r.body||null,r.createdAt||new Date().toISOString());
  },
  deleteRule(id) { db.prepare(`DELETE FROM rules WHERE id=?`).run(id); },

  // CRUD TABLES
  getCrudTablesForEndpoint(epId) { return db.prepare(`SELECT * FROM crud_tables WHERE endpoint_id=?`).all(epId).map(rowToCrudTable); },
  getCrudTable(key)              { return rowToCrudTable(db.prepare(`SELECT * FROM crud_tables WHERE key=?`).get(key)); },
  saveCrudTable(key,epId,path,idField) {
    db.prepare(`INSERT OR REPLACE INTO crud_tables VALUES (?,?,?,?,?)`).run(key,epId,path,idField||'id',new Date().toISOString());
  },
  deleteCrudTable(key) { db.prepare(`DELETE FROM crud_tables WHERE key=?`).run(key); },

  // CRUD ROWS
  getCrudRows(tableKey) { return db.prepare(`SELECT * FROM crud_rows WHERE table_key=? ORDER BY created_at ASC`).all(tableKey).map(r=>safeJSON(r.data)); },
  getCrudRow(tableKey,rowId) {
    const r = db.prepare(`SELECT * FROM crud_rows WHERE row_id=? AND table_key=?`).get(rowId,tableKey);
    return r ? safeJSON(r.data) : null;
  },
  saveCrudRow(tableKey,rowId,data) {
    const existing = db.prepare(`SELECT row_id FROM crud_rows WHERE row_id=? AND table_key=?`).get(rowId,tableKey);
    const ds = safeStr(data);
    if (existing) db.prepare(`UPDATE crud_rows SET data=?,updated_at=datetime('now') WHERE row_id=? AND table_key=?`).run(ds,rowId,tableKey);
    else db.prepare(`INSERT INTO crud_rows VALUES (?,?,?,datetime('now'),datetime('now'))`).run(rowId,tableKey,ds);
  },
  deleteCrudRow(tableKey,rowId) { db.prepare(`DELETE FROM crud_rows WHERE row_id=? AND table_key=?`).run(rowId,tableKey); },
  clearCrudRows(tableKey)       { db.prepare(`DELETE FROM crud_rows WHERE table_key=?`).run(tableKey); },
  countCrudRows(tableKey)       { return db.prepare(`SELECT COUNT(*) as n FROM crud_rows WHERE table_key=?`).get(tableKey)?.n||0; },

  // EXPORT / IMPORT
  exportTable(tableKey) {
    const tbl = db.prepare(`SELECT * FROM crud_tables WHERE key=?`).get(tableKey);
    if (!tbl) return null;
    return { meta: rowToCrudTable(tbl), rows: module.exports.getCrudRows(tableKey) };
  },
  importTable(tableKey,epId,path,idField,rows) {
    module.exports.saveCrudTable(tableKey,epId,path,idField);
    module.exports.clearCrudRows(tableKey);
    for (const row of rows) {
      const rowId = String(row[idField]||row.id||require('crypto').randomBytes(4).toString('hex').toUpperCase());
      module.exports.saveCrudRow(tableKey,rowId,row);
    }
    return rows.length;
  },

  // ADMIN STATS
  getAdminStats() {
    return {
      totalUsers:     db.prepare(`SELECT COUNT(*) as n FROM users`).get()?.n||0,
      totalEndpoints: db.prepare(`SELECT COUNT(*) as n FROM endpoints`).get()?.n||0,
      totalRequests:  db.prepare(`SELECT COUNT(*) as n FROM requests`).get()?.n||0,
      reqToday:       db.prepare(`SELECT COUNT(*) as n FROM requests WHERE date(ts)=date('now')`).get()?.n||0,
      newUsersWeek:   db.prepare(`SELECT COUNT(*) as n FROM users WHERE created_at>=datetime('now','-7 days')`).get()?.n||0,
      chart:          db.prepare(`SELECT date(ts) as day,COUNT(*) as n FROM requests WHERE ts>=datetime('now','-29 days') GROUP BY day ORDER BY day`).all(),
      topEndpoints:   db.prepare(`SELECT e.id,e.name,e.req_count,u.login as owner FROM endpoints e LEFT JOIN users u ON e.user_id=u.id ORDER BY e.req_count DESC LIMIT 10`).all(),
      usersByPlan:    db.prepare(`SELECT plan,COUNT(*) as n FROM users GROUP BY plan`).all(),
      totalRules:     db.prepare(`SELECT COUNT(*) as n FROM rules`).get()?.n||0,
    };
  },

  raw: db,
};
