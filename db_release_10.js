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
    github_id   TEXT UNIQUE,
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
  CREATE TABLE IF NOT EXISTS api_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    name        TEXT NOT NULL,
    token       TEXT UNIQUE NOT NULL,
    last_used   TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_api_tokens_token ON api_tokens(token);
  CREATE INDEX IF NOT EXISTS idx_api_tokens_user  ON api_tokens(user_id);
  CREATE TABLE IF NOT EXISTS workspaces (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    owner_id    TEXT NOT NULL,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS workspace_members (
    workspace_id TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    role         TEXT DEFAULT 'viewer',
    invited_by   TEXT,
    joined_at    TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (workspace_id, user_id),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)      REFERENCES users(id)      ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_wm_user      ON workspace_members(user_id);
  CREATE TABLE IF NOT EXISTS workspace_invites (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    github_login TEXT NOT NULL,
    invited_by   TEXT NOT NULL,
    created_at   TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS plan_config (
    plan          TEXT PRIMARY KEY,
    ep_limit      INTEGER NOT NULL,
    req_per_day   INTEGER NOT NULL,
    label         TEXT NOT NULL,
    enabled       INTEGER DEFAULT 1,
    price_brl     INTEGER DEFAULT 0,
    member_limit  INTEGER DEFAULT 1
  );
`);

// Seed default plan config if not exists
const planSeeds = [
  { plan:'free',       ep_limit:3,       req_per_day:1000,      label:'Free',       enabled:1, price_brl:0,   member_limit:1      },
  { plan:'pro',        ep_limit:50,      req_per_day:100000,    label:'Pro',        enabled:1, price_brl:59,  member_limit:3      },
  { plan:'team',       ep_limit:200,     req_per_day:1000000,   label:'Team',       enabled:1, price_brl:199, member_limit:10     },
  { plan:'enterprise', ep_limit:999999,  req_per_day:999999999, label:'Enterprise', enabled:1, price_brl:0,   member_limit:999999 },
];
const insertPlan = db.prepare(`INSERT OR IGNORE INTO plan_config (plan,ep_limit,req_per_day,label,enabled,price_brl,member_limit) VALUES (?,?,?,?,?,?,?)`);
for (const p of planSeeds) insertPlan.run(p.plan, p.ep_limit, p.req_per_day, p.label, p.enabled, p.price_brl, p.member_limit);
// Migrate existing DB: add member_limit column and set correct defaults
try { db.exec(`ALTER TABLE plan_config ADD COLUMN member_limit INTEGER DEFAULT 1`); } catch(_) {}
db.prepare(`UPDATE plan_config SET member_limit=3       WHERE plan='pro'        AND member_limit<=1`).run();
db.prepare(`UPDATE plan_config SET member_limit=10      WHERE plan='team'       AND member_limit<=1`).run();
db.prepare(`UPDATE plan_config SET member_limit=999999  WHERE plan='enterprise' AND member_limit<=1`).run();

try { db.exec(`ALTER TABLE endpoints ADD COLUMN user_id TEXT`); } catch(_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN google_id TEXT`); } catch(_) {}
try { db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id) WHERE google_id IS NOT NULL`); } catch(_) {}
try { db.exec(`ALTER TABLE endpoints ADD COLUMN workspace_id TEXT`); } catch(_) {}
// Index on workspace_id must come AFTER the column is guaranteed to exist
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_ep_workspace ON endpoints(workspace_id)`); } catch(_) {}

// Migrate: create personal workspace for users who don't have one yet
// and assign their orphaned endpoints to it
const migrateWorkspaces = db.transaction(() => {
  const usersWithoutWs = db.prepare(`
    SELECT DISTINCT u.id, u.login FROM users u
    WHERE NOT EXISTS (
      SELECT 1 FROM workspaces w WHERE w.owner_id = u.id AND w.name LIKE '%(pessoal)%' OR w.name = u.login
    )
  `).all();
  for (const u of usersWithoutWs) {
    const wsId = require('crypto').randomBytes(6).toString('hex').toUpperCase();
    db.prepare(`INSERT OR IGNORE INTO workspaces (id,name,owner_id) VALUES (?,?,?)`).run(wsId, u.login + ' (pessoal)', u.id);
    db.prepare(`INSERT OR IGNORE INTO workspace_members (workspace_id,user_id,role) VALUES (?,?,'owner')`).run(wsId, u.id);
    // Assign orphaned endpoints (no workspace_id) to this personal workspace
    db.prepare(`UPDATE endpoints SET workspace_id=? WHERE user_id=? AND (workspace_id IS NULL OR workspace_id='')`).run(wsId, u.id);
  }
});
try { migrateWorkspaces(); } catch(e) { console.warn('[db] workspace migration:', e.message); }

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
  return { id:r.id, userId:r.user_id||null, workspaceId:r.workspace_id||null,
           name:r.name, path:r.path,
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
  getUserByLogin(login)   { return rowToUser(db.prepare(`SELECT * FROM users WHERE LOWER(login)=LOWER(?)`).get(login)); },
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
  upsertGoogleUser(u) {
    // Try find existing user by google_id first, then by email
    let existing = db.prepare(`SELECT * FROM users WHERE google_id=?`).get(u.googleId);
    if (!existing && u.email) {
      existing = db.prepare(`SELECT * FROM users WHERE email=? AND google_id IS NULL`).get(u.email);
    }
    if (existing) {
      // Update profile fields and set google_id
      db.prepare(`UPDATE users SET google_id=?,name=?,email=?,avatar=?,last_login=datetime('now') WHERE id=?`)
        .run(u.googleId, u.name||existing.name, u.email||existing.email, u.avatar||existing.avatar, existing.id);
      return module.exports.getUserById(existing.id);
    }
    // New user
    db.prepare(`INSERT INTO users (id,github_id,google_id,login,name,email,avatar,plan,is_admin,last_login)
      VALUES (?,NULL,?,?,?,?,?,?,?,datetime('now'))`)
      .run(u.id, u.googleId, u.login, u.name||null, u.email||null, u.avatar||null, u.plan||'free', u.isAdmin?1:0);
    return module.exports.getUserById(u.id);
  },
  getUserByGoogleId(gid) {
    return rowToUser(db.prepare(`SELECT * FROM users WHERE google_id=?`).get(String(gid)));
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
  getAllEndpoints(userId, workspaceId) {
    if (workspaceId) {
      // Return endpoints belonging to the workspace (if user is a member)
      return db.prepare(`SELECT e.* FROM endpoints e
        JOIN workspace_members wm ON wm.workspace_id=e.workspace_id AND wm.user_id=?
        WHERE e.workspace_id=? ORDER BY e.created_at DESC`).all(userId, workspaceId).map(rowToEndpoint);
    }
    if (userId) return db.prepare(`SELECT * FROM endpoints WHERE user_id=? ORDER BY created_at DESC`).all(userId).map(rowToEndpoint);
    return db.prepare(`SELECT * FROM endpoints ORDER BY created_at DESC`).all().map(rowToEndpoint);
  },
  getEndpoint(id)  { return rowToEndpoint(db.prepare(`SELECT * FROM endpoints WHERE id=?`).get(id)); },
  saveEndpoint(ep) {
    db.prepare(`INSERT OR REPLACE INTO endpoints (id,user_id,workspace_id,name,path,cors,global_delay,rate_limit,req_count,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`
    ).run(ep.id,ep.userId||null,ep.workspaceId||null,ep.name,ep.path||null,ep.corsEnabled?1:0,ep.globalDelay||0,ep.rateLimit||100,ep.requestCount||0,ep.createdAt||new Date().toISOString());
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
  // Plan config (admin-managed)
  getPlanConfig(plan) {
    const row = db.prepare(`SELECT * FROM plan_config WHERE plan=?`).get(plan);
    if (!row) return { plan, ep_limit:3, req_per_day:1000, label:plan, enabled:1, price_brl:0, member_limit:1 };
    return { ...row, member_limit: row.member_limit ?? 1 };
  },
  getAllPlanConfigs() { return db.prepare(`SELECT * FROM plan_config ORDER BY price_brl`).all(); },
  updatePlanConfig(plan, fields) {
    const sets=[],vals=[];
    if (fields.ep_limit      !==undefined){sets.push('ep_limit=?');     vals.push(fields.ep_limit);}
    if (fields.req_per_day   !==undefined){sets.push('req_per_day=?');  vals.push(fields.req_per_day);}
    if (fields.label         !==undefined){sets.push('label=?');        vals.push(fields.label);}
    if (fields.enabled       !==undefined){sets.push('enabled=?');      vals.push(fields.enabled?1:0);}
    if (fields.price_brl     !==undefined){sets.push('price_brl=?');    vals.push(fields.price_brl);}
    if (fields.member_limit  !==undefined){sets.push('member_limit=?'); vals.push(fields.member_limit);}
    if (sets.length) { vals.push(plan); db.prepare(`UPDATE plan_config SET ${sets.join(',')} WHERE plan=?`).run(...vals); }
    return db.prepare(`SELECT * FROM plan_config WHERE plan=?`).get(plan);
  },
  countUserEndpoints(userId) { return db.prepare(`SELECT COUNT(*) as n FROM endpoints WHERE user_id=?`).get(userId)?.n||0; },
  countWorkspaceEndpoints(wsId) { return db.prepare(`SELECT COUNT(*) as n FROM endpoints WHERE workspace_id=?`).get(wsId)?.n||0; },
  countUserReqsToday(userId) {
    return db.prepare(
      `SELECT COUNT(*) as n FROM requests r
       JOIN endpoints e ON r.endpoint_id=e.id
       WHERE e.user_id=? AND date(r.ts)=date('now')`
    ).get(userId)?.n||0;
  },
  upgradeUserPlan(userId, plan) { db.prepare(`UPDATE users SET plan=? WHERE id=?`).run(plan, userId); },

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
  getRule(id)    { const r = db.prepare(`SELECT * FROM rules WHERE id=?`).get(id); return r ? rowToRule(r) : null; },
  saveRule(r) {
    db.prepare(`INSERT INTO rules VALUES (?,?,?,?,?,?,?,?)`
    ).run(r.id,r.endpointId,r.method||'*',r.path||'/*',r.status||200,r.delay||0,r.body||null,r.createdAt||new Date().toISOString());
  },
  deleteRule(id) { db.prepare(`DELETE FROM rules WHERE id=?`).run(id); },

  // CRUD TABLES
  getCrudTablesForEndpoint(epId) { return db.prepare(`SELECT * FROM crud_tables WHERE endpoint_id=?`).all(epId).map(rowToCrudTable); },
  getAllCrudTables() { return db.prepare(`SELECT * FROM crud_tables ORDER BY endpoint_id`).all().map(rowToCrudTable); },
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

  // ── API TOKENS ────────────────────────────────────────────────────────────
  createApiToken(userId, name, token) {
    const id = require('crypto').randomBytes(6).toString('hex').toUpperCase();
    db.prepare(`INSERT INTO api_tokens (id,user_id,name,token) VALUES (?,?,?,?)`).run(id, userId, name, token);
    return db.prepare(`SELECT * FROM api_tokens WHERE id=?`).get(id);
  },
  getApiToken(token) {
    const row = db.prepare(`SELECT * FROM api_tokens WHERE token=?`).get(token);
    if (row) db.prepare(`UPDATE api_tokens SET last_used=datetime('now') WHERE token=?`).run(token);
    return row;
  },
  listApiTokens(userId) {
    return db.prepare(`SELECT id,name,substr(token,1,8)||'...' as token_preview,last_used,created_at FROM api_tokens WHERE user_id=? ORDER BY created_at DESC`).all(userId);
  },
  deleteApiToken(id, userId) {
    db.prepare(`DELETE FROM api_tokens WHERE id=? AND user_id=?`).run(id, userId);
  },

  // ── WORKSPACES ────────────────────────────────────────────────────────────
  createWorkspace(id, name, ownerId) {
    db.prepare(`INSERT INTO workspaces (id,name,owner_id) VALUES (?,?,?)`).run(id, name, ownerId);
    db.prepare(`INSERT OR IGNORE INTO workspace_members (workspace_id,user_id,role) VALUES (?,?,'owner')`).run(id, ownerId);
    return db.prepare(`SELECT * FROM workspaces WHERE id=?`).get(id);
  },
  getWorkspace(id) { return db.prepare(`SELECT * FROM workspaces WHERE id=?`).get(id); },
  getUserWorkspaces(userId) {
    return db.prepare(`
      SELECT w.*, wm.role,
        (SELECT COUNT(*) FROM endpoints e WHERE e.workspace_id=w.id) as ep_count,
        (SELECT COUNT(*) FROM workspace_members wm2 WHERE wm2.workspace_id=w.id) as member_count
      FROM workspaces w
      JOIN workspace_members wm ON wm.workspace_id=w.id AND wm.user_id=?
      ORDER BY w.created_at ASC`).all(userId);
  },
  renameWorkspace(id, name, userId) {
    db.prepare(`UPDATE workspaces SET name=? WHERE id=? AND owner_id=?`).run(name, id, userId);
  },
  deleteWorkspace(id, userId) {
    // Only owner can delete; personal workspace cannot be deleted
    const ws = db.prepare(`SELECT * FROM workspaces WHERE id=? AND owner_id=?`).get(id, userId);
    if (!ws) return false;
    db.prepare(`DELETE FROM workspaces WHERE id=?`).run(id);
    return true;
  },
  getWorkspaceMembers(wsId) {
    return db.prepare(`
      SELECT u.id, u.login, u.name, u.avatar, wm.role, wm.joined_at
      FROM workspace_members wm
      JOIN users u ON u.id=wm.user_id
      WHERE wm.workspace_id=?
      ORDER BY wm.role='owner' DESC, wm.joined_at ASC`).all(wsId);
  },
  getWorkspaceMember(wsId, userId) {
    return db.prepare(`SELECT * FROM workspace_members WHERE workspace_id=? AND user_id=?`).get(wsId, userId);
  },
  addWorkspaceMember(wsId, userId, role, invitedBy) {
    db.prepare(`INSERT OR REPLACE INTO workspace_members (workspace_id,user_id,role,invited_by,joined_at) VALUES (?,?,?,?,datetime('now'))`).run(wsId, userId, role||'editor', invitedBy||null);
  },
  updateMemberRole(wsId, userId, role) {
    db.prepare(`UPDATE workspace_members SET role=? WHERE workspace_id=? AND user_id=?`).run(role, wsId, userId);
  },
  removeWorkspaceMember(wsId, userId) {
    db.prepare(`DELETE FROM workspace_members WHERE workspace_id=? AND user_id=?`).run(wsId, userId);
  },
  // Personal workspace — the one auto-created for each user
  getPersonalWorkspace(userId) {
    return db.prepare(`SELECT w.* FROM workspaces w WHERE w.owner_id=? ORDER BY w.created_at ASC LIMIT 1`).get(userId);
  },
  ensurePersonalWorkspace(userId, login) {
    const existing = db.prepare(`SELECT w.* FROM workspaces w WHERE w.owner_id=? ORDER BY w.created_at ASC LIMIT 1`).get(userId);
    if (existing) return existing;
    const wsId = require('crypto').randomBytes(6).toString('hex').toUpperCase();
    db.prepare(`INSERT OR IGNORE INTO workspaces (id,name,owner_id) VALUES (?,?,?)`).run(wsId, login + ' (pessoal)', userId);
    db.prepare(`INSERT OR IGNORE INTO workspace_members (workspace_id,user_id,role) VALUES (?,?,'owner')`).run(wsId, userId);
    db.prepare(`UPDATE endpoints SET workspace_id=? WHERE user_id=? AND (workspace_id IS NULL OR workspace_id='')`).run(wsId, userId);
    return db.prepare(`SELECT * FROM workspaces WHERE id=?`).get(wsId);
  },
  // Pending invites
  getInviteById(id) { return db.prepare(`SELECT * FROM workspace_invites WHERE id=?`).get(id); },
  createInvite(wsId, githubLogin, invitedBy) {
    const id = require('crypto').randomBytes(5).toString('hex').toUpperCase();
    db.prepare(`INSERT OR REPLACE INTO workspace_invites (id,workspace_id,github_login,invited_by) VALUES (?,?,?,?)`).run(id, wsId, githubLogin.toLowerCase(), invitedBy);
    return id;
  },
  getPendingInvitesByLogin(login) {
    return db.prepare(`SELECT wi.*, w.name as workspace_name, u.login as inviter_login FROM workspace_invites wi JOIN workspaces w ON w.id=wi.workspace_id JOIN users u ON u.id=wi.invited_by WHERE LOWER(wi.github_login)=LOWER(?)`).all(login);
  },
  deleteInvite(id) { db.prepare(`DELETE FROM workspace_invites WHERE id=?`).run(id); },
  getPendingInvitesForWorkspace(wsId) {
    return db.prepare(`SELECT * FROM workspace_invites WHERE workspace_id=?`).all(wsId);
  },

  raw: db,
};
