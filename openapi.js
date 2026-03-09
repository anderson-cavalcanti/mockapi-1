/**
 * openapi.js — Parse OpenAPI 2.0 (Swagger) and 3.x YAML/JSON specs.
 * Returns endpoint definitions and CRUD table suggestions.
 * Zero dependencies — uses a minimal YAML parser.
 */

// ── MINIMAL YAML PARSER ───────────────────────────────────────────────────────
function parseYAML(text) {
  // Convert YAML to JSON by handling common patterns
  // This handles typical OpenAPI YAML — indentation-based, key:value, arrays
  try {
    // Try JSON first
    return JSON.parse(text);
  } catch(_) {}

  const lines = text.split('\n');
  return parseYAMLLines(lines, 0, 0).value;
}

function parseYAMLLines(lines, startIdx, baseIndent) {
  const result = {};
  let i = startIdx;
  let lastKey = null;
  let currentArray = null;

  while (i < lines.length) {
    const raw = lines[i];
    const stripped = raw.trimEnd();
    if (!stripped || stripped.trimStart().startsWith('#')) { i++; continue; }

    const indent = raw.search(/\S/);
    if (indent < baseIndent) break;
    if (indent > baseIndent && lastKey !== null) { i++; continue; }

    const trimmed = stripped.trim();

    // Array item
    if (trimmed.startsWith('- ')) {
      const val = trimmed.slice(2).trim();
      if (!currentArray) currentArray = [];
      if (val.includes(': ')) {
        // inline object
        const obj = {};
        val.split(/,\s*/).forEach(pair => {
          const [k, v] = pair.split(/:\s*/);
          if (k) obj[k.trim()] = parseScalar(v?.trim());
        });
        currentArray.push(obj);
      } else {
        currentArray.push(parseScalar(val));
      }
      if (lastKey && currentArray) result[lastKey] = currentArray;
      i++; continue;
    }

    // Key: value pair
    const colonIdx = trimmed.indexOf(':');
    if (colonIdx > 0) {
      const key = trimmed.slice(0, colonIdx).trim();
      const rest = trimmed.slice(colonIdx + 1).trim();
      currentArray = null;
      lastKey = key;

      if (rest === '' || rest === '|' || rest === '>') {
        // Next lines are the value (nested object or multiline)
        const nextIndent = findNextIndent(lines, i+1);
        if (nextIndent > indent) {
          const sub = parseYAMLLines(lines, i+1, nextIndent);
          result[key] = sub.value;
          i = sub.nextIdx;
          continue;
        }
        result[key] = null;
      } else {
        result[key] = parseScalar(rest);
      }
    }
    i++;
  }
  return { value: result, nextIdx: i };
}

function findNextIndent(lines, startIdx) {
  for (let i = startIdx; i < lines.length; i++) {
    const s = lines[i];
    if (s.trim() && !s.trim().startsWith('#')) return s.search(/\S/);
  }
  return 0;
}

function parseScalar(v) {
  if (v === undefined || v === null || v === '') return null;
  if (v === 'true') return true;
  if (v === 'false') return false;
  if (v === 'null' || v === '~') return null;
  if (/^-?\d+$/.test(v)) return parseInt(v);
  if (/^-?\d+\.\d+$/.test(v)) return parseFloat(v);
  // Remove surrounding quotes
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    return v.slice(1, -1);
  }
  return v;
}

// ── OPENAPI PARSER ────────────────────────────────────────────────────────────
function parseOpenAPI(text) {
  let spec;
  try { spec = parseYAML(text); }
  catch(e) { throw new Error('Failed to parse YAML/JSON: ' + e.message); }

  if (!spec || (!spec.paths && !spec.swagger && !spec.openapi)) {
    throw new Error('Not a valid OpenAPI/Swagger spec');
  }

  const version = spec.openapi || spec.swagger || '2.0';
  const isV3 = String(version).startsWith('3');

  const info = spec.info || {};
  const title = info.title || 'Imported API';
  const baseUrl = isV3
    ? (spec.servers?.[0]?.url || '')
    : ((spec.host || '') + (spec.basePath || ''));

  const paths = spec.paths || {};
  const routes = [];
  const crudCandidates = new Map(); // path -> methods[]

  for (const [pathPattern, methods] of Object.entries(paths)) {
    if (typeof methods !== 'object') continue;
    for (const [method, operation] of Object.entries(methods)) {
      if (!['get','post','put','patch','delete','head','options'].includes(method)) continue;
      const op = operation || {};

      // Extract response body example
      let responseBody = null;
      const responses = op.responses || {};
      const okResp = responses['200'] || responses['201'] || responses['default'];
      if (okResp) {
        const content = isV3 ? okResp.content : null;
        const schema  = isV3
          ? content?.['application/json']?.schema || content?.['*/*']?.schema
          : okResp.schema;
        if (schema) responseBody = schemaToExample(schema, spec);
      }

      routes.push({
        method: method.toUpperCase(),
        path: pathPattern,
        summary: op.summary || op.description || '',
        tags: op.tags || [],
        responseBody: responseBody ? JSON.stringify(responseBody, null, 2) : null,
        status: 200,
      });

      // Track for CRUD detection
      const basePath = pathPattern.replace(/\{[^}]+\}$/, '').replace(/\/$/, '') || '/';
      if (!crudCandidates.has(basePath)) crudCandidates.set(basePath, new Set());
      crudCandidates.get(basePath).add(method.toUpperCase());
    }
  }

  // Detect CRUD-ready paths (have GET + POST at collection level)
  const crudPaths = [];
  for (const [basePath, methods] of crudCandidates) {
    if (methods.has('GET') && methods.has('POST')) {
      crudPaths.push(basePath);
    }
  }

  return { title, version, baseUrl, routes, crudPaths, spec };
}

function schemaToExample(schema, fullSpec, depth = 0) {
  if (depth > 4) return {};
  if (!schema) return null;

  // Handle $ref
  if (schema.$ref) {
    const refPath = schema.$ref.replace('#/', '').split('/');
    let resolved = fullSpec;
    for (const part of refPath) resolved = resolved?.[part];
    return resolved ? schemaToExample(resolved, fullSpec, depth + 1) : {};
  }

  const type = schema.type || (schema.properties ? 'object' : 'string');

  if (type === 'object' || schema.properties) {
    const result = {};
    const props = schema.properties || {};
    for (const [k, v] of Object.entries(props)) {
      result[k] = schemaToExample(v, fullSpec, depth + 1);
    }
    return result;
  }
  if (type === 'array') {
    return [schemaToExample(schema.items || {type:'string'}, fullSpec, depth+1)];
  }

  // Scalar examples
  if (schema.example !== undefined) return schema.example;
  if (schema.default !== undefined) return schema.default;
  if (schema.enum?.length) return schema.enum[0];

  const fmt = schema.format || '';
  if (type === 'integer' || type === 'number') return 1;
  if (type === 'boolean') return true;
  if (fmt === 'date-time') return new Date().toISOString();
  if (fmt === 'date') return new Date().toISOString().split('T')[0];
  if (fmt === 'email') return 'user@example.com';
  if (fmt === 'uuid') return '00000000-0000-0000-0000-000000000000';
  if (fmt === 'uri') return 'https://example.com';
  return 'string';
}

module.exports = { parseOpenAPI, parseYAML };
