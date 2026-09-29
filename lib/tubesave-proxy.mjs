const TUBESAVE_BASE = 'https://tubesave.in/api/v1';
const CHECK_MIN_INTERVAL_MS = Number(process.env.CHECK_MIN_INTERVAL_MS || 5000);
const MAX_CHECK_BODY_BYTES = 1024;
let apiKeyCursor = 0;
const nextCheckAtByKey = new Map();

function json(body, status = 200, headers = {}) {
  return Response.json(body, {
    status,
    headers: { ...headers, Vary: 'Origin' }
  });
}

function normalizeIp(ip) {
  const value = String(ip || '').trim();
  if (!value) return '';
  const withoutZone = value.split('%')[0];
  return withoutZone.startsWith('::ffff:') ? withoutZone.slice(7) : withoutZone;
}

function getClientIp(request) {
  const forwardedFor = request.headers.get('x-forwarded-for');
  if (forwardedFor) return normalizeIp(forwardedFor.split(',')[0]);
  return normalizeIp(request.headers.get('x-real-ip') || '');
}

function getAllowedIps() {
  return String(process.env.ALLOWED_CLIENT_IPS || '')
    .split(',')
    .map(normalizeIp)
    .filter(Boolean);
}

function sameOrigin(request) {
  const origin = request.headers.get('origin');
  if (!origin) return true;

  try {
    return new URL(origin).host === new URL(request.url).host;
  } catch {
    return false;
  }
}

function browserSameOriginPost(request) {
  if (request.method !== 'POST') return true;
  const secFetchSite = request.headers.get('sec-fetch-site');
  return !secFetchSite || secFetchSite === 'same-origin';
}

function rejectBlockedRequest(request) {
  const allowedIps = getAllowedIps();
  const clientIp = getClientIp(request);

  if (allowedIps.length && !allowedIps.includes(clientIp)) {
    return json({ detail: 'Scan proxy is not allowed from this IP' }, 403);
  }
  if (!sameOrigin(request) || !browserSameOriginPost(request)) {
    return json({ detail: 'Scan proxy origin is not allowed' }, 403);
  }
  return null;
}

async function readCheckBody(request) {
  const raw = await request.text();
  if (new TextEncoder().encode(raw).length > MAX_CHECK_BODY_BYTES) {
    throw Object.assign(new Error('Request body too large'), { status: 413 });
  }
  try {
    return raw.trim() ? JSON.parse(raw) : {};
  } catch {
    throw Object.assign(new Error('Invalid JSON body'), { status: 400 });
  }
}

async function buildUpstreamBody(request) {
  const body = await readCheckBody(request);
  const number = String(body.number || '').replace(/\D/g, '');
  const service = String(body.service || '').trim();

  if (!/^[6-9]\d{9}$/.test(number)) {
    throw Object.assign(new Error('Invalid phone number'), { status: 400 });
  }
  if (!/^[a-z0-9_-]{2,40}$/i.test(service)) {
    throw Object.assign(new Error('Invalid service'), { status: 400 });
  }
  return JSON.stringify({ number, service });
}

function getRateLimitHeaders() {
  return CHECK_MIN_INTERVAL_MS > 0
    ? { 'Retry-After': String(Math.ceil(CHECK_MIN_INTERVAL_MS / 1000)) }
    : {};
}

function getApiKeys() {
  const rawKeys = String(process.env.TUBESAVE_API_KEYS || process.env.TUBESAVE_API_KEY || '');
  return [...new Set(rawKeys.split(/[\s,;]+/).map(key => key.trim()).filter(Boolean))];
}

function reserveCheckKey(requestedSlot = null) {
  const keys = getApiKeys();
  if (!keys.length) return { key: '', retryAfterMs: 0 };

  const now = Date.now();
  if (Number.isInteger(requestedSlot) && requestedSlot >= 0 && requestedSlot < keys.length) {
    const key = keys[requestedSlot];
    const availableAt = nextCheckAtByKey.get(key) || 0;
    if (availableAt <= now) {
      nextCheckAtByKey.set(key, now + Math.max(0, CHECK_MIN_INTERVAL_MS));
      return { key, retryAfterMs: 0 };
    }
    return { key: '', retryAfterMs: Math.max(1, availableAt - now) };
  }

  let shortestWait = Infinity;
  for (let offset = 0; offset < keys.length; offset++) {
    const index = (apiKeyCursor + offset) % keys.length;
    const key = keys[index];
    const availableAt = nextCheckAtByKey.get(key) || 0;
    if (availableAt <= now) {
      apiKeyCursor = (index + 1) % keys.length;
      nextCheckAtByKey.set(key, now + Math.max(0, CHECK_MIN_INTERVAL_MS));
      return { key, retryAfterMs: 0 };
    }
    shortestWait = Math.min(shortestWait, availableAt - now);
  }
  return { key: '', retryAfterMs: Math.max(1, shortestWait) };
}

export function getScanCapacity() {
  return {
    parallelism: getApiKeys().length,
    minIntervalMs: Math.max(0, CHECK_MIN_INTERVAL_MS)
  };
}

export function getScanCapacityResponse(request) {
  const blocked = rejectBlockedRequest(request);
  if (blocked) return blocked;
  if (request.method !== 'GET') return json({ detail: 'Method not allowed' }, 405);
  const capacity = getScanCapacity();
  if (!capacity.parallelism) return json({ detail: 'Missing TUBESAVE_API_KEYS or TUBESAVE_API_KEY on Vercel' }, 401);
  return json(capacity);
}

function toHeaders(nodeHeaders = {}) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(nodeHeaders)) {
    if (value === undefined) continue;
    headers.set(name, Array.isArray(value) ? value.join(', ') : String(value));
  }
  return headers;
}

async function readNodeBody(request) {
  if (request.body !== undefined && request.body !== null) {
    if (Buffer.isBuffer(request.body)) return request.body.toString('utf8');
    return typeof request.body === 'string' ? request.body : JSON.stringify(request.body);
  }

  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', chunk => chunks.push(chunk));
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    request.on('error', reject);
  });
}

async function createWebRequest(request) {
  const protocol = String(request.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  const host = request.headers.host || 'localhost';
  const method = request.method || 'GET';
  const init = { method, headers: toHeaders(request.headers) };
  if (!['GET', 'HEAD'].includes(method)) init.body = await readNodeBody(request);
  return new Request(`${protocol}://${host}${request.url || '/'}`, init);
}

async function sendNodeResponse(response, result) {
  response.statusCode = result.status;
  result.headers.forEach((value, name) => response.setHeader(name, value));
  response.end(Buffer.from(await result.arrayBuffer()));
}

export async function handleNodeCapacityRequest(request, response) {
  try {
    await sendNodeResponse(response, getScanCapacityResponse(await createWebRequest(request)));
  } catch (error) {
    response.statusCode = 500;
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    response.end(JSON.stringify({ detail: error.message || 'Capacity endpoint failed' }));
  }
}

export async function handleNodeProxyRequest(request, response, endpoint, allowedMethods) {
  try {
    const webRequest = await createWebRequest(request);
    await sendNodeResponse(response, await proxyPhoneLookup(webRequest, endpoint, allowedMethods));
  } catch (error) {
    response.statusCode = 500;
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    response.end(JSON.stringify({ detail: error.message || 'Proxy endpoint failed' }));
  }
}

export async function proxyPhoneLookup(request, endpoint, allowedMethods) {
  const blocked = rejectBlockedRequest(request);
  if (blocked) return blocked;
  if (!allowedMethods.includes(request.method)) {
    return json({ detail: 'Method not allowed' }, 405);
  }
  const keys = getApiKeys();
  if (!keys.length) return json({ detail: 'Missing TUBESAVE_API_KEYS or TUBESAVE_API_KEY on Vercel' }, 401);

  let requestBody = null;
  if (request.method === 'POST') {
    try {
      requestBody = await buildUpstreamBody(request);
    } catch (error) {
      return json({ detail: error.message || 'Invalid request body' }, error.status || 400);
    }
  }

  const slotHeader = request.headers.get('x-scan-slot');
  const requestedSlot = slotHeader === null ? NaN : Number(slotHeader);
  const reserved = endpoint === 'check'
    ? reserveCheckKey(Number.isInteger(requestedSlot) ? requestedSlot : null)
    : { key: keys[0], retryAfterMs: 0 };
  if (!reserved.key) {
    return json(
      { detail: 'Scan proxy rate limit', retryAfterMs: reserved.retryAfterMs },
      429,
      { 'Retry-After': String(Math.ceil(reserved.retryAfterMs / 1000)) }
    );
  }

  const headers = {
    Accept: 'application/json',
    'X-API-Key': reserved.key
  };
  const init = { method: request.method, headers };

  if (request.method === 'POST') {
    init.body = requestBody;
    headers['Content-Type'] = 'application/json';
  }

  let upstream;
  try {
    upstream = await fetch(`${TUBESAVE_BASE}/${endpoint}`, init);
  } catch (error) {
    return json({ detail: error.message || 'Upstream request failed' }, 502);
  }

  const contentType = upstream.headers.get('content-type') || 'application/json; charset=utf-8';
  const body = await upstream.text();
  return new Response(body, {
    status: upstream.status,
    headers: { 'Content-Type': contentType, ...getRateLimitHeaders() }
  });
}
