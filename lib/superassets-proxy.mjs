const SUPERASSETS_BASE = 'https://superassets.in/api/v1';
const CHECK_MIN_INTERVAL_MS = Number(process.env.CHECK_MIN_INTERVAL_MS || 5000);
const MAX_CHECK_BODY_BYTES = 1024;

function json(body, status = 200, headers = {}) {
  return Response.json(body, {
    status,
    headers: {
      ...headers,
      Vary: 'Origin'
    }
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

export async function proxySuperassets(request, endpoint, allowedMethods) {
  const blocked = rejectBlockedRequest(request);
  if (blocked) return blocked;

  if (!allowedMethods.includes(request.method)) {
    return json({ detail: 'Method not allowed' }, 405);
  }

  if (!process.env.SUPERASSETS_API_KEY) {
    return json({ detail: 'Missing SUPERASSETS_API_KEY on Vercel' }, 401);
  }

  const headers = {
    Accept: 'application/json',
    'X-API-Key': process.env.SUPERASSETS_API_KEY
  };
  const init = { method: request.method, headers };

  if (request.method === 'POST') {
    try {
      init.body = await buildUpstreamBody(request);
      headers['Content-Type'] = 'application/json';
    } catch (error) {
      return json({ detail: error.message || 'Invalid request body' }, error.status || 400);
    }
  }

  let upstream;
  try {
    upstream = await fetch(`${SUPERASSETS_BASE}/${endpoint}`, init);
  } catch (error) {
    return json({ detail: error.message || 'Upstream request failed' }, 502);
  }

  const contentType = upstream.headers.get('content-type') || 'application/json; charset=utf-8';
  const body = await upstream.text();
  return new Response(body, {
    status: upstream.status,
    headers: {
      'Content-Type': contentType,
      ...getRateLimitHeaders()
    }
  });
}
