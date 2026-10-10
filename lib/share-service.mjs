import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
  timingSafeEqual
} from 'node:crypto';

const MAX_SHARED_URLS = 50;
const DEFAULT_EXPIRY_DAYS = 30;

export class ShareError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

export function sendJson(response, status, body) {
  response.statusCode = status;
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.setHeader('Cache-Control', 'no-store');
  response.end(JSON.stringify(body));
}

export function methodNotAllowed(response) {
  response.setHeader('Allow', 'GET, POST');
  return sendJson(response, 405, { detail: 'Method not allowed' });
}

export async function readJsonBody(request, maxBytes = 16 * 1024) {
  if (request.body && typeof request.body === 'object' && !Buffer.isBuffer(request.body)) return request.body;
  const raw = await new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on('data', chunk => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new ShareError('Request body is too large', 413));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    request.on('error', reject);
  });
  try {
    return raw.trim() ? JSON.parse(raw) : {};
  } catch {
    throw new ShareError('Invalid JSON body');
  }
}

function getRequiredEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) throw new ShareError(`Missing server configuration: ${name}`, 503);
  return value;
}

function getEncryptionKey() {
  const raw = getRequiredEnv('SHARE_ENCRYPTION_KEY');
  let key;
  try {
    key = Buffer.from(raw, 'base64url');
  } catch {
    throw new ShareError('SHARE_ENCRYPTION_KEY must be Base64URL encoded', 503);
  }
  if (key.length !== 32) throw new ShareError('SHARE_ENCRYPTION_KEY must contain exactly 32 bytes', 503);
  return key;
}

function normalizeFirebaseUrl(value) {
  try {
    const url = new URL(String(value || '').trim());
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) return '';
    if (!/^[a-z0-9-]+\.firebaseio\.com$/i.test(url.hostname)) return '';
    if (url.pathname !== '/.json') return '';
    return `https://${url.hostname.toLowerCase()}/.json`;
  } catch {
    return '';
  }
}

function validateUrls(urls) {
  if (!Array.isArray(urls) || !urls.length) throw new ShareError('Select at least one Firebase node');
  if (urls.length > MAX_SHARED_URLS) throw new ShareError(`You can share up to ${MAX_SHARED_URLS} Firebase nodes at once`);
  const normalized = [...new Set(urls.map(normalizeFirebaseUrl).filter(Boolean))];
  if (normalized.length !== urls.length) throw new ShareError('One or more Firebase URLs are invalid');
  return normalized;
}

function validateAlias(alias, type) {
  const value = String(alias || '').trim().toLowerCase();
  if (type === 'default') return null;
  if (!/^[a-z0-9][a-z0-9-]{2,59}$/.test(value)) {
    throw new ShareError('Custom URL must use 3-60 letters, numbers, or dashes');
  }
  return value;
}

function encryptPayload(payload) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', getEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
  return {
    encryptedPayload: encrypted.toString('base64url'),
    iv: iv.toString('base64url'),
    authTag: cipher.getAuthTag().toString('base64url')
  };
}

function decryptPayload(record) {
  try {
    const decipher = createDecipheriv('aes-256-gcm', getEncryptionKey(), Buffer.from(record.iv, 'base64url'));
    decipher.setAuthTag(Buffer.from(record.auth_tag, 'base64url'));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(record.encrypted_payload, 'base64url')),
      decipher.final()
    ]);
    const payload = JSON.parse(plain.toString('utf8'));
    const urls = validateUrls(payload.urls);
    return { urls };
  } catch (error) {
    if (error instanceof ShareError) throw error;
    throw new ShareError('This shared link cannot be decrypted', 500);
  }
}

function hashPassword(password, salt) {
  return scryptSync(password, salt, 64).toString('base64url');
}

function buildPasswordFields(protection) {
  const mode = protection && protection.mode === 'password' ? 'password' : 'public';
  if (mode === 'public') return { passwordHash: null, passwordSalt: null };
  const password = String(protection.password || '');
  if (password.length < 8 || password.length > 128) {
    throw new ShareError('Password must contain 8-128 characters');
  }
  const salt = randomBytes(16).toString('base64url');
  return { passwordHash: hashPassword(password, salt), passwordSalt: salt };
}

function supabaseHeaders(extra = {}) {
  const key = getRequiredEnv('SUPABASE_SECRET_KEY');
  return {
    apikey: key,
    Authorization: `Bearer ${key}`,
    ...extra
  };
}

function supabaseUrl(path) {
  return `${getRequiredEnv('SUPABASE_URL').replace(/\/$/, '')}/rest/v1/${path}`;
}

async function supabaseRequest(path, options = {}) {
  const response = await fetch(supabaseUrl(path), {
    ...options,
    headers: supabaseHeaders(options.headers)
  });
  const raw = await response.text();
  let data = null;
  try { data = raw ? JSON.parse(raw) : null; } catch { data = raw; }
  if (!response.ok) {
    const message = data && typeof data === 'object' ? (data.message || data.details || data.hint) : raw;
    throw new ShareError(message || 'Database request failed', response.status >= 500 ? 502 : 500);
  }
  return data;
}

function toToken() {
  return randomBytes(18).toString('base64url');
}

function requestOrigin(request) {
  const protocol = String(request.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  const host = String(request.headers.host || '').trim();
  return host ? `${protocol}://${host}` : '';
}

export function requireTrustedCreateOrigin(request) {
  const allowedOrigin = String(process.env.APP_ORIGIN || '').replace(/\/$/, '');
  const origin = String(request.headers.origin || '').replace(/\/$/, '');
  if (!allowedOrigin) throw new ShareError('Missing server configuration: APP_ORIGIN', 503);
  if (!origin || origin !== allowedOrigin) throw new ShareError('Share creation is not allowed from this origin', 403);
}

function buildShareUrl(request, identifier) {
  const base = String(process.env.SHARE_BASE_URL || requestOrigin(request)).replace(/\/$/, '');
  if (!base) throw new ShareError('Unable to determine the share URL', 503);
  return `${base}/s/${identifier}`;
}

export async function createShare(request, body) {
  const urls = validateUrls(body.urls);
  const linkType = body.linkType === 'custom' ? 'custom' : 'default';
  const alias = validateAlias(body.alias, linkType);
  const passwordFields = buildPasswordFields(body.protection);
  const encrypted = encryptPayload({ urls, createdAt: new Date().toISOString() });
  const token = toToken();
  const expiresAt = new Date(Date.now() + DEFAULT_EXPIRY_DAYS * 24 * 60 * 60 * 1000).toISOString();

  try {
    await supabaseRequest('shared_links', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({
        token,
        alias,
        encrypted_payload: encrypted.encryptedPayload,
        iv: encrypted.iv,
        auth_tag: encrypted.authTag,
        password_hash: passwordFields.passwordHash,
        password_salt: passwordFields.passwordSalt,
        expires_at: expiresAt
      })
    });
  } catch (error) {
    if (error instanceof ShareError && /duplicate key|unique constraint/i.test(error.message)) {
      throw new ShareError('This custom URL is already in use', 409);
    }
    throw error;
  }

  return {
    url: buildShareUrl(request, alias || token),
    expiresAt,
    protected: Boolean(passwordFields.passwordHash)
  };
}

function validateLookup(value) {
  const lookup = String(value || '').trim();
  if (!/^[a-zA-Z0-9_-]{3,80}$/.test(lookup)) throw new ShareError('Invalid share link', 404);
  return lookup.toLowerCase();
}

export async function findShare(lookup) {
  const value = validateLookup(lookup);
  const params = new URLSearchParams({
    select: 'id,token,alias,encrypted_payload,iv,auth_tag,password_hash,password_salt,expires_at,revoked_at,access_count,max_accesses',
    or: `(token.eq.${value},alias.eq.${value})`,
    limit: '1'
  });
  const rows = await supabaseRequest(`shared_links?${params.toString()}`);
  if (!Array.isArray(rows) || !rows.length) throw new ShareError('This share link was not found', 404);
  const record = rows[0];
  if (record.revoked_at) throw new ShareError('This share link has been revoked', 410);
  if (new Date(record.expires_at).getTime() <= Date.now()) throw new ShareError('This share link has expired', 410);
  if (record.max_accesses && record.access_count >= record.max_accesses) throw new ShareError('This share link has reached its access limit', 410);
  return record;
}

async function incrementAccess(record) {
  await supabaseRequest(`shared_links?id=eq.${encodeURIComponent(record.id)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
    body: JSON.stringify({ access_count: Number(record.access_count || 0) + 1 })
  });
}

export async function openPublicShare(lookup) {
  const record = await findShare(lookup);
  if (record.password_hash) {
    return { protected: true, expiresAt: record.expires_at, label: record.alias || record.token };
  }
  const payload = decryptPayload(record);
  await incrementAccess(record);
  return { protected: false, expiresAt: record.expires_at, label: record.alias || record.token, ...payload };
}

export async function unlockProtectedShare(lookup, password) {
  const record = await findShare(lookup);
  if (!record.password_hash || !record.password_salt) throw new ShareError('This share link is public');
  const candidate = Buffer.from(hashPassword(String(password || ''), record.password_salt), 'base64url');
  const expected = Buffer.from(record.password_hash, 'base64url');
  if (candidate.length !== expected.length || !timingSafeEqual(candidate, expected)) {
    throw new ShareError('Incorrect share password', 401);
  }
  const payload = decryptPayload(record);
  await incrementAccess(record);
  return { expiresAt: record.expires_at, label: record.alias || record.token, ...payload };
}
