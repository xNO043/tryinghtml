import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { ShareError, supabaseRequest } from './share-service.mjs';

const SESSION_DAYS = 30;

function cleanUsername(value) {
  const username = String(value || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{2,31}$/.test(username)) {
    throw new ShareError('Username must be 3-32 characters: letters, numbers, _ or -');
  }
  return username;
}

function cleanPassword(value) {
  const password = String(value || '');
  if (password.length < 8 || password.length > 128) {
    throw new ShareError('Password must contain 8-128 characters');
  }
  return password;
}

function passwordHash(password, salt) {
  return scryptSync(password, salt, 64).toString('base64url');
}

function equalValues(left, right) {
  const a = Buffer.from(String(left || ''), 'utf8');
  const b = Buffer.from(String(right || ''), 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function sessionHash(token) {
  return createHash('sha256').update(String(token)).digest('base64url');
}

function parseCookies(request) {
  return String(request.headers.cookie || '').split(';').reduce((cookies, item) => {
    const index = item.indexOf('=');
    if (index > 0) cookies[item.slice(0, index).trim()] = decodeURIComponent(item.slice(index + 1).trim());
    return cookies;
  }, {});
}

function sessionExpiry() {
  return new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();
}

async function getAccountByUsername(username) {
  const params = new URLSearchParams({
    select: 'id,username,password_hash,password_salt,created_at,last_login_at',
    username: `eq.${username}`,
    limit: '1'
  });
  const rows = await supabaseRequest(`app_accounts?${params.toString()}`);
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

async function getBackupInfo(accountId) {
  const params = new URLSearchParams({
    select: 'firebase_count,updated_at,created_at',
    account_id: `eq.${accountId}`,
    limit: '1'
  });
  const rows = await supabaseRequest(`firebase_backups?${params.toString()}`);
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

function publicAccount(account, backup = null) {
  return {
    id: account.id,
    username: account.username,
    createdAt: account.created_at,
    lastLoginAt: account.last_login_at,
    backup: backup ? {
      firebaseCount: Number(backup.firebase_count || 0),
      updatedAt: backup.updated_at,
      createdAt: backup.created_at
    } : null
  };
}

async function createSession(accountId) {
  const token = randomBytes(32).toString('base64url');
  const expiresAt = sessionExpiry();
  await supabaseRequest('app_sessions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
    body: JSON.stringify({ token_hash: sessionHash(token), account_id: accountId, expires_at: expiresAt })
  });
  return { token, expiresAt };
}

export function setAccountSessionCookie(response, token) {
  response.setHeader('Set-Cookie', `void_account_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 24 * 60 * 60}`);
}

export function clearAccountSessionCookie(response) {
  response.setHeader('Set-Cookie', 'void_account_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
}

export async function requireAccountSession(request) {
  const token = parseCookies(request).void_account_session;
  if (!token || !/^[A-Za-z0-9_-]{30,100}$/.test(token)) throw new ShareError('Please log in to access the account vault', 401);
  const params = new URLSearchParams({
    select: 'account_id,expires_at,app_accounts(id,username,created_at,last_login_at)',
    token_hash: `eq.${sessionHash(token)}`,
    limit: '1'
  });
  const rows = await supabaseRequest(`app_sessions?${params.toString()}`);
  const session = Array.isArray(rows) && rows.length ? rows[0] : null;
  if (!session || !session.app_accounts || Date.parse(session.expires_at) <= Date.now()) {
    throw new ShareError('Your login session has expired', 401);
  }
  return session.app_accounts;
}

export async function signupAccount(body) {
  const username = cleanUsername(body.username);
  const password = cleanPassword(body.password);
  const salt = randomBytes(16).toString('base64url');
  try {
    const rows = await supabaseRequest('app_accounts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({ username, password_hash: passwordHash(password, salt), password_salt: salt })
    });
    const account = Array.isArray(rows) && rows[0];
    if (!account) throw new ShareError('Account could not be created', 500);
    const session = await createSession(account.id);
    return { account: publicAccount(account), session };
  } catch (error) {
    if (error instanceof ShareError && /duplicate key|unique/i.test(error.message)) {
      throw new ShareError('That username is already taken', 409);
    }
    throw error;
  }
}

export async function loginAccount(body) {
  const username = cleanUsername(body.username);
  const password = cleanPassword(body.password);
  const account = await getAccountByUsername(username);
  if (!account || !equalValues(account.password_hash, passwordHash(password, account.password_salt))) {
    throw new ShareError('Invalid username or password', 401);
  }
  const loggedInAt = new Date().toISOString();
  await supabaseRequest(`app_accounts?id=eq.${encodeURIComponent(account.id)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
    body: JSON.stringify({ last_login_at: loggedInAt })
  });
  account.last_login_at = loggedInAt;
  const session = await createSession(account.id);
  return { account: publicAccount(account, await getBackupInfo(account.id)), session };
}

export async function getAccountProfile(request) {
  const account = await requireAccountSession(request);
  return { account: publicAccount(account, await getBackupInfo(account.id)) };
}

export async function logoutAccount(request) {
  const token = parseCookies(request).void_account_session;
  if (token) {
    await supabaseRequest(`app_sessions?token_hash=eq.${encodeURIComponent(sessionHash(token))}`, { method: 'DELETE' });
  }
}
