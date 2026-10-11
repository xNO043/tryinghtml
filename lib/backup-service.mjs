import { timingSafeEqual } from 'node:crypto';
import { ShareError, supabaseRequest } from './share-service.mjs';

function validateVaultId(value) {
  const vaultId = String(value || '').trim();
  if (!/^[A-Za-z0-9_-]{20,100}$/.test(vaultId)) throw new ShareError('Invalid backup vault ID');
  return vaultId;
}

function validateAuthHash(value) {
  const authHash = String(value || '').trim();
  if (!/^[A-Za-z0-9_-]{43,100}$/.test(authHash)) throw new ShareError('Invalid backup recovery key', 401);
  return authHash;
}

function validateEncryptedBackup(payload, iv) {
  const encryptedPayload = String(payload || '').trim();
  const safeIv = String(iv || '').trim();
  if (!/^[A-Za-z0-9_-]{16,120000}$/.test(encryptedPayload) || !/^[A-Za-z0-9_-]{16,100}$/.test(safeIv)) {
    throw new ShareError('Invalid encrypted backup');
  }
  return { encryptedPayload, iv: safeIv };
}

function validateFirebaseCount(value) {
  const count = Number(value);
  if (!Number.isInteger(count) || count < 0 || count > 10000) throw new ShareError('Invalid Firebase count');
  return count;
}

function matchingHash(expected, candidate) {
  const left = Buffer.from(String(expected || ''), 'utf8');
  const right = Buffer.from(String(candidate || ''), 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}

async function getVault(vaultId) {
  const params = new URLSearchParams({
    select: 'vault_id,auth_hash,encrypted_payload,iv,created_at,updated_at',
    vault_id: `eq.${vaultId}`,
    limit: '1'
  });
  const rows = await supabaseRequest(`firebase_backups?${params.toString()}`);
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

export async function createBackupVault(body) {
  const vaultId = validateVaultId(body.vaultId);
  const authHash = validateAuthHash(body.authHash);
  const encrypted = validateEncryptedBackup(body.encryptedPayload, body.iv);
  try {
    await supabaseRequest('firebase_backups', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({
        vault_id: vaultId,
        auth_hash: authHash,
        encrypted_payload: encrypted.encryptedPayload,
        iv: encrypted.iv
      })
    });
  } catch (error) {
    if (error instanceof ShareError && /duplicate key|unique constraint/i.test(error.message)) {
      throw new ShareError('This backup vault already exists', 409);
    }
    throw error;
  }
  return { vaultId, created: true };
}

export async function updateBackupVault(body) {
  const vaultId = validateVaultId(body.vaultId);
  const authHash = validateAuthHash(body.authHash);
  const encrypted = validateEncryptedBackup(body.encryptedPayload, body.iv);
  const vault = await getVault(vaultId);
  if (!vault || !matchingHash(vault.auth_hash, authHash)) throw new ShareError('Backup vault could not be unlocked', 403);
  const updatedAt = new Date().toISOString();
  await supabaseRequest(`firebase_backups?vault_id=eq.${encodeURIComponent(vaultId)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
    body: JSON.stringify({ encrypted_payload: encrypted.encryptedPayload, iv: encrypted.iv, updated_at: updatedAt })
  });
  return { vaultId, updatedAt };
}

export async function readBackupVault(body) {
  const vaultId = validateVaultId(body.vaultId);
  const authHash = validateAuthHash(body.authHash);
  const vault = await getVault(vaultId);
  if (!vault || !matchingHash(vault.auth_hash, authHash)) throw new ShareError('Backup vault could not be unlocked', 403);
  return {
    vaultId: vault.vault_id,
    encryptedPayload: vault.encrypted_payload,
    iv: vault.iv,
    createdAt: vault.created_at,
    updatedAt: vault.updated_at
  };
}

// Account vaults are keyed by the authenticated account instead of browser-held
// recovery credentials. The encrypted payload remains unreadable to the server.
export async function syncAccountBackup(account, body) {
  const encrypted = validateEncryptedBackup(body.encryptedPayload, body.iv);
  const firebaseCount = validateFirebaseCount(body.firebaseCount);
  const accountId = String(account && account.id || '');
  if (!accountId) throw new ShareError('Please log in to access the account vault', 401);
  const updatedAt = new Date().toISOString();
  const vaultId = `account_${accountId.replace(/-/g, '')}`;
  const current = await supabaseRequest(`firebase_backups?${new URLSearchParams({ select: 'vault_id', account_id: `eq.${accountId}`, limit: '1' }).toString()}`);
  const record = {
    vault_id: vaultId,
    account_id: accountId,
    auth_hash: 'account-session',
    encrypted_payload: encrypted.encryptedPayload,
    iv: encrypted.iv,
    firebase_count: firebaseCount,
    updated_at: updatedAt
  };
  if (Array.isArray(current) && current.length) {
    await supabaseRequest(`firebase_backups?vault_id=eq.${encodeURIComponent(current[0].vault_id)}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify(record)
    });
  } else {
    await supabaseRequest('firebase_backups', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify(record)
    });
  }
  return { firebaseCount, updatedAt };
}

export async function readAccountBackup(account) {
  const accountId = String(account && account.id || '');
  if (!accountId) throw new ShareError('Please log in to access the account vault', 401);
  const params = new URLSearchParams({
    select: 'encrypted_payload,iv,firebase_count,created_at,updated_at',
    account_id: `eq.${accountId}`,
    limit: '1'
  });
  const rows = await supabaseRequest(`firebase_backups?${params.toString()}`);
  const backup = Array.isArray(rows) && rows.length ? rows[0] : null;
  if (!backup) throw new ShareError('No backup has been saved to this account yet', 404);
  return {
    encryptedPayload: backup.encrypted_payload,
    iv: backup.iv,
    firebaseCount: Number(backup.firebase_count || 0),
    createdAt: backup.created_at,
    updatedAt: backup.updated_at
  };
}
