import {
  readAccountBackup,
  syncAccountBackup
} from '../lib/backup-service.mjs';
import { requireAccountSession } from '../lib/account-service.mjs';
import {
  ShareError,
  methodNotAllowed,
  readJsonBody,
  requireTrustedCreateOrigin,
  sendJson
} from '../lib/share-service.mjs';

export default async function handler(request, response) {
  if (request.method !== 'POST') return methodNotAllowed(response);
  try {
    requireTrustedCreateOrigin(request);
    const body = await readJsonBody(request, 128 * 1024);
    const account = await requireAccountSession(request);
    if (body.action === 'sync') return sendJson(response, 200, await syncAccountBackup(account, body));
    if (body.action === 'read') return sendJson(response, 200, await readAccountBackup(account));
    throw new ShareError('Invalid backup action');
  } catch (error) {
    const status = error instanceof ShareError ? error.status : 500;
    return sendJson(response, status, { detail: error.message || 'Unable to access backup vault' });
  }
}
