import {
  ShareError,
  deleteManagedShare,
  getManagedShareContent,
  listManagedShareActivity,
  listManagedShares,
  methodNotAllowed,
  readJsonBody,
  requireTrustedCreateOrigin,
  sendJson,
  setManagedShareMessage,
  setManagedShareStatus,
  updateManagedShareContent,
  updateManagedShareControls
} from '../../lib/share-service.mjs';

export default async function handler(request, response) {
  if (request.method !== 'POST') return methodNotAllowed(response);
  try {
    requireTrustedCreateOrigin(request);
    const body = await readJsonBody(request, 32 * 1024);
    if (body.action === 'list') return sendJson(response, 200, { shares: await listManagedShares(request, body.links) });
    if (body.action === 'set-status') {
      const share = await setManagedShareStatus(request, body.identifier, body.managementKey, Boolean(body.revoked));
      return sendJson(response, 200, { share });
    }
    if (body.action === 'set-message') {
      const share = await setManagedShareMessage(request, body.identifier, body.managementKey, body.message);
      return sendJson(response, 200, { share });
    }
    if (body.action === 'get-content') {
      return sendJson(response, 200, await getManagedShareContent(request, body.identifier, body.managementKey));
    }
    if (body.action === 'set-content') {
      const share = await updateManagedShareContent(request, body.identifier, body.managementKey, body.urls);
      return sendJson(response, 200, { share });
    }
    if (body.action === 'set-controls') {
      const share = await updateManagedShareControls(request, body.identifier, body.managementKey, body.controls);
      return sendJson(response, 200, { share });
    }
    if (body.action === 'activity') {
      return sendJson(response, 200, { events: await listManagedShareActivity(body.identifier, body.managementKey) });
    }
    if (body.action === 'delete') {
      return sendJson(response, 200, await deleteManagedShare(body.identifier, body.managementKey));
    }
    throw new ShareError('Invalid management action');
  } catch (error) {
    const status = error instanceof ShareError ? error.status : 500;
    return sendJson(response, status, { detail: error.message || 'Unable to manage share link' });
  }
}
