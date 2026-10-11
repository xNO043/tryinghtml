import {
  ShareError,
  createShare,
  methodNotAllowed,
  readJsonBody,
  requireTrustedCreateOrigin,
  sendJson
} from '../lib/share-service.mjs';

export default async function handler(request, response) {
  if (request.method !== 'POST') return methodNotAllowed(response);
  try {
    requireTrustedCreateOrigin(request);
    const body = await readJsonBody(request);
    const share = await createShare(request, body);
    return sendJson(response, 201, share);
  } catch (error) {
    const status = error instanceof ShareError ? error.status : 500;
    return sendJson(response, status, { detail: error.message || 'Unable to create share link' });
  }
}
