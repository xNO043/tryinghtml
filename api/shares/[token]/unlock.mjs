import {
  ShareError,
  methodNotAllowed,
  readJsonBody,
  sendJson,
  unlockProtectedShare
} from '../../../lib/share-service.mjs';

export default async function handler(request, response) {
  if (request.method !== 'POST') return methodNotAllowed(response);
  try {
    const token = Array.isArray(request.query.token) ? request.query.token[0] : request.query.token;
    const body = await readJsonBody(request);
    return sendJson(response, 200, await unlockProtectedShare(token, body.password));
  } catch (error) {
    const status = error instanceof ShareError ? error.status : 500;
    return sendJson(response, status, { detail: error.message || 'Unable to unlock share link' });
  }
}
