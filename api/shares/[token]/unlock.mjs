import {
  ShareError,
  methodNotAllowed,
  readJsonBody,
  sendJson,
  setShareUnlockCookie,
  unlockProtectedShare
} from '../../../lib/share-service.mjs';

export default async function handler(request, response) {
  if (request.method !== 'POST') return methodNotAllowed(response);
  try {
    const token = Array.isArray(request.query.token) ? request.query.token[0] : request.query.token;
    const body = await readJsonBody(request);
    const unlocked = await unlockProtectedShare(token, body.password, request.headers['x-share-browser-id']);
    setShareUnlockCookie(response, token, unlocked.record);
    return sendJson(response, 200, unlocked.share);
  } catch (error) {
    const status = error instanceof ShareError ? error.status : 500;
    return sendJson(response, status, { detail: error.message || 'Unable to unlock share link' });
  }
}
