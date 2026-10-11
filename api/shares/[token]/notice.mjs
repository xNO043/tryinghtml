import {
  getShareNotice,
  methodNotAllowed,
  sendJson,
  ShareError
} from '../../../lib/share-service.mjs';

export default async function handler(request, response) {
  if (request.method !== 'GET') return methodNotAllowed(response);
  try {
    const token = Array.isArray(request.query.token) ? request.query.token[0] : request.query.token;
    return sendJson(response, 200, await getShareNotice(request, token));
  } catch (error) {
    const status = error instanceof ShareError ? error.status : 500;
    return sendJson(response, status, { detail: error.message || 'Unable to read share notice' });
  }
}
