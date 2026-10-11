import {
  clearAccountSessionCookie,
  getAccountProfile,
  loginAccount,
  logoutAccount,
  setAccountSessionCookie,
  signupAccount
} from '../lib/account-service.mjs';
import { ShareError, methodNotAllowed, readJsonBody, requireTrustedCreateOrigin, sendJson } from '../lib/share-service.mjs';

export default async function handler(request, response) {
  if (request.method !== 'POST') return methodNotAllowed(response);
  try {
    requireTrustedCreateOrigin(request);
    const body = await readJsonBody(request);
    if (body.action === 'signup' || body.action === 'login') {
      const result = body.action === 'signup' ? await signupAccount(body) : await loginAccount(body);
      setAccountSessionCookie(response, result.session.token);
      return sendJson(response, body.action === 'signup' ? 201 : 200, { account: result.account });
    }
    if (body.action === 'me') return sendJson(response, 200, await getAccountProfile(request));
    if (body.action === 'logout') {
      await logoutAccount(request);
      clearAccountSessionCookie(response);
      return sendJson(response, 200, { loggedOut: true });
    }
    throw new ShareError('Invalid account action');
  } catch (error) {
    const status = error instanceof ShareError ? error.status : 500;
    return sendJson(response, status, { detail: error.message || 'Unable to access account' });
  }
}
