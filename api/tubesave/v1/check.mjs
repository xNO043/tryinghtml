import { handleNodeProxyRequest } from '../../../lib/tubesave-proxy.mjs';

export default function handler(request, response) {
  return handleNodeProxyRequest(request, response, 'check', ['POST']);
}
