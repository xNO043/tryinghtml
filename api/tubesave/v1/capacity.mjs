import { handleNodeCapacityRequest } from '../../../lib/tubesave-proxy.mjs';

export default function handler(request, response) {
  return handleNodeCapacityRequest(request, response);
}
