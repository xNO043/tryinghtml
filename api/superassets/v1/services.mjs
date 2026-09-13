import { proxySuperassets } from '../../../lib/superassets-proxy.mjs';

export default {
  fetch(request) {
    return proxySuperassets(request, 'services', ['GET']);
  }
};
