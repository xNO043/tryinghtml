import { proxySuperassets } from '../../../lib/tubesave-proxy.mjs';

export default {
  fetch(request) {
    return proxySuperassets(request, 'me', ['GET']);
  }
};
