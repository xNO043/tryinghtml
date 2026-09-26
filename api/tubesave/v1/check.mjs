import { proxyPhoneLookup } from '../../../lib/tubesave-proxy.mjs';

export default {
  fetch(request) {
    return proxyPhoneLookup(request, 'check', ['POST']);
  }
};
