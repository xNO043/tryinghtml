import { getScanCapacityResponse } from '../../../lib/tubesave-proxy.mjs';

export default {
  fetch(request) {
    return getScanCapacityResponse(request);
  }
};
