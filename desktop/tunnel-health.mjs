// SPDX-License-Identifier: AGPL-3.0-only
export async function probePublicRelay(url, { fetchImpl = fetch, signal } = {}) {
  try {
    const timeout = AbortSignal.timeout(8000);
    const response = await fetchImpl(url + '/v1/health', {
      redirect: 'error', signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
      headers: { 'cache-control': 'no-cache' }
    });
    if (!response.ok) return false;
    const value = await response.json();
    return value.service === 'ENCPTD' && value.protectedTransport === true;
  } catch { return false; }
}

export class TunnelHealth {
  constructor() { this.ready = false; this.failures = 0; }
  observe(healthy) {
    if (healthy) {
      this.failures = 0;
      if (!this.ready) { this.ready = true; return 'ready'; }
      return 'healthy';
    }
    return ++this.failures >= 3 ? 'restart' : 'waiting';
  }
}
