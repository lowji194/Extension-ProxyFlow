// shared/ip-probe.js — Standard high-availability HTTPS check-live & IP lookup providers

export const IP_PROVIDERS = {
  cloudflare: {
    id: 'cloudflare',
    label: 'Cloudflare Trace (Recommended · IP + Country)',
    url: 'https://cloudflare.com/cdn-cgi/trace',
    type: 'cf_trace'
  },
  oneone: {
    id: 'oneone',
    label: 'Cloudflare 1.1.1.1 Anycast Trace',
    url: 'https://1.1.1.1/cdn-cgi/trace',
    type: 'cf_trace'
  },
  icanhazip: {
    id: 'icanhazip',
    label: 'icanhazip.com (Cloudflare Plain IP)',
    url: 'https://icanhazip.com/',
    type: 'text'
  },
  ipify: {
    id: 'ipify',
    label: 'ipify IPv4 (api.ipify.org)',
    url: 'https://api.ipify.org/',
    type: 'text'
  },
  ipify64: {
    id: 'ipify64',
    label: 'ipify IPv4/IPv6 (api64.ipify.org)',
    url: 'https://api64.ipify.org/',
    type: 'text'
  }
};

export function isValidIpLiteral(value) {
  if (!value || typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 45 || /[<>\s]/.test(trimmed)) return false;

  // IPv4 check
  const ipv4Parts = trimmed.split('.');
  if (ipv4Parts.length === 4) {
    return ipv4Parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
  }

  // IPv6 check
  return trimmed.includes(':') && /^[0-9a-fA-F:]+$/.test(trimmed);
}

export function parseProbeBody(rawText, type) {
  if (!rawText || typeof rawText !== 'string') return null;

  if (type === 'cf_trace') {
    const map = {};
    for (const line of rawText.split(/\r?\n/)) {
      const idx = line.indexOf('=');
      if (idx > 0) {
        map[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      }
    }
    if (!isValidIpLiteral(map.ip)) return null;
    return {
      exitIp: map.ip,
      country: map.loc || null
    };
  }

  const ip = rawText.trim();
  if (!isValidIpLiteral(ip)) return null;
  return { exitIp: ip, country: null };
}

export function getProviderOrder(preferredId = 'cloudflare') {
  const defaultOrder = ['cloudflare', 'oneone', 'icanhazip', 'ipify', 'ipify64'];
  const keys = IP_PROVIDERS[preferredId]
    ? [preferredId, ...defaultOrder.filter((id) => id !== preferredId)]
    : defaultOrder;
  return keys.map((k) => IP_PROVIDERS[k]);
}

export async function runStandardIpProbe(preferredProviderId = 'cloudflare', timeoutMs = 6000) {
  const providers = getProviderOrder(preferredProviderId);
  let lastError = 'Connection failed';

  for (const provider of providers) {
    const startedAt = performance.now();
    try {
      const res = await fetch(provider.url, {
        cache: 'no-store',
        signal: AbortSignal.timeout(timeoutMs)
      });
      if (!res.ok) {
        lastError = `${provider.id}: HTTP ${res.status}`;
        continue;
      }
      const body = await res.text();
      const parsed = parseProbeBody(body, provider.type);
      if (!parsed) {
        lastError = `${provider.id}: Invalid response`;
        continue;
      }

      return {
        status: 'live',
        latencyMs: Math.round(performance.now() - startedAt),
        exitIp: parsed.exitIp,
        country: parsed.country,
        provider: provider.id,
        error: null,
        checkedAt: Date.now()
      };
    } catch (err) {
      lastError = err.message || `${provider.id}: Network error`;
    }
  }

  return {
    status: 'dead',
    latencyMs: null,
    exitIp: null,
    country: null,
    provider: null,
    error: lastError,
    checkedAt: Date.now()
  };
}
