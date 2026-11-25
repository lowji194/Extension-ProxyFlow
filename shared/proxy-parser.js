// shared/proxy-parser.js — Parse and format proxy strings across common notations

const VALID_SCHEMES = new Set(['http', 'https', 'socks4', 'socks5']);

/**
 * Parses a single proxy string into normalized fields.
 * Supported formats:
 * - ip:port
 * - ip:port:user:pass
 * - user:pass@ip:port
 * - scheme://ip:port
 * - scheme://user:pass@ip:port
 * - scheme://ip:port:user:pass
 * - [ipv6]:port[:user:pass]
 * - Optional trailing "|label" for bulk imports
 */
export function parseProxyLine(rawInput) {
  if (!rawInput || typeof rawInput !== 'string') return null;

  let text = rawInput.trim();
  if (!text || text.startsWith('#') || text.startsWith('//')) return null;

  let label = '';
  const pipeIdx = text.indexOf('|');
  if (pipeIdx !== -1) {
    label = text.slice(pipeIdx + 1).trim();
    text = text.slice(0, pipeIdx).trim();
  }

  let scheme = 'http';
  const schemeMatch = text.match(/^([a-zA-Z0-9]+):\/\//);
  if (schemeMatch) {
    const candidate = schemeMatch[1].toLowerCase();
    if (VALID_SCHEMES.has(candidate)) {
      scheme = candidate;
    } else if (candidate === 'socks') {
      scheme = 'socks5';
    }
    text = text.slice(schemeMatch[0].length);
  }

  // Strip trailing slash/path if URL-like
  const slashIdx = text.indexOf('/');
  if (slashIdx !== -1) {
    text = text.slice(0, slashIdx);
  }

  let host = '';
  let portStr = '';
  let username = '';
  let password = '';

  const atIdx = text.lastIndexOf('@');
  if (atIdx !== -1) {
    const authPart = text.slice(0, atIdx);
    const hostPart = text.slice(atIdx + 1);
    const colonAuth = authPart.indexOf(':');
    if (colonAuth !== -1) {
      username = decodeSafe(authPart.slice(0, colonAuth));
      password = decodeSafe(authPart.slice(colonAuth + 1));
    } else {
      username = decodeSafe(authPart);
    }
    const parsedHostPort = splitHostPort(hostPart);
    if (!parsedHostPort) return null;
    host = parsedHostPort.host;
    portStr = parsedHostPort.port;
  } else if (text.startsWith('[')) {
    const closeBracket = text.indexOf(']');
    if (closeBracket === -1) return null;
    host = text.slice(1, closeBracket);
    const rest = text.slice(closeBracket + 1);
    if (!rest.startsWith(':')) return null;
    const parts = rest.slice(1).split(':');
    portStr = parts[0] || '';
    username = parts[1] || '';
    password = parts.slice(2).join(':') || '';
  } else {
    const parts = text.split(':');
    if (parts.length < 2) return null;
    host = parts[0].trim();
    portStr = parts[1].trim();
    username = (parts[2] ?? '').trim();
    password = parts.slice(3).join(':').trim();
  }

  const port = parseInt(portStr, 10);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    return null;
  }

  return {
    scheme,
    host,
    port,
    username,
    password,
    name: label || `${host}:${port}`
  };
}

export function parseProxyBulk(multilineText) {
  if (!multilineText || typeof multilineText !== 'string') {
    return { valid: [], invalidLines: [] };
  }
  const lines = multilineText.split(/\r?\n/);
  const valid = [];
  const invalidLines = [];

  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) return;
    const parsed = parseProxyLine(trimmed);
    if (parsed) {
      valid.push(parsed);
    } else {
      invalidLines.push({ lineNumber: idx + 1, text: trimmed });
    }
  });

  return { valid, invalidLines };
}

function splitHostPort(hostPart) {
  if (!hostPart) return null;
  if (hostPart.startsWith('[')) {
    const end = hostPart.indexOf(']');
    if (end === -1) return null;
    const host = hostPart.slice(1, end);
    const port = hostPart.slice(end + 1).replace(/^:/, '');
    return { host, port };
  }
  const colonIdx = hostPart.lastIndexOf(':');
  if (colonIdx === -1) return null;
  return {
    host: hostPart.slice(0, colonIdx).trim(),
    port: hostPart.slice(colonIdx + 1).trim()
  };
}

function decodeSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function formatProxyColon(profile) {
  if (!profile || !profile.host || !profile.port) return '';
  if (profile.username || profile.password) {
    return `${profile.host}:${profile.port}:${profile.username || ''}:${profile.password || ''}`;
  }
  return `${profile.host}:${profile.port}`;
}

export function formatProxyUri(profile) {
  if (!profile || !profile.host || !profile.port) return '';
  const scheme = profile.scheme || 'http';
  const host = profile.host.includes(':') ? `[${profile.host}]` : profile.host;
  if (profile.username) {
    const u = encodeURIComponent(profile.username);
    const p = encodeURIComponent(profile.password || '');
    return `${scheme}://${u}:${p}@${host}:${profile.port}`;
  }
  return `${scheme}://${host}:${profile.port}`;
}

export function proxyIdentityKey(profile) {
  if (!profile) return '';
  return `${(profile.scheme || 'http').toLowerCase()}://${profile.host}:${profile.port}`;
}

export function maskSecret(secret) {
  if (!secret) return 'None';
  if (secret.length <= 2) return '••';
  return `${secret[0]}${'•'.repeat(Math.min(8, secret.length - 2))}${secret[secret.length - 1]}`;
}
