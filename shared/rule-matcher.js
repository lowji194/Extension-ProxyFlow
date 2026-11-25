// shared/rule-matcher.js — ZeroOmega-inspired rule evaluator, rule-list parser, and PAC compiler

import { BUILTIN_PROFILES, DEFAULT_BYPASS_LIST, getProfileById } from './models.js';

/**
 * Escapes regex metacharacters while keeping wildcard '*' and '?' conversion optional.
 */
function escapeRegexChars(str) {
  return str.replace(/[.+^${}()|[\]\\]/g, '\\$&');
}

function wildcardToRegexSource(pattern) {
  return escapeRegexChars(pattern)
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
}

/**
 * Compiles a HostWildcard pattern following ZeroOmega semantics:
 * - `*.example.com` matches subdomains AND `example.com` itself
 * - `**.example.com` matches subdomains ONLY
 * - Otherwise exact wildcard match
 */
export function buildHostWildcardRegex(pattern) {
  const p = (pattern || '').trim().toLowerCase();
  if (!p) return null;
  if (p.startsWith('**.')) {
    const rest = wildcardToRegexSource(p.slice(3));
    return new RegExp(`^.+\\.${rest}$`, 'i');
  }
  if (p.startsWith('*.')) {
    const rest = wildcardToRegexSource(p.slice(2));
    return new RegExp(`^(?:.+\\.)?${rest}$`, 'i');
  }
  return new RegExp(`^${wildcardToRegexSource(p)}$`, 'i');
}

export function parseIpv4Int(ip) {
  if (!ip || typeof ip !== 'string') return null;
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return null;
    num = ((num << 8) | octet) >>> 0;
  }
  return num;
}

export function matchIpv4Cidr(host, cidrPattern) {
  const ipNum = parseIpv4Int(host);
  if (ipNum === null) return false;
  const [netStr, prefixStr] = (cidrPattern || '').trim().split('/');
  const netNum = parseIpv4Int(netStr);
  if (netNum === null) return false;
  const prefix = prefixStr === undefined ? 32 : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  if (prefix === 0) return true;
  const mask = (~0 << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (netNum & mask);
}

export function extractUrlParts(rawUrl) {
  try {
    const u = new URL(rawUrl);
    return {
      url: rawUrl,
      host: u.hostname.toLowerCase(),
      scheme: u.protocol.replace(':', '').toLowerCase()
    };
  } catch {
    return { url: rawUrl || '', host: '', scheme: '' };
  }
}

export function matchCondition(conditionType, pattern, url, host) {
  const rawPattern = (pattern || '').trim();
  if (!rawPattern) return false;

  switch (conditionType) {
    case 'hostWildcard': {
      const re = buildHostWildcardRegex(rawPattern);
      return re ? re.test(host) : false;
    }
    case 'hostRegex': {
      try {
        return new RegExp(rawPattern, 'i').test(host);
      } catch {
        return false;
      }
    }
    case 'urlWildcard': {
      const re = new RegExp(`^${wildcardToRegexSource(rawPattern)}$`, 'i');
      return re.test(url);
    }
    case 'urlRegex': {
      try {
        return new RegExp(rawPattern, 'i').test(url);
      } catch {
        return false;
      }
    }
    case 'cidr': {
      return matchIpv4Cidr(host, rawPattern);
    }
    case 'keyword': {
      return url.toLowerCase().includes(rawPattern.toLowerCase());
    }
    default:
      return false;
  }
}

export function validateConditionPattern(conditionType, pattern) {
  const raw = (pattern || '').trim();
  if (!raw) return 'Pattern is required.';
  if (conditionType === 'hostRegex' || conditionType === 'urlRegex') {
    try {
      new RegExp(raw);
    } catch (err) {
      return `Invalid regular expression: ${err.message}`;
    }
  }
  if (conditionType === 'cidr') {
    const [ipStr, prefixStr] = raw.split('/');
    if (parseIpv4Int(ipStr) === null) return 'Invalid IPv4 address for CIDR.';
    if (prefixStr !== undefined) {
      const p = Number(prefixStr);
      if (!Number.isInteger(p) || p < 0 || p > 32) return 'CIDR prefix must be between 0 and 32.';
    }
  }
  return null;
}

/**
 * Parses AutoProxy or Switchy rule-list text into normalized rule descriptors.
 * Exceptions (@@...) resolve to 'direct'.
 */
export function parseRuleList(text, format = 'autoproxy', matchProfileId = 'direct') {
  if (!text || typeof text !== 'string') return [];
  const lines = text.split(/\r?\n/);
  const parsed = [];

  if (format === 'switchy') {
    let section = 'hostWildcard';
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith(';') || line.startsWith('!') || line.startsWith('#') || line.startsWith('@')) continue;
      const secMatch = line.match(/^\[(.+)\]$/);
      if (secMatch) {
        const s = secMatch[1].toLowerCase();
        if (s.includes('regexp') || s.includes('regex')) section = 'urlRegex';
        else if (s.includes('wildcard')) section = 'urlWildcard';
        else section = 'hostWildcard';
        continue;
      }
      if (line === '*') continue;
      parsed.push({
        conditionType: section,
        pattern: line,
        profileId: matchProfileId,
        source: 'ruleList'
      });
    }
    return parsed;
  }

  // AutoProxy format: exception rules (@@...) always take precedence over match rules.
  const exceptions = [];
  const normalRules = [];

  for (const rawLine of lines) {
    let line = rawLine.trim();
    if (!line || line.startsWith('!') || line.startsWith('[') || line.startsWith(';')) continue;

    let isException = false;
    let targetProfileId = matchProfileId;
    if (line.startsWith('@@')) {
      isException = true;
      targetProfileId = 'direct';
      line = line.slice(2).trim();
      if (!line) continue;
    }

    const bucket = isException ? exceptions : normalRules;

    if (line.startsWith('/') && line.endsWith('/') && line.length > 2) {
      bucket.push({
        conditionType: 'urlRegex',
        pattern: line.slice(1, -1),
        profileId: targetProfileId,
        source: 'ruleList'
      });
    } else if (line.startsWith('||')) {
      const domain = line.slice(2).replace(/\/.*$/, '');
      if (domain) {
        bucket.push({
          conditionType: 'hostWildcard',
          pattern: `*.${domain.replace(/^\*\./, '')}`,
          profileId: targetProfileId,
          source: 'ruleList'
        });
      }
    } else if (line.startsWith('|')) {
      bucket.push({
        conditionType: 'urlWildcard',
        pattern: `${line.slice(1)}*`,
        profileId: targetProfileId,
        source: 'ruleList'
      });
    } else if (line.startsWith('.')) {
      const domain = line.slice(1).split('/')[0];
      if (domain) {
        bucket.push({
          conditionType: 'hostWildcard',
          pattern: `*.${domain}`,
          profileId: targetProfileId,
          source: 'ruleList'
        });
      }
    } else if (!line.includes('/') && line.includes('.')) {
      bucket.push({
        conditionType: 'hostWildcard',
        pattern: line.startsWith('*') ? line : `*.${line}`,
        profileId: targetProfileId,
        source: 'ruleList'
      });
    } else {
      bucket.push({
        conditionType: 'urlWildcard',
        pattern: `*${line}*`,
        profileId: targetProfileId,
        source: 'ruleList'
      });
    }
  }

  return [...exceptions, ...normalRules];
}

/**
 * Matches a URL against the active profile (plus Temp Rules) and returns detailed resolution trace.
 */
export function matchUrl(rawUrl, state, overrideProfileId = null) {
  const { url, host } = extractUrlParts(rawUrl);
  const activeProfile = getProfileById(state, overrideProfileId || state.activeProfileId);

  const trace = [];

  // Temp rules take highest priority per domain
  const tempRules = Object.values(state.tempRules || {});
  for (const rule of tempRules) {
    if (matchCondition(rule.conditionType || 'hostWildcard', rule.pattern, url, host)) {
      const resolved = getProfileById(state, rule.profileId);
      trace.push({
        source: 'temp',
        pattern: rule.pattern,
        conditionType: rule.conditionType || 'hostWildcard',
        profile: resolved
      });
      return {
        activeProfile,
        resolvedProfile: resolved,
        matchedRule: trace[0],
        trace
      };
    }
  }

  const visited = new Set();
  function resolveProfile(profile) {
    if (!profile) return BUILTIN_PROFILES.direct;
    if (visited.has(profile.id)) return BUILTIN_PROFILES.direct;
    visited.add(profile.id);

    if (profile.type === 'direct' || profile.type === 'pac') {
      return profile;
    }

    if (profile.type === 'fixed') {
      const bypass = profile.bypassList || DEFAULT_BYPASS_LIST;
      if (matchesBypassList(host, bypass)) {
        trace.push({
          source: 'bypass',
          pattern: 'bypassList',
          conditionType: 'bypass',
          profile: BUILTIN_PROFILES.direct
        });
        return BUILTIN_PROFILES.direct;
      }
      return profile;
    }

    if (profile.type === 'switch') {
      for (const rule of profile.rules || []) {
        if (rule.enabled === false) continue;
        if (matchCondition(rule.conditionType, rule.pattern, url, host)) {
          const target = getProfileById(state, rule.profileId);
          trace.push({
            source: 'rule',
            pattern: rule.pattern,
            conditionType: rule.conditionType,
            note: rule.note || '',
            profile: target
          });
          return resolveProfile(target);
        }
      }

      if (profile.ruleList?.enabled && profile.ruleList?.text) {
        const listRules = parseRuleList(
          profile.ruleList.text,
          profile.ruleList.format,
          profile.ruleList.matchProfileId
        );
        for (const rule of listRules) {
          if (matchCondition(rule.conditionType, rule.pattern, url, host)) {
            const target = getProfileById(state, rule.profileId);
            trace.push({
              source: 'ruleList',
              pattern: rule.pattern,
              conditionType: rule.conditionType,
              profile: target
            });
            return resolveProfile(target);
          }
        }
      }

      const fallback = getProfileById(state, profile.defaultProfileId || 'direct');
      trace.push({
        source: 'default',
        pattern: '*',
        conditionType: 'default',
        profile: fallback
      });
      return resolveProfile(fallback);
    }

    return BUILTIN_PROFILES.direct;
  }

  const resolvedProfile = resolveProfile(activeProfile);
  return {
    activeProfile,
    resolvedProfile,
    matchedRule: trace[0] || null,
    trace
  };
}

function matchesBypassList(host, bypassList) {
  if (!host || !Array.isArray(bypassList)) return false;
  for (const rawEntry of bypassList) {
    const entry = (rawEntry || '').trim().toLowerCase();
    if (!entry) continue;
    if (entry === '<local>') {
      if (!host.includes('.') || host === 'localhost' || host === '127.0.0.1' || host === '::1') {
        return true;
      }
      continue;
    }
    const clean = entry.replace(/^\[/, '').replace(/\]$/, '');
    if (clean.includes('/')) {
      if (matchIpv4Cidr(host, clean)) return true;
    } else if (clean.includes('*') || clean.includes('?')) {
      const re = buildHostWildcardRegex(clean);
      if (re && re.test(host)) return true;
    } else if (host === clean || host.endsWith(`.${clean}`)) {
      return true;
    }
  }
  return false;
}

/**
 * Converts a fixed profile into a PAC return directive.
 */
export function profileToPacReturn(profile) {
  if (!profile || profile.type !== 'fixed' || !profile.host || !profile.port) {
    return 'DIRECT';
  }
  const host = profile.host.includes(':') ? `[${profile.host}]` : profile.host;
  const endpoint = `${host}:${profile.port}`;
  switch ((profile.scheme || 'http').toLowerCase()) {
    case 'https':
      return `HTTPS ${endpoint}`;
    case 'socks5':
      return `SOCKS5 ${endpoint}; SOCKS ${endpoint}`;
    case 'socks4':
      return `SOCKS4 ${endpoint}; SOCKS ${endpoint}`;
    case 'http':
    default:
      return `PROXY ${endpoint}`;
  }
}

/**
 * Generates a self-contained FindProxyForURL(url, host) PAC script for Switch profiles
 * or Fixed profiles when Temp Rules are present.
 */
export function compilePacScript(state, profileId = null) {
  const activeProfile = getProfileById(state, profileId || state.activeProfileId);

  if (activeProfile.type === 'pac' && (!state.tempRules || Object.keys(state.tempRules).length === 0)) {
    return activeProfile.pacScript || 'function FindProxyForURL(url, host) { return "DIRECT"; }';
  }

  // Build lookup map of fixed profile PAC return strings + bypass lists
  const fixedMeta = {};
  for (const p of state.profiles || []) {
    if (p.type === 'fixed') {
      fixedMeta[p.id] = {
        directive: profileToPacReturn(p),
        bypass: p.bypassList || DEFAULT_BYPASS_LIST
      };
    }
  }

  const compiledProfiles = {};
  for (const p of state.profiles || []) {
    if (p.type === 'switch') {
      const combinedRules = [];
      for (const r of p.rules || []) {
        if (r.enabled !== false && r.pattern) {
          combinedRules.push({
            conditionType: r.conditionType,
            pattern: r.pattern,
            profileId: r.profileId || 'direct'
          });
        }
      }
      if (p.ruleList?.enabled && p.ruleList?.text) {
        const listRules = parseRuleList(p.ruleList.text, p.ruleList.format, p.ruleList.matchProfileId);
        for (const r of listRules) {
          combinedRules.push({
            conditionType: r.conditionType,
            pattern: r.pattern,
            profileId: r.profileId || 'direct'
          });
        }
      }
      compiledProfiles[p.id] = {
        type: 'switch',
        defaultProfileId: p.defaultProfileId || 'direct',
        rules: combinedRules
      };
    }
  }

  const tempRules = Object.values(state.tempRules || {}).map((r) => ({
    conditionType: r.conditionType || 'hostWildcard',
    pattern: r.pattern,
    profileId: r.profileId || 'direct'
  }));

  const payload = JSON.stringify({
    rootProfileId: activeProfile.id,
    tempRules,
    fixedMeta,
    switchProfiles: compiledProfiles
  });

  return `// Generated by ProxyFlow
var __PM_CONFIG__ = ${payload};

function __pmEscapeRegex(s) {
  return s.replace(/[.+^\${}()|[\\]\\\\]/g, "\\\\$&");
}
function __pmWildcardToRegexSource(p) {
  return __pmEscapeRegex(p).replace(/\\*/g, ".*").replace(/\\?/g, ".");
}
function __pmHostWildcard(host, pattern) {
  var p = String(pattern || "").toLowerCase();
  if (!p) return false;
  var re;
  if (p.indexOf("**.") === 0) {
    re = new RegExp("^.+\\\\." + __pmWildcardToRegexSource(p.slice(3)) + "$", "i");
  } else if (p.indexOf("*.") === 0) {
    re = new RegExp("^(?:.+\\\\.)?" + __pmWildcardToRegexSource(p.slice(2)) + "$", "i");
  } else {
    re = new RegExp("^" + __pmWildcardToRegexSource(p) + "$", "i");
  }
  return re.test(host);
}
function __pmParseIpv4(ip) {
  var parts = String(ip || "").split(".");
  if (parts.length !== 4) return null;
  var num = 0;
  for (var i = 0; i < 4; i++) {
    if (!/^\\d+$/.test(parts[i])) return null;
    var n = Number(parts[i]);
    if (n < 0 || n > 255) return null;
    num = ((num << 8) | n) >>> 0;
  }
  return num;
}
function __pmMatchCidr(host, cidr) {
  var ipNum = __pmParseIpv4(host);
  if (ipNum === null) return false;
  var seg = String(cidr || "").split("/");
  var netNum = __pmParseIpv4(seg[0]);
  if (netNum === null) return false;
  var prefix = seg.length > 1 ? Number(seg[1]) : 32;
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;
  if (prefix === 0) return true;
  var mask = (~0 << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (netNum & mask);
}
function __pmMatchRule(type, pattern, url, host) {
  try {
    switch (type) {
      case "hostWildcard": return __pmHostWildcard(host, pattern);
      case "hostRegex": return new RegExp(pattern, "i").test(host);
      case "urlWildcard": return new RegExp("^" + __pmWildcardToRegexSource(pattern) + "$", "i").test(url);
      case "urlRegex": return new RegExp(pattern, "i").test(url);
      case "cidr": return __pmMatchCidr(host, pattern);
      case "keyword": return url.toLowerCase().indexOf(String(pattern || "").toLowerCase()) !== -1;
      default: return false;
    }
  } catch (e) {
    return false;
  }
}
function __pmMatchesBypass(host, bypass) {
  if (!bypass || !bypass.length) return false;
  for (var i = 0; i < bypass.length; i++) {
    var entry = String(bypass[i] || "").trim().toLowerCase();
    if (!entry) continue;
    if (entry === "<local>") {
      if (host.indexOf(".") === -1 || host === "localhost" || host === "127.0.0.1" || host === "::1") return true;
      continue;
    }
    var clean = entry.replace(/^\\[/, "").replace(/\\]$/, "");
    if (clean.indexOf("/") !== -1) {
      if (__pmMatchCidr(host, clean)) return true;
    } else if (clean.indexOf("*") !== -1 || clean.indexOf("?") !== -1) {
      if (__pmHostWildcard(host, clean)) return true;
    } else if (host === clean || host.slice(-(clean.length + 1)) === "." + clean) {
      return true;
    }
  }
  return false;
}
function __pmResolve(profileId, url, host, depth) {
  if (depth > 8 || !profileId || profileId === "direct") return "DIRECT";
  var fixed = __PM_CONFIG__.fixedMeta[profileId];
  if (fixed) {
    if (__pmMatchesBypass(host, fixed.bypass)) return "DIRECT";
    return fixed.directive;
  }
  var sw = __PM_CONFIG__.switchProfiles[profileId];
  if (sw) {
    for (var i = 0; i < sw.rules.length; i++) {
      var r = sw.rules[i];
      if (__pmMatchRule(r.conditionType, r.pattern, url, host)) {
        return __pmResolve(r.profileId, url, host, depth + 1);
      }
    }
    return __pmResolve(sw.defaultProfileId, url, host, depth + 1);
  }
  return "DIRECT";
}
function FindProxyForURL(url, host) {
  var h = String(host || "").toLowerCase();
  var temps = __PM_CONFIG__.tempRules;
  for (var i = 0; i < temps.length; i++) {
    if (__pmMatchRule(temps[i].conditionType, temps[i].pattern, url, h)) {
      return __pmResolve(temps[i].profileId, url, h, 0);
    }
  }
  return __pmResolve(__PM_CONFIG__.rootProfileId, url, h, 0);
}
`;
}

export function extractDomainFromUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function domainToWildcard(domain) {
  if (!domain) return '';
  const clean = domain.replace(/^\*+\./, '');
  return `*.${clean}`;
}
