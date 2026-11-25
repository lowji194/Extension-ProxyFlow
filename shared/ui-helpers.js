// shared/ui-helpers.js — DOM utilities, local SVG icon registry, and semantic status mapping

const SVG_NS = 'http://www.w3.org/2000/svg';

// Consistent 24x24 Lucide-style stroke icon paths (2px stroke, round cap/join)
const ICON_PATHS = {
  direct: [
    ['path', { d: 'M8 3 4 7l4 4' }],
    ['path', { d: 'M4 7h16' }],
    ['path', { d: 'm16 21 4-4-4-4' }],
    ['path', { d: 'M20 17H4' }]
  ],
  system: [
    ['rect', { x: '2', y: '3', width: '20', height: '14', rx: '2' }],
    ['path', { d: 'M8 21h8' }],
    ['path', { d: 'M12 17v4' }]
  ],
  proxy: [
    ['circle', { cx: '12', cy: '12', r: '10' }],
    ['path', { d: 'M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20' }],
    ['path', { d: 'M2 12h20' }]
  ],
  switch: [
    ['circle', { cx: '18', cy: '18', r: '3' }],
    ['circle', { cx: '6', cy: '6', r: '3' }],
    ['path', { d: 'M6 21V9a9 9 0 0 0 9 9' }]
  ],
  pac: [
    ['path', { d: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z' }],
    ['path', { d: 'M14 2v6h6' }],
    ['path', { d: 'm10 13-2 2 2 2' }],
    ['path', { d: 'm14 17 2-2-2-2' }]
  ],
  filter: [
    ['polygon', { points: '22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3' }]
  ],
  plus: [
    ['path', { d: 'M5 12h14' }],
    ['path', { d: 'M12 5v14' }]
  ],
  check: [
    ['circle', { cx: '12', cy: '12', r: '10' }],
    ['path', { d: 'm9 12 2 2 4-4' }]
  ],
  checkPlain: [
    ['path', { d: 'M20 6 9 17l-5-5' }]
  ],
  error: [
    ['circle', { cx: '12', cy: '12', r: '10' }],
    ['path', { d: 'm15 9-6 6' }],
    ['path', { d: 'm9 9 6 6' }]
  ],
  warning: [
    ['path', { d: 'm21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z' }],
    ['path', { d: 'M12 9v4' }],
    ['path', { d: 'M12 17h.01' }]
  ],
  loading: [
    ['path', { d: 'M21 12a9 9 0 1 1-6.219-8.56' }]
  ],
  unknown: [
    ['circle', { cx: '12', cy: '12', r: '10' }],
    ['path', { d: 'M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3' }],
    ['path', { d: 'M12 17h.01' }]
  ],
  refresh: [
    ['path', { d: 'M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8' }],
    ['path', { d: 'M21 3v5h-5' }],
    ['path', { d: 'M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16' }],
    ['path', { d: 'M3 21v-5h5' }]
  ],
  activity: [
    ['path', { d: 'M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2' }]
  ],
  settings: [
    ['path', { d: 'M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z' }],
    ['circle', { cx: '12', cy: '12', r: '3' }]
  ],
  eye: [
    ['path', { d: 'M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0' }],
    ['circle', { cx: '12', cy: '12', r: '3' }]
  ],
  pencil: [
    ['path', { d: 'M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z' }],
    ['path', { d: 'm15 5 4 4' }]
  ],
  copy: [
    ['rect', { width: '14', height: '14', x: '8', y: '8', rx: '2', ry: '2' }],
    ['path', { d: 'M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2' }]
  ],
  trash: [
    ['path', { d: 'M3 6h18' }],
    ['path', { d: 'M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6' }],
    ['path', { d: 'M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2' }]
  ],
  lock: [
    ['rect', { width: '18', height: '11', x: '3', y: '11', rx: '2', ry: '2' }],
    ['path', { d: 'M7 11V7a5 5 0 0 1 10 0v4' }]
  ],
  upload: [
    ['path', { d: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4' }],
    ['polyline', { points: '17 8 12 3 7 8' }],
    ['line', { x1: '12', x2: '12', y1: '3', y2: '15' }]
  ],
  download: [
    ['path', { d: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4' }],
    ['polyline', { points: '7 10 12 15 17 10' }],
    ['line', { x1: '12', x2: '12', y1: '15', y2: '3' }]
  ],
  search: [
    ['circle', { cx: '11', cy: '11', r: '8' }],
    ['path', { d: 'm21 21-4.3-4.3' }]
  ],
  sliders: [
    ['line', { x1: '21', x2: '14', y1: '4', y2: '4' }],
    ['line', { x1: '10', x2: '3', y1: '4', y2: '4' }],
    ['line', { x1: '21', x2: '12', y1: '12', y2: '12' }],
    ['line', { x1: '8', x2: '3', y1: '12', y2: '12' }],
    ['line', { x1: '21', x2: '16', y1: '20', y2: '20' }],
    ['line', { x1: '12', x2: '3', y1: '20', y2: '20' }],
    ['line', { x1: '14', x2: '14', y1: '2', y2: '6' }],
    ['line', { x1: '8', x2: '8', y1: '10', y2: '14' }],
    ['line', { x1: '16', x2: '16', y1: '18', y2: '22' }]
  ],
  external: [
    ['path', { d: 'M15 3h6v6' }],
    ['path', { d: 'M10 14 21 3' }],
    ['path', { d: 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6' }]
  ],
  chevronDown: [
    ['path', { d: 'm6 9 6 6 6-6' }]
  ],
  arrowUp: [
    ['path', { d: 'm18 15-6-6-6 6' }]
  ],
  arrowDown: [
    ['path', { d: 'm6 9 6 6 6-6' }]
  ],
  x: [
    ['path', { d: 'M18 6 6 18' }],
    ['path', { d: 'm6 6 12 12' }]
  ],
  shieldAlert: [
    ['path', { d: 'M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z' }],
    ['path', { d: 'M12 8v4' }],
    ['path', { d: 'M12 16h.01' }]
  ],
  zap: [
    ['path', { d: 'M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z' }]
  ],
  clock: [
    ['circle', { cx: '12', cy: '12', r: '10' }],
    ['polyline', { points: '12 6 12 12 16 14' }]
  ]
};

export function svgIcon(name, size = 16, extraClass = '') {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  svg.classList.add('pm-icon');
  if (extraClass) {
    extraClass.split(/\s+/).filter(Boolean).forEach((c) => svg.classList.add(c));
  }
  if (name === 'loading') {
    svg.classList.add('pm-spin');
  }

  const shapes = ICON_PATHS[name] || ICON_PATHS.unknown;
  for (const [tag, attrs] of shapes) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) {
      node.setAttribute(k, v);
    }
    svg.appendChild(node);
  }
  return svg;
}

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, val] of Object.entries(attrs || {})) {
    if (val === undefined || val === null) continue;
    if (key === 'className') {
      node.className = val;
    } else if (key === 'dataset') {
      for (const [dk, dv] of Object.entries(val)) {
        node.dataset[dk] = dv;
      }
    } else if (key.startsWith('on') && typeof val === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), val);
    } else if (key === 'disabled' || key === 'checked' || key === 'selected' || key === 'required') {
      node[key] = Boolean(val);
    } else {
      node.setAttribute(key, String(val));
    }
  }
  const list = Array.isArray(children) ? children : [children];
  for (const child of list) {
    if (child === null || child === undefined || child === false) continue;
    if (typeof child === 'string' || typeof child === 'number') {
      node.appendChild(document.createTextNode(String(child)));
    } else {
      node.appendChild(child);
    }
  }
  return node;
}

export const HEALTH_STATUS_MAP = {
  live: { label: 'Live', tone: 'success', icon: 'check' },
  dead: { label: 'Dead', tone: 'danger', icon: 'error' },
  checking: { label: 'Checking', tone: 'processing', icon: 'loading' },
  unknown: { label: 'Unchecked', tone: 'neutral', icon: 'unknown' }
};

export const PROFILE_TYPE_MAP = {
  direct: { label: 'Direct', tone: 'neutral', icon: 'direct' },
  system: { label: 'System', tone: 'neutral', icon: 'system' },
  fixed: { label: 'Proxy', tone: 'info', icon: 'proxy' },
  switch: { label: 'Auto Switch', tone: 'scheduled', icon: 'switch' },
  pac: { label: 'PAC Script', tone: 'processing', icon: 'pac' }
};

export function createSemanticBadge(label, tone = 'neutral', iconName = null, title = '') {
  return el(
    'span',
    { className: `pm-badge pm-badge--${tone}`, title: title || undefined },
    [iconName ? svgIcon(iconName, 12) : null, el('span', {}, label)]
  );
}

export function createHealthBadge(health = {}) {
  const status = health?.status || 'unknown';
  const meta = HEALTH_STATUS_MAP[status] || HEALTH_STATUS_MAP.unknown;
  let text = meta.label;
  if (status === 'live') {
    const parts = [meta.label];
    if (health.country) parts.push(health.country);
    if (typeof health.latencyMs === 'number') parts.push(`${health.latencyMs}ms`);
    text = parts.join(' · ');
  }
  const titleParts = [];
  if (health?.exitIp) titleParts.push(`Exit IP: ${health.exitIp}`);
  if (health?.country) titleParts.push(`Country: ${health.country}`);
  if (health?.provider) titleParts.push(`Via: ${health.provider}`);
  if (health?.error) titleParts.push(`Detail: ${health.error}`);
  if (health?.checkedAt) titleParts.push(`Checked: ${new Date(health.checkedAt).toLocaleTimeString()}`);
  return createSemanticBadge(text, meta.tone, meta.icon, titleParts.join(' | '));
}

export function createProfileDot(color) {
  return el('span', {
    className: 'pm-color-dot',
    style: `background-color: ${color || '#64748B'}`
  });
}

let toastTimer = null;
export function showToast(containerEl, message, tone = 'info', durationMs = 2600) {
  if (!containerEl) return;
  const iconMap = {
    success: 'check',
    danger: 'error',
    warning: 'warning',
    info: 'proxy',
    processing: 'loading'
  };
  containerEl.replaceChildren(
    el('div', { className: `pm-toast pm-toast--${tone}`, role: 'status' }, [
      svgIcon(iconMap[tone] || 'proxy', 15),
      el('span', {}, message)
    ])
  );
  containerEl.classList.add('is-visible');
  clearTimeout(toastTimer);
  if (durationMs > 0) {
    toastTimer = setTimeout(() => {
      containerEl.classList.remove('is-visible');
    }, durationMs);
  }
}

export async function copyToClipboard(text) {
  await navigator.clipboard.writeText(text);
}

export function sendBgMessage(type, payload = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, ...payload }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (response && response.ok === false) {
        reject(new Error(response.error || 'Background request failed'));
        return;
      }
      resolve(response);
    });
  });
}

export function formatRelativeTime(ts) {
  if (!ts) return 'Never';
  const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 10) return 'Just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return new Date(ts).toLocaleDateString();
}
