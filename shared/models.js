// shared/models.js — Core data models, built-in profiles, and defaults

export const STATE_COLORS = {
  noProxy: '#DC2626',   // Red: Direct / Proxy Off
  proxy: '#16A34A',     // Green: Proxy active
  autoSwitch: '#7C3AED' // Purple: Auto Switch active
};

export const BUILTIN_PROFILES = {
  direct: {
    id: 'direct',
    name: 'Direct (Off)',
    type: 'direct',
    color: STATE_COLORS.noProxy,
    builtin: true,
    description: 'Turn off proxy in the browser and connect directly.'
  }
};

export const DEFAULT_BYPASS_LIST = ['127.0.0.1', '[::1]', 'localhost', '<local>'];

export const PROFILE_COLOR_PALETTE = [
  '#16A34A', // Green (Primary proxy color)
  '#059669', // Emerald
  '#0D9488', // Teal
  '#0891B2', // Cyan
  '#2563EB', // Ocean Blue
  '#0284C7', // Sky Blue
  '#4F46E5', // Indigo
  '#D97706'  // Amber
];

export const SCHEME_OPTIONS = [
  { value: 'http', label: 'HTTP' },
  { value: 'https', label: 'HTTPS' },
  { value: 'socks4', label: 'SOCKS4' },
  { value: 'socks5', label: 'SOCKS5' }
];

export const CONDITION_TYPES = [
  { value: 'hostWildcard', label: 'Host Wildcard', group: 'Host', placeholder: '*.example.com' },
  { value: 'hostRegex', label: 'Host Regex', group: 'Host', placeholder: '^api\\..*\\.example\\.com$' },
  { value: 'urlWildcard', label: 'URL Wildcard', group: 'URL', placeholder: '*://example.com/api/*' },
  { value: 'urlRegex', label: 'URL Regex', group: 'URL', placeholder: '^https?://example\\.com/' },
  { value: 'cidr', label: 'IP / CIDR', group: 'Special', placeholder: '192.168.0.0/16' },
  { value: 'keyword', label: 'Keyword', group: 'Special', placeholder: 'internal-api' }
];

export const DEFAULT_AUTO_SWITCH_ID = 'auto-switch';

export function createStandardBypassRules() {
  return [
    {
      id: generateId('rule'),
      enabled: true,
      conditionType: 'hostWildcard',
      pattern: 'localhost',
      profileId: 'direct',
      note: 'Bypass localhost'
    },
    {
      id: generateId('rule'),
      enabled: true,
      conditionType: 'hostWildcard',
      pattern: '*.local',
      profileId: 'direct',
      note: 'Bypass local domains'
    },
    {
      id: generateId('rule'),
      enabled: true,
      conditionType: 'cidr',
      pattern: '127.0.0.0/8',
      profileId: 'direct',
      note: 'Bypass IPv4 loopback'
    },
    {
      id: generateId('rule'),
      enabled: true,
      conditionType: 'cidr',
      pattern: '192.168.0.0/16',
      profileId: 'direct',
      note: 'Bypass private LAN (192.168.x.x)'
    },
    {
      id: generateId('rule'),
      enabled: true,
      conditionType: 'cidr',
      pattern: '10.0.0.0/8',
      profileId: 'direct',
      note: 'Bypass private network (10.x.x.x)'
    },
    {
      id: generateId('rule'),
      enabled: true,
      conditionType: 'cidr',
      pattern: '172.16.0.0/12',
      profileId: 'direct',
      note: 'Bypass private network (172.16-31.x.x)'
    }
  ];
}

export function createDefaultAutoSwitchProfile(defaultTargetId = 'direct') {
  return {
    id: DEFAULT_AUTO_SWITCH_ID,
    name: 'Auto Switch',
    type: 'switch',
    color: '#7C3AED',
    defaultProfileId: defaultTargetId,
    rules: createStandardBypassRules(),
    ruleList: {
      enabled: false,
      format: 'autoproxy',
      url: '',
      text: '',
      matchProfileId: 'direct',
      lastUpdated: null,
      error: ''
    },
    createdAt: Date.now(),
    updatedAt: Date.now()
  };
}

export const DEFAULT_SETTINGS = {
  startupProfileId: null, // null = keep last active profile
  refreshOnSwitch: true,
  confirmDelete: true,
  autoFailoverDeadProxy: false,
  healthCheckIntervalMin: 0, // 0 = manual only
  monitorNetworkErrors: true,
  showResultBadge: false,
  showContextMenu: true,
  enableQuickSwitch: false,
  quickSwitchIds: ['direct', DEFAULT_AUTO_SWITCH_ID],
  addConditionsToBottom: false,
  ipCheckProvider: 'cloudflare'
};

export function createDefaultState() {
  return {
    schemaVersion: 7,
    activeProfileId: 'direct',
    profiles: [createDefaultAutoSwitchProfile()],
    tempRules: {}, // { [domain]: { domain, conditionType: 'hostWildcard', pattern, profileId, createdAt } }
    settings: { ...DEFAULT_SETTINGS },
    migrationCompleted: false
  };
}

export function generateId(prefix = 'p') {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
  }
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
}

export function pickNextColor(existingProfiles = []) {
  const used = new Set(existingProfiles.map((p) => p.color));
  return PROFILE_COLOR_PALETTE.find((c) => !used.has(c)) || PROFILE_COLOR_PALETTE[existingProfiles.length % PROFILE_COLOR_PALETTE.length];
}

export function getProfileById(state, profileId) {
  if (!profileId || profileId === 'direct' || profileId === 'system') {
    return BUILTIN_PROFILES.direct;
  }
  const found = (state?.profiles || []).find((p) => p.id === profileId);
  return found || BUILTIN_PROFILES.direct;
}

export function getSelectableProfiles(state) {
  return [
    BUILTIN_PROFILES.direct,
    ...(state?.profiles || [])
  ];
}
