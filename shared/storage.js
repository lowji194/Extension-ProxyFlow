// shared/storage.js — Encrypted AES-256-GCM chrome.storage.local state manager

import {
  DEFAULT_AUTO_SWITCH_ID,
  DEFAULT_BYPASS_LIST,
  DEFAULT_SETTINGS,
  STATE_COLORS,
  createDefaultAutoSwitchProfile,
  createDefaultState,
  createStandardBypassRules,
  generateId,
  pickNextColor
} from './models.js';
import { decryptStatePayload, encryptStatePayload } from './crypto-storage.js';
import { parseProxyLine, proxyIdentityKey } from './proxy-parser.js';

export const VAULT_STATE_KEY = 'pmStateVault';
const LEGACY_STATE_KEY = 'pmState';
const RUNTIME_KEY = 'pmRuntime';

function sanitizeSettings(rawSettings = {}) {
  const clean = { ...DEFAULT_SETTINGS, ...(rawSettings || {}) };
  delete clean.remoteApiUrl;
  delete clean.remoteAutoCheck;
  delete clean.remoteBackupEnabled;
  delete clean.remoteBackupUrl;
  delete clean.ipLookupUrl;
  if (!clean.ipCheckProvider) {
    clean.ipCheckProvider = 'cloudflare';
  }
  return clean;
}

function normalizeState(raw) {
  const state = raw && typeof raw === 'object' ? raw : createDefaultState();

  state.profiles = Array.isArray(state.profiles) ? state.profiles : [];
  if (!state.profiles.some((p) => p.type === 'switch')) {
    state.profiles.unshift(createDefaultAutoSwitchProfile());
  }

  const prevVersion = Number(state.schemaVersion || 0);
  for (const p of state.profiles) {
    if (p.type === 'switch') {
      p.color = STATE_COLORS.autoSwitch;
    } else if (p.type === 'fixed') {
      if (!p.color || p.color === '#DC2626' || p.color === '#7C3AED') {
        p.color = STATE_COLORS.proxy;
      }
      if (prevVersion < 5 && p.health?.status === 'dead') {
        p.health = { status: 'unknown', checkedAt: null };
      }
    }
  }

  state.tempRules = state.tempRules && typeof state.tempRules === 'object' ? state.tempRules : {};
  state.settings = sanitizeSettings(state.settings);
  if (prevVersion < 5) {
    state.settings.autoFailoverDeadProxy = false;
  }

  if (prevVersion < 6) {
    const fixedProxies = state.profiles.filter((p) => p.type === 'fixed');
    const preferredProxyId =
      fixedProxies.find((p) => p.id === state.activeProfileId)?.id || fixedProxies[0]?.id || null;
    const sw =
      state.profiles.find((p) => p.id === DEFAULT_AUTO_SWITCH_ID && p.type === 'switch') ||
      state.profiles.find((p) => p.type === 'switch');

    if (sw) {
      if (!Array.isArray(sw.rules) || sw.rules.length === 0) {
        sw.rules = createStandardBypassRules();
      }
      const hasProxyRule = sw.rules.some((r) => r.profileId && r.profileId !== 'direct' && r.profileId !== 'system');
      if (sw.defaultProfileId === 'direct' && !hasProxyRule && preferredProxyId) {
        sw.defaultProfileId = preferredProxyId;
      }
    }
  }

  if (!state.activeProfileId || state.activeProfileId === 'system') {
    state.activeProfileId = 'direct';
  }
  if (state.settings.startupProfileId === 'system') {
    state.settings.startupProfileId = null;
  }
  if (Array.isArray(state.settings.quickSwitchIds)) {
    state.settings.quickSwitchIds = state.settings.quickSwitchIds.filter((id) => id !== 'system');
  }
  state.schemaVersion = 7;
  return state;
}

export async function loadState() {
  const localData = await chrome.storage.local.get([VAULT_STATE_KEY, LEGACY_STATE_KEY]);

  let state = null;
  let needsSave = false;
  let shouldClearPlaintext = false;

  if (localData[VAULT_STATE_KEY]) {
    try {
      state = await decryptStatePayload(localData[VAULT_STATE_KEY]);
    } catch (err) {
      console.warn('[ProxyFlow] Encrypted vault decode fallback:', err.message);
      state = null;
    }
  }

  if (!state && localData[LEGACY_STATE_KEY]) {
    state = localData[LEGACY_STATE_KEY];
    needsSave = true;
    shouldClearPlaintext = true;
  }

  if (!state) {
    state = createDefaultState();
    state = await migrateFromLegacySync(state);
    needsSave = true;
  } else {
    const prevVersion = Number(state.schemaVersion || 0);
    state = normalizeState(state);
    if (prevVersion < 7) needsSave = true;
    if (!state.migrationCompleted) {
      state = await migrateFromLegacySync(state);
      needsSave = true;
    }
  }

  if (needsSave) {
    await saveState(state);
  }
  if (shouldClearPlaintext || localData[LEGACY_STATE_KEY]) {
    await chrome.storage.local.remove([LEGACY_STATE_KEY]);
  }

  return state;
}

export async function saveState(state) {
  const normalized = normalizeState(structuredClone(state));
  const encrypted = await encryptStatePayload(normalized);
  await chrome.storage.local.set({ [VAULT_STATE_KEY]: encrypted });
  return normalized;
}

export async function updateState(updater) {
  const current = await loadState();
  const next = await updater(structuredClone(current));
  return saveState(next);
}

export async function loadRuntime() {
  const data = await chrome.storage.local.get([RUNTIME_KEY]);
  return {
    proxyDiedAlert: null,
    lastProxyError: null,
    ...(data[RUNTIME_KEY] || {})
  };
}

export async function updateRuntime(patch) {
  const current = await loadRuntime();
  const next = { ...current, ...patch };
  await chrome.storage.local.set({ [RUNTIME_KEY]: next });
  return next;
}

/**
 * One-time migration from legacy plaintext chrome.storage.sync keys, then clears sync keys
 * so no unencrypted credentials remain in browser sync storage.
 */
async function migrateFromLegacySync(state) {
  try {
    const syncData = await chrome.storage.sync.get([
      'proxies',
      'currentProxy',
      'proxyEnabled',
      'proxyStatus'
    ]);

    const legacyProxies = Array.isArray(syncData.proxies) ? syncData.proxies : [];
    const legacyCurrent = typeof syncData.currentProxy === 'string' ? syncData.currentProxy : '';
    const legacyEnabled = syncData.proxyEnabled === true;

    if (legacyProxies.length > 0) {
      const existingKeys = new Set(
        state.profiles.filter((p) => p.type === 'fixed').map((p) => proxyIdentityKey(p))
      );

      let activeMatchId = null;

      legacyProxies.forEach((raw) => {
        const parsed = parseProxyLine(raw);
        if (!parsed) return;
        const key = proxyIdentityKey(parsed);
        let profile = state.profiles.find((p) => p.type === 'fixed' && proxyIdentityKey(p) === key);
        if (!profile && !existingKeys.has(key)) {
          profile = {
            id: generateId('proxy'),
            name: parsed.name,
            type: 'fixed',
            color: pickNextColor(state.profiles),
            scheme: parsed.scheme,
            host: parsed.host,
            port: parsed.port,
            username: parsed.username,
            password: parsed.password,
            bypassList: [...DEFAULT_BYPASS_LIST],
            notes: '',
            health: { status: 'unknown', checkedAt: null },
            createdAt: Date.now(),
            updatedAt: Date.now()
          };
          state.profiles.push(profile);
          existingKeys.add(key);
        }

        if (profile && legacyCurrent && raw === legacyCurrent) {
          activeMatchId = profile.id;
        }
      });

      if (legacyEnabled && activeMatchId) {
        state.activeProfileId = activeMatchId;
      }

      // Remove unencrypted legacy keys once migrated into AES-GCM local vault
      await chrome.storage.sync.remove(['proxies', 'currentProxy', 'proxyEnabled', 'proxyStatus']);
    }

    state.migrationCompleted = true;
  } catch (err) {
    console.warn('[ProxyFlow] Legacy storage migration skipped:', err.message);
    state.migrationCompleted = true;
  }

  return state;
}
