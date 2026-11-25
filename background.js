// background.js — ProxyFlow v2.0 (Unified MV3 Service Worker)

import {
  BUILTIN_PROFILES,
  DEFAULT_AUTO_SWITCH_ID,
  DEFAULT_BYPASS_LIST,
  STATE_COLORS,
  createDefaultState,
  generateId,
  getProfileById,
  pickNextColor
} from './shared/models.js';
import { parseProxyBulk, proxyIdentityKey } from './shared/proxy-parser.js';
import {
  compilePacScript,
  domainToWildcard,
  extractDomainFromUrl,
  matchUrl
} from './shared/rule-matcher.js';
import { runStandardIpProbe } from './shared/ip-probe.js';
import {
  loadRuntime,
  loadState,
  saveState,
  updateRuntime,
  updateState
} from './shared/storage.js';
import { applyActionVisual } from './shared/icon-renderer.js';

const ALARM_ACTIVE_MONITOR = 'pm-active-monitor';
const ALARM_BATCH_CHECK = 'pm-batch-check';
const ALARM_RULE_REFRESH = 'pm-rule-refresh';

const MAX_MONITOR_LOGS = 400;
const IGNORED_ERROR_STRINGS = new Set([
  'net::ERR_ABORTED',
  'net::ERR_BLOCKED_BY_CLIENT',
  'net::ERR_CACHE_MISS'
]);

let stateCache = null;
let initPromise = null;
let isApplyingProxy = false;
let isProbing = false;
let tempProbeProfile = null;

// Strict serialized queues to prevent race conditions across events
let stateQueue = Promise.resolve();
let menuQueue = Promise.resolve();
let probeQueue = Promise.resolve();

// Ephemeral MV3 memory caches
const authAttempts = new Map();
const tabErrors = new Map(); // tabId -> { totalErrors, domains: Map<domain, { count, lastError, lastUrl }> }
const monitorLogs = [];

/* ──────────────────────────────────────────────────────────────
   Serialized State Hydration & Mutation
────────────────────────────────────────────────────────────── */

function enqueueStateOp(task) {
  const run = stateQueue.then(task, task);
  stateQueue = run.catch(() => {});
  return run;
}

async function ensureInitialized(forceReload = false) {
  if (stateCache && !forceReload) return stateCache;
  if (!initPromise || forceReload) {
    initPromise = (async () => {
      stateCache = await loadState();
      return stateCache;
    })();
  }
  return initPromise;
}

function setStateAndApply(
  mutator,
  { applyProxy = true, refreshTab = false, rebuildMenus = false } = {}
) {
  return enqueueStateOp(async () => {
    const next = await updateState(mutator);
    stateCache = next;

    if (applyProxy) {
      authAttempts.clear();
      await applyActiveProxyConfig(next);
    }
    if (rebuildMenus) {
      await syncContextMenus(next);
    }
    await syncAlarms(next);
    await refreshAllTabVisuals(next);

    if (refreshTab && next.settings?.refreshOnSwitch) {
      await reloadActiveHttpTab();
    }
    return next;
  });
}

/* ──────────────────────────────────────────────────────────────
   Proxy Settings Application (ZeroOmega Clean Model)
────────────────────────────────────────────────────────────── */

async function applyActiveProxyConfig(state) {
  const activeProfile = getProfileById(state, state.activeProfileId);
  const hasTempRules = Object.keys(state.tempRules || {}).length > 0;

  isApplyingProxy = true;
  try {
    if (activeProfile.type === 'direct' && !hasTempRules) {
      await chrome.proxy.settings.set({
        value: { mode: 'direct' },
        scope: 'regular'
      });
    } else if (activeProfile.type === 'fixed' && !hasTempRules) {
      await chrome.proxy.settings.set({
        value: {
          mode: 'fixed_servers',
          rules: {
            singleProxy: {
              scheme: activeProfile.scheme || 'http',
              host: activeProfile.host,
              port: Number(activeProfile.port)
            },
            bypassList:
              Array.isArray(activeProfile.bypassList) && activeProfile.bypassList.length > 0
                ? activeProfile.bypassList
                : DEFAULT_BYPASS_LIST
          }
        },
        scope: 'regular'
      });
    } else if (
      activeProfile.type === 'pac' &&
      activeProfile.pacUrl &&
      !activeProfile.pacScript &&
      !hasTempRules
    ) {
      await chrome.proxy.settings.set({
        value: {
          mode: 'pac_script',
          pacScript: { url: activeProfile.pacUrl, mandatory: false }
        },
        scope: 'regular'
      });
    } else {
      const pacData = compilePacScript(state, activeProfile.id);
      await chrome.proxy.settings.set({
        value: {
          mode: 'pac_script',
          pacScript: { data: pacData, mandatory: false }
        },
        scope: 'regular'
      });
    }
  } catch (err) {
    console.error('[ProxyFlow] Failed to apply proxy config:', err);
    await updateRuntime({ lastProxyError: err.message });
  } finally {
    setTimeout(() => {
      isApplyingProxy = false;
    }, 350);
  }
}

/* ──────────────────────────────────────────────────────────────
   Top-Level Proxy Auth & Request Listeners
────────────────────────────────────────────────────────────── */

function resolveAuthCredentials(state, details) {
  const challengerHost = (details.challenger?.host || '').toLowerCase();
  const challengerPort = Number(details.challenger?.port || 0);

  // 0. Active local probe override
  if (
    tempProbeProfile?.username &&
    (!challengerHost ||
      (tempProbeProfile.host.toLowerCase() === challengerHost &&
        Number(tempProbeProfile.port) === challengerPort))
  ) {
    return {
      username: tempProbeProfile.username,
      password: tempProbeProfile.password || ''
    };
  }

  const activeProfile = getProfileById(state, state.activeProfileId);

  // 1. Exact match on active fixed profile
  if (
    activeProfile.type === 'fixed' &&
    activeProfile.username &&
    (!challengerHost ||
      (activeProfile.host.toLowerCase() === challengerHost &&
        Number(activeProfile.port) === challengerPort))
  ) {
    return {
      username: activeProfile.username,
      password: activeProfile.password || ''
    };
  }

  // 2. Match any fixed profile matching challenger host:port (Auto Switch / Temp Rules)
  const matchingFixed = (state.profiles || []).find(
    (p) =>
      p.type === 'fixed' &&
      p.username &&
      p.host.toLowerCase() === challengerHost &&
      Number(p.port) === challengerPort
  );
  if (matchingFixed) {
    return {
      username: matchingFixed.username,
      password: matchingFixed.password || ''
    };
  }

  // 3. Active fixed proxy fallback (covers hostname proxies resolved to IP in challenger)
  if (activeProfile.type === 'fixed' && activeProfile.username) {
    return {
      username: activeProfile.username,
      password: activeProfile.password || ''
    };
  }

  // 4. PAC explicit auth fallback
  if (activeProfile.type === 'pac' && activeProfile.auth?.username) {
    return {
      username: activeProfile.auth.username,
      password: activeProfile.auth.password || ''
    };
  }

  return null;
}

// Registered synchronously at top level; responds synchronously when stateCache is warm
chrome.webRequest.onAuthRequired.addListener(
  (details, callback) => {
    if (!details.isProxy) {
      callback({});
      return;
    }

    const host = (details.challenger?.host || '').toLowerCase();
    const port = Number(details.challenger?.port || 0);
    const attemptKey = `${details.requestId}:${host}:${port}`;
    const attempts = (authAttempts.get(attemptKey) || 0) + 1;

    if (authAttempts.size > 400) authAttempts.clear();
    authAttempts.set(attemptKey, attempts);

    if (attempts > 2) {
      callback({});
      return;
    }

    const respondWithState = (state) => {
      const creds = resolveAuthCredentials(state, details);
      callback(creds ? { authCredentials: creds } : {});
    };

    if (stateCache) {
      respondWithState(stateCache);
      return;
    }

    ensureInitialized()
      .then(respondWithState)
      .catch(() => callback({}));
  },
  { urls: ['<all_urls>'] },
  ['asyncBlocking']
);

function clearAuthAttemptsForRequest(requestId) {
  const prefix = `${requestId}:`;
  for (const key of authAttempts.keys()) {
    if (key.startsWith(prefix)) authAttempts.delete(key);
  }
}

function recordMonitorEvent(details, status, extra = {}) {
  if (isProbing) return;

  const logWithState = (state) => {
    let routeLabel = 'Direct';
    let routeColor = STATE_COLORS.noProxy;
    try {
      const match = matchUrl(details.url, state);
      routeLabel = match.resolvedProfile?.name || 'Direct';
      routeColor = match.resolvedProfile?.color || STATE_COLORS.noProxy;
    } catch {
      // ignore invalid URL
    }

    monitorLogs.unshift({
      id: details.requestId,
      tabId: details.tabId,
      method: details.method,
      type: details.type,
      url: details.url,
      domain: extractDomainFromUrl(details.url) || '',
      status,
      statusCode: extra.statusCode || null,
      error: extra.error || null,
      routeLabel,
      routeColor,
      timestamp: Date.now()
    });
    if (monitorLogs.length > MAX_MONITOR_LOGS) {
      monitorLogs.length = MAX_MONITOR_LOGS;
    }
  };

  if (stateCache) {
    logWithState(stateCache);
  } else {
    ensureInitialized().then(logWithState).catch(() => {});
  }
}

chrome.webRequest.onCompleted.addListener(
  (details) => {
    clearAuthAttemptsForRequest(details.requestId);
    if (details.tabId < 0) return;
    recordMonitorEvent(details, details.statusCode >= 400 ? 'http_error' : 'ok', {
      statusCode: details.statusCode
    });
  },
  { urls: ['<all_urls>'] }
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    clearAuthAttemptsForRequest(details.requestId);
    if (details.tabId < 0 || isProbing) return;
    if (!details.url.startsWith('http://') && !details.url.startsWith('https://')) return;

    const isIgnored = IGNORED_ERROR_STRINGS.has(details.error);
    recordMonitorEvent(details, isIgnored ? 'aborted' : 'failed', {
      error: details.error
    });

    if (isIgnored) return;

    const domain = extractDomainFromUrl(details.url);
    if (!domain) return;

    let entry = tabErrors.get(details.tabId);
    if (!entry) {
      entry = { totalErrors: 0, domains: new Map() };
      tabErrors.set(details.tabId, entry);
    }
    entry.totalErrors += 1;
    const prev = entry.domains.get(domain) || { domain, count: 0, lastError: '', lastUrl: '' };
    prev.count += 1;
    prev.lastError = details.error;
    prev.lastUrl = details.url;
    entry.domains.set(domain, prev);

    ensureInitialized().then((state) => {
      if (state.settings?.monitorNetworkErrors) {
        updateTabVisualById(details.tabId, state);
      }
    });
  },
  { urls: ['<all_urls>'] }
);

chrome.proxy.onProxyError.addListener((details) => {
  if (isProbing || !details?.fatal) return;
  updateRuntime({
    lastProxyError: `${details.error || 'Proxy error'}: ${details.details || ''}`.trim()
  });
});

/* ──────────────────────────────────────────────────────────────
   Toolbar Icon (3-State: Red No Proxy / Green Proxy / Purple Auto Switch)
────────────────────────────────────────────────────────────── */

function semanticColorForType(type) {
  if (type === 'switch') return STATE_COLORS.autoSwitch;
  if (type === 'fixed' || type === 'pac') return STATE_COLORS.proxy;
  return STATE_COLORS.noProxy;
}

async function updateTabVisual(tab, state) {
  if (!tab || typeof tab.id !== 'number') return;
  const runtime = await loadRuntime();
  const activeProfile = getProfileById(state, state.activeProfileId);

  let outerColor = semanticColorForType(activeProfile.type);
  let innerColor = null;
  const titleLines = [`ProxyFlow :: ${activeProfile.name}`];
  let resultBadge = '';

  const url = tab.url || tab.pendingUrl || '';
  if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
    const match = matchUrl(url, state);
    const resolved = match.resolvedProfile;
    const hasTemp = Object.keys(state.tempRules || {}).length > 0;

    if (activeProfile.type === 'switch') {
      outerColor = STATE_COLORS.autoSwitch;
      innerColor =
        resolved.type === 'fixed' || resolved.type === 'pac' ? STATE_COLORS.proxy : null;
      titleLines.push(`Route: ${resolved.name}`);
      if (match.matchedRule) {
        titleLines.push(`Matched: ${match.matchedRule.pattern} (${match.matchedRule.source})`);
      }
    } else if (hasTemp && match.matchedRule?.source === 'temp') {
      outerColor = semanticColorForType(resolved.type);
      innerColor = semanticColorForType(activeProfile.type);
      titleLines.push(`Route: ${resolved.name} (Temp Rule)`);
    } else if (activeProfile.type === 'fixed') {
      if (resolved.id === 'direct') {
        outerColor = STATE_COLORS.noProxy;
        innerColor = STATE_COLORS.proxy;
        titleLines.push('Route: Direct (Bypass List)');
      } else {
        outerColor = STATE_COLORS.proxy;
        titleLines.push(
          `${(activeProfile.scheme || 'http').toUpperCase()} ${activeProfile.host}:${activeProfile.port}`
        );
      }
    } else if (activeProfile.type === 'pac') {
      outerColor = STATE_COLORS.proxy;
      titleLines.push('Route: Evaluated by PAC script');
    }

    if (state.settings?.showResultBadge) {
      resultBadge = (resolved.name || '').slice(0, 4);
    }
  } else if (activeProfile.type === 'fixed') {
    outerColor = STATE_COLORS.proxy;
    titleLines.push(
      `${(activeProfile.scheme || 'http').toUpperCase()} ${activeProfile.host}:${activeProfile.port}`
    );
  }

  let badgeText = resultBadge;
  let badgeColor = '#2563EB';

  if (state.settings?.monitorNetworkErrors) {
    const errInfo = tabErrors.get(tab.id);
    if (errInfo && errInfo.totalErrors > 0) {
      badgeText = errInfo.totalErrors > 99 ? '99+' : String(errInfo.totalErrors);
      badgeColor = '#D97706';
      titleLines.push(`${errInfo.totalErrors} failed request(s) on this tab`);
    }
  }

  await applyActionVisual({
    tabId: tab.id,
    outerColor,
    innerColor,
    title: titleLines.join('\n'),
    badgeText,
    badgeColor
  });
}

async function updateTabVisualById(tabId, state) {
  try {
    const tab = await chrome.tabs.get(tabId);
    await updateTabVisual(tab, state);
  } catch {
    // Tab closed
  }
}

async function refreshAllTabVisuals(state) {
  try {
    const activeProfile = getProfileById(state, state.activeProfileId);
    await applyActionVisual({
      tabId: null,
      outerColor: semanticColorForType(activeProfile.type),
      innerColor: null,
      title: `ProxyFlow :: ${activeProfile.name}`
    });

    const tabs = await chrome.tabs.query({});
    await Promise.all(tabs.map((tab) => updateTabVisual(tab, state)));
  } catch (err) {
    console.warn('[ProxyFlow] Refresh tab visuals skipped:', err.message);
  }
}

async function reloadActiveHttpTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (!tab?.id || !tab.url) return;
    if (tab.url.startsWith('http://') || tab.url.startsWith('https://')) {
      await chrome.tabs.reload(tab.id, { bypassCache: true });
    }
  } catch {
    // Ignore restricted tabs
  }
}

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const state = await ensureInitialized();
  await updateTabVisualById(tabId, state);
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    tabErrors.delete(tabId);
  }
  if (changeInfo.status === 'complete' || changeInfo.url) {
    const state = await ensureInitialized();
    await updateTabVisual(tab, state);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabErrors.delete(tabId);
});

/* ──────────────────────────────────────────────────────────────
   Local Health Check (Standard HTTPS IP / Trace Endpoints)
────────────────────────────────────────────────────────────── */

function enqueueProbe(task) {
  const run = probeQueue.then(task, task);
  probeQueue = run.catch(() => {});
  return run;
}

async function runLocalProbe(profile, stateSnapshot) {
  return enqueueProbe(async () => {
    const providerId = stateSnapshot.settings?.ipCheckProvider || 'cloudflare';
    const current = await ensureInitialized();
    const isAlreadyDirectTarget =
      current.activeProfileId === profile.id &&
      Object.keys(current.tempRules || {}).length === 0;

    if (isAlreadyDirectTarget) {
      return runStandardIpProbe(providerId, 6000);
    }

    const expectedActiveIdAtStart = current.activeProfileId;
    tempProbeProfile = profile;
    isProbing = true;
    isApplyingProxy = true;
    try {
      await chrome.proxy.settings.set({
        value: {
          mode: 'fixed_servers',
          rules: {
            singleProxy: {
              scheme: profile.scheme || 'http',
              host: profile.host,
              port: Number(profile.port)
            },
            bypassList: ['localhost', '127.0.0.1']
          }
        },
        scope: 'regular'
      });
      await new Promise((r) => setTimeout(r, 140));
      return await runStandardIpProbe(providerId, 5000);
    } finally {
      tempProbeProfile = null;
      isProbing = false;
      const latest = await ensureInitialized();
      // Only restore if user didn't already apply a new profile mid-probe
      if (latest.activeProfileId === expectedActiveIdAtStart) {
        await applyActiveProxyConfig(latest);
      } else {
        isApplyingProxy = false;
      }
    }
  });
}

async function checkProxyAndPersist(profileId) {
  const state = await ensureInitialized();
  const target = (state.profiles || []).find((p) => p.id === profileId && p.type === 'fixed');
  if (!target) return null;

  await setStateAndApply(
    (draft) => {
      const p = draft.profiles.find((item) => item.id === profileId);
      if (p) p.health = { ...(p.health || {}), status: 'checking' };
      return draft;
    },
    { applyProxy: false }
  );

  const result = await runLocalProbe(target, state);

  await setStateAndApply(
    (draft) => {
      const p = draft.profiles.find((item) => item.id === profileId);
      if (p) p.health = result;
      return draft;
    },
    { applyProxy: false }
  );

  return result;
}

async function checkAllProxies() {
  const state = await ensureInitialized();
  const fixedProfiles = (state.profiles || []).filter((p) => p.type === 'fixed');
  if (!fixedProfiles.length) return [];

  await setStateAndApply(
    (draft) => {
      for (const p of draft.profiles) {
        if (p.type === 'fixed') {
          p.health = { ...(p.health || {}), status: 'checking' };
        }
      }
      return draft;
    },
    { applyProxy: false }
  );

  const results = [];
  for (const profile of fixedProfiles) {
    const health = await runLocalProbe(profile, state);
    results.push({ id: profile.id, health });
    await setStateAndApply(
      (draft) => {
        const p = draft.profiles.find((prof) => prof.id === profile.id);
        if (p) p.health = health;
        return draft;
      },
      { applyProxy: false }
    );
  }
  return results;
}

async function refreshOnlineRuleLists() {
  const state = await ensureInitialized();
  let changed = false;

  for (const profile of state.profiles || []) {
    if (profile.type === 'switch' && profile.ruleList?.enabled && profile.ruleList?.url) {
      try {
        const res = await fetch(profile.ruleList.url, {
          cache: 'no-store',
          signal: AbortSignal.timeout(12000)
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = await res.text();
        await setStateAndApply(
          (draft) => {
            const target = draft.profiles.find((p) => p.id === profile.id);
            if (target?.ruleList) {
              target.ruleList.text = text;
              target.ruleList.lastUpdated = Date.now();
              target.ruleList.error = '';
            }
            return draft;
          },
          { applyProxy: state.activeProfileId === profile.id }
        );
        changed = true;
      } catch (err) {
        await setStateAndApply(
          (draft) => {
            const target = draft.profiles.find((p) => p.id === profile.id);
            if (target?.ruleList) target.ruleList.error = err.message;
            return draft;
          },
          { applyProxy: false }
        );
      }
    } else if (profile.type === 'pac' && profile.pacUrl && !profile.pacUrl.startsWith('file:')) {
      try {
        const res = await fetch(profile.pacUrl, {
          cache: 'no-store',
          signal: AbortSignal.timeout(12000)
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const script = await res.text();
        await setStateAndApply(
          (draft) => {
            const target = draft.profiles.find((p) => p.id === profile.id);
            if (target) {
              target.pacScript = script;
              target.lastUpdated = Date.now();
            }
            return draft;
          },
          { applyProxy: state.activeProfileId === profile.id }
        );
        changed = true;
      } catch (err) {
        console.warn(`[ProxyFlow] PAC refresh failed (${profile.name}):`, err.message);
      }
    }
  }
  return changed;
}

/* ──────────────────────────────────────────────────────────────
   Alarms (MV3 Reliable Scheduling)
────────────────────────────────────────────────────────────── */

async function syncAlarms(state) {
  const activeProfile = getProfileById(state, state.activeProfileId);

  if (state.settings?.autoFailoverDeadProxy && activeProfile.type === 'fixed') {
    await chrome.alarms.create(ALARM_ACTIVE_MONITOR, { periodInMinutes: 1 });
  } else {
    await chrome.alarms.clear(ALARM_ACTIVE_MONITOR);
  }

  const interval = Number(state.settings?.healthCheckIntervalMin || 0);
  if (interval > 0) {
    await chrome.alarms.create(ALARM_BATCH_CHECK, { periodInMinutes: interval });
  } else {
    await chrome.alarms.clear(ALARM_BATCH_CHECK);
  }

  const hasRemoteRules = (state.profiles || []).some(
    (p) => (p.type === 'switch' && p.ruleList?.enabled && p.ruleList?.url) || (p.type === 'pac' && p.pacUrl)
  );
  if (hasRemoteRules) {
    await chrome.alarms.create(ALARM_RULE_REFRESH, { periodInMinutes: 60 });
  } else {
    await chrome.alarms.clear(ALARM_RULE_REFRESH);
  }
}

chrome.alarms.onAlarm.addListener(async (alarm) => {
  const state = await ensureInitialized();

  if (alarm.name === ALARM_ACTIVE_MONITOR) {
    if (isProbing || tempProbeProfile) return;
    const active = getProfileById(state, state.activeProfileId);
    if (active.type !== 'fixed' || !state.settings?.autoFailoverDeadProxy) return;

    const health = await runLocalProbe(active, state);
    if (health.status === 'dead') {
      console.warn(`[ProxyFlow] Active proxy ${active.name} offline. Auto-switching to Direct.`);
      await updateRuntime({
        proxyDiedAlert: {
          profileName: active.name,
          host: `${active.host}:${active.port}`,
          at: Date.now()
        }
      });
      await setStateAndApply(
        (draft) => {
          const p = draft.profiles.find((item) => item.id === active.id);
          if (p) p.health = health;
          draft.activeProfileId = 'direct';
          return draft;
        },
        { applyProxy: true }
      );
    } else if (health.status === 'live') {
      await setStateAndApply(
        (draft) => {
          const p = draft.profiles.find((item) => item.id === active.id);
          if (p) p.health = health;
          return draft;
        },
        { applyProxy: false }
      );
    }
  } else if (alarm.name === ALARM_BATCH_CHECK) {
    await checkAllProxies();
  } else if (alarm.name === ALARM_RULE_REFRESH) {
    await refreshOnlineRuleLists();
  }
});

/* ──────────────────────────────────────────────────────────────
   Context Menus (Serialized Queue — Zero Duplicate ID Errors)
────────────────────────────────────────────────────────────── */

function createContextMenuSafe(props) {
  return new Promise((resolve) => {
    chrome.contextMenus.create(props, () => {
      void chrome.runtime.lastError;
      resolve();
    });
  });
}

function removeAllContextMenusSafe() {
  return new Promise((resolve) => {
    chrome.contextMenus.removeAll(() => {
      void chrome.runtime.lastError;
      resolve();
    });
  });
}

function syncContextMenus(state) {
  if (!chrome.contextMenus) return Promise.resolve();

  const run = menuQueue.then(async () => {
    await removeAllContextMenusSafe();
    if (!state?.settings?.showContextMenu) return;

    await createContextMenuSafe({
      id: 'pm-inspect-page',
      title: 'Inspect proxy route for this page',
      contexts: ['page']
    });
    await createContextMenuSafe({
      id: 'pm-inspect-link',
      title: 'Inspect proxy route for this link',
      contexts: ['link']
    });
    await createContextMenuSafe({
      id: 'pm-quick-switch',
      title: 'Cycle Quick Switch profile',
      contexts: ['action', 'page']
    });
  });

  menuQueue = run.catch(() => {});
  return run;
}

if (chrome.contextMenus) {
  chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    const state = await ensureInitialized();
    if (info.menuItemId === 'pm-quick-switch') {
      await cycleQuickSwitch();
      return;
    }
    const targetUrl = info.linkUrl || info.pageUrl || tab?.url;
    if (!targetUrl || !tab?.id) return;
    const match = matchUrl(targetUrl, state);
    const domain = extractDomainFromUrl(targetUrl) || targetUrl;
    await applyActionVisual({
      tabId: tab.id,
      outerColor: semanticColorForType(match.resolvedProfile.type),
      innerColor: semanticColorForType(match.activeProfile.type),
      title: `[Inspect] ${domain}\nProfile: ${match.resolvedProfile.name}${match.matchedRule ? `\nRule: ${match.matchedRule.pattern}` : ''}`,
      badgeText: (match.resolvedProfile.name || 'DIR').slice(0, 4),
      badgeColor: semanticColorForType(match.resolvedProfile.type)
    });
  });
}

async function cycleQuickSwitch() {
  const state = await ensureInitialized();
  const list = (state.settings?.quickSwitchIds || []).filter((id) => {
    if (id === 'direct') return true;
    return state.profiles.some((p) => p.id === id);
  });
  const pool = list.length >= 2 ? list : ['direct', ...state.profiles.map((p) => p.id)];
  if (pool.length < 2) return null;

  const idx = pool.indexOf(state.activeProfileId);
  const nextId = pool[(idx + 1) % pool.length];
  await setStateAndApply(
    (draft) => {
      draft.activeProfileId = nextId;
      return draft;
    },
    { applyProxy: true, refreshTab: true }
  );
  return nextId;
}

if (chrome.commands) {
  chrome.commands.onCommand.addListener(async (command) => {
    if (command === 'quick-switch') {
      await cycleQuickSwitch();
    }
  });
}

/* ──────────────────────────────────────────────────────────────
   Lifecycle Events
────────────────────────────────────────────────────────────── */

chrome.runtime.onStartup.addListener(() => {
  enqueueStateOp(async () => {
    const state = await ensureInitialized(true);
    if (state.settings?.startupProfileId) {
      const updated = await updateState((draft) => {
        draft.activeProfileId = draft.settings.startupProfileId;
        return draft;
      });
      stateCache = updated;
      await applyActiveProxyConfig(updated);
      await syncContextMenus(updated);
      await syncAlarms(updated);
      await refreshAllTabVisuals(updated);
    } else {
      await applyActiveProxyConfig(state);
      await syncContextMenus(state);
      await syncAlarms(state);
      await refreshAllTabVisuals(state);
    }
  });
});

chrome.runtime.onInstalled.addListener(() => {
  enqueueStateOp(async () => {
    const state = await ensureInitialized(true);
    await applyActiveProxyConfig(state);
    await syncContextMenus(state);
    await syncAlarms(state);
    await refreshAllTabVisuals(state);
  });
});

/* ──────────────────────────────────────────────────────────────
   Message Router (Popup, Options, Monitor)
────────────────────────────────────────────────────────────── */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message)
    .then((data) => sendResponse({ ok: true, ...data }))
    .catch((err) => sendResponse({ ok: false, error: err.message || String(err) }));
  return true;
});

function linkAutoSwitchIfUnconfigured(draft, fallbackProxyId) {
  if (!fallbackProxyId) return;
  const sw = draft.profiles.find((p) => p.id === DEFAULT_AUTO_SWITCH_ID && p.type === 'switch');
  if (!sw || sw.defaultProfileId !== 'direct') return;
  const hasProxyRule = (sw.rules || []).some(
    (r) => r.profileId && r.profileId !== 'direct'
  );
  if (!hasProxyRule) {
    sw.defaultProfileId = fallbackProxyId;
  }
}

async function handleMessage(msg) {
  const state = await ensureInitialized();

  switch (msg.type) {
    case 'PING':
      return { alive: true };

    case 'GET_BOOTSTRAP': {
      const runtime = await loadRuntime();
      const [activeTab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      if (activeTab) {
        updateTabVisual(activeTab, state);
      }
      const diagnostics = buildTabDiagnostics(activeTab, state);
      return { state, runtime, diagnostics };
    }

    case 'GET_TAB_DIAGNOSTICS': {
      const [activeTab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      return { diagnostics: buildTabDiagnostics(activeTab, state) };
    }

    case 'CLEAR_DIED_ALERT': {
      await updateRuntime({ proxyDiedAlert: null });
      return {};
    }

    case 'APPLY_PROFILE': {
      const next = await setStateAndApply(
        (draft) => {
          draft.activeProfileId = msg.profileId || 'direct';
          return draft;
        },
        { applyProxy: true, refreshTab: msg.refreshTab !== false }
      );
      await updateRuntime({ proxyDiedAlert: null, lastProxyError: null });
      return { state: next };
    }

    case 'UPSERT_PROXY': {
      const incoming = msg.proxy || {};
      const host = (incoming.host || '').trim();
      const port = parseInt(incoming.port, 10);
      if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error('Please enter a valid host and port (1–65535).');
      }

      let savedProfile = null;
      const next = await setStateAndApply(
        (draft) => {
          const existing = incoming.id
            ? draft.profiles.find((p) => p.id === incoming.id)
            : draft.profiles.find(
                (p) =>
                  p.type === 'fixed' &&
                  p.host.toLowerCase() === host.toLowerCase() &&
                  Number(p.port) === port &&
                  (p.scheme || 'http') === (incoming.scheme || 'http')
              );

          if (existing) {
            existing.name = (incoming.name || `${host}:${port}`).trim();
            existing.scheme = incoming.scheme || 'http';
            existing.host = host;
            existing.port = port;
            existing.username = (incoming.username || '').trim();
            existing.password = incoming.password || '';
            existing.color = incoming.color || existing.color;
            existing.bypassList = Array.isArray(incoming.bypassList)
              ? incoming.bypassList
              : existing.bypassList || [...DEFAULT_BYPASS_LIST];
            existing.notes = incoming.notes ?? existing.notes ?? '';
            existing.updatedAt = Date.now();
            savedProfile = existing;
          } else {
            savedProfile = {
              id: generateId('proxy'),
              name: (incoming.name || `${host}:${port}`).trim(),
              type: 'fixed',
              color: incoming.color || pickNextColor(draft.profiles),
              scheme: incoming.scheme || 'http',
              host,
              port,
              username: (incoming.username || '').trim(),
              password: incoming.password || '',
              bypassList: Array.isArray(incoming.bypassList)
                ? incoming.bypassList
                : [...DEFAULT_BYPASS_LIST],
              notes: incoming.notes || '',
              health: { status: 'unknown', checkedAt: null },
              createdAt: Date.now(),
              updatedAt: Date.now()
            };
            draft.profiles.push(savedProfile);
          }

          if (msg.activate) {
            draft.activeProfileId = savedProfile.id;
          }
          linkAutoSwitchIfUnconfigured(draft, savedProfile.id);
          return draft;
        },
        {
          applyProxy: Boolean(
            msg.activate ||
              state.activeProfileId === incoming.id ||
              state.activeProfileId === DEFAULT_AUTO_SWITCH_ID
          ),
          refreshTab: Boolean(msg.activate)
        }
      );

      return { state: next, profile: savedProfile };
    }

    case 'BULK_IMPORT_PROXIES': {
      const { valid, invalidLines } = parseProxyBulk(msg.text || '');
      if (!valid.length) {
        throw new Error('No valid proxy lines found.');
      }
      let added = 0;
      let updated = 0;

      const next = await setStateAndApply(
        (draft) => {
          const map = new Map();
          for (const p of draft.profiles) {
            if (p.type === 'fixed') map.set(proxyIdentityKey(p), p);
          }

          for (const item of valid) {
            const key = proxyIdentityKey(item);
            const existing = map.get(key);
            if (existing) {
              existing.username = item.username;
              existing.password = item.password;
              if (item.name && item.name !== `${item.host}:${item.port}`) {
                existing.name = item.name;
              }
              existing.updatedAt = Date.now();
              updated += 1;
            } else {
              const created = {
                id: generateId('proxy'),
                name: item.name,
                type: 'fixed',
                color: pickNextColor(draft.profiles),
                scheme: item.scheme,
                host: item.host,
                port: item.port,
                username: item.username,
                password: item.password,
                bypassList: [...DEFAULT_BYPASS_LIST],
                notes: '',
                health: { status: 'unknown', checkedAt: null },
                createdAt: Date.now(),
                updatedAt: Date.now()
              };
              draft.profiles.push(created);
              map.set(key, created);
              added += 1;
            }
          }
          const firstFixed = draft.profiles.find((p) => p.type === 'fixed');
          linkAutoSwitchIfUnconfigured(draft, firstFixed?.id);
          return draft;
        },
        { applyProxy: state.activeProfileId === DEFAULT_AUTO_SWITCH_ID }
      );

      return { state: next, added, updated, invalidCount: invalidLines.length };
    }

    case 'UPSERT_PROFILE_GENERIC': {
      const profile = msg.profile;
      if (!profile || !profile.type || !profile.name) {
        throw new Error('Profile name and type are required.');
      }
      const next = await setStateAndApply(
        (draft) => {
          const idx = draft.profiles.findIndex((p) => p.id === profile.id);
          if (idx >= 0) {
            draft.profiles[idx] = { ...draft.profiles[idx], ...profile, updatedAt: Date.now() };
          } else {
            draft.profiles.push({
              ...profile,
              id: profile.id || generateId(profile.type),
              color: profile.color || pickNextColor(draft.profiles),
              createdAt: Date.now(),
              updatedAt: Date.now()
            });
          }
          return draft;
        },
        { applyProxy: true }
      );
      return { state: next };
    }

    case 'DELETE_PROFILE': {
      const targetId = msg.profileId;
      if (!targetId || targetId === 'direct') {
        throw new Error('Built-in profiles cannot be deleted.');
      }
      const next = await setStateAndApply(
        (draft) => {
          draft.profiles = draft.profiles.filter((p) => p.id !== targetId);
          for (const p of draft.profiles) {
            if (p.type === 'switch') {
              if (p.defaultProfileId === targetId) p.defaultProfileId = 'direct';
              if (p.ruleList?.matchProfileId === targetId) p.ruleList.matchProfileId = 'direct';
              p.rules = (p.rules || []).map((r) =>
                r.profileId === targetId ? { ...r, profileId: 'direct' } : r
              );
            }
          }
          for (const [dom, tr] of Object.entries(draft.tempRules || {})) {
            if (tr.profileId === targetId) delete draft.tempRules[dom];
          }
          if (draft.settings?.startupProfileId === targetId) {
            draft.settings.startupProfileId = null;
          }
          draft.settings.quickSwitchIds = (draft.settings.quickSwitchIds || []).filter(
            (id) => id !== targetId
          );
          if (draft.activeProfileId === targetId) {
            draft.activeProfileId = 'direct';
          }
          return draft;
        },
        { applyProxy: state.activeProfileId === targetId }
      );
      return { state: next };
    }

    case 'ADD_TEMP_RULE': {
      const domain = (msg.domain || '').trim().toLowerCase();
      if (!domain) throw new Error('Domain is required for temporary rule.');
      const next = await setStateAndApply(
        (draft) => {
          if (!msg.profileId) {
            delete draft.tempRules[domain];
          } else {
            draft.tempRules[domain] = {
              domain,
              conditionType: 'hostWildcard',
              pattern: domainToWildcard(domain),
              profileId: msg.profileId,
              createdAt: Date.now()
            };
          }
          return draft;
        },
        { applyProxy: true, refreshTab: msg.refreshTab !== false }
      );
      return { state: next };
    }

    case 'REMOVE_TEMP_RULE': {
      const next = await setStateAndApply(
        (draft) => {
          delete draft.tempRules[msg.domain];
          return draft;
        },
        { applyProxy: true, refreshTab: Boolean(msg.refreshTab) }
      );
      return { state: next };
    }

    case 'CLEAR_TEMP_RULES': {
      const next = await setStateAndApply(
        (draft) => {
          draft.tempRules = {};
          return draft;
        },
        { applyProxy: true }
      );
      return { state: next };
    }

    case 'ADD_SWITCH_RULE': {
      const switchId = msg.switchProfileId || DEFAULT_AUTO_SWITCH_ID;
      const rule = {
        id: generateId('rule'),
        enabled: true,
        conditionType: msg.conditionType || 'hostWildcard',
        pattern: (msg.pattern || '').trim(),
        profileId: msg.profileId || 'direct',
        note: (msg.note || '').trim()
      };
      if (!rule.pattern) throw new Error('Condition pattern is required.');

      const next = await setStateAndApply(
        (draft) => {
          let sw = draft.profiles.find((p) => p.id === switchId && p.type === 'switch');
          if (!sw) sw = draft.profiles.find((p) => p.type === 'switch');
          if (!sw) throw new Error('No Auto Switch profile found.');
          if (draft.settings?.addConditionsToBottom) {
            sw.rules.push(rule);
          } else {
            sw.rules.unshift(rule);
          }
          sw.updatedAt = Date.now();
          if (msg.activateSwitch) {
            draft.activeProfileId = sw.id;
          }
          return draft;
        },
        { applyProxy: true, refreshTab: msg.refreshTab !== false }
      );
      return { state: next };
    }

    case 'CHECK_PROXY': {
      const health = await checkProxyAndPersist(msg.profileId);
      const latest = await ensureInitialized();
      return { health, state: latest };
    }

    case 'CHECK_ALL_PROXIES': {
      const results = await checkAllProxies();
      const latest = await ensureInitialized();
      return { results, state: latest };
    }

    case 'REFRESH_ONLINE_RULES': {
      const updated = await refreshOnlineRuleLists();
      const latest = await ensureInitialized();
      return { updated, state: latest };
    }

    case 'UPDATE_SETTINGS': {
      const next = await setStateAndApply(
        (draft) => {
          draft.settings = { ...draft.settings, ...(msg.settings || {}) };
          return draft;
        },
        { applyProxy: false, rebuildMenus: true }
      );
      return { state: next };
    }

    case 'CYCLE_QUICK_SWITCH': {
      const nextId = await cycleQuickSwitch();
      const latest = await ensureInitialized();
      return { nextId, state: latest };
    }

    case 'IMPORT_BACKUP': {
      const imported = msg.backup;
      if (!imported || !Array.isArray(imported.profiles)) {
        throw new Error('Invalid backup JSON file.');
      }
      const next = await enqueueStateOp(async () => {
        const base = createDefaultState();
        const merged = {
          ...base,
          ...imported,
          schemaVersion: 7,
          migrationCompleted: true,
          settings: { ...base.settings, ...(imported.settings || {}) }
        };
        const saved = await saveState(merged);
        stateCache = saved;
        await applyActiveProxyConfig(saved);
        await syncContextMenus(saved);
        await syncAlarms(saved);
        await refreshAllTabVisuals(saved);
        return saved;
      });
      return { state: next };
    }

    case 'RESET_ALL': {
      const next = await enqueueStateOp(async () => {
        const fresh = createDefaultState();
        fresh.migrationCompleted = true;
        const saved = await saveState(fresh);
        stateCache = saved;
        tabErrors.clear();
        monitorLogs.length = 0;
        await applyActiveProxyConfig(saved);
        await syncContextMenus(saved);
        await syncAlarms(saved);
        await refreshAllTabVisuals(saved);
        return saved;
      });
      return { state: next };
    }

    case 'GET_MONITOR_DATA': {
      const tabs = await chrome.tabs.query({});
      return {
        logs: monitorLogs,
        tabs: tabs.map((t) => ({ id: t.id, title: t.title, url: t.url })),
        state
      };
    }

    case 'CLEAR_MONITOR_DATA': {
      monitorLogs.length = 0;
      tabErrors.clear();
      await refreshAllTabVisuals(state);
      return {};
    }

    default:
      throw new Error(`Unknown command: ${msg.type}`);
  }
}

function buildTabDiagnostics(tab, state) {
  if (!tab || !tab.url) {
    return {
      tabId: tab?.id || null,
      url: '',
      domain: null,
      match: null,
      tempRule: null,
      failedDomains: [],
      totalFailedCount: 0
    };
  }

  const domain = extractDomainFromUrl(tab.url);
  const match = domain ? matchUrl(tab.url, state) : null;
  const tempRule = domain ? state.tempRules?.[domain] || null : null;
  const errRecord = tabErrors.get(tab.id);
  const failedDomains = errRecord
    ? Array.from(errRecord.domains.values()).sort((a, b) => b.count - a.count)
    : [];

  return {
    tabId: tab.id,
    url: tab.url,
    domain,
    match: match
      ? {
          activeProfileId: match.activeProfile.id,
          activeProfileName: match.activeProfile.name,
          resolvedProfileId: match.resolvedProfile.id,
          resolvedProfileName: match.resolvedProfile.name,
          resolvedProfileColor: match.resolvedProfile.color,
          matchedRule: match.matchedRule
        }
      : null,
    tempRule,
    failedDomains,
    totalFailedCount: errRecord?.totalErrors || 0
  };
}

// Cold wake-up hydration ONLY loads state into memory and refreshes toolbar icon visuals
// without overwriting proxy settings or colliding with onInstalled/onStartup menus.
ensureInitialized().then((state) => {
  refreshAllTabVisuals(state);
});
