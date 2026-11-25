// popup.js — Light-mode Popup UI controller

import {
  BUILTIN_PROFILES,
  CONDITION_TYPES,
  DEFAULT_AUTO_SWITCH_ID,
  PROFILE_COLOR_PALETTE,
  SCHEME_OPTIONS,
  STATE_COLORS,
  getProfileById
} from './shared/models.js';
import {
  formatProxyColon,
  formatProxyUri,
  parseProxyLine
} from './shared/proxy-parser.js';
import { domainToWildcard, validateConditionPattern } from './shared/rule-matcher.js';
import { runStandardIpProbe } from './shared/ip-probe.js';
import { VAULT_STATE_KEY } from './shared/storage.js';
import {
  copyToClipboard,
  createHealthBadge,
  createProfileDot,
  createSemanticBadge,
  el,
  sendBgMessage,
  showToast,
  svgIcon
} from './shared/ui-helpers.js';

const dom = {
  activeSummary: document.getElementById('activeSummary'),
  headerActions: document.getElementById('headerActions'),
  alertRegion: document.getElementById('alertRegion'),
  ipPillBtn: document.getElementById('ipPillBtn'),
  currentIpValue: document.getElementById('currentIpValue'),
  ipRefreshSlot: document.getElementById('ipRefreshSlot'),
  tabRouteRow: document.getElementById('tabRouteRow'),
  tabDomainLabel: document.getElementById('tabDomainLabel'),
  tabResolvedBadge: document.getElementById('tabResolvedBadge'),
  tabRouteActions: document.getElementById('tabRouteActions'),
  failedDomainsDrawer: document.getElementById('failedDomainsDrawer'),
  addRuleDrawer: document.getElementById('addRuleDrawer'),
  modePills: document.getElementById('modePills'),
  modeAddBtnSlot: document.getElementById('modeAddBtnSlot'),
  quickAddDrawer: document.getElementById('quickAddDrawer'),
  closeQuickAddBtn: document.getElementById('closeQuickAddBtn'),
  quickParseInput: document.getElementById('quickParseInput'),
  addSchemeInput: document.getElementById('addSchemeInput'),
  addHostInput: document.getElementById('addHostInput'),
  addPortInput: document.getElementById('addPortInput'),
  addLabelInput: document.getElementById('addLabelInput'),
  addUserInput: document.getElementById('addUserInput'),
  addPassInput: document.getElementById('addPassInput'),
  socksAuthHint: document.getElementById('socksAuthHint'),
  saveOnlyProxyBtn: document.getElementById('saveOnlyProxyBtn'),
  saveActivateProxyBtn: document.getElementById('saveActivateProxyBtn'),
  searchWrap: document.getElementById('searchWrap'),
  proxySearchInput: document.getElementById('proxySearchInput'),
  listToolbarActions: document.getElementById('listToolbarActions'),
  proxyListContainer: document.getElementById('proxyListContainer'),
  detailModalHost: document.getElementById('detailModalHost'),
  toastHost: document.getElementById('toastHost')
};

let appState = null;
let appRuntime = null;
let tabDiagnostics = null;
let currentExitIp = '';
let showFailedDrawer = false;
let showRuleDrawer = false;

document.addEventListener('DOMContentLoaded', async () => {
  initStaticIcons();
  bindEvents();
  await loadAndRender();
  fetchPublicIp();
});

function initStaticIcons() {
  dom.closeQuickAddBtn.replaceChildren(svgIcon('x', 14));
  const searchIcon = svgIcon('search', 13);
  dom.searchWrap.insertBefore(searchIcon, dom.proxySearchInput);

  const refreshIpBtn = el(
    'button',
    {
      type: 'button',
      className: 'pm-btn pm-btn--xs',
      title: 'Refresh Public IP',
      onClick: () => fetchPublicIp()
    },
    [svgIcon('refresh', 12), 'Refresh IP']
  );
  dom.ipRefreshSlot.replaceChildren(refreshIpBtn);
}

function bindEvents() {
  dom.ipPillBtn.addEventListener('click', async () => {
    if (!currentExitIp) return;
    await copyToClipboard(currentExitIp);
    showToast(dom.toastHost, `Copied IP: ${currentExitIp}`, 'success');
  });

  dom.closeQuickAddBtn.addEventListener('click', () => {
    dom.quickAddDrawer.classList.add('pm-hidden');
  });

  dom.quickParseInput.addEventListener('input', () => {
    const parsed = parseProxyLine(dom.quickParseInput.value);
    if (parsed) {
      dom.addSchemeInput.value = parsed.scheme;
      dom.addHostInput.value = parsed.host;
      dom.addPortInput.value = String(parsed.port);
      dom.addUserInput.value = parsed.username || '';
      dom.addPassInput.value = parsed.password || '';
      if (!dom.addLabelInput.value.trim() && parsed.name !== `${parsed.host}:${parsed.port}`) {
        dom.addLabelInput.value = parsed.name;
      }
    }
    updateSocksAuthHint();
  });

  [dom.addSchemeInput, dom.addUserInput, dom.addPassInput].forEach((input) => {
    input.addEventListener('input', updateSocksAuthHint);
    input.addEventListener('change', updateSocksAuthHint);
  });

  dom.saveOnlyProxyBtn.addEventListener('click', () => handleSaveQuickProxy(false));
  dom.saveActivateProxyBtn.addEventListener('click', () => handleSaveQuickProxy(true));

  dom.proxySearchInput.addEventListener('input', () => {
    renderProxyList();
  });

  dom.detailModalHost.addEventListener('click', (e) => {
    if (e.target === dom.detailModalHost) {
      dom.detailModalHost.classList.add('pm-hidden');
    }
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && (changes[VAULT_STATE_KEY] || changes.pmRuntime)) {
      loadAndRender(false);
    }
  });
}

function updateSocksAuthHint() {
  const isSocks = dom.addSchemeInput.value === 'socks4' || dom.addSchemeInput.value === 'socks5';
  const hasCreds = Boolean(dom.addUserInput.value.trim() || dom.addPassInput.value);
  dom.socksAuthHint.classList.toggle('pm-hidden', !(isSocks && hasCreds));
}

async function loadAndRender(refreshDiagnostics = true) {
  try {
    const res = await sendBgMessage('GET_BOOTSTRAP');
    appState = res.state;
    appRuntime = res.runtime;
    if (refreshDiagnostics || !tabDiagnostics) {
      tabDiagnostics = res.diagnostics;
    }
    renderAll();
  } catch (err) {
    showToast(dom.toastHost, err.message, 'danger');
  }
}

function renderAll() {
  if (!appState) return;
  renderHeader();
  renderAlerts();
  renderTabRoute();
  renderModeBar();
  renderToolbarActions();
  renderProxyList();
  renderFailedDomainsDrawer();
  renderAddRuleDrawer();
}

function getSemanticStateDotColor(type) {
  if (type === 'switch') return STATE_COLORS.autoSwitch;
  if (type === 'fixed' || type === 'pac') return STATE_COLORS.proxy;
  return STATE_COLORS.noProxy;
}

function renderHeader() {
  const active = getProfileById(appState, appState.activeProfileId);
  const subParts = [createProfileDot(getSemanticStateDotColor(active.type)), el('span', {}, active.name)];
  if (active.type === 'fixed') {
    subParts.push(el('span', { className: 'pm-mono' }, `(${active.host}:${active.port})`));
  }
  dom.activeSummary.replaceChildren(...subParts);

  const buttons = [];

  if (appState.settings?.enableQuickSwitch) {
    buttons.push(
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--icon pm-btn--ghost',
          title: 'Cycle Quick Switch profile (Alt+Shift+P)',
          'aria-label': 'Cycle Quick Switch profile',
          onClick: async () => {
            const res = await sendBgMessage('CYCLE_QUICK_SWITCH');
            appState = res.state;
            renderAll();
            setTimeout(fetchPublicIp, 600);
            showToast(dom.toastHost, `Switched to ${getProfileById(appState, appState.activeProfileId).name}`, 'info');
          }
        },
        svgIcon('zap', 15)
      )
    );
  }

  const monitorBtn = el(
    'button',
    {
      type: 'button',
      className: 'pm-btn pm-btn--icon pm-btn--ghost pm-monitor-btn',
      title: 'Open Network Monitor',
      'aria-label': 'Open Network Monitor',
      onClick: () => chrome.tabs.create({ url: chrome.runtime.getURL('monitor.html') })
    },
    [
      svgIcon('activity', 15),
      tabDiagnostics?.totalFailedCount > 0
        ? el('span', { className: 'pm-btn-dot', title: `${tabDiagnostics.totalFailedCount} failed requests` })
        : null
    ]
  );
  buttons.push(monitorBtn);

  buttons.push(
    el(
      'button',
      {
        type: 'button',
        className: 'pm-btn pm-btn--icon pm-btn--ghost',
        title: 'Open Full Options & Rules',
        'aria-label': 'Open Options',
        onClick: () => chrome.runtime.openOptionsPage()
      },
      svgIcon('settings', 15)
    )
  );

  dom.headerActions.replaceChildren(...buttons);
}

function renderAlerts() {
  const nodes = [];

  if (appRuntime?.proxyDiedAlert) {
    const { profileName, host } = appRuntime.proxyDiedAlert;
    nodes.push(
      el('div', { className: 'pm-alert pm-alert--danger' }, [
        el('div', { className: 'pm-alert__body' }, [
          svgIcon('error', 15),
          el('span', {}, `Proxy "${profileName}" (${host}) went offline and auto-switched to Direct.`)
        ]),
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
            'aria-label': 'Dismiss alert',
            onClick: async () => {
              await sendBgMessage('CLEAR_DIED_ALERT');
              appRuntime.proxyDiedAlert = null;
              renderAlerts();
            }
          },
          svgIcon('x', 13)
        )
      ])
    );
  }

  if (tabDiagnostics?.totalFailedCount > 0) {
    nodes.push(
      el('div', { className: 'pm-alert pm-alert--warning' }, [
        el('div', { className: 'pm-alert__body' }, [
          svgIcon('warning', 15),
          el(
            'span',
            {},
            `${tabDiagnostics.totalFailedCount} failed resource(s) across ${tabDiagnostics.failedDomains.length} domain(s) on this tab.`
          )
        ]),
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--xs',
            onClick: () => {
              showFailedDrawer = !showFailedDrawer;
              showRuleDrawer = false;
              if (showFailedDrawer) dom.quickAddDrawer.classList.add('pm-hidden');
              renderFailedDomainsDrawer();
              renderAddRuleDrawer();
            }
          },
          showFailedDrawer ? 'Hide' : 'Fix Domains'
        )
      ])
    );
  }

  dom.alertRegion.replaceChildren(...nodes);
}

function renderTabRoute() {
  if (!tabDiagnostics?.domain) {
    dom.tabRouteRow.classList.add('pm-hidden');
    return;
  }

  dom.tabRouteRow.classList.remove('pm-hidden');
  dom.tabDomainLabel.textContent = tabDiagnostics.domain;
  dom.tabDomainLabel.title = tabDiagnostics.url;

  const match = tabDiagnostics.match;
  const resolvedId = match?.resolvedProfileId || 'direct';
  const resolvedName = match?.resolvedProfileName || 'Direct (Off)';
  const isNoProxyRoute = resolvedId === 'direct';
  const badgeTone =
    match?.matchedRule?.source === 'temp'
      ? 'warning'
      : isNoProxyRoute
        ? 'danger'
        : 'success';
  const iconName =
    match?.matchedRule?.source === 'temp'
      ? 'filter'
      : isNoProxyRoute
        ? 'direct'
        : 'proxy';

  dom.tabResolvedBadge.replaceChildren(
    createSemanticBadge(
      resolvedName,
      badgeTone,
      iconName,
      match?.matchedRule ? `Matched rule: ${match.matchedRule.pattern}` : 'Active route for this tab'
    )
  );

  // Temp Rule selector (ZeroOmega style)
  const fixedProfiles = appState.profiles.filter((p) => p.type === 'fixed');
  const tempSelect = el('select', {
    className: 'pm-select pm-temp-select',
    'aria-label': `Temporary rule for ${tabDiagnostics.domain}`,
    title: `Temporary route for ${tabDiagnostics.domain}`
  });

  tempSelect.appendChild(el('option', { value: '' }, 'Temp rule: Off'));
  tempSelect.appendChild(
    el('option', { value: 'direct', selected: tabDiagnostics.tempRule?.profileId === 'direct' }, 'Temp → Direct')
  );
  for (const p of fixedProfiles) {
    tempSelect.appendChild(
      el(
        'option',
        { value: p.id, selected: tabDiagnostics.tempRule?.profileId === p.id },
        `Temp → ${p.name}`
      )
    );
  }

  tempSelect.addEventListener('change', async () => {
    const val = tempSelect.value;
    const res = val
      ? await sendBgMessage('ADD_TEMP_RULE', { domain: tabDiagnostics.domain, profileId: val })
      : await sendBgMessage('REMOVE_TEMP_RULE', { domain: tabDiagnostics.domain, refreshTab: true });
    appState = res.state;
    await refreshDiagnosticsOnly();
    renderAll();
    setTimeout(fetchPublicIp, 600);
    showToast(
      dom.toastHost,
      val ? `Temp rule set for ${tabDiagnostics.domain}` : `Temp rule cleared for ${tabDiagnostics.domain}`,
      'info'
    );
  });

  const addRuleBtn = el(
    'button',
    {
      type: 'button',
      className: 'pm-btn pm-btn--xs',
      title: `Add permanent Auto Switch rule for ${tabDiagnostics.domain}`,
      onClick: () => {
        showRuleDrawer = !showRuleDrawer;
        showFailedDrawer = false;
        if (showRuleDrawer) dom.quickAddDrawer.classList.add('pm-hidden');
        renderAddRuleDrawer();
        renderFailedDomainsDrawer();
      }
    },
    [svgIcon('plus', 12), 'Rule']
  );

  dom.tabRouteActions.replaceChildren(tempSelect, addRuleBtn);
}

function renderFailedDomainsDrawer() {
  if (!showFailedDrawer || !tabDiagnostics?.failedDomains?.length) {
    dom.failedDomainsDrawer.classList.add('pm-hidden');
    return;
  }
  dom.failedDomainsDrawer.classList.remove('pm-hidden');

  const fixedProfiles = appState.profiles.filter((p) => p.type === 'fixed');
  const selectedDomains = new Set(tabDiagnostics.failedDomains.map((d) => d.domain));

  const targetSelect = el('select', { className: 'pm-select pm-select--sm', 'aria-label': 'Route failed domains via' });
  targetSelect.appendChild(el('option', { value: 'direct' }, 'Direct'));
  for (const p of fixedProfiles) {
    targetSelect.appendChild(el('option', { value: p.id }, p.name));
  }
  if (fixedProfiles.length) {
    targetSelect.value = fixedProfiles[0].id;
  }

  const listNode = el('div', { className: 'pm-failed-list' });
  for (const item of tabDiagnostics.failedDomains) {
    const cb = el('input', { type: 'checkbox', checked: true });
    cb.addEventListener('change', () => {
      if (cb.checked) selectedDomains.add(item.domain);
      else selectedDomains.delete(item.domain);
    });
    listNode.appendChild(
      el('div', { className: 'pm-failed-item' }, [
        el('label', {}, [
          cb,
          el('span', { className: 'pm-failed-domain', title: item.lastUrl }, item.domain)
        ]),
        createSemanticBadge(`${item.count}×`, 'warning', null, item.lastError)
      ])
    );
  }

  dom.failedDomainsDrawer.replaceChildren(
    el('div', { className: 'pm-drawer__head' }, [
      el('span', {}, 'Route Failed Domains'),
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
          'aria-label': 'Close',
          onClick: () => {
            showFailedDrawer = false;
            renderFailedDomainsDrawer();
          }
        },
        svgIcon('x', 13)
      )
    ]),
    listNode,
    el('div', { className: 'pm-grid-2' }, [
      targetSelect,
      el('div', { className: 'pm-drawer-actions' }, [
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--sm',
            onClick: async () => {
              for (const d of selectedDomains) {
                await sendBgMessage('ADD_TEMP_RULE', {
                  domain: d,
                  profileId: targetSelect.value,
                  refreshTab: false
                });
              }
              showFailedDrawer = false;
              await loadAndRender();
              showToast(dom.toastHost, `Added ${selectedDomains.size} temp rule(s).`, 'success');
            }
          },
          'Temp Rule'
        ),
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--sm pm-btn--primary',
            onClick: async () => {
              for (const d of selectedDomains) {
                await sendBgMessage('ADD_SWITCH_RULE', {
                  conditionType: 'hostWildcard',
                  pattern: domainToWildcard(d),
                  profileId: targetSelect.value,
                  activateSwitch: true,
                  refreshTab: false
                });
              }
              showFailedDrawer = false;
              await loadAndRender();
              showToast(dom.toastHost, `Added ${selectedDomains.size} Auto Switch rule(s).`, 'success');
            }
          },
          'Add Rule'
        )
      ])
    ])
  );
}

function renderAddRuleDrawer() {
  if (!showRuleDrawer || !tabDiagnostics?.domain) {
    dom.addRuleDrawer.classList.add('pm-hidden');
    return;
  }
  dom.addRuleDrawer.classList.remove('pm-hidden');

  const typeSelect = el('select', { className: 'pm-select pm-select--sm', 'aria-label': 'Condition type' });
  for (const ct of CONDITION_TYPES) {
    typeSelect.appendChild(el('option', { value: ct.value }, ct.label));
  }

  const patternInput = el('input', {
    type: 'text',
    className: 'pm-input pm-input--sm pm-mono',
    value: domainToWildcard(tabDiagnostics.domain),
    'aria-label': 'Condition pattern'
  });

  const targetSelect = el('select', { className: 'pm-select pm-select--sm', 'aria-label': 'Target profile' });
  targetSelect.appendChild(el('option', { value: 'direct' }, 'Direct'));
  for (const p of appState.profiles.filter((item) => item.type === 'fixed')) {
    targetSelect.appendChild(el('option', { value: p.id }, p.name));
  }
  const activeFixed = appState.profiles.find((p) => p.id === appState.activeProfileId && p.type === 'fixed');
  const activeSwitch = appState.profiles.find((p) => p.id === DEFAULT_AUTO_SWITCH_ID && p.type === 'switch');
  if (activeFixed) {
    targetSelect.value = activeFixed.id;
  } else if (
    appState.activeProfileId === DEFAULT_AUTO_SWITCH_ID &&
    activeSwitch?.defaultProfileId &&
    activeSwitch.defaultProfileId !== 'direct'
  ) {
    // When Auto Switch already defaults to Proxy, pre-select Direct for easy site exclusions
    targetSelect.value = 'direct';
  } else if (appState.profiles.some((p) => p.type === 'fixed')) {
    targetSelect.value = appState.profiles.find((p) => p.type === 'fixed').id;
  }

  const toggleWildcardBtn = el(
    'button',
    {
      type: 'button',
      className: 'pm-btn pm-btn--sm',
      title: 'Toggle subdomain wildcard (*.domain) vs exact domain',
      onClick: () => {
        if (patternInput.value.startsWith('*.')) {
          patternInput.value = patternInput.value.slice(2);
        } else {
          patternInput.value = domainToWildcard(patternInput.value || tabDiagnostics.domain);
        }
      }
    },
    '*.Sub'
  );

  dom.addRuleDrawer.replaceChildren(
    el('div', { className: 'pm-drawer__head' }, [
      el('span', {}, `Add Auto Switch Rule (${tabDiagnostics.domain})`),
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
          'aria-label': 'Close',
          onClick: () => {
            showRuleDrawer = false;
            renderAddRuleDrawer();
          }
        },
        svgIcon('x', 13)
      )
    ]),
    el('div', { className: 'pm-grid-2' }, [typeSelect, targetSelect]),
    el('div', { style: 'display:flex; gap:6px;' }, [patternInput, toggleWildcardBtn]),
    el('div', { className: 'pm-drawer-actions' }, [
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--sm',
          onClick: () => submitPopupRule(typeSelect.value, patternInput.value, targetSelect.value, false)
        },
        'Save Rule'
      ),
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--sm pm-btn--primary',
          onClick: () => submitPopupRule(typeSelect.value, patternInput.value, targetSelect.value, true)
        },
        'Save & Enable Auto Switch'
      )
    ])
  );
}

async function submitPopupRule(conditionType, pattern, profileId, activateSwitch) {
  const err = validateConditionPattern(conditionType, pattern);
  if (err) {
    showToast(dom.toastHost, err, 'danger');
    return;
  }
  const res = await sendBgMessage('ADD_SWITCH_RULE', {
    switchProfileId: DEFAULT_AUTO_SWITCH_ID,
    conditionType,
    pattern,
    profileId,
    activateSwitch
  });
  appState = res.state;
  showRuleDrawer = false;
  await refreshDiagnosticsOnly();
  renderAll();
  setTimeout(fetchPublicIp, 600);
  showToast(dom.toastHost, 'Auto Switch rule added.', 'success');
}

function renderModeBar() {
  const routingProfiles = [
    BUILTIN_PROFILES.direct,
    ...appState.profiles.filter((p) => p.type === 'switch' || p.type === 'pac')
  ];

  const pills = routingProfiles.map((profile) => {
    const isActive = appState.activeProfileId === profile.id;
    const iconName =
      profile.type === 'direct'
        ? 'direct'
        : profile.type === 'pac'
          ? 'pac'
          : 'switch';

    const isNoProxy = profile.type === 'direct';
    const pillClass = [
      'pm-mode-pill',
      profile.type === 'switch' ? 'is-switch' : '',
      isNoProxy ? 'is-noproxy' : '',
      isActive ? 'is-active' : ''
    ]
      .filter(Boolean)
      .join(' ');

    return el(
      'button',
      {
        type: 'button',
        className: pillClass,
        title: profile.description || profile.name,
        onClick: () => activateProfile(profile.id)
      },
      [svgIcon(iconName, 13), el('span', {}, profile.name)]
    );
  });

  dom.modePills.replaceChildren(...pills);

  dom.modeAddBtnSlot.replaceChildren(
    el(
      'button',
      {
        type: 'button',
        className: 'pm-btn pm-btn--sm pm-btn--primary',
        onClick: () => {
          const opening = dom.quickAddDrawer.classList.contains('pm-hidden');
          dom.quickAddDrawer.classList.toggle('pm-hidden');
          if (opening) {
            showFailedDrawer = false;
            showRuleDrawer = false;
            renderFailedDomainsDrawer();
            renderAddRuleDrawer();
            dom.quickParseInput.focus();
          }
        }
      },
      [svgIcon('plus', 13), 'Add Proxy']
    )
  );
}

function renderToolbarActions() {
  const buttons = [
    el(
      'button',
      {
        type: 'button',
        className: 'pm-btn pm-btn--xs',
        title: 'Test live status of saved proxies via standard HTTPS check',
        onClick: async () => {
          showToast(dom.toastHost, 'Checking proxies...', 'processing', 0);
          const res = await sendBgMessage('CHECK_ALL_PROXIES');
          appState = res.state;
          renderProxyList();
          showToast(
            dom.toastHost,
            res.results.length ? `Checked ${res.results.length} proxy server(s).` : 'No saved proxies to check.',
            res.results.length ? 'success' : 'info'
          );
        }
      },
      [svgIcon('activity', 12), 'Check All']
    )
  ];

  dom.listToolbarActions.replaceChildren(...buttons);
}

function renderProxyList() {
  const query = (dom.proxySearchInput.value || '').trim().toLowerCase();
  const proxies = appState.profiles.filter((p) => p.type === 'fixed');

  const filtered = proxies.filter((p) => {
    if (!query) return true;
    const status = p.health?.status || 'unknown';
    return (
      p.name.toLowerCase().includes(query) ||
      p.host.toLowerCase().includes(query) ||
      String(p.port).includes(query) ||
      (p.scheme || 'http').toLowerCase().includes(query) ||
      status.includes(query)
    );
  });

  if (!filtered.length) {
    dom.proxyListContainer.replaceChildren(
      el('div', { className: 'pm-empty-state' }, [
        svgIcon('proxy', 24),
        el(
          'p',
          {},
          proxies.length
            ? 'No proxies match your search filter.'
            : 'No saved proxies yet. Click "Add Proxy" or open Options for bulk import.'
        )
      ])
    );
    return;
  }

  const rows = filtered.map((proxy) => {
    const isActive = appState.activeProfileId === proxy.id;
    const endpoint = `${proxy.host}:${proxy.port}`;
    const showEndpoint = proxy.name !== endpoint;

    const mainBtn = el(
      'button',
      {
        type: 'button',
        className: 'pm-proxy-main',
        title: isActive ? 'Currently active proxy' : `Activate ${proxy.name}`,
        onClick: () => activateProfile(proxy.id)
      },
      [
        createProfileDot(isActive ? STATE_COLORS.proxy : proxy.color || STATE_COLORS.proxy),
        el('div', { className: 'pm-proxy-info' }, [
          el('div', { className: 'pm-proxy-title-row' }, [
            el('span', { className: 'pm-proxy-name' }, proxy.name),
            isActive ? createSemanticBadge('Active', 'success', 'checkPlain') : null
          ]),
          el('div', { className: 'pm-proxy-meta' }, [
            el('span', { className: 'pm-badge pm-badge--neutral' }, (proxy.scheme || 'http').toUpperCase()),
            showEndpoint ? el('span', { className: 'pm-proxy-endpoint' }, endpoint) : null,
            proxy.username
              ? el('span', { title: `Auth: ${proxy.username}`, style: 'display:inline-flex;align-items:center;gap:2px;' }, [
                  svgIcon('lock', 11),
                  'Auth'
                ])
              : null
          ])
        ])
      ]
    );

    const actions = el('div', { className: 'pm-row-actions' }, [
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
          title: 'Test proxy status',
          'aria-label': `Check ${proxy.name}`,
          onClick: async (e) => {
            e.stopPropagation();
            const res = await sendBgMessage('CHECK_PROXY', { profileId: proxy.id });
            appState = res.state;
            renderProxyList();
            if (res.health?.status === 'unknown' && res.health?.error) {
              showToast(dom.toastHost, res.health.error, 'warning');
            }
          }
        },
        svgIcon('refresh', 13)
      ),
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
          title: 'View, copy, or edit proxy',
          'aria-label': `View details for ${proxy.name}`,
          onClick: (e) => {
            e.stopPropagation();
            openDetailModal(proxy);
          }
        },
        svgIcon('eye', 13)
      ),
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
          title: 'Delete proxy',
          'aria-label': `Delete ${proxy.name}`,
          onClick: async (e) => {
            e.stopPropagation();
            if (appState.settings?.confirmDelete && !confirm(`Delete proxy "${proxy.name}"?`)) {
              return;
            }
            const res = await sendBgMessage('DELETE_PROFILE', { profileId: proxy.id });
            appState = res.state;
            await refreshDiagnosticsOnly();
            renderAll();
            setTimeout(fetchPublicIp, 500);
            showToast(dom.toastHost, `Deleted "${proxy.name}".`, 'info');
          }
        },
        svgIcon('trash', 13)
      )
    ]);

    return el(
      'div',
      { className: `pm-proxy-row ${isActive ? 'is-active' : ''}` },
      [
        mainBtn,
        el('div', { className: 'pm-proxy-right' }, [createHealthBadge(proxy.health), actions])
      ]
    );
  });

  dom.proxyListContainer.replaceChildren(...rows);
}

function openDetailModal(proxy) {
  let selectedColor = proxy.color || PROFILE_COLOR_PALETTE[0];
  let showPass = false;

  const nameInput = el('input', { type: 'text', className: 'pm-input pm-input--sm', value: proxy.name });
  const schemeSelect = el('select', { className: 'pm-select pm-select--sm' });
  for (const opt of SCHEME_OPTIONS) {
    schemeSelect.appendChild(el('option', { value: opt.value, selected: opt.value === (proxy.scheme || 'http') }, opt.label));
  }
  const hostInput = el('input', { type: 'text', className: 'pm-input pm-input--sm pm-mono', value: proxy.host });
  const portInput = el('input', { type: 'number', className: 'pm-input pm-input--sm pm-mono', min: '1', max: '65535', value: String(proxy.port) });
  const userInput = el('input', { type: 'text', className: 'pm-input pm-input--sm', value: proxy.username || '' });
  const passInput = el('input', { type: 'password', className: 'pm-input pm-input--sm', value: proxy.password || '' });

  const togglePassBtn = el(
    'button',
    {
      type: 'button',
      className: 'pm-btn pm-btn--sm',
      onClick: () => {
        showPass = !showPass;
        passInput.type = showPass ? 'text' : 'password';
        togglePassBtn.textContent = showPass ? 'Hide' : 'Show';
      }
    },
    'Show'
  );

  const swatchesWrap = el('div', { className: 'pm-color-swatches' });
  const renderSwatches = () => {
    swatchesWrap.replaceChildren(
      ...PROFILE_COLOR_PALETTE.map((color) =>
        el('button', {
          type: 'button',
          className: `pm-swatch ${color === selectedColor ? 'is-selected' : ''}`,
          style: `background-color:${color}`,
          'aria-label': `Color ${color}`,
          onClick: () => {
            selectedColor = color;
            renderSwatches();
          }
        })
      )
    );
  };
  renderSwatches();

  const colonPreview = formatProxyColon(proxy);
  const uriPreview = formatProxyUri(proxy);

  const modal = el('div', { className: 'pm-modal' }, [
    el('div', { className: 'pm-modal__header' }, [
      el('h3', { id: 'detailModalTitle', className: 'pm-modal__title' }, 'Proxy Details & Edit'),
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
          'aria-label': 'Close modal',
          onClick: () => dom.detailModalHost.classList.add('pm-hidden')
        },
        svgIcon('x', 15)
      )
    ]),
    el('div', { className: 'pm-modal__body' }, [
      el('div', { className: 'pm-grid-2' }, [
        el('div', { className: 'pm-field' }, [el('label', {}, 'Label'), nameInput]),
        el('div', { className: 'pm-field' }, [el('label', {}, 'Protocol'), schemeSelect])
      ]),
      el('div', { className: 'pm-grid-2', style: 'margin-top:8px;' }, [
        el('div', { className: 'pm-field' }, [el('label', {}, 'Host / IP'), hostInput]),
        el('div', { className: 'pm-field' }, [el('label', {}, 'Port'), portInput])
      ]),
      el('div', { className: 'pm-grid-2', style: 'margin-top:8px;' }, [
        el('div', { className: 'pm-field' }, [el('label', {}, 'Username'), userInput]),
        el('div', { className: 'pm-field' }, [
          el('label', {}, 'Password'),
          el('div', { style: 'display:flex; gap:5px;' }, [passInput, togglePassBtn])
        ])
      ]),
      el('div', { className: 'pm-field', style: 'margin-top:10px;' }, [
        el('label', {}, 'Badge Color'),
        swatchesWrap
      ]),
      el('div', { className: 'pm-copy-strip' }, [
        el('code', {}, colonPreview),
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--xs',
            onClick: async () => {
              await copyToClipboard(colonPreview);
              showToast(dom.toastHost, 'Copied host:port:user:pass', 'success');
            }
          },
          [svgIcon('copy', 11), 'Copy']
        )
      ]),
      el('div', { className: 'pm-copy-strip' }, [
        el('code', {}, uriPreview),
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--xs',
            onClick: async () => {
              await copyToClipboard(uriPreview);
              showToast(dom.toastHost, 'Copied proxy URI', 'success');
            }
          },
          [svgIcon('copy', 11), 'URI']
        )
      ])
    ]),
    el('div', { className: 'pm-modal__footer' }, [
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--sm',
          onClick: () => dom.detailModalHost.classList.add('pm-hidden')
        },
        'Cancel'
      ),
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--sm pm-btn--primary',
          onClick: async () => {
            try {
              const res = await sendBgMessage('UPSERT_PROXY', {
                proxy: {
                  ...proxy,
                  name: nameInput.value.trim() || `${hostInput.value.trim()}:${portInput.value}`,
                  scheme: schemeSelect.value,
                  host: hostInput.value.trim(),
                  port: parseInt(portInput.value, 10),
                  username: userInput.value.trim(),
                  password: passInput.value,
                  color: selectedColor
                },
                activate: false
              });
              appState = res.state;
              dom.detailModalHost.classList.add('pm-hidden');
              renderAll();
              showToast(dom.toastHost, 'Proxy updated.', 'success');
            } catch (err) {
              showToast(dom.toastHost, err.message, 'danger');
            }
          }
        },
        'Save Changes'
      )
    ])
  ]);

  dom.detailModalHost.replaceChildren(modal);
  dom.detailModalHost.classList.remove('pm-hidden');
}

async function handleSaveQuickProxy(activate) {
  const host = dom.addHostInput.value.trim();
  const port = parseInt(dom.addPortInput.value.trim(), 10);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    showToast(dom.toastHost, 'Please enter a valid host and port (1–65535).', 'danger');
    return;
  }

  try {
    const res = await sendBgMessage('UPSERT_PROXY', {
      proxy: {
        name: dom.addLabelInput.value.trim() || `${host}:${port}`,
        scheme: dom.addSchemeInput.value,
        host,
        port,
        username: dom.addUserInput.value.trim(),
        password: dom.addPassInput.value
      },
      activate
    });
    appState = res.state;
    clearQuickAddInputs();
    dom.quickAddDrawer.classList.add('pm-hidden');
    await refreshDiagnosticsOnly();
    renderAll();
    if (activate) setTimeout(fetchPublicIp, 650);
    showToast(dom.toastHost, activate ? 'Proxy added and activated.' : 'Proxy added to list.', 'success');
  } catch (err) {
    showToast(dom.toastHost, err.message, 'danger');
  }
}

function clearQuickAddInputs() {
  dom.quickParseInput.value = '';
  dom.addSchemeInput.value = 'http';
  dom.addHostInput.value = '';
  dom.addPortInput.value = '';
  dom.addLabelInput.value = '';
  dom.addUserInput.value = '';
  dom.addPassInput.value = '';
  dom.socksAuthHint.classList.add('pm-hidden');
}

async function activateProfile(profileId) {
  try {
    const res = await sendBgMessage('APPLY_PROFILE', { profileId });
    appState = res.state;
    await refreshDiagnosticsOnly();
    renderAll();
    setTimeout(fetchPublicIp, 450);
  } catch (err) {
    showToast(dom.toastHost, err.message, 'danger');
  }
}

async function refreshDiagnosticsOnly() {
  const res = await sendBgMessage('GET_TAB_DIAGNOSTICS');
  tabDiagnostics = res.diagnostics;
}

async function fetchPublicIp() {
  const providerId = appState?.settings?.ipCheckProvider || 'cloudflare';
  dom.currentIpValue.textContent = 'Checking...';
  dom.currentIpValue.className = 'pm-ip-value is-loading';

  const result = await runStandardIpProbe(providerId, 6500);
  if (result.status === 'live' && result.exitIp) {
    currentExitIp = result.exitIp;
    dom.currentIpValue.textContent = result.country
      ? `${result.exitIp} (${result.country})`
      : result.exitIp;
    dom.currentIpValue.className = 'pm-ip-value is-live';
    return;
  }

  currentExitIp = '';
  dom.currentIpValue.textContent = 'Unavailable';
  dom.currentIpValue.className = 'pm-ip-value is-error';
}
