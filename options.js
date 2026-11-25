// options.js — Light-Mode Control Center & ZeroOmega-Inspired Rule Studio

import {
  BUILTIN_PROFILES,
  CONDITION_TYPES,
  DEFAULT_AUTO_SWITCH_ID,
  DEFAULT_BYPASS_LIST,
  PROFILE_COLOR_PALETTE,
  SCHEME_OPTIONS,
  STATE_COLORS,
  createStandardBypassRules,
  generateId,
  getProfileById,
  pickNextColor
} from './shared/models.js';
import {
  formatProxyColon,
  parseProxyBulk
} from './shared/proxy-parser.js';
import {
  compilePacScript,
  matchUrl,
  parseRuleList,
  validateConditionPattern
} from './shared/rule-matcher.js';
import { IP_PROVIDERS } from './shared/ip-probe.js';
import {
  decryptBackupWithPassphrase,
  encryptBackupWithPassphrase
} from './shared/crypto-storage.js';
import { VAULT_STATE_KEY } from './shared/storage.js';
import {
  copyToClipboard,
  createHealthBadge,
  createProfileDot,
  createSemanticBadge,
  el,
  formatRelativeTime,
  sendBgMessage,
  showToast,
  svgIcon
} from './shared/ui-helpers.js';

const dom = {
  extVersion: document.getElementById('extVersion'),
  navProfilesGroup: document.getElementById('navProfilesGroup'),
  navSystemGroup: document.getElementById('navSystemGroup'),
  sidebarStatus: document.getElementById('sidebarStatus'),
  optionsMain: document.getElementById('optionsMain'),
  optionsModalHost: document.getElementById('optionsModalHost'),
  toastHost: document.getElementById('toastHost')
};

let state = null;
let runtime = null;
let currentTab = 'proxies';
let selectedSwitchId = DEFAULT_AUTO_SWITCH_ID;
let selectedPacId = null;
let proxySearchQuery = '';
let showBulkImport = false;
let ruleTesterUrl = 'https://api.github.com/users';
let editRawRules = false;

document.addEventListener('DOMContentLoaded', async () => {
  const manifest = chrome.runtime.getManifest();
  if (manifest?.version) {
    dom.extVersion.textContent = `v${manifest.version}`;
  }

  dom.optionsModalHost.addEventListener('click', (e) => {
    if (e.target === dom.optionsModalHost) {
      dom.optionsModalHost.classList.add('pm-hidden');
    }
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && (changes[VAULT_STATE_KEY] || changes.pmRuntime)) {
      loadAndRender(false);
    }
  });

  const hashTab = location.hash.replace('#', '');
  if (['proxies', 'rules', 'pac', 'temp', 'io', 'general'].includes(hashTab)) {
    currentTab = hashTab;
  }

  await loadAndRender(true);
});

async function loadAndRender() {
  const res = await sendBgMessage('GET_BOOTSTRAP');
  state = res.state;
  runtime = res.runtime;

  if (!state.profiles.some((p) => p.id === selectedSwitchId && p.type === 'switch')) {
    selectedSwitchId = state.profiles.find((p) => p.type === 'switch')?.id || DEFAULT_AUTO_SWITCH_ID;
  }
  const pacProfiles = state.profiles.filter((p) => p.type === 'pac');
  if (!pacProfiles.some((p) => p.id === selectedPacId)) {
    selectedPacId = pacProfiles[0]?.id || null;
  }

  renderSidebar();
  renderMain();
}

function renderSidebar() {
  const proxyCount = state.profiles.filter((p) => p.type === 'fixed').length;
  const switchProfile = state.profiles.find((p) => p.id === selectedSwitchId);
  const ruleCount = switchProfile?.rules?.length || 0;
  const pacCount = state.profiles.filter((p) => p.type === 'pac').length;
  const tempCount = Object.keys(state.tempRules || {}).length;

  const profileNav = [
    { id: 'proxies', label: 'Proxies & Servers', icon: 'proxy', count: proxyCount },
    { id: 'rules', label: 'Auto Switch Rules', icon: 'switch', count: ruleCount },
    { id: 'pac', label: 'PAC Scripts', icon: 'pac', count: pacCount },
    { id: 'temp', label: 'Temp Rules', icon: 'filter', count: tempCount }
  ];

  const systemNav = [
    { id: 'io', label: 'Backup & Export', icon: 'download' },
    { id: 'general', label: 'General & Shortcuts', icon: 'sliders' }
  ];

  const buildNavBtn = (item) =>
    el(
      'button',
      {
        type: 'button',
        className: `pm-nav-item ${currentTab === item.id ? 'is-active' : ''}`,
        onClick: () => {
          currentTab = item.id;
          location.hash = item.id;
          renderSidebar();
          renderMain();
        }
      },
      [
        el('span', { className: 'pm-nav-item__left' }, [
          svgIcon(item.icon, 16),
          el('span', {}, item.label)
        ]),
        item.count !== undefined ? el('span', { className: 'pm-nav-count' }, String(item.count)) : null
      ]
    );

  const monitorLink = el(
    'a',
    {
      href: 'monitor.html',
      target: '_blank',
      className: 'pm-nav-item'
    },
    [
      el('span', { className: 'pm-nav-item__left' }, [
        svgIcon('activity', 16),
        el('span', {}, 'Network Monitor')
      ]),
      svgIcon('external', 13)
    ]
  );

  dom.navProfilesGroup.replaceChildren(...profileNav.map(buildNavBtn));
  dom.navSystemGroup.replaceChildren(...systemNav.map(buildNavBtn), monitorLink);

  const active = getProfileById(state, state.activeProfileId);
  const activeDotColor =
    active.type === 'switch'
      ? STATE_COLORS.autoSwitch
      : active.type === 'fixed' || active.type === 'pac'
        ? STATE_COLORS.proxy
        : STATE_COLORS.noProxy;
  dom.sidebarStatus.replaceChildren(
    el('div', { style: 'display:flex;align-items:center;gap:6px;font-weight:600;color:var(--text-primary);' }, [
      createProfileDot(activeDotColor),
      el('span', {}, `Active: ${active.name}`)
    ])
  );
}

function renderMain() {
  switch (currentTab) {
    case 'proxies':
      renderProxiesTab();
      break;
    case 'rules':
      renderRulesTab();
      break;
    case 'pac':
      renderPacTab();
      break;
    case 'temp':
      renderTempRulesTab();
      break;
    case 'io':
      renderIoTab();
      break;
    case 'general':
      renderGeneralTab();
      break;
    default:
      renderProxiesTab();
  }
}

/* ──────────────────────────────────────────────────────────────
   Tab 1: Proxies & Servers
────────────────────────────────────────────────────────────── */

function renderProxiesTab() {
  const proxies = state.profiles.filter((p) => p.type === 'fixed');
  const filtered = proxies.filter((p) => {
    const q = proxySearchQuery.trim().toLowerCase();
    if (!q) return true;
    return (
      p.name.toLowerCase().includes(q) ||
      p.host.toLowerCase().includes(q) ||
      String(p.port).includes(q) ||
      (p.scheme || '').toLowerCase().includes(q)
    );
  });

  const header = el('div', { className: 'pm-page-header' }, [
    el('div', {}, [
      el('h1', {}, 'Proxies & Servers'),
      el('p', {}, 'Manage HTTP, HTTPS, SOCKS4, and SOCKS5 proxy servers, credentials, and bypass lists.')
    ]),
    el('div', { className: 'pm-page-actions' }, [
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--sm',
          onClick: () => {
            showBulkImport = !showBulkImport;
            renderProxiesTab();
          }
        },
        [svgIcon('upload', 14), showBulkImport ? 'Hide Bulk Import' : 'Bulk Import']
      ),
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--sm',
          onClick: async () => {
            showToast(dom.toastHost, 'Checking proxies...', 'processing', 0);
            const res = await sendBgMessage('CHECK_ALL_PROXIES');
            state = res.state;
            renderProxiesTab();
            showToast(
              dom.toastHost,
              res.results.length
                ? `Checked ${res.results.length} proxy server(s).`
                : 'No saved proxy servers to check.',
              res.results.length ? 'success' : 'info'
            );
          }
        },
        [svgIcon('activity', 14), 'Check All']
      ),
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--sm pm-btn--primary',
          onClick: () => openProxyEditorModal(null)
        },
        [svgIcon('plus', 14), 'New Proxy']
      )
    ])
  ]);

  const blocks = [header];

  if (showBulkImport) {
    const bulkTextarea = el('textarea', {
      rows: 5,
      className: 'pm-textarea pm-mono',
      placeholder:
        'Paste one proxy per line:\n103.10.10.5:8080:user:pass\nsocks5://user:pass@127.0.0.1:1080|Local Tunnel\n192.168.1.50:3128'
    });
    const previewLabel = el('span', { className: 'pm-help' }, 'Supports ip:port:user:pass, user:pass@ip:port, scheme://..., and optional |Label.');

    bulkTextarea.addEventListener('input', () => {
      const parsed = parseProxyBulk(bulkTextarea.value);
      previewLabel.textContent = `Detected ${parsed.valid.length} valid proxy line(s), ${parsed.invalidLines.length} invalid.`;
    });

    blocks.push(
      el('section', { className: 'pm-card pm-section' }, [
        el('div', { className: 'pm-section__header' }, [
          el('div', {}, [
            el('h2', { className: 'pm-section__title' }, 'Bulk Proxy Import'),
            el('p', { className: 'pm-section__desc' }, 'Import multiple proxies at once without duplicating existing endpoints.')
          ])
        ]),
        bulkTextarea,
        el('div', { style: 'display:flex;justify-content:space-between;align-items:center;margin-top:10px;gap:12px;' }, [
          previewLabel,
          el(
            'button',
            {
              type: 'button',
              className: 'pm-btn pm-btn--sm pm-btn--primary',
              onClick: async () => {
                try {
                  const res = await sendBgMessage('BULK_IMPORT_PROXIES', { text: bulkTextarea.value });
                  state = res.state;
                  showBulkImport = false;
                  renderSidebar();
                  renderProxiesTab();
                  showToast(
                    dom.toastHost,
                    `Imported ${res.added} new, ${res.updated} updated (${res.invalidCount} skipped).`,
                    'success'
                  );
                } catch (err) {
                  showToast(dom.toastHost, err.message, 'danger');
                }
              }
            },
            'Import Proxies'
          )
        ])
      ])
    );
  }

  const searchInput = el('input', {
    type: 'search',
    className: 'pm-input pm-input--sm',
    style: 'max-width:300px;',
    value: proxySearchQuery,
    placeholder: 'Search by label, host, port, or protocol...'
  });
  searchInput.addEventListener('input', () => {
    proxySearchQuery = searchInput.value;
    renderProxiesTab();
  });

  const rows = filtered.map((proxy) => {
    const isActive = state.activeProfileId === proxy.id;
    return el('tr', { className: isActive ? 'is-active-row' : '' }, [
      el('td', {}, [
        el('div', { style: 'display:flex;align-items:center;gap:8px;' }, [
          createProfileDot(proxy.color),
          el('strong', {}, proxy.name),
          isActive ? createSemanticBadge('Active', 'info', 'checkPlain') : null
        ])
      ]),
      el('td', {}, el('span', { className: 'pm-badge pm-badge--neutral' }, (proxy.scheme || 'http').toUpperCase())),
      el('td', { className: 'pm-mono' }, `${proxy.host}:${proxy.port}`),
      el(
        'td',
        {},
        proxy.username
          ? el('span', { style: 'display:inline-flex;align-items:center;gap:4px;' }, [
              svgIcon('lock', 12),
              proxy.username
            ])
          : el('span', { style: 'color:var(--text-muted);' }, 'None')
      ),
      el('td', {}, createHealthBadge(proxy.health)),
      el('td', {}, [
        el('div', { className: 'pm-row-actions' }, [
          el(
            'button',
            {
              type: 'button',
              className: `pm-btn pm-btn--xs ${isActive ? 'pm-btn--primary' : ''}`,
              onClick: async () => {
                const res = await sendBgMessage('APPLY_PROFILE', { profileId: proxy.id, refreshTab: false });
                state = res.state;
                renderSidebar();
                renderProxiesTab();
                showToast(dom.toastHost, `Activated "${proxy.name}".`, 'success');
              }
            },
            isActive ? 'Active' : 'Use'
          ),
          el(
            'button',
            {
              type: 'button',
              className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
              title: 'Test proxy',
              'aria-label': `Test ${proxy.name}`,
              onClick: async () => {
                const res = await sendBgMessage('CHECK_PROXY', { profileId: proxy.id });
                state = res.state;
                renderProxiesTab();
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
              title: 'Copy proxy string',
              'aria-label': `Copy ${proxy.name}`,
              onClick: async () => {
                await copyToClipboard(formatProxyColon(proxy));
                showToast(dom.toastHost, 'Copied proxy string.', 'success');
              }
            },
            svgIcon('copy', 13)
          ),
          el(
            'button',
            {
              type: 'button',
              className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
              title: 'Edit proxy',
              'aria-label': `Edit ${proxy.name}`,
              onClick: () => openProxyEditorModal(proxy)
            },
            svgIcon('pencil', 13)
          ),
          el(
            'button',
            {
              type: 'button',
              className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
              title: 'Delete proxy',
              'aria-label': `Delete ${proxy.name}`,
              onClick: async () => {
                if (state.settings?.confirmDelete && !confirm(`Delete "${proxy.name}"?`)) return;
                const res = await sendBgMessage('DELETE_PROFILE', { profileId: proxy.id });
                state = res.state;
                renderSidebar();
                renderProxiesTab();
                showToast(dom.toastHost, `Deleted "${proxy.name}".`, 'info');
              }
            },
            svgIcon('trash', 13)
          )
        ])
      ])
    ]);
  });

  blocks.push(
    el('section', { className: 'pm-card pm-section' }, [
      el('div', { className: 'pm-section__header' }, [
        el('div', {}, [
          el('h2', { className: 'pm-section__title' }, `Saved Proxy Profiles (${filtered.length})`)
        ]),
        searchInput
      ]),
      filtered.length
        ? el('div', { className: 'pm-table-wrap' }, [
            el('table', { className: 'pm-table' }, [
              el('thead', {}, [
                el('tr', {}, [
                  el('th', {}, 'Label'),
                  el('th', {}, 'Protocol'),
                  el('th', {}, 'Server'),
                  el('th', {}, 'Auth'),
                  el('th', {}, 'Health'),
                  el('th', {}, 'Actions')
                ])
              ]),
              el('tbody', {}, rows)
            ])
          ])
        : el('p', { className: 'pm-help', style: 'padding:16px 0;text-align:center;' }, 'No proxy profiles found.')
    ])
  );

  dom.optionsMain.replaceChildren(...blocks);
}

function openProxyEditorModal(proxy) {
  const isNew = !proxy;
  const draft = proxy
    ? structuredClone(proxy)
    : {
        name: '',
        scheme: 'http',
        host: '',
        port: '',
        username: '',
        password: '',
        color: pickNextColor(state.profiles),
        bypassList: [...DEFAULT_BYPASS_LIST],
        notes: ''
      };

  const nameInput = el('input', { type: 'text', className: 'pm-input', value: draft.name, placeholder: 'e.g. US Residential 1' });
  const schemeSelect = el('select', { className: 'pm-select' });
  for (const s of SCHEME_OPTIONS) {
    schemeSelect.appendChild(el('option', { value: s.value, selected: s.value === draft.scheme }, s.label));
  }
  const hostInput = el('input', { type: 'text', className: 'pm-input pm-mono', value: draft.host, placeholder: '127.0.0.1' });
  const portInput = el('input', { type: 'number', className: 'pm-input pm-mono', min: '1', max: '65535', value: String(draft.port || ''), placeholder: '8080' });
  const userInput = el('input', { type: 'text', className: 'pm-input', value: draft.username || '' });
  const passInput = el('input', { type: 'password', className: 'pm-input', value: draft.password || '' });
  const bypassArea = el('textarea', { rows: 4, className: 'pm-textarea pm-mono' }, (draft.bypassList || DEFAULT_BYPASS_LIST).join('\n'));
  const notesInput = el('input', { type: 'text', className: 'pm-input', value: draft.notes || '', placeholder: 'Optional notes...' });

  const socksNote = el(
    'div',
    { className: 'pm-alert pm-alert--warning pm-hidden', style: 'margin-top:8px;' },
    [svgIcon('warning', 14), el('span', {}, 'Chromium does not support username/password auth on SOCKS4/SOCKS5 proxies.')]
  );

  const checkSocks = () => {
    const isSocks = schemeSelect.value === 'socks4' || schemeSelect.value === 'socks5';
    const hasAuth = Boolean(userInput.value.trim() || passInput.value);
    socksNote.classList.toggle('pm-hidden', !(isSocks && hasAuth));
  };
  schemeSelect.addEventListener('change', checkSocks);
  userInput.addEventListener('input', checkSocks);
  passInput.addEventListener('input', checkSocks);
  checkSocks();

  const swatchesWrap = el('div', { className: 'pm-color-swatches' });
  const renderSwatches = () => {
    swatchesWrap.replaceChildren(
      ...PROFILE_COLOR_PALETTE.map((color) =>
        el('button', {
          type: 'button',
          className: `pm-swatch ${color === draft.color ? 'is-selected' : ''}`,
          style: `background-color:${color}`,
          onClick: () => {
            draft.color = color;
            renderSwatches();
          }
        })
      )
    );
  };
  renderSwatches();

  dom.optionsModalHost.replaceChildren(
    el('div', { className: 'pm-modal', style: 'max-width:520px;' }, [
      el('div', { className: 'pm-modal__header' }, [
        el('h3', { className: 'pm-modal__title' }, isNew ? 'New Proxy Profile' : `Edit: ${draft.name}`),
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
            onClick: () => dom.optionsModalHost.classList.add('pm-hidden')
          },
          svgIcon('x', 15)
        )
      ]),
      el('div', { className: 'pm-modal__body' }, [
        el('div', { className: 'pm-form-grid' }, [
          el('div', { className: 'pm-field' }, [el('label', {}, 'Profile Name'), nameInput]),
          el('div', { className: 'pm-field' }, [el('label', {}, 'Protocol'), schemeSelect]),
          el('div', { className: 'pm-field' }, [el('label', {}, 'Server Host / IP'), hostInput]),
          el('div', { className: 'pm-field' }, [el('label', {}, 'Port'), portInput]),
          el('div', { className: 'pm-field' }, [el('label', {}, 'Username (optional)'), userInput]),
          el('div', { className: 'pm-field' }, [el('label', {}, 'Password (optional)'), passInput])
        ]),
        socksNote,
        el('div', { className: 'pm-field', style: 'margin-top:10px;' }, [el('label', {}, 'Color Badge'), swatchesWrap]),
        el('div', { className: 'pm-field', style: 'margin-top:10px;' }, [
          el('label', {}, 'Bypass List (one host, CIDR, or wildcard per line)'),
          bypassArea
        ]),
        el('div', { className: 'pm-field', style: 'margin-top:10px;' }, [el('label', {}, 'Notes'), notesInput])
      ]),
      el('div', { className: 'pm-modal__footer' }, [
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--sm',
            onClick: () => dom.optionsModalHost.classList.add('pm-hidden')
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
                const bypassList = bypassArea.value
                  .split(/\r?\n/)
                  .map((l) => l.trim())
                  .filter(Boolean);
                const res = await sendBgMessage('UPSERT_PROXY', {
                  proxy: {
                    ...draft,
                    name: nameInput.value.trim() || `${hostInput.value.trim()}:${portInput.value}`,
                    scheme: schemeSelect.value,
                    host: hostInput.value.trim(),
                    port: parseInt(portInput.value, 10),
                    username: userInput.value.trim(),
                    password: passInput.value,
                    bypassList: bypassList.length ? bypassList : [...DEFAULT_BYPASS_LIST],
                    notes: notesInput.value.trim()
                  },
                  activate: false
                });
                state = res.state;
                dom.optionsModalHost.classList.add('pm-hidden');
                renderSidebar();
                renderProxiesTab();
                showToast(dom.toastHost, 'Proxy profile saved.', 'success');
              } catch (err) {
                showToast(dom.toastHost, err.message, 'danger');
              }
            }
          },
          'Save Profile'
        )
      ])
    ])
  );
  dom.optionsModalHost.classList.remove('pm-hidden');
}

/* ──────────────────────────────────────────────────────────────
   Tab 2: Auto Switch Rules (ZeroOmega Core)
────────────────────────────────────────────────────────────── */

function renderRulesTab() {
  const switchProfiles = state.profiles.filter((p) => p.type === 'switch');
  const activeSwitch = switchProfiles.find((p) => p.id === selectedSwitchId) || switchProfiles[0];
  if (!activeSwitch) return;

  const isCurrentlyActive = state.activeProfileId === activeSwitch.id;
  const targetChoices = [
    BUILTIN_PROFILES.direct,
    ...state.profiles.filter((p) => p.id !== activeSwitch.id)
  ];

  const profileSelect = el('select', { className: 'pm-select pm-select--sm', style: 'width:auto;min-width:170px;' });
  for (const sw of switchProfiles) {
    profileSelect.appendChild(el('option', { value: sw.id, selected: sw.id === activeSwitch.id }, sw.name));
  }
  profileSelect.addEventListener('change', () => {
    selectedSwitchId = profileSelect.value;
    renderSidebar();
    renderRulesTab();
  });

  const header = el('div', { className: 'pm-page-header' }, [
    el('div', {}, [
      el('h1', {}, 'Auto Switch Rules'),
      el('p', {}, 'Evaluate ordered host, URL, CIDR, and rule-list conditions to route each site automatically.')
    ]),
    el('div', { className: 'pm-page-actions' }, [
      profileSelect,
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--sm',
          onClick: async () => {
            const name = prompt('New Auto Switch profile name:', `Switch ${switchProfiles.length + 1}`);
            if (!name || !name.trim()) return;
            const createdId = generateId('switch');
            const firstFixed = state.profiles.find((p) => p.type === 'fixed');
            const res = await sendBgMessage('UPSERT_PROFILE_GENERIC', {
              profile: {
                id: createdId,
                name: name.trim(),
                type: 'switch',
                color: STATE_COLORS.autoSwitch,
                defaultProfileId: firstFixed?.id || 'direct',
                rules: createStandardBypassRules(),
                ruleList: { enabled: false, format: 'autoproxy', url: '', text: '', matchProfileId: 'direct' }
              }
            });
            state = res.state;
            selectedSwitchId = createdId;
            renderSidebar();
            renderRulesTab();
          }
        },
        [svgIcon('plus', 13), 'New Switch Profile']
      ),
      el(
        'button',
        {
          type: 'button',
          className: `pm-btn pm-btn--sm ${isCurrentlyActive ? 'pm-btn--primary' : ''}`,
          onClick: async () => {
            const res = await sendBgMessage('APPLY_PROFILE', { profileId: activeSwitch.id, refreshTab: false });
            state = res.state;
            renderSidebar();
            renderRulesTab();
            showToast(dom.toastHost, `Activated "${activeSwitch.name}".`, 'success');
          }
        },
        isCurrentlyActive ? 'Currently Active' : `Activate ${activeSwitch.name}`
      )
    ])
  ]);

  // Live URL Tester Card
  const testerInput = el('input', {
    type: 'text',
    className: 'pm-input pm-input--sm pm-mono',
    value: ruleTesterUrl,
    placeholder: 'https://example.com/path'
  });
  const testerOutput = el('div', { className: 'pm-tester-result' });

  const runRuleTest = () => {
    ruleTesterUrl = testerInput.value;
    const result = matchUrl(ruleTesterUrl, state, activeSwitch.id);
    const resolved = result.resolvedProfile;
    const rule = result.matchedRule;
    testerOutput.replaceChildren(
      el('div', { style: 'display:flex;align-items:center;gap:8px;' }, [
        el('span', { style: 'font-weight:600;' }, 'Resolved Route:'),
        createProfileDot(resolved.color),
        createSemanticBadge(resolved.name, resolved.id === 'direct' ? 'neutral' : 'info')
      ]),
      el(
        'div',
        { className: 'pm-help', style: 'margin:0;' },
        rule ? `Matched ${rule.source}: ${rule.pattern} (${rule.conditionType})` : 'No condition matched — using Default profile'
      )
    );
  };
  testerInput.addEventListener('input', runRuleTest);
  runRuleTest();

  const testerCard = el('section', { className: 'pm-card pm-section' }, [
    el('div', { className: 'pm-section__header' }, [
      el('div', {}, [
        el('h2', { className: 'pm-section__title' }, 'Live URL Rule Tester'),
        el('p', { className: 'pm-section__desc' }, 'Test how any URL resolves against temporary rules, switch rules, and attached rule lists.')
      ])
    ]),
    testerInput,
    testerOutput
  ]);

  // Rules Table Card
  const saveSwitchChanges = async (updatedSwitch, msg = 'Switch rules saved.') => {
    const res = await sendBgMessage('UPSERT_PROFILE_GENERIC', { profile: updatedSwitch });
    state = res.state;
    renderSidebar();
    renderRulesTab();
    showToast(dom.toastHost, msg, 'success');
  };

  const hasHttpsPathRules = (activeSwitch.rules || []).some(
    (r) => r.enabled !== false && (r.conditionType === 'urlWildcard' || r.conditionType === 'urlRegex' || r.conditionType === 'keyword')
  );

  let rulesBodyNode;
  if (editRawRules) {
    const sourceLines = (activeSwitch.rules || []).map(
      (r) => `${r.conditionType} | ${r.pattern} | ${r.profileId} | ${r.note || ''}`
    );
    const rawArea = el('textarea', {
      rows: 10,
      className: 'pm-textarea pm-mono',
      placeholder: 'hostWildcard | *.github.com | direct | Dev traffic'
    }, sourceLines.join('\n'));

    rulesBodyNode = el('div', {}, [
      el('p', { className: 'pm-help', style: 'margin-bottom:8px;' }, 'Format: conditionType | pattern | profileId | optional note (one rule per line).'),
      rawArea,
      el('div', { style: 'display:flex;justify-content:flex-end;gap:8px;margin-top:10px;' }, [
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--sm pm-btn--primary',
            onClick: async () => {
              const parsedRules = [];
              for (const raw of rawArea.value.split(/\r?\n/)) {
                const line = raw.trim();
                if (!line || line.startsWith('#')) continue;
                const [ct, pat, pid, ...noteParts] = line.split('|').map((s) => s.trim());
                if (!pat) continue;
                parsedRules.push({
                  id: generateId('rule'),
                  enabled: true,
                  conditionType: CONDITION_TYPES.some((c) => c.value === ct) ? ct : 'hostWildcard',
                  pattern: pat,
                  profileId: pid || 'direct',
                  note: noteParts.join(' | ')
                });
              }
              const copy = structuredClone(activeSwitch);
              copy.rules = parsedRules;
              editRawRules = false;
              await saveSwitchChanges(copy, `Saved ${parsedRules.length} rule(s) from source.`);
            }
          },
          'Apply Source'
        )
      ])
    ]);
  } else {
    const ruleRows = (activeSwitch.rules || []).map((rule, idx) => {
      const enabledCb = el('input', { type: 'checkbox', checked: rule.enabled !== false, 'aria-label': 'Enable rule' });
      enabledCb.addEventListener('change', () => {
        rule.enabled = enabledCb.checked;
      });

      const typeSel = el('select', { className: 'pm-select pm-select--sm', 'aria-label': 'Condition type' });
      for (const ct of CONDITION_TYPES) {
        typeSel.appendChild(el('option', { value: ct.value, selected: ct.value === rule.conditionType }, ct.label));
      }

      const patInput = el('input', {
        type: 'text',
        className: 'pm-input pm-input--sm pm-mono',
        value: rule.pattern || '',
        placeholder: '*.example.com'
      });

      const errHint = el('div', { style: 'font-size:11px;color:var(--tone-danger-fg);margin-top:2px;' });
      const validatePat = () => {
        const msg = validateConditionPattern(typeSel.value, patInput.value);
        errHint.textContent = msg || '';
      };
      typeSel.addEventListener('change', () => {
        rule.conditionType = typeSel.value;
        validatePat();
      });
      patInput.addEventListener('input', () => {
        rule.pattern = patInput.value;
        validatePat();
        runRuleTest();
      });
      validatePat();

      const targetSel = el('select', { className: 'pm-select pm-select--sm', 'aria-label': 'Result profile' });
      for (const t of targetChoices) {
        targetSel.appendChild(el('option', { value: t.id, selected: t.id === rule.profileId }, t.name));
      }
      targetSel.addEventListener('change', () => {
        rule.profileId = targetSel.value;
      });

      const noteInput = el('input', {
        type: 'text',
        className: 'pm-input pm-input--sm',
        value: rule.note || '',
        placeholder: 'Note...'
      });
      noteInput.addEventListener('input', () => {
        rule.note = noteInput.value;
      });

      return el('tr', {}, [
        el('td', { style: 'text-align:center;' }, enabledCb),
        el('td', {}, typeSel),
        el('td', {}, [patInput, errHint]),
        el('td', {}, targetSel),
        el('td', {}, noteInput),
        el('td', {}, [
          el('div', { className: 'pm-row-actions' }, [
            el(
              'button',
              {
                type: 'button',
                className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
                disabled: idx === 0,
                title: 'Move up',
                onClick: () => {
                  const arr = activeSwitch.rules;
                  [arr[idx - 1], arr[idx]] = [arr[idx], arr[idx - 1]];
                  renderRulesTab();
                }
              },
              svgIcon('arrowUp', 13)
            ),
            el(
              'button',
              {
                type: 'button',
                className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
                disabled: idx === activeSwitch.rules.length - 1,
                title: 'Move down',
                onClick: () => {
                  const arr = activeSwitch.rules;
                  [arr[idx + 1], arr[idx]] = [arr[idx], arr[idx + 1]];
                  renderRulesTab();
                }
              },
              svgIcon('arrowDown', 13)
            ),
            el(
              'button',
              {
                type: 'button',
                className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
                title: 'Clone rule',
                onClick: () => {
                  activeSwitch.rules.splice(idx + 1, 0, { ...structuredClone(rule), id: generateId('rule') });
                  renderRulesTab();
                }
              },
              svgIcon('copy', 13)
            ),
            el(
              'button',
              {
                type: 'button',
                className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
                title: 'Delete rule',
                onClick: () => {
                  activeSwitch.rules.splice(idx, 1);
                  renderRulesTab();
                }
              },
              svgIcon('trash', 13)
            )
          ])
        ])
      ]);
    });

    const defaultSelect = el('select', { className: 'pm-select pm-select--sm', style: 'max-width:240px;' });
    for (const t of targetChoices) {
      defaultSelect.appendChild(el('option', { value: t.id, selected: t.id === activeSwitch.defaultProfileId }, t.name));
    }
    defaultSelect.addEventListener('change', () => {
      activeSwitch.defaultProfileId = defaultSelect.value;
    });

    rulesBodyNode = el('div', {}, [
      hasHttpsPathRules
        ? el('div', { className: 'pm-alert pm-alert--warning', style: 'margin-bottom:10px;' }, [
            svgIcon('warning', 14),
            el('span', {}, 'Note: Browsers strip full HTTPS paths when evaluating PAC rules; Host Wildcard or Host Regex is recommended for HTTPS.')
          ])
        : null,
      el('div', { className: 'pm-table-wrap' }, [
        el('table', { className: 'pm-table' }, [
          el('thead', {}, [
            el('tr', {}, [
              el('th', { style: 'width:40px;' }, 'On'),
              el('th', { style: 'width:140px;' }, 'Condition Type'),
              el('th', {}, 'Pattern'),
              el('th', { style: 'width:165px;' }, 'Profile'),
              el('th', { style: 'width:130px;' }, 'Note'),
              el('th', { style: 'width:120px;' }, 'Actions')
            ])
          ]),
          el('tbody', {}, [
            ...ruleRows,
            el('tr', { style: 'background:var(--bg-subtle);' }, [
              el('td', {}),
              el('td', { colSpan: 2 }, el('strong', {}, 'Default Fallback (when no rules match)')),
              el('td', { colSpan: 3 }, defaultSelect)
            ])
          ])
        ])
      ]),
      el('div', { style: 'display:flex;justify-content:space-between;align-items:center;margin-top:12px;' }, [
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--sm',
            onClick: () => {
              activeSwitch.rules.push({
                id: generateId('rule'),
                enabled: true,
                conditionType: 'hostWildcard',
                pattern: '*.example.com',
                profileId: targetChoices.find((t) => t.type === 'fixed')?.id || 'direct',
                note: ''
              });
              renderRulesTab();
            }
          },
          [svgIcon('plus', 13), 'Add Condition']
        ),
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--sm pm-btn--primary',
            onClick: () => saveSwitchChanges(activeSwitch)
          },
          'Save Rules'
        )
      ])
    ]);
  }

  const rulesCard = el('section', { className: 'pm-card pm-section' }, [
    el('div', { className: 'pm-section__header' }, [
      el('div', {}, [
        el('h2', { className: 'pm-section__title' }, 'Switch Conditions'),
        el('p', { className: 'pm-section__desc' }, 'Rules are evaluated from top to bottom. Use *.domain.com to match both domain and subdomains, or **.domain.com for subdomains only.')
      ]),
      el('div', { className: 'pm-row-actions' }, [
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--sm',
            title: 'Bypass LAN/localhost to Direct and route all other traffic via Proxy',
            onClick: async () => {
              const firstFixed = targetChoices.find((t) => t.type === 'fixed');
              const copy = structuredClone(activeSwitch);
              copy.rules = createStandardBypassRules();
              copy.defaultProfileId = firstFixed?.id || 'direct';
              editRawRules = false;
              await saveSwitchChanges(
                copy,
                firstFixed
                  ? `Applied standard preset: Bypass LAN → Direct, All else → ${firstFixed.name}.`
                  : 'Applied standard LAN bypass rules (add a proxy to set as default).'
              );
            }
          },
          'Preset: Proxy + LAN Bypass'
        ),
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--sm',
            title: 'Direct by default; only matched rules use a proxy',
            onClick: async () => {
              const copy = structuredClone(activeSwitch);
              copy.rules = createStandardBypassRules();
              copy.defaultProfileId = 'direct';
              editRawRules = false;
              await saveSwitchChanges(copy, 'Applied preset: Direct by default + LAN bypass.');
            }
          },
          'Preset: Direct Default'
        ),
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--sm',
            onClick: () => {
              editRawRules = !editRawRules;
              renderRulesTab();
            }
          },
          editRawRules ? 'Table View' : 'Edit Raw Source'
        )
      ])
    ]),
    rulesBodyNode
  ]);

  // Attached Rule List Card (ZeroOmega style)
  const rl = activeSwitch.ruleList || {
    enabled: false,
    format: 'autoproxy',
    url: '',
    text: '',
    matchProfileId: 'direct'
  };

  const rlEnableCb = el('input', { type: 'checkbox', checked: Boolean(rl.enabled) });
  const rlFormatSel = el('select', { className: 'pm-select pm-select--sm' }, [
    el('option', { value: 'autoproxy', selected: rl.format !== 'switchy' }, 'AutoProxy (GFWList / ||domain)'),
    el('option', { value: 'switchy', selected: rl.format === 'switchy' }, 'Switchy Format')
  ]);
  const rlMatchSel = el('select', { className: 'pm-select pm-select--sm' });
  for (const t of targetChoices) {
    rlMatchSel.appendChild(el('option', { value: t.id, selected: t.id === rl.matchProfileId }, t.name));
  }
  const rlUrlInput = el('input', {
    type: 'url',
    className: 'pm-input pm-input--sm',
    value: rl.url || '',
    placeholder: 'https://example.com/rules.txt (leave blank to edit text below)'
  });
  const rlTextArea = el('textarea', {
    rows: 6,
    className: 'pm-textarea pm-mono',
    placeholder: '||example.com\n@@||internal.example.com'
  }, rl.text || '');

  const parsedPreviewCount = parseRuleList(rlTextArea.value, rlFormatSel.value, rlMatchSel.value).length;

  const ruleListCard = el('section', { className: 'pm-card pm-section' }, [
    el('div', { className: 'pm-section__header' }, [
      el('div', {}, [
        el('h2', { className: 'pm-section__title' }, 'Attached Rule List'),
        el('p', { className: 'pm-section__desc' }, 'Import and auto-update AutoProxy or Switchy rule lists.')
      ]),
      el('label', { className: 'pm-switch', title: 'Enable attached rule list' }, [
        rlEnableCb,
        el('span', { className: 'pm-switch__track' })
      ])
    ]),
    el('div', { className: 'pm-form-grid' }, [
      el('div', { className: 'pm-field' }, [el('label', {}, 'Format'), rlFormatSel]),
      el('div', { className: 'pm-field' }, [el('label', {}, 'Match Profile'), rlMatchSel])
    ]),
    el('div', { className: 'pm-field', style: 'margin-top:10px;' }, [
      el('label', {}, 'Rule List URL (optional)'),
      el('div', { style: 'display:flex;gap:8px;' }, [
        rlUrlInput,
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--sm',
            onClick: async () => {
              const copy = structuredClone(activeSwitch);
              copy.ruleList = {
                ...rl,
                enabled: true,
                format: rlFormatSel.value,
                matchProfileId: rlMatchSel.value,
                url: rlUrlInput.value.trim(),
                text: rlTextArea.value
              };
              await saveSwitchChanges(copy, 'Saving URL and downloading...');
              await sendBgMessage('REFRESH_ONLINE_RULES');
              await loadAndRender();
              showToast(dom.toastHost, 'Rule list downloaded.', 'success');
            }
          },
          [svgIcon('download', 13), 'Download Now']
        )
      ])
    ]),
    el('div', { className: 'pm-field', style: 'margin-top:10px;' }, [
      el('label', {}, `Rule List Content (${parsedPreviewCount} parsed rules${rl.lastUpdated ? ` · updated ${formatRelativeTime(rl.lastUpdated)}` : ''})`),
      rlTextArea
    ]),
    rl.error
      ? el('div', { className: 'pm-alert pm-alert--danger', style: 'margin-top:8px;' }, [
          svgIcon('error', 14),
          el('span', {}, `Last download error: ${rl.error}`)
        ])
      : null,
    el('div', { style: 'display:flex;justify-content:flex-end;margin-top:10px;' }, [
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--sm pm-btn--primary',
          onClick: async () => {
            const copy = structuredClone(activeSwitch);
            copy.ruleList = {
              ...rl,
              enabled: rlEnableCb.checked,
              format: rlFormatSel.value,
              matchProfileId: rlMatchSel.value,
              url: rlUrlInput.value.trim(),
              text: rlTextArea.value
            };
            await saveSwitchChanges(copy, 'Rule list settings saved.');
          }
        },
        'Save Rule List'
      )
    ])
  ]);

  dom.optionsMain.replaceChildren(header, testerCard, rulesCard, ruleListCard);
}

/* ──────────────────────────────────────────────────────────────
   Tab 3: PAC Scripts
────────────────────────────────────────────────────────────── */

function renderPacTab() {
  const pacProfiles = state.profiles.filter((p) => p.type === 'pac');
  const activePac = pacProfiles.find((p) => p.id === selectedPacId) || pacProfiles[0] || null;

  const createPacProfile = async () => {
    const name = prompt('PAC Profile Name:', `PAC Profile ${pacProfiles.length + 1}`);
    if (!name || !name.trim()) return;
    const id = generateId('pac');
    const res = await sendBgMessage('UPSERT_PROFILE_GENERIC', {
      profile: {
        id,
        name: name.trim(),
        type: 'pac',
        color: '#0891B2',
        pacUrl: '',
        pacScript: 'function FindProxyForURL(url, host) {\n  if (shExpMatch(host, "*.example.com")) {\n    return "PROXY 127.0.0.1:8080";\n  }\n  return "DIRECT";\n}',
        auth: { username: '', password: '' }
      }
    });
    state = res.state;
    selectedPacId = id;
    renderSidebar();
    renderPacTab();
  };

  const pacSelect = el('select', { className: 'pm-select pm-select--sm', style: 'width:auto;min-width:170px;' });
  for (const p of pacProfiles) {
    pacSelect.appendChild(el('option', { value: p.id, selected: activePac && p.id === activePac.id }, p.name));
  }
  pacSelect.addEventListener('change', () => {
    selectedPacId = pacSelect.value;
    renderPacTab();
  });

  const header = el('div', { className: 'pm-page-header' }, [
    el('div', {}, [
      el('h1', {}, 'PAC Scripts'),
      el('p', {}, 'Run custom Proxy Auto-Config (FindProxyForURL) scripts or fetch scripts from an online URL.')
    ]),
    el('div', { className: 'pm-page-actions' }, [
      pacProfiles.length ? pacSelect : null,
      el(
        'button',
        { type: 'button', className: 'pm-btn pm-btn--sm pm-btn--primary', onClick: createPacProfile },
        [svgIcon('plus', 13), 'New PAC Profile']
      )
    ])
  ]);

  if (!activePac) {
    dom.optionsMain.replaceChildren(
      header,
      el('section', { className: 'pm-card pm-section', style: 'text-align:center;padding:36px;' }, [
        svgIcon('pac', 28),
        el('p', { style: 'margin:10px 0 14px;color:var(--text-secondary);' }, 'No custom PAC Script profiles yet.'),
        el(
          'button',
          { type: 'button', className: 'pm-btn pm-btn--sm pm-btn--primary', onClick: createPacProfile },
          'Create PAC Profile'
        )
      ])
    );
    return;
  }

  const nameInput = el('input', { type: 'text', className: 'pm-input pm-input--sm', value: activePac.name });
  const pacUrlInput = el('input', {
    type: 'url',
    className: 'pm-input pm-input--sm',
    value: activePac.pacUrl || '',
    placeholder: 'https://example.com/proxy.pac (optional)'
  });
  const pacArea = el('textarea', { rows: 12, className: 'pm-textarea pm-mono' }, activePac.pacScript || '');
  const authUser = el('input', { type: 'text', className: 'pm-input pm-input--sm', value: activePac.auth?.username || '' });
  const authPass = el('input', { type: 'password', className: 'pm-input pm-input--sm', value: activePac.auth?.password || '' });

  const isCurrentlyActive = state.activeProfileId === activePac.id;

  dom.optionsMain.replaceChildren(
    header,
    el('section', { className: 'pm-card pm-section' }, [
      el('div', { className: 'pm-section__header' }, [
        el('div', {}, [
          el('h2', { className: 'pm-section__title' }, activePac.name),
          activePac.lastUpdated
            ? el('p', { className: 'pm-section__desc' }, `Last downloaded: ${new Date(activePac.lastUpdated).toLocaleString()}`)
            : null
        ]),
        el('div', { className: 'pm-row-actions' }, [
          el(
            'button',
            {
              type: 'button',
              className: `pm-btn pm-btn--sm ${isCurrentlyActive ? 'pm-btn--primary' : ''}`,
              onClick: async () => {
                const res = await sendBgMessage('APPLY_PROFILE', { profileId: activePac.id, refreshTab: false });
                state = res.state;
                renderSidebar();
                renderPacTab();
                showToast(dom.toastHost, `Activated "${activePac.name}".`, 'success');
              }
            },
            isCurrentlyActive ? 'Currently Active' : 'Activate'
          ),
          el(
            'button',
            {
              type: 'button',
              className: 'pm-btn pm-btn--sm pm-btn--danger',
              onClick: async () => {
                if (!confirm(`Delete PAC profile "${activePac.name}"?`)) return;
                const res = await sendBgMessage('DELETE_PROFILE', { profileId: activePac.id });
                state = res.state;
                selectedPacId = null;
                renderSidebar();
                renderPacTab();
              }
            },
            [svgIcon('trash', 13), 'Delete']
          )
        ])
      ]),
      el('div', { className: 'pm-form-grid' }, [
        el('div', { className: 'pm-field' }, [el('label', {}, 'Profile Name'), nameInput]),
        el('div', { className: 'pm-field' }, [
          el('label', {}, 'PAC URL (optional)'),
          el('div', { style: 'display:flex;gap:6px;' }, [
            pacUrlInput,
            el(
              'button',
              {
                type: 'button',
                className: 'pm-btn pm-btn--sm',
                onClick: async () => {
                  const copy = structuredClone(activePac);
                  copy.name = nameInput.value.trim() || copy.name;
                  copy.pacUrl = pacUrlInput.value.trim();
                  await sendBgMessage('UPSERT_PROFILE_GENERIC', { profile: copy });
                  await sendBgMessage('REFRESH_ONLINE_RULES');
                  await loadAndRender();
                  showToast(dom.toastHost, 'Downloaded PAC script.', 'success');
                }
              },
              [svgIcon('download', 13), 'Fetch']
            )
          ])
        ])
      ]),
      el('div', { className: 'pm-field', style: 'margin-top:12px;' }, [
        el('label', {}, 'PAC Script (FindProxyForURL)'),
        pacArea
      ]),
      el('div', { className: 'pm-form-grid', style: 'margin-top:12px;' }, [
        el('div', { className: 'pm-field' }, [el('label', {}, 'PAC Proxy Auth Username (optional)'), authUser]),
        el('div', { className: 'pm-field' }, [el('label', {}, 'PAC Proxy Auth Password'), authPass])
      ]),
      el('div', { style: 'display:flex;justify-content:flex-end;margin-top:14px;' }, [
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--sm pm-btn--primary',
            onClick: async () => {
              const copy = structuredClone(activePac);
              copy.name = nameInput.value.trim() || copy.name;
              copy.pacUrl = pacUrlInput.value.trim();
              copy.pacScript = pacArea.value;
              copy.auth = { username: authUser.value.trim(), password: authPass.value };
              const res = await sendBgMessage('UPSERT_PROFILE_GENERIC', { profile: copy });
              state = res.state;
              renderSidebar();
              renderPacTab();
              showToast(dom.toastHost, 'PAC profile saved.', 'success');
            }
          },
          'Save PAC Profile'
        )
      ])
    ])
  );
}

/* ──────────────────────────────────────────────────────────────
   Tab 4: Temp Rules Manager
────────────────────────────────────────────────────────────── */

function renderTempRulesTab() {
  const rules = Object.values(state.tempRules || {});

  const header = el('div', { className: 'pm-page-header' }, [
    el('div', {}, [
      el('h1', {}, 'Temporary Rules'),
      el('p', {}, 'Session-level domain overrides created from the popup or Network Monitor. Temp rules take highest priority.')
    ]),
    el('div', { className: 'pm-page-actions' }, [
      rules.length
        ? el(
            'button',
            {
              type: 'button',
              className: 'pm-btn pm-btn--sm pm-btn--danger',
              onClick: async () => {
                const res = await sendBgMessage('CLEAR_TEMP_RULES');
                state = res.state;
                renderSidebar();
                renderTempRulesTab();
                showToast(dom.toastHost, 'Cleared all temporary rules.', 'info');
              }
            },
            [svgIcon('trash', 13), 'Clear All Temp Rules']
          )
        : null
    ])
  ]);

  const rows = rules.map((tr) => {
    const target = getProfileById(state, tr.profileId);
    return el('tr', {}, [
      el('td', { className: 'pm-mono', style: 'font-weight:600;' }, tr.domain),
      el('td', { className: 'pm-mono' }, tr.pattern),
      el('td', {}, [
        el('span', { style: 'display:inline-flex;align-items:center;gap:6px;' }, [
          createProfileDot(target.color),
          el('span', {}, target.name)
        ])
      ]),
      el('td', {}, formatRelativeTime(tr.createdAt)),
      el('td', {}, [
        el('div', { className: 'pm-row-actions' }, [
          el(
            'button',
            {
              type: 'button',
              className: 'pm-btn pm-btn--xs',
              title: 'Promote to permanent Auto Switch rule',
              onClick: async () => {
                await sendBgMessage('ADD_SWITCH_RULE', {
                  switchProfileId: DEFAULT_AUTO_SWITCH_ID,
                  conditionType: 'hostWildcard',
                  pattern: tr.pattern,
                  profileId: tr.profileId,
                  activateSwitch: false,
                  refreshTab: false
                });
                const res = await sendBgMessage('REMOVE_TEMP_RULE', { domain: tr.domain });
                state = res.state;
                renderSidebar();
                renderTempRulesTab();
                showToast(dom.toastHost, `Promoted ${tr.domain} to Auto Switch.`, 'success');
              }
            },
            'Promote to Rule'
          ),
          el(
            'button',
            {
              type: 'button',
              className: 'pm-btn pm-btn--ghost pm-btn--icon-sm',
              title: 'Remove temporary rule',
              onClick: async () => {
                const res = await sendBgMessage('REMOVE_TEMP_RULE', { domain: tr.domain });
                state = res.state;
                renderSidebar();
                renderTempRulesTab();
              }
            },
            svgIcon('trash', 13)
          )
        ])
      ])
    ]);
  });

  dom.optionsMain.replaceChildren(
    header,
    el('section', { className: 'pm-card pm-section' }, [
      rules.length
        ? el('div', { className: 'pm-table-wrap' }, [
            el('table', { className: 'pm-table' }, [
              el('thead', {}, [
                el('tr', {}, [
                  el('th', {}, 'Domain'),
                  el('th', {}, 'Pattern'),
                  el('th', {}, 'Routed Profile'),
                  el('th', {}, 'Created'),
                  el('th', {}, 'Actions')
                ])
              ]),
              el('tbody', {}, rows)
            ])
          ])
        : el('p', { className: 'pm-help', style: 'text-align:center;padding:24px 0;' }, 'No active temporary rules.')
    ])
  );
}

/* ──────────────────────────────────────────────────────────────
   Tab 5: Backup, Security & Export
────────────────────────────────────────────────────────────── */

function renderIoTab() {
  const header = el('div', { className: 'pm-page-header' }, [
    el('div', {}, [
      el('h1', {}, 'Backup & Export'),
      el('p', {}, 'Encrypted local vault status, passphrase-protected backups, and PAC script export.')
    ])
  ]);

  const securityCard = el('section', { className: 'pm-card pm-section' }, [
    el('div', { className: 'pm-section__header' }, [
      el('div', {}, [
        el('h2', { className: 'pm-section__title' }, 'Encrypted Local Storage'),
        el('p', { className: 'pm-section__desc' }, 'All saved proxies, credentials, rules, and PAC scripts are stored locally using AES-256-GCM encryption and never sent to custom remote servers.')
      ]),
      createSemanticBadge('AES-256-GCM Active', 'success', 'lock')
    ])
  ]);

  const passphraseInput = el('input', {
    type: 'password',
    className: 'pm-input pm-input--sm',
    placeholder: 'Optional backup passphrase (recommended for encrypted export)'
  });
  const stripCredsCb = el('input', { type: 'checkbox', checked: false });

  const fileInput = el('input', { type: 'file', accept: '.json,application/json', className: 'pm-hidden' });
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      let payload = JSON.parse(text);
      if (
        payload?.format === 'proxyflow-encrypted-backup' ||
        payload?.format === 'proxy-manager-encrypted-backup'
      ) {
        const pass = prompt('Enter passphrase to decrypt this backup:');
        if (!pass) return;
        payload = await decryptBackupWithPassphrase(payload, pass);
      }
      const res = await sendBgMessage('IMPORT_BACKUP', { backup: payload });
      state = res.state;
      renderSidebar();
      renderIoTab();
      showToast(dom.toastHost, 'Backup restored successfully.', 'success');
    } catch (err) {
      showToast(dom.toastHost, `Import failed: ${err.message}`, 'danger');
    } finally {
      fileInput.value = '';
    }
  });

  const backupCard = el('section', { className: 'pm-card pm-section' }, [
    el('div', { className: 'pm-section__header' }, [
      el('div', {}, [
        el('h2', { className: 'pm-section__title' }, 'Local Backup & PAC Export'),
        el('p', { className: 'pm-section__desc' }, 'Export an encrypted or plain JSON backup, or export the active profile as a standalone .pac file.')
      ])
    ]),
    fileInput,
    el('div', { className: 'pm-field', style: 'margin-bottom:10px;max-width:420px;' }, [
      el('label', {}, 'Backup Passphrase (optional)'),
      passphraseInput
    ]),
    el('div', { className: 'pm-setting-row', style: 'padding-top:4px;margin-bottom:12px;' }, [
      el('div', { className: 'pm-setting-info' }, [
        el('strong', {}, 'Exclude proxy usernames and passwords from export'),
        el('span', {}, 'Helpful when sharing rules and server lists without credentials.')
      ]),
      el('label', { className: 'pm-switch' }, [stripCredsCb, el('span', { className: 'pm-switch__track' })])
    ]),
    el('div', { style: 'display:flex;flex-wrap:wrap;gap:10px;' }, [
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--sm pm-btn--primary',
          onClick: async () => {
            const exportPayload = structuredClone(state);
            if (stripCredsCb.checked) {
              for (const p of exportPayload.profiles || []) {
                if (p.type === 'fixed') {
                  p.username = '';
                  p.password = '';
                } else if (p.type === 'pac' && p.auth) {
                  p.auth = { username: '', password: '' };
                }
              }
            }

            const pass = passphraseInput.value;
            const finalObj = pass
              ? await encryptBackupWithPassphrase(exportPayload, pass)
              : exportPayload;
            const suffix = pass ? 'encrypted' : 'backup';
            downloadTextFile(
              `proxyflow-${suffix}-${new Date().toISOString().slice(0, 10)}.json`,
              JSON.stringify(finalObj, null, 2),
              'application/json'
            );
            passphraseInput.value = '';
            showToast(
              dom.toastHost,
              pass ? 'Encrypted backup downloaded.' : 'Backup JSON downloaded.',
              'success'
            );
          }
        },
        [svgIcon('download', 13), 'Make Backup (.json)']
      ),
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--sm',
          onClick: () => fileInput.click()
        },
        [svgIcon('upload', 13), 'Restore from File']
      ),
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--sm',
          onClick: () => {
            const pac = compilePacScript(state, state.activeProfileId);
            downloadTextFile('proxyflow.pac', pac, 'application/x-ns-proxy-autoconfig');
          }
        },
        [svgIcon('pac', 13), 'Export Active PAC (.pac)']
      ),
      el(
        'button',
        {
          type: 'button',
          className: 'pm-btn pm-btn--sm pm-btn--danger',
          onClick: async () => {
            if (!confirm('Reset all profiles, rules, and settings to factory defaults?')) return;
            const res = await sendBgMessage('RESET_ALL');
            state = res.state;
            renderSidebar();
            renderIoTab();
            showToast(dom.toastHost, 'All options reset to defaults.', 'info');
          }
        },
        [svgIcon('trash', 13), 'Reset All Settings']
      )
    ])
  ]);

  dom.optionsMain.replaceChildren(header, securityCard, backupCard);
}

/* ──────────────────────────────────────────────────────────────
   Tab 6: General, Quick Switch & Shortcuts
────────────────────────────────────────────────────────────── */

function renderGeneralTab() {
  const s = state.settings;
  const selectableProfiles = [BUILTIN_PROFILES.direct, ...state.profiles];

  const header = el('div', { className: 'pm-page-header' }, [
    el('div', {}, [
      el('h1', {}, 'General & Shortcuts'),
      el('p', {}, 'Configure startup behavior, dead-proxy failover, Quick Switch cycling, and keyboard shortcuts.')
    ])
  ]);

  const startupSel = el('select', { className: 'pm-select pm-select--sm', style: 'max-width:220px;' });
  startupSel.appendChild(el('option', { value: '', selected: !s.startupProfileId }, 'Keep last active profile'));
  for (const p of selectableProfiles) {
    startupSel.appendChild(el('option', { value: p.id, selected: s.startupProfileId === p.id }, p.name));
  }

  const intervalSel = el('select', { className: 'pm-select pm-select--sm', style: 'max-width:170px;' }, [
    el('option', { value: '0', selected: Number(s.healthCheckIntervalMin) === 0 }, 'Off (Manual only)'),
    el('option', { value: '5', selected: Number(s.healthCheckIntervalMin) === 5 }, 'Every 5 minutes'),
    el('option', { value: '15', selected: Number(s.healthCheckIntervalMin) === 15 }, 'Every 15 minutes'),
    el('option', { value: '30', selected: Number(s.healthCheckIntervalMin) === 30 }, 'Every 30 minutes'),
    el('option', { value: '60', selected: Number(s.healthCheckIntervalMin) === 60 }, 'Every hour')
  ]);

  const providerSel = el('select', { className: 'pm-select pm-select--sm', style: 'max-width:290px;' });
  for (const prov of Object.values(IP_PROVIDERS)) {
    providerSel.appendChild(
      el('option', { value: prov.id, selected: (s.ipCheckProvider || 'cloudflare') === prov.id }, prov.label)
    );
  }

  const makeToggle = (checked) => {
    const cb = el('input', { type: 'checkbox', checked: Boolean(checked) });
    return {
      cb,
      node: el('label', { className: 'pm-switch' }, [cb, el('span', { className: 'pm-switch__track' })])
    };
  };

  const tRefresh = makeToggle(s.refreshOnSwitch);
  const tFailover = makeToggle(s.autoFailoverDeadProxy);
  const tMonitor = makeToggle(s.monitorNetworkErrors);
  const tBadge = makeToggle(s.showResultBadge);
  const tContext = makeToggle(s.showContextMenu);
  const tConfirm = makeToggle(s.confirmDelete);
  const tBottom = makeToggle(s.addConditionsToBottom);
  const tQuickSwitch = makeToggle(s.enableQuickSwitch);

  const quickSet = new Set(s.quickSwitchIds || ['direct', DEFAULT_AUTO_SWITCH_ID]);
  const quickChips = el('div', { className: 'pm-check-chips' });

  const renderQuickChips = () => {
    quickChips.replaceChildren(
      ...selectableProfiles.map((p) => {
        const checked = quickSet.has(p.id);
        const cb = el('input', { type: 'checkbox', checked });
        cb.addEventListener('change', () => {
          if (cb.checked) quickSet.add(p.id);
          else quickSet.delete(p.id);
          renderQuickChips();
        });
        return el('label', { className: `pm-chip-toggle ${checked ? 'is-checked' : ''}` }, [
          cb,
          createProfileDot(p.color),
          el('span', {}, p.name)
        ]);
      })
    );
  };
  renderQuickChips();

  const generalCard = el('section', { className: 'pm-card pm-section' }, [
    el('h2', { className: 'pm-section__title', style: 'margin-bottom:10px;' }, 'Behavior & Safety'),
    el('div', { className: 'pm-setting-row' }, [
      el('div', { className: 'pm-setting-info' }, [
        el('strong', {}, 'Startup Profile'),
        el('span', {}, 'Choose which profile to apply when Chrome starts.')
      ]),
      startupSel
    ]),
    el('div', { className: 'pm-setting-row' }, [
      el('div', { className: 'pm-setting-info' }, [
        el('strong', {}, 'Auto-failover if active proxy goes offline'),
        el('span', {}, 'Monitors your active proxy every minute and switches to Direct if unreachable.')
      ]),
      tFailover.node
    ]),
    el('div', { className: 'pm-setting-row' }, [
      el('div', { className: 'pm-setting-info' }, [
        el('strong', {}, 'Refresh active tab on profile change'),
        el('span', {}, 'Automatically reloads the current HTTP/HTTPS tab after switching proxies.')
      ]),
      tRefresh.node
    ]),
    el('div', { className: 'pm-setting-row' }, [
      el('div', { className: 'pm-setting-info' }, [
        el('strong', {}, 'Monitor failed requests on active tab'),
        el('span', {}, 'Shows a warning count badge when resources fail to load so you can route them quickly.')
      ]),
      tMonitor.node
    ]),
    el('div', { className: 'pm-setting-row' }, [
      el('div', { className: 'pm-setting-info' }, [
        el('strong', {}, 'Show resolved profile name on toolbar badge'),
        el('span', {}, 'Displays a short 4-character profile tag on the extension icon.')
      ]),
      tBadge.node
    ]),
    el('div', { className: 'pm-setting-row' }, [
      el('div', { className: 'pm-setting-info' }, [
        el('strong', {}, 'Enable page/link inspect context menu'),
        el('span', {}, 'Right-click any page or link to inspect which proxy route applies.')
      ]),
      tContext.node
    ]),
    el('div', { className: 'pm-setting-row' }, [
      el('div', { className: 'pm-setting-info' }, [
        el('strong', {}, 'Append new popup conditions to bottom of Auto Switch'),
        el('span', {}, 'By default, new popup conditions are added to the top for immediate priority.')
      ]),
      tBottom.node
    ]),
    el('div', { className: 'pm-setting-row' }, [
      el('div', { className: 'pm-setting-info' }, [
        el('strong', {}, 'Confirm before deleting proxies or profiles'),
        el('span', {}, 'Prompts for confirmation before removing saved servers.')
      ]),
      tConfirm.node
    ]),
    el('div', { className: 'pm-setting-row' }, [
      el('div', { className: 'pm-setting-info' }, [
        el('strong', {}, 'Background Batch Check Interval'),
        el('span', {}, 'Periodically probes saved proxies locally (Off recommended for manual checking).')
      ]),
      intervalSel
    ]),
    el('div', { className: 'pm-setting-row' }, [
      el('div', { className: 'pm-setting-info' }, [
        el('strong', {}, 'Standard Check-Live & Public IP Provider'),
        el('span', {}, 'Primary HTTPS service used for live checks with automatic multi-provider fallback.')
      ]),
      providerSel
    ])
  ]);

  const quickCard = el('section', { className: 'pm-card pm-section' }, [
    el('div', { className: 'pm-setting-row', style: 'border-bottom:none;padding:0;' }, [
      el('div', { className: 'pm-setting-info' }, [
        el('strong', {}, 'Quick Switch'),
        el('span', {}, 'Cycle between selected profiles using Alt+Shift+P or the lightning button in the popup.')
      ]),
      tQuickSwitch.node
    ]),
    quickChips,
    el('div', { style: 'display:flex;justify-content:space-between;align-items:center;margin-top:16px;padding-top:12px;border-top:1px solid var(--border);' }, [
      el('div', { className: 'pm-help', style: 'margin:0;' }, 'Default shortcuts: Alt+Shift+O (open popup), Alt+Shift+P (cycle Quick Switch).'),
      el('div', { className: 'pm-row-actions' }, [
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--sm',
            onClick: () => chrome.tabs.create({ url: 'chrome://extensions/shortcuts' })
          },
          [svgIcon('external', 13), 'Configure Shortcuts']
        ),
        el(
          'button',
          {
            type: 'button',
            className: 'pm-btn pm-btn--sm pm-btn--primary',
            onClick: async () => {
              const res = await sendBgMessage('UPDATE_SETTINGS', {
                settings: {
                  startupProfileId: startupSel.value || null,
                  refreshOnSwitch: tRefresh.cb.checked,
                  autoFailoverDeadProxy: tFailover.cb.checked,
                  monitorNetworkErrors: tMonitor.cb.checked,
                  showResultBadge: tBadge.cb.checked,
                  showContextMenu: tContext.cb.checked,
                  addConditionsToBottom: tBottom.cb.checked,
                  confirmDelete: tConfirm.cb.checked,
                  healthCheckIntervalMin: Number(intervalSel.value),
                  ipCheckProvider: providerSel.value || 'cloudflare',
                  enableQuickSwitch: tQuickSwitch.cb.checked,
                  quickSwitchIds: Array.from(quickSet)
                }
              });
              state = res.state;
              showToast(dom.toastHost, 'General settings saved.', 'success');
            }
          },
          'Save Settings'
        )
      ])
    ])
  ]);

  dom.optionsMain.replaceChildren(header, generalCard, quickCard);
}

function downloadTextFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
