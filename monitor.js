// monitor.js — Network Request & Route Monitor (ZeroOmega-inspired)

import { DEFAULT_AUTO_SWITCH_ID } from './shared/models.js';
import { domainToWildcard } from './shared/rule-matcher.js';
import {
  createProfileDot,
  createSemanticBadge,
  el,
  sendBgMessage,
  showToast,
  svgIcon
} from './shared/ui-helpers.js';

const dom = {
  monitorCountBadge: document.getElementById('monitorCountBadge'),
  tabFilterSelect: document.getElementById('tabFilterSelect'),
  statusFilterSelect: document.getElementById('statusFilterSelect'),
  urlSearchInput: document.getElementById('urlSearchInput'),
  monitorActionBtns: document.getElementById('monitorActionBtns'),
  monitorTableBody: document.getElementById('monitorTableBody'),
  toastHost: document.getElementById('toastHost')
};

let monitorData = { logs: [], tabs: [], state: null };
let autoRefreshTimer = null;

document.addEventListener('DOMContentLoaded', async () => {
  renderActionButtons();
  bindFilters();
  await refreshMonitor();
  autoRefreshTimer = setInterval(refreshMonitor, 2500);
});

function renderActionButtons() {
  const refreshBtn = el(
    'button',
    {
      type: 'button',
      className: 'pm-btn pm-btn--sm',
      onClick: () => refreshMonitor()
    },
    [svgIcon('refresh', 13), 'Refresh']
  );

  const clearBtn = el(
    'button',
    {
      type: 'button',
      className: 'pm-btn pm-btn--sm pm-btn--danger',
      onClick: async () => {
        await sendBgMessage('CLEAR_MONITOR_DATA');
        await refreshMonitor();
        showToast(dom.toastHost, 'Cleared captured network logs.', 'info');
      }
    },
    [svgIcon('trash', 13), 'Clear Logs']
  );

  const optionsBtn = el(
    'button',
    {
      type: 'button',
      className: 'pm-btn pm-btn--sm',
      onClick: () => chrome.runtime.openOptionsPage()
    },
    [svgIcon('settings', 13), 'Options']
  );

  dom.monitorActionBtns.replaceChildren(refreshBtn, clearBtn, optionsBtn);
}

function bindFilters() {
  dom.tabFilterSelect.addEventListener('change', renderTable);
  dom.statusFilterSelect.addEventListener('change', renderTable);
  dom.urlSearchInput.addEventListener('input', renderTable);
}

async function refreshMonitor() {
  try {
    const res = await sendBgMessage('GET_MONITOR_DATA');
    monitorData = res;
    syncTabOptions();
    renderTable();
  } catch (err) {
    showToast(dom.toastHost, err.message, 'danger');
  }
}

function syncTabOptions() {
  const prev = dom.tabFilterSelect.value;
  const opts = [el('option', { value: 'all' }, 'All Tabs')];
  for (const t of monitorData.tabs || []) {
    if (!t.url || t.url.startsWith('chrome-extension://')) continue;
    const label = (t.title || t.url).slice(0, 46);
    opts.push(el('option', { value: String(t.id) }, `#${t.id} ${label}`));
  }
  dom.tabFilterSelect.replaceChildren(...opts);
  if ([...opts].some((o) => o.value === prev)) {
    dom.tabFilterSelect.value = prev;
  }
}

function renderTable() {
  const tabFilter = dom.tabFilterSelect.value;
  const statusFilter = dom.statusFilterSelect.value;
  const query = (dom.urlSearchInput.value || '').trim().toLowerCase();

  const filtered = (monitorData.logs || []).filter((item) => {
    if (tabFilter !== 'all' && String(item.tabId) !== tabFilter) return false;
    if (statusFilter !== 'all' && item.status !== statusFilter) return false;
    if (
      query &&
      !item.domain.toLowerCase().includes(query) &&
      !item.url.toLowerCase().includes(query) &&
      !(item.routeLabel || '').toLowerCase().includes(query)
    ) {
      return false;
    }
    return true;
  });

  dom.monitorCountBadge.textContent = `${filtered.length} request${filtered.length === 1 ? '' : 's'}`;

  if (!filtered.length) {
    dom.monitorTableBody.replaceChildren(
      el('tr', {}, [
        el('td', { colSpan: 7, style: 'text-align:center; padding: 32px; color: var(--text-muted);' }, 'No captured requests match the current filter. Browse any website to inspect live traffic.')
      ])
    );
    return;
  }

  const fixedProxies = (monitorData.state?.profiles || []).filter((p) => p.type === 'fixed');
  const defaultTarget = fixedProxies[0]?.id || 'direct';

  const rows = filtered.slice(0, 200).map((entry) => {
    const timeStr = new Date(entry.timestamp).toLocaleTimeString();
    let statusBadge;
    if (entry.status === 'failed') {
      statusBadge = createSemanticBadge(entry.error || 'Failed', 'danger', 'error');
    } else if (entry.status === 'http_error') {
      statusBadge = createSemanticBadge(`HTTP ${entry.statusCode}`, 'warning', 'warning');
    } else if (entry.status === 'aborted') {
      statusBadge = createSemanticBadge('Aborted', 'neutral', 'unknown');
    } else {
      statusBadge = createSemanticBadge(`OK ${entry.statusCode || 200}`, 'success', 'check');
    }

    const routeCell = el(
      'span',
      { style: 'display:inline-flex; align-items:center; gap:6px; font-weight:500;' },
      [createProfileDot(entry.routeColor), el('span', {}, entry.routeLabel || 'Direct')]
    );

    const actions = entry.domain
      ? el('div', { className: 'pm-row-actions' }, [
          el(
            'button',
            {
              type: 'button',
              className: 'pm-btn pm-btn--xs',
              title: `Add temporary rule for ${entry.domain}`,
              onClick: async () => {
                await sendBgMessage('ADD_TEMP_RULE', {
                  domain: entry.domain,
                  profileId: defaultTarget,
                  refreshTab: false
                });
                showToast(dom.toastHost, `Added temp rule for ${entry.domain}`, 'success');
              }
            },
            'Temp'
          ),
          el(
            'button',
            {
              type: 'button',
              className: 'pm-btn pm-btn--xs pm-btn--primary',
              title: `Add permanent Auto Switch rule for *.${entry.domain}`,
              onClick: async () => {
                await sendBgMessage('ADD_SWITCH_RULE', {
                  switchProfileId: DEFAULT_AUTO_SWITCH_ID,
                  conditionType: 'hostWildcard',
                  pattern: domainToWildcard(entry.domain),
                  profileId: defaultTarget,
                  activateSwitch: true,
                  refreshTab: false
                });
                showToast(dom.toastHost, `Added Auto Switch rule for *.${entry.domain}`, 'success');
              }
            },
            '+ Rule'
          )
        ])
      : el('span', { style: 'color:var(--text-muted);' }, '—');

    return el('tr', {}, [
      el('td', { className: 'pm-mono', style: 'white-space:nowrap;' }, timeStr),
      el('td', {}, statusBadge),
      el('td', { className: 'pm-mono' }, entry.method || 'GET'),
      el('td', { className: 'pm-mon-domain' }, entry.domain || '—'),
      el('td', {}, el('div', { className: 'pm-mon-url', title: entry.url }, entry.url)),
      el('td', {}, routeCell),
      el('td', {}, actions)
    ]);
  });

  dom.monitorTableBody.replaceChildren(...rows);
}

window.addEventListener('unload', () => {
  clearInterval(autoRefreshTimer);
});
