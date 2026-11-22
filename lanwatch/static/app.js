'use strict';

/* lanwatch dashboard
 * Plain ES2020, no build step.  The server is the source of truth; SSE events
 * arrive for every device change and the UI re-renders from the local map.
 */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const PREFS_KEY = 'lanwatch.prefs.v1';
const COLLECTORS = [
  ['icmp', 'ICMP'],
  ['arp', 'ARP'],
  ['tcp', 'TCP'],
  ['http', 'HTTP'],
  ['mdns', 'mDNS'],
  ['ssdp', 'SSDP'],
  ['nbns', 'NBNS'],
  ['rdns', 'rDNS'],
];

const ICONS = {
  router:
    '<rect x="3" y="12" width="18" height="8" rx="2"/><path d="M7 16h.01M11 16h.01"/><path d="M17 12V7a3 3 0 0 0-3-3h-3"/>',
  printer:
    '<path d="M7 8V4h10v4"/><rect x="4" y="8" width="16" height="8" rx="2"/><path d="M7 14h10v6H7z"/>',
  tv: '<rect x="3" y="4.5" width="18" height="12" rx="2"/><path d="M8 21h8M12 16.5V21"/>',
  media: '<circle cx="12" cy="12" r="9"/><path d="M10 8.5l6 3.5-6 3.5z"/>',
  nas:
    '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01M11 7.5h2M11 16.5h2"/>',
  computer:
    '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  camera:
    '<path d="M4 8h3l2-2.5h6L17 8h3v11H4z"/><circle cx="12" cy="13" r="3"/>',
  phone:
    '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/>',
  speaker:
    '<rect x="6" y="3" width="12" height="18" rx="3"/><circle cx="12" cy="14.5" r="3"/><circle cx="12" cy="7.5" r="1"/>',
  console:
    '<rect x="2.5" y="8" width="19" height="9" rx="4.5"/><path d="M7.5 11v3M6 12.5h3M15.5 11.5h.01M17.5 13.5h.01"/>',
  iot:
    '<circle cx="12" cy="12" r="3"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.4 5.4l1.4 1.4M17.2 17.2l1.4 1.4M18.6 5.4l-1.4 1.4M6.8 17.2l-1.4 1.4"/>',
  device:
    '<rect x="6" y="6" width="12" height="12" rx="2.5"/><path d="M9.5 2.5v3M14.5 2.5v3M9.5 18.5v3M14.5 18.5v3M2.5 9.5h3M2.5 14.5h3M18.5 9.5h3M18.5 14.5h3"/>',
};

const ICON_ALIASES = { self: 'computer', '': 'device' };
const CHEVRON =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>';

const PHASE_LABELS = {
  idle: 'Ready',
  starting: 'Starting',
  sweep: 'Pinging hosts',
  probe: 'Probing services',
  names: 'Resolving names',
  done: 'Scan complete',
  stopped: 'Scan stopped',
  error: 'Scan failed',
};

const state = {
  devices: new Map(),
  scan: { running: false, phase: 'idle', message: 'ready', done: 0, total: 0, hosts_total: 0, found: 0 },
  collectors: {},
  network: null,
  networks: [],
  activeNetwork: null,
  showArchived: false,
  interfaces: [],
  options: {},
  host: null,
  version: '0.1.0',
  statePath: '',
  connected: false,
  drawerIp: null,
  drawerDirty: false,
  autoTimer: null,
  renderQueued: false,
  search: '',
  latestDiff: null,
  history: { scans: [], path: '', error: null },
  events: {
    items: [],
    unread: 0,
    path: '',
    error: null,
    severity: 'all',
    unreadOnly: false,
    hasMore: false,
  },
  prefs: { showOffline: true, sort: 'ip', autoScan: false, autoInterval: 60, trustFilter: 'all' },
};

const TRUST_LABELS = { trusted: 'Trusted', unknown: 'Unknown', ignored: 'Ignored' };
const SEVERITY_LABELS = { info: 'Info', notice: 'Notice', warning: 'Warning', critical: 'Critical' };

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[char]));
}

function icon(kind) {
  const key = ICON_ALIASES[kind] || kind;
  const body = ICONS[key] || ICONS.device;
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
}

function ago(timestamp) {
  if (!timestamp) return 'never';
  const seconds = Math.max(0, Date.now() / 1000 - Number(timestamp));
  if (seconds < 10) return 'just now';
  if (seconds < 60) return `${Math.floor(seconds)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function absolute(timestamp) {
  if (!timestamp) return 'never';
  return new Date(Number(timestamp) * 1000).toLocaleString();
}

function formatDuration(seconds) {
  if (seconds == null) return '—';
  const value = Number(seconds);
  if (!isFinite(value)) return '—';
  if (value < 60) return `${value < 10 ? value.toFixed(1) : Math.round(value)}s`;
  const minutes = Math.floor(value / 60);
  const rest = Math.round(value % 60);
  return `${minutes}m ${rest}s`;
}

function ipNumber(ip) {
  return String(ip).split('.').reduce((total, part) => ((total << 8) >>> 0) + (Number(part) || 0), 0);
}

function plural(count, word) {
  return `${count} ${word}${count === 1 ? '' : 's'}`;
}

async function api(path, options = {}) {
  const { method = 'GET', body } = options;
  const headers = { 'X-Lanwatch': '1' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: 'no-store',
  });
  let data = null;
  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }
  if (!response.ok) {
    throw new Error((data && data.error) || `Request failed (${response.status})`);
  }
  return data || {};
}

function toast(message, kind = '') {
  const host = $('#toasts');
  if (!host) return;
  const element = document.createElement('div');
  element.className = 'toast' + (kind ? ` ${kind}` : '');
  element.textContent = message;
  host.appendChild(element);
  while (host.children.length > 4) host.firstElementChild.remove();
  setTimeout(() => {
    element.classList.add('leaving');
    setTimeout(() => element.remove(), 230);
  }, 4200);
}

/* ------------------------------------------------------------------ */
/* state ingestion                                                     */
/* ------------------------------------------------------------------ */

function upsertDevice(device) {
  if (!device || !device.ip) return;
  state.devices.set(device.ip, device);
}

function applySnapshot(data) {
  state.devices = new Map((data.devices || []).map((device) => [device.ip, device]));
  if (data.state) state.scan = data.state;
  if (data.collectors) state.collectors = data.collectors;
  state.network = data.network || null;
  state.networks = data.networks || [];
  state.activeNetwork = data.active_network || null;
  state.interfaces = data.interfaces || [];
  state.options = data.options || {};
  state.host = data.host || null;
  state.version = data.version || state.version;
  state.statePath = data.state_path || '';
  if (data.history) {
    state.history.path = data.history.path || '';
    state.history.error = data.history.error || null;
  }
  if (data.events) {
    state.events.path = data.events.path || state.events.path;
    state.events.error = data.events.error || null;
    state.events.unread = Number(data.events.unread) || 0;
  }
  state.latestDiff = data.latest_diff || null;
  renderAll();
}

function handleEvent(event) {
  switch (event.type) {
    case 'hello':
      if (event.state) state.scan = event.state;
      if (event.unread != null) state.events.unread = Number(event.unread) || 0;
      if (event.latest_diff) state.latestDiff = event.latest_diff;
      setSync(true);
      break;
    case 'scan.started':
      if (event.state) state.scan = event.state;
      if (event.network) state.network = event.network;
      if (event.options) state.options = event.options;
      state.latestDiff = null;
      state.collectors = {};
      COLLECTORS.forEach(([name]) => {
        state.collectors[name] = { status: 'pending', detail: 'waiting', count: 0 };
      });
      toast('Scan started');
      break;
    case 'collector':
      if (event.name && event.collector) state.collectors[event.name] = event.collector;
      break;
    case 'progress':
      if (event.state) state.scan = event.state;
      break;
    case 'network':
      state.network = event.network || state.network;
      break;
    case 'network.changed':
      state.networks = event.networks || state.networks;
      renderNetworks();
      // The active inventory changed (scan on another network, or a switch from
      // another browser tab): reload so the device list matches.
      if ((state.activeNetwork && state.activeNetwork.id) !== event.active) {
        loadState();
        loadEvents(true, true);
      }
      break;
    case 'device':
      upsertDevice(event.device);
      if (state.drawerIp === (event.device && event.device.ip)) renderDrawerStats();
      break;
    case 'device.removed':
      state.devices.delete(event.ip);
      if (state.drawerIp === event.ip) closeDrawer();
      break;
    case 'scan.diff':
      state.latestDiff = event.diff || event;
      announceDiff(state.latestDiff);
      if ($('#event-center') && $('#event-center').open) loadEvents(true);
      break;
    case 'event.new':
      acceptEvent(event.event || event);
      break;
    case 'scan.finished':
      if (event.state) state.scan = event.state;
      if (event.stopped) {
        toast('Scan stopped');
      } else if (event.state && event.state.error) {
        toast(event.state.error, 'error');
      } else {
        const online = [...state.devices.values()].filter((d) => d.online).length;
        toast(`Scan complete · ${plural(online, 'device')} online`);
      }
      loadHistory();
      loadEvents(true, true);
      break;
    case 'scan.error':
      toast(event.error || 'Scan failed', 'error');
      break;
    default:
      break;
  }
  queueRender();
}

/* ------------------------------------------------------------------ */
/* rendering                                                           */
/* ------------------------------------------------------------------ */

function queueRender() {
  if (state.renderQueued) return;
  state.renderQueued = true;
  requestAnimationFrame(() => {
    state.renderQueued = false;
    renderAll();
  });
}

function renderAll() {
  renderNetwork();
  if ($('#networks') && $('#networks').open) renderNetworks();
  renderStats();
  renderScan();
  renderDiff();
  renderCollectors();
  renderTable();
  renderHistory();
  renderEventBadge();
  renderEvents();
  renderFooter();
}

function deviceList() {
  return Array.from(state.devices.values());
}

function renderNetwork() {
  const network = state.network;
  const cidr = $('#net-cidr');
  const iface = $('#net-if');
  const dot = $('#net-dot');
  const online = deviceList().filter((d) => d.online).length;

  const active = state.activeNetwork;
  const saved = state.networks.filter((n) => !n.archived).length;
  const switchHint = saved > 1 ? `${saved} saved networks · ` : '';

  if (network) {
    cidr.textContent = (active && active.label) || network.cidr || 'unknown subnet';
    const bits = [];
    if (network.interface) bits.push(network.interface);
    if (network.address) bits.push(network.address);
    iface.textContent = bits.join(' · ');
    const bitsTitle = [`Network ${network.cidr}`];
    if (network.gateway) bitsTitle.push(`gateway ${network.gateway}`);
    if (network.host_count) bitsTitle.push(`${network.host_count} addresses`);
    bitsTitle.push('click to switch network');
    $('#net-chip').title = switchHint + bitsTitle.join(' · ');
    $('#brand-sub').textContent = `${plural(online, 'device')} online on ${network.cidr}`;
  } else if (active && active.cidr) {
    cidr.textContent = active.label || active.cidr;
    iface.textContent = '';
    $('#net-chip').title = `${switchHint}not scanned yet · click to switch network`;
    $('#brand-sub').textContent = `${plural(online, 'device')} online on ${active.cidr}`;
  } else {
    cidr.textContent = 'no network yet';
    iface.textContent = '';
    $('#net-chip').title = 'Switch network';
    $('#brand-sub').textContent = 'LAN device discovery';
  }

  dot.className = 'net-dot';
  if (state.scan.running) dot.classList.add('scanning');
  else if (state.scan.phase === 'done') dot.classList.add('live');
}

function renderStats() {
  const devices = deviceList();
  const online = devices.filter((d) => d.online);
  const services = devices.reduce((total, device) => total + (device.ports || []).length, 0);
  const withServices = devices.filter((device) => (device.ports || []).length > 0).length;
  const labeled = devices.filter((device) => device.label).length;
  const latencies = online
    .map((device) => device.rtt_ms)
    .filter((value) => typeof value === 'number')
    .sort((a, b) => a - b);
  const median = latencies.length ? latencies[Math.floor(latencies.length / 2)] : null;

  $('#stat-online').textContent = String(online.length);
  $('#stat-known').textContent = String(devices.length);
  $('#stat-services').textContent = String(services);
  $('#stat-latency').textContent = median == null ? '—' : `${Math.round(median)} ms`;

  if (state.scan.running) {
    $('#stat-online-sub').textContent = `${state.scan.found || 0} found so far`;
  } else if (state.scan.finished_at) {
    $('#stat-online-sub').textContent = `last scan ${ago(state.scan.finished_at)}`;
  } else {
    $('#stat-online-sub').textContent = 'no scan yet';
  }
  $('#stat-known-sub').textContent = labeled ? `${labeled} labeled` : 'saved inventory';
  $('#stat-services-sub').textContent = withServices ? `on ${plural(withServices, 'device')}` : 'no open ports';
  $('#stat-latency-sub').textContent = median == null ? 'ICMP round trip' : 'median ICMP reply';
}

function renderScan() {
  const scan = state.scan || {};
  const running = !!scan.running;
  const phase = scan.phase || 'idle';
  const pulse = $('#scan-pulse');
  const bar = $('#progress-bar');
  const track = bar.parentElement;

  $('#scan-phase').textContent = PHASE_LABELS[phase] || phase;

  let detail = '';
  if (running) {
    detail = scan.message || 'working';
    if (scan.total && (phase === 'sweep' || phase === 'probe')) {
      detail += ` · ${scan.done || 0}/${scan.total}`;
    }
    if (scan.found) detail += ` · ${plural(scan.found, 'device')} found`;
  } else if (phase === 'error') {
    detail = scan.error || scan.message || 'something went wrong';
  } else if (scan.finished_at) {
    detail = `${plural(scan.found || 0, 'device')} · ${formatDuration(scan.duration_s)} · ${ago(scan.finished_at)}`;
  } else {
    detail = scan.message || 'ready to scan';
  }
  $('#scan-detail').textContent = detail;

  pulse.className = 'pulse';
  if (running) pulse.classList.add('active');
  else if (phase === 'done') pulse.classList.add('done');
  else if (phase === 'error') pulse.classList.add('error');

  track.classList.remove('indeterminate');
  if (running) {
    if (scan.total > 0 && scan.done > 0) {
      const percent = Math.max(2, Math.min(100, (scan.done / scan.total) * 100));
      bar.style.width = `${percent}%`;
    } else {
      track.classList.add('indeterminate');
      bar.style.width = '';
    }
  } else {
    bar.style.width = phase === 'done' ? '100%' : '0%';
  }

  $('#scan-btn').hidden = running;
  $('#stop-btn').hidden = !running;
}

function diffParts(diff) {
  const counts = (diff && diff.counts) || {};
  const parts = [];
  [
    ['new', 'new'],
    ['returned', 'returned'],
    ['offline', 'offline'],
    ['changed', 'changed'],
  ].forEach(([key, label]) => {
    const value = Number(counts[key]) || 0;
    if (value) parts.push({ key, label, value });
  });
  return parts;
}

function renderDiff() {
  const host = $('#scan-diff');
  if (!host) return;
  const diff = state.latestDiff;
  if (!diff || state.scan.running) {
    host.hidden = true;
    host.innerHTML = '';
    return;
  }
  host.hidden = false;
  host.className = 'scan-diff';
  if (diff.baseline) {
    host.classList.add('baseline');
    host.innerHTML = `<span class="diff-tag">baseline</span><span class="diff-copy">${plural(Number(diff.current_devices) || 0, 'device')} recorded for future comparisons</span>`;
    return;
  }
  if (diff.partial) {
    host.classList.add('partial');
    host.innerHTML = '<span class="diff-tag">partial</span><span class="diff-copy">Scan stopped early · comparison skipped</span>';
    return;
  }
  const parts = diffParts(diff);
  if (!parts.length) {
    host.classList.add('quiet');
    host.innerHTML = '<span class="diff-tag">unchanged</span><span class="diff-copy">No changes since the previous scan</span>';
    return;
  }
  const titles = (diff.changes || []).map((change) => change.title).filter(Boolean).slice(0, 6).join('\n');
  host.title = titles;
  host.innerHTML = `<span class="diff-tag">changes</span>${parts
    .map((part) => `<span class="diff-pill ${esc(part.key)}"><b>${part.value}</b> ${esc(part.label)}</span>`)
    .join('')}`;
}

function announceDiff(diff) {
  if (!diff || !diff.counts) return;
  const parts = diffParts(diff);
  if (!parts.length) return;
  toast(`Changes · ${parts.map((part) => `${part.value} ${part.label}`).join(' · ')}`, 'warn');
}

function renderEventBadge() {
  const badge = $('#events-unread');
  if (!badge) return;
  const unread = Number(state.events.unread) || 0;
  badge.hidden = unread <= 0;
  badge.textContent = unread > 99 ? '99+' : String(unread);
  const button = $('#events-btn');
  if (button) {
    button.title = unread ? `Event center · ${plural(unread, 'unread event')}` : 'Event center';
  }
}

function renderCollectors() {
  const host = $('#collectors');
  const html = COLLECTORS.map(([name, label]) => {
    const entry = state.collectors[name] || { status: 'idle', detail: 'not run yet', count: 0 };
    const count = entry.count ? `<b>${esc(entry.count)}</b>` : '';
    return `<span class="collector" data-status="${esc(entry.status || 'idle')}" title="${esc(`${label}: ${entry.detail || ''}`)}"><i></i><span>${label}</span>${count}</span>`;
  }).join('');
  host.innerHTML = html;
}

function renderTable() {
  const total = state.devices.size;
  const query = state.search.trim().toLowerCase();
  let list = deviceList();

  if (!state.prefs.showOffline) list = list.filter((device) => device.online);
  const trustFilter = state.prefs.trustFilter || 'all';
  if (trustFilter === 'all') list = list.filter((device) => (device.trust || 'unknown') !== 'ignored');
  else list = list.filter((device) => (device.trust || 'unknown') === trustFilter);
  if (query) {
    list = list.filter((device) => {
      const haystack = [
        device.ip,
        device.name,
        device.label,
        device.hostname,
        device.vendor,
        device.mac,
        device.notes,
        device.kind,
        device.trust,
        ...(device.ports || []),
        ...(device.port_names || []),
        ...(device.mdns_services || []),
        ...Object.values(device.ssdp || {}),
        ...(device.sources || []),
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return haystack.includes(query);
    });
  }

  list.sort(comparator(state.prefs.sort));
  $('#device-rows').innerHTML = list.map(rowHtml).join('');
  $('#empty-state').hidden = list.length > 0;
  $('#device-table').hidden = list.length === 0;

  if (!list.length) {
    const emptyScan = $('#empty-scan');
    if (total === 0) {
      $('#empty-title').textContent = 'No devices yet';
      $('#empty-text').textContent = 'Run a scan to discover what is on your network.';
      emptyScan.hidden = false;
      emptyScan.textContent = 'Scan now';
      emptyScan.dataset.action = 'scan';
    } else {
      $('#empty-title').textContent = 'No matches';
      const trustActive = trustFilter !== 'all';
      $('#empty-text').textContent = query
        ? `Nothing matches “${query}”${state.prefs.showOffline ? '' : ' while offline devices are hidden'}.`
        : trustActive
          ? `No ${TRUST_LABELS[trustFilter] || trustFilter} devices.`
          : 'Offline devices are hidden.';
      emptyScan.hidden = false;
      emptyScan.textContent = 'Clear filters';
      emptyScan.dataset.action = 'clear';
    }
  }

  const online = deviceList().filter((device) => device.online).length;
  const stamp = state.scan.finished_at
    ? `last scan ${ago(state.scan.finished_at)} · ${formatDuration(state.scan.duration_s)}`
    : 'no scan yet';
  const filtering = list.length !== total ? `${list.length} of ${plural(total, 'device')}` : plural(total, 'device');
  $('#table-hint').textContent = `${filtering} shown · ${online} online · ${stamp}${state.scan.running ? ' · scanning…' : ''}`;
}

function renderHistory() {
  const scans = state.history.scans || [];
  const spark = $('#history-spark');
  const count = $('#history-count');
  const hint = $('#history-hint');

  count.textContent = scans.length ? `${scans.length} recent` : '0 scans';
  if (state.history.error) {
    $('#history-sub').textContent = `History unavailable · ${state.history.error}`;
  } else if (scans.length) {
    $('#history-sub').textContent = `Last scan ${ago(scans[0].finished_at)} · recorded automatically`;
  } else {
    $('#history-sub').textContent = 'No scans recorded yet';
  }

  const chronological = scans.slice().reverse();
  const max = Math.max(1, ...chronological.map((scan) => Number(scan.devices_found) || 0));
  const bars = [];
  for (let index = chronological.length; index < 12; index += 1) {
    bars.push('<span class="spark-bar spark-bar--empty"></span>');
  }
  for (const scan of chronological) {
    const found = Number(scan.devices_found) || 0;
    const height = Math.max(4, Math.round((found / max) * 100));
    const title = `${absolute(scan.finished_at)} · ${plural(found, 'device')} found`;
    bars.push(`<span class="spark-bar" style="height:${height}%" title="${esc(title)}"></span>`);
  }
  spark.innerHTML = chronological.length
    ? bars.join('')
    : '<span class="spark-empty">History appears after the first scan</span>';

  if (!scans.length) {
    $('#history-rows').innerHTML =
      '<tr><td class="history-empty" colspan="7">Run a scan to start the timeline.</td></tr>';
  } else {
    $('#history-rows').innerHTML = scans
      .map((scan) => {
        const status = scan.error ? 'error' : scan.stopped ? 'stopped' : 'ok';
        const found = Number(scan.devices_found) || 0;
        const up = Number(scan.hosts_up) || 0;
        const changes =
          (Number(scan.new_devices) || 0) +
          (Number(scan.returned_devices) || 0) +
          (Number(scan.offline_devices) || 0) +
          (Number(scan.changed_devices) || 0);
        const changeText = scan.baseline ? 'base' : changes ? String(changes) : '—';
        const changeTitle = scan.baseline
          ? 'First scan for this network'
          : `${Number(scan.new_devices) || 0} new · ${Number(scan.returned_devices) || 0} returned · ${Number(scan.offline_devices) || 0} offline · ${Number(scan.changed_devices) || 0} changed`;
        return `<tr title="${esc(absolute(scan.finished_at))}">
          <td><span data-ts="${Number(scan.finished_at) || 0}">${ago(scan.finished_at)}</span></td>
          <td class="mono col-history-network">${esc(scan.subnet || '—')}</td>
          <td class="num">${found}</td>
          <td class="num col-history-up">${up}</td>
          <td class="col-history-duration">${formatDuration(scan.duration_s)}</td>
          <td class="num col-history-changes" title="${esc(changeTitle)}">${changeText}</td>
          <td><span class="status ${status}">${status}</span></td>
        </tr>`;
      })
      .join('');
  }

  hint.textContent = state.history.path ? `history ${state.history.path}` : '';
}

function comparator(sort) {
  const byIp = (a, b) => ipNumber(a.ip) - ipNumber(b.ip);
  switch (sort) {
    case 'name':
      return (a, b) => String(a.name || '').localeCompare(String(b.name || ''), undefined, { sensitivity: 'base' }) || byIp(a, b);
    case 'latency':
      return (a, b) => (a.rtt_ms == null ? 1e9 : a.rtt_ms) - (b.rtt_ms == null ? 1e9 : b.rtt_ms) || byIp(a, b);
    case 'seen':
      return (a, b) => (b.last_seen || 0) - (a.last_seen || 0) || byIp(a, b);
    case 'services':
      return (a, b) => (b.ports || []).length - (a.ports || []).length || byIp(a, b);
    default:
      return byIp;
  }
}

function portLabel(device, port) {
  const index = (device.ports || []).indexOf(port);
  const name = index >= 0 ? (device.port_names || [])[index] : '';
  return name || String(port);
}

function portTitle(device, port) {
  const label = portLabel(device, port);
  const banner = (device.banners || {})[String(port)];
  return banner ? `${label} · ${banner}` : label;
}

const KIND_LABELS = {
  router: 'Router',
  printer: 'Printer',
  tv: 'TV',
  media: 'Media device',
  nas: 'NAS',
  computer: 'Computer',
  camera: 'Camera',
  iot: 'Smart device',
  phone: 'Phone / tablet',
  speaker: 'Speaker',
  console: 'Game console',
};

function kindLabel(device) {
  const identity = device.identity;
  if (!identity || !KIND_LABELS[identity.kind]) return '';
  const label = KIND_LABELS[identity.kind];
  if (identity.confidence >= 55) return label;
  if (identity.confidence >= 25) return `maybe ${label.toLowerCase()}`;
  return '';
}

function rowHtml(device) {
  const online = !!device.online;
  const name = device.name || device.hostname || 'Unknown device';
  const subBits = [];
  const kindText = kindLabel(device);
  if (kindText) subBits.push(kindText);
  if (device.vendor) subBits.push(device.vendor);
  else if (device.hostname && device.hostname !== name) subBits.push(device.hostname);
  if (device.mac) subBits.push(device.mac);
  if (!subBits.length && (device.sources || []).length) subBits.push(`via ${device.sources.join(', ')}`);
  const sub = subBits.join(' · ');

  const badges = [];
  if (device.is_gateway) badges.push('<span class="badge gw">gateway</span>');
  if (device.is_self) badges.push('<span class="badge self">this device</span>');
  if (device.trust === 'trusted') badges.push('<span class="badge trusted">trusted</span>');
  else if (device.trust === 'ignored') badges.push('<span class="badge ignored">ignored</span>');
  if (!online) badges.push('<span class="badge off">offline</span>');

  const ports = device.ports || [];
  const chips = ports
    .slice(0, 4)
    .map((port) => `<span class="chip" title="${esc(portTitle(device, port))}">${esc(portLabel(device, port))}</span>`)
    .join('');
  const more = ports.length > 4 ? `<span class="chip more">+${ports.length - 4}</span>` : '';
  const services = chips || more ? chips + more : '<span class="chip blank">none</span>';

  const latency = device.rtt_ms;
  const latencyClass = latency == null ? 'none' : latency < 25 ? 'good' : latency < 120 ? 'warn' : 'bad';
  const latencyText = latency == null ? '—' : `${Math.round(latency)} ms`;

  return `<tr class="device-row ${online ? '' : 'is-offline'}" data-ip="${esc(device.ip)}" tabindex="0">
      <td class="col-device">
        <div class="device-cell">
          <span class="device-icon kind-${esc(device.kind || 'device')}">${icon(device.kind || 'device')}</span>
          <span class="device-names">
            <span class="device-name">${esc(name)}</span>
            <span class="device-sub">${esc(sub || 'no details')}</span>
          </span>
        </div>
      </td>
      <td class="col-addr"><span class="ip">${esc(device.ip)}</span><span class="badges">${badges.join('')}</span></td>
      <td class="col-services"><div class="chips">${services}</div></td>
      <td class="col-latency"><span class="lat ${latencyClass}">${latencyText}</span></td>
      <td class="col-seen"><span class="ago" data-ts="${Number(device.last_seen) || 0}">${ago(device.last_seen)}</span></td>
      <td class="col-go">${CHEVRON}</td>
    </tr>`;
}

function renderFooter() {
  $('#version').textContent = state.version;
  if (state.host) {
    const bits = [state.host.name, state.host.system];
    if (state.host.android && state.host.system !== 'Android') bits.push('Android');
    $('#foot-host').textContent = bits.filter(Boolean).join(' · ');
  } else {
    $('#foot-host').textContent = '';
  }
  $('#state-path').textContent = state.statePath ? `inventory ${state.statePath}` : '';
}

/* ------------------------------------------------------------------ */
/* event center                                                        */
/* ------------------------------------------------------------------ */

const SEVERITY_RANK = { info: 0, notice: 1, warning: 2, critical: 3 };

function eventMatches(event) {
  const selected = state.events.severity || 'all';
  const severity = event.severity || 'info';
  if (selected === 'warning' && (SEVERITY_RANK[severity] || 0) < 2) return false;
  if (selected === 'warning-only' && severity !== 'warning') return false;
  if (['info', 'notice', 'critical'].includes(selected) && severity !== selected) return false;
  if (state.events.unreadOnly && event.read) return false;
  return true;
}

function eventHtml(event) {
  const severity = ['info', 'notice', 'warning', 'critical'].includes(event.severity)
    ? event.severity
    : 'info';
  const ip = event.device_ip ? String(event.device_ip) : '';
  const clickable = ip && state.devices.has(ip);
  const title = event.title || event.type || 'Event';
  return `<li class="event-item sev-${severity} ${event.read ? 'read' : 'unread'}" data-id="${esc(event.id || '')}"${clickable ? ` data-ip="${esc(ip)}"` : ''} tabindex="0">
      <span class="event-dot" aria-hidden="true"></span>
      <span class="event-main">
        <span class="event-title">${esc(title)}</span>
        ${event.message ? `<span class="event-message">${esc(event.message)}</span>` : ''}
        <span class="event-meta">${esc(SEVERITY_LABELS[severity] || severity)} · <span data-ts="${Number(event.ts) || 0}">${ago(event.ts)}</span>${ip ? ` · ${esc(ip)}` : ''}${event.type ? ` · ${esc(event.type)}` : ''}</span>
      </span>
    </li>`;
}

function renderEvents() {
  const list = $('#event-list');
  const empty = $('#event-empty');
  const hint = $('#event-hint');
  if (!list || !empty || !hint) return;
  const visible = (state.events.items || []).filter(eventMatches);
  list.innerHTML = visible.map(eventHtml).join('');
  empty.hidden = visible.length > 0;
  if (state.events.error) {
    empty.textContent = `Event log unavailable · ${state.events.error}`;
  } else if (state.events.items.length) {
    empty.textContent = 'No events match these filters.';
  } else {
    empty.textContent = 'No events yet. Scan twice to see changes between scans.';
  }
  const unread = Number(state.events.unread) || 0;
  const bits = [`${plural(visible.length, 'event')} shown`, `${unread} unread`];
  if (state.events.path) bits.push(`log ${state.events.path}`);
  hint.textContent = bits.join(' · ');
  const more = $('#events-load-more');
  if (more) more.hidden = !state.events.hasMore;
  const mark = $('#events-mark-read');
  if (mark) mark.disabled = unread === 0;
  renderEventBadge();
}

function acceptEvent(event) {
  if (!event) return;
  const items = state.events.items || [];
  const index = items.findIndex((item) => item.id != null && item.id === event.id);
  if (index >= 0) items[index] = { ...items[index], ...event };
  else {
    items.unshift(event);
    if (!event.read) state.events.unread = (Number(state.events.unread) || 0) + 1;
  }
  state.events.items = items.slice(0, 100);
  renderEvents();
}

async function loadEvents(reset = true, quiet = false) {
  const params = new URLSearchParams();
  params.set('limit', '50');
  const selected = state.events.severity || 'all';
  if (selected === 'warning') params.set('severity', 'warning,critical');
  else if (selected === 'warning-only') params.set('severity', 'warning');
  else if (selected !== 'all') params.set('severity', selected);
  if (state.events.unreadOnly) params.set('unread', '1');
  if (state.activeNetwork && state.activeNetwork.id) {
    params.set('network_id', state.activeNetwork.id);
  }
  if (!reset && state.events.items.length) {
    const last = state.events.items[state.events.items.length - 1];
    if (last && last.id) params.set('before_id', String(last.id));
  }
  try {
    const data = await api(`/api/event-log?${params.toString()}`);
    const incoming = data.events || [];
    if (reset) {
      state.events.items = incoming;
    } else {
      const known = new Set(state.events.items.map((item) => item.id));
      state.events.items = state.events.items.concat(incoming.filter((item) => !known.has(item.id)));
    }
    state.events.unread = Number(data.unread) || 0;
    state.events.hasMore = !!data.has_more;
    state.events.path = data.path || state.events.path;
    state.events.error = data.error || null;
  } catch (error) {
    state.events.error = error.message || 'unavailable';
    if (!quiet) toast(`Event log unavailable: ${state.events.error}`, 'error');
  }
  renderEvents();
}

function openEventCenter() {
  const dialog = $('#event-center');
  if (!dialog || dialog.open) return;
  if (typeof dialog.showModal === 'function') dialog.showModal();
  else dialog.setAttribute('open', '');
  loadEvents(true);
}

function closeEventCenter() {
  const dialog = $('#event-center');
  if (!dialog) return;
  if (typeof dialog.close === 'function') dialog.close();
  else dialog.removeAttribute('open');
}

async function markAllEventsRead() {
  try {
    const networkId = state.activeNetwork && state.activeNetwork.id;
    const data = await api('/api/event-log/read', { method: 'POST', body: { all: true, network_id: networkId || null } });
    state.events.unread = Number(data.unread) || 0;
    state.events.items = state.events.items.map((item) => ({ ...item, read: true, read_at: item.read_at || Date.now() / 1000 }));
    renderEvents();
    toast('Event log marked read');
  } catch (error) {
    toast(error.message || 'Could not update events', 'error');
  }
}

async function markEventRead(id, element) {
  if (!id) return;
  const item = state.events.items.find((event) => String(event.id) === String(id));
  if (!item || item.read) return;
  try {
    const networkId = state.activeNetwork && state.activeNetwork.id;
    const data = await api('/api/event-log/read', {
      method: 'POST',
      body: { ids: [Number(id)], network_id: networkId || null },
    });
    item.read = true;
    item.read_at = Date.now() / 1000;
    state.events.unread = Number(data.unread) || 0;
    if (element) element.classList.add('read');
    renderEventBadge();
  } catch (_) {
    /* reading an individual event is best effort */
  }
}

function onEventListClick(event) {
  const item = event.target.closest('.event-item[data-id]');
  if (!item) return;
  markEventRead(item.dataset.id, item);
  const ip = item.dataset.ip;
  if (ip && state.devices.has(ip)) {
    closeEventCenter();
    openDrawer(ip);
  }
}

async function loadLatestDiff() {
  if (state.scan.running) return;
  try {
    const data = await api('/api/scan/diff');
    state.latestDiff = data;
    renderDiff();
  } catch (_) {
    /* no scan yet, or history is unavailable */
  }
}

function setSync(connected) {
  const element = $('#sync');
  if (!element) return;
  state.connected = connected;
  element.className = `sync ${connected ? 'live' : 'off'}`;
  element.textContent = connected ? 'live' : 'reconnecting…';
}

/* ------------------------------------------------------------------ */
/* drawer                                                              */
/* ------------------------------------------------------------------ */

function openDrawer(ip) {
  const device = state.devices.get(ip);
  if (!device) return;
  state.drawerIp = ip;
  state.drawerDirty = false;
  $('#drawer-label').value = device.label || '';
  $('#drawer-notes').value = device.notes || '';
  $('#drawer-trust').value = device.trust || 'unknown';
  const drawer = $('#drawer');
  drawer.classList.add('open');
  drawer.setAttribute('aria-hidden', 'false');
  const backdrop = $('#backdrop');
  backdrop.hidden = false;
  requestAnimationFrame(() => backdrop.classList.add('show'));
  document.body.classList.add('drawer-open');
  renderDrawer(device);
  $('#drawer-close').focus({ preventScroll: true });
}

function closeDrawer() {
  state.drawerIp = null;
  state.drawerDirty = false;
  const drawer = $('#drawer');
  if (!drawer.classList.contains('open')) return;
  drawer.classList.remove('open');
  drawer.setAttribute('aria-hidden', 'true');
  document.body.classList.remove('drawer-open');
  const backdrop = $('#backdrop');
  backdrop.classList.remove('show');
  setTimeout(() => {
    if (!drawer.classList.contains('open')) backdrop.hidden = true;
  }, 220);
}

function renderDrawer(device) {
  $('#drawer-icon').className = `device-icon lg kind-${device.kind || 'device'}`;
  $('#drawer-icon').innerHTML = icon(device.kind || 'device');
  $('#drawer-title').textContent = device.name || device.hostname || 'Unknown device';
  $('#drawer-ip').textContent = device.ip;

  const badges = [];
  if (device.online) badges.push('<span class="badge self">online</span>');
  else badges.push('<span class="badge off">offline</span>');
  if (device.is_gateway) badges.push('<span class="badge gw">gateway</span>');
  if (device.is_self) badges.push('<span class="badge self">this device</span>');
  if (device.trust === 'trusted') badges.push('<span class="badge trusted">trusted</span>');
  else if (device.trust === 'ignored') badges.push('<span class="badge ignored">ignored</span>');
  badges.push(`<span class="badge">${esc(KIND_LABELS[device.kind] || device.kind || 'device')}${confidenceHtml(device)}</span>`);
  $('#drawer-badges').innerHTML = badges.join('');

  if (document.activeElement !== $('#drawer-label')) $('#drawer-label').value = device.label || '';
  if (document.activeElement !== $('#drawer-notes')) $('#drawer-notes').value = device.notes || '';
  if (document.activeElement !== $('#drawer-trust')) $('#drawer-trust').value = device.trust || 'unknown';
  renderDrawerStats(device);
}

function confidenceHtml(device) {
  const identity = device.identity;
  if (!identity || !identity.confidence || !KIND_LABELS[identity.kind]) return '';
  return `<span class="conf">${identity.confidence}%</span>`;
}

function renderDrawerStats(deviceArg) {
  const device = deviceArg || state.devices.get(state.drawerIp);
  if (!device) return;

  const identity = [];
  if (device.hostname) {
    identity.push(['Hostname', `${esc(device.hostname)} <span class="sub">via ${esc(device.hostname_source || 'unknown')}</span>`]);
  }
  if (device.nbns_name && device.nbns_name !== device.hostname) identity.push(['NetBIOS', esc(device.nbns_name)]);
  if (device.mac) identity.push(['MAC address', `<span class="mono">${esc(device.mac)}</span>`]);
  if (device.vendor) identity.push(['Vendor', esc(device.vendor)]);
  const fp = device.identity || {};
  identity.push(['Category', `${esc(KIND_LABELS[device.kind] || device.kind || 'device')}${confidenceHtml(device)}`]);
  if (fp.model) identity.push(['Model', esc(fp.model)]);
  if (fp.os) identity.push(['OS guess', esc(fp.os)]);
  if (device.ttl) identity.push(['TTL', String(device.ttl)]);
  identity.push(['Latency', device.rtt_ms == null ? '—' : `${Math.round(device.rtt_ms)} ms`]);
  identity.push(['First seen', `${esc(absolute(device.first_seen))} <span class="sub">${esc(ago(device.first_seen))}</span>`]);
  identity.push(['Last seen', `${esc(absolute(device.last_seen))} <span class="sub">${esc(ago(device.last_seen))}</span>`]);
  if (device.seen_count) identity.push(['Seen', `${device.seen_count} scan${device.seen_count === 1 ? '' : 's'}`]);
  if ((device.sources || []).length) identity.push(['Sources', esc(device.sources.join(', '))]);
  $('#drawer-identity').innerHTML = identity
    .map(([key, value]) => `<dt>${esc(key)}</dt><dd>${value}</dd>`)
    .join('');

  const ports = device.ports || [];
  const services = ports
    .map((port) => `<span class="chip" title="${esc(portTitle(device, port))}">${esc(portLabel(device, port))}</span>`)
    .join('');
  const mdns = (device.mdns_services || [])
    .map((service) => `<span class="chip" title="mDNS service">${esc(service)}</span>`)
    .join('');
  $('#drawer-services').innerHTML = services + mdns || '<span class="chip blank">no services seen</span>';

  const evidence = fp.evidence || [];
  $('#drawer-fp-section').hidden = evidence.length === 0;
  $('#drawer-evidence').innerHTML = evidence.map((line) => `<li>${esc(line)}</li>`).join('');

  const webRows = [];
  const webLabels = { title: 'Title', server: 'Server', realm: 'Login realm', cert_cn: 'Certificate', cert_org: 'Cert. organisation', powered_by: 'Powered by' };
  Object.keys(device.web || {}).sort((x, y) => Number(x) - Number(y)).forEach((port) => {
    const page = device.web[port] || {};
    Object.keys(webLabels).forEach((key) => {
      if (page[key]) webRows.push([`:${port} ${webLabels[key]}`, esc(page[key])]);
    });
  });
  $('#drawer-web-section').hidden = webRows.length === 0;
  $('#drawer-web').innerHTML = webRows.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${value}</dd>`).join('');

  const advertised = [];
  const ssdp = device.ssdp || {};
  const labels = {
    friendlyName: 'UPnP name',
    manufacturer: 'Manufacturer',
    model: 'Model',
    modelNumber: 'Model number',
    deviceType: 'Device type',
    server: 'Server',
  };
  Object.keys(labels).forEach((key) => {
    if (ssdp[key]) advertised.push([labels[key], esc(ssdp[key])]);
  });
  $('#drawer-adv-section').hidden = advertised.length === 0;
  $('#drawer-adv').innerHTML = advertised
    .map(([key, value]) => `<dt>${esc(key)}</dt><dd>${value}</dd>`)
    .join('');
}

/* ------------------------------------------------------------------ */
/* actions                                                             */
/* ------------------------------------------------------------------ */

async function startScan(payload = {}) {
  try {
    await api('/api/scan', { method: 'POST', body: payload });
  } catch (error) {
    toast(error.message || 'Could not start scan', 'error');
  }
}

async function stopScan() {
  try {
    const result = await api('/api/stop', { method: 'POST', body: {} });
    if (!result.stopped) toast('No scan is running', 'warn');
  } catch (error) {
    toast(error.message || 'Could not stop scan', 'error');
  }
}

async function saveDrawer() {
  const ip = state.drawerIp;
  if (!ip) return;
  const button = $('#drawer-save');
  const original = button.textContent;
  button.disabled = true;
  button.textContent = 'Saving…';
  try {
    const result = await api('/api/device', {
      method: 'POST',
      body: {
        ip,
        label: $('#drawer-label').value.trim(),
        notes: $('#drawer-notes').value.trim(),
        trust: $('#drawer-trust').value,
      },
    });
    upsertDevice(result.device);
    renderAll();
    renderDrawer(result.device);
    toast('Saved', 'success');
  } catch (error) {
    toast(error.message || 'Could not save', 'error');
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

async function probeDrawer() {
  const ip = state.drawerIp;
  if (!ip) return;
  const button = $('#drawer-probe');
  button.disabled = true;
  button.textContent = 'Probing…';
  try {
    const result = await api('/api/probe', { method: 'POST', body: { ip } });
    upsertDevice(result.device);
    renderAll();
    renderDrawer(result.device);
    toast(result.device.online ? `Reply from ${ip}` : `No reply from ${ip}`, result.device.online ? 'success' : 'warn');
  } catch (error) {
    toast(error.message || 'Probe failed', 'error');
  } finally {
    button.disabled = false;
    button.textContent = 'Probe now';
  }
}

async function forgetDrawer() {
  const ip = state.drawerIp;
  if (!ip) return;
  const device = state.devices.get(ip);
  const name = (device && device.name) || ip;
  if (!window.confirm(`Remove ${name} (${ip}) from the inventory?`)) return;
  try {
    await api('/api/forget', { method: 'POST', body: { ip } });
    state.devices.delete(ip);
    closeDrawer();
    renderAll();
    toast('Removed from inventory');
  } catch (error) {
    toast(error.message || 'Could not remove device', 'error');
  }
}

/* ------------------------------------------------------------------ */
/* settings dialog                                                     */
/* ------------------------------------------------------------------ */

function syncSubnetField() {
  $('#opt-subnet-field').hidden = $('#opt-target').value !== 'custom';
}

function openSettings() {
  const dialog = $('#settings');
  if (dialog.open) return;
  const target = $('#opt-target');
  target.innerHTML = '';
  target.add(new Option('Auto-detect (recommended)', 'auto'));
  (state.interfaces || []).forEach((iface) => {
    target.add(new Option(`${iface.name} · ${iface.cidr}`, iface.name));
  });
  target.add(new Option('Custom subnet…', 'custom'));

  const current = state.options.subnet || '';
  const interfaceNames = (state.interfaces || []).map((iface) => iface.name);
  if (!current) target.value = 'auto';
  else if (interfaceNames.includes(current)) target.value = current;
  else target.value = 'custom';
  $('#opt-subnet').value = current && !interfaceNames.includes(current) ? current : '';
  syncSubnetField();

  const ports = state.options.ports || [];
  $('#opt-ports').value = ports.length ? ports.join(',') : '';
  $('#opt-deep').checked = !!state.options.deep;
  $('#opt-http').checked = state.options.http !== false;
  $('#opt-mdns').checked = state.options.mdns !== false;
  $('#opt-ssdp').checked = state.options.ssdp !== false;
  $('#opt-nbns').checked = state.options.nbns !== false;
  $('#opt-rdns').checked = state.options.rdns !== false;
  $('#opt-timeout').value = state.options.ping_timeout ?? 1;
  $('#opt-concurrency').value = state.options.concurrency ?? 64;

  if (typeof dialog.showModal === 'function') dialog.showModal();
  else dialog.setAttribute('open', '');
}

function closeSettings() {
  const dialog = $('#settings');
  if (typeof dialog.close === 'function') dialog.close();
  else dialog.removeAttribute('open');
}

async function submitSettings(event) {
  event.preventDefault();
  const targetValue = $('#opt-target').value;
  let subnet = '';
  if (targetValue === 'custom') subnet = $('#opt-subnet').value.trim();
  else if (targetValue !== 'auto') subnet = targetValue;

  const payload = {
    subnet,
    deep: $('#opt-deep').checked,
    http: $('#opt-http').checked,
    mdns: $('#opt-mdns').checked,
    ssdp: $('#opt-ssdp').checked,
    nbns: $('#opt-nbns').checked,
    rdns: $('#opt-rdns').checked,
    ping_timeout: Number($('#opt-timeout').value) || 1,
    concurrency: Number($('#opt-concurrency').value) || 64,
  };
  payload.ports = $('#opt-ports').value.trim();

  closeSettings();
  await startScan(payload);
}

/* ------------------------------------------------------------------ */
/* networks                                                            */
/* ------------------------------------------------------------------ */

function openNetworks() {
  const dialog = $('#networks');
  if (dialog.open) return;
  renderNetworks();
  if (typeof dialog.showModal === 'function') dialog.showModal();
  else dialog.setAttribute('open', '');
}

function closeNetworks() {
  const dialog = $('#networks');
  if (typeof dialog.close === 'function') dialog.close();
  else dialog.removeAttribute('open');
}

function renderNetworks() {
  const list = $('#net-list');
  if (!list) return;
  const rows = state.networks.filter((n) => state.showArchived || !n.archived || n.active);
  $('#net-archived-toggle').hidden = !state.networks.some((n) => n.archived);
  if (!rows.length) {
    list.innerHTML = '<li class="dialog-note">No networks saved yet. Run a scan to create one.</li>';
    return;
  }
  const busy = state.scan.running;
  list.innerHTML = rows.map((net) => {
    const meta = [
      net.cidr || 'unknown subnet',
      plural(net.devices, 'device'),
      net.online ? `${net.online} online` : 'none online',
      net.gateway ? `gateway ${net.gateway}` : '',
      `seen ${ago(net.last_seen)}`,
    ].filter(Boolean).join(' · ');
    const id = esc(net.id);
    const actions = [];
    if (!net.active) {
      actions.push(`<button class="btn primary" data-act="select" data-id="${id}" ${busy ? 'disabled' : ''}>Switch</button>`);
    }
    actions.push(`<button class="btn ghost" data-act="rename" data-id="${id}">Rename</button>`);
    if (!net.active) {
      actions.push(`<button class="btn ghost" data-act="archive" data-id="${id}">${net.archived ? 'Restore' : 'Archive'}</button>`);
      actions.push(`<button class="btn ghost danger-text" data-act="delete" data-id="${id}">Delete</button>`);
    }
    return `<li class="net-item ${net.active ? 'active' : ''} ${net.archived ? 'archived' : ''}" data-id="${id}">
        <span class="net-title">${esc(net.title)}</span>
        ${net.active ? '<span class="badge self">active</span>' : net.archived ? '<span class="badge off">archived</span>' : '<span></span>'}
        <span class="net-meta">${esc(meta)}</span>
        <span class="net-actions">${actions.join('')}</span>
      </li>`;
  }).join('');
}

async function networkAction(action, id, extra = {}) {
  try {
    const result = await api(`/api/network/${action}`, { method: 'POST', body: { id, ...extra } });
    if (result.networks) state.networks = result.networks;
    if (action === 'select') {
      await loadState();
      closeNetworks();
      loadLatestDiff();
      loadEvents(true, true);
      toast('Switched network');
    } else {
      renderNetworks();
      renderNetwork();
    }
  } catch (error) {
    toast(error.message || 'Network action failed', 'error');
  }
}

function startRename(item) {
  const id = item.dataset.id;
  const net = state.networks.find((n) => n.id === id);
  if (!net || item.querySelector('.net-rename')) return;
  const input = document.createElement('input');
  input.className = 'net-rename';
  input.maxLength = 60;
  input.placeholder = 'e.g. Home Wi-Fi';
  input.value = net.label || '';
  item.appendChild(input);
  input.focus();
  const finish = (save) => {
    if (!input.isConnected) return;
    const value = input.value.trim();
    input.remove();
    if (save && value !== (net.label || '')) networkAction('rename', id, { label: value });
  };
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') { event.preventDefault(); finish(true); }
    if (event.key === 'Escape') { event.stopPropagation(); finish(false); }
  });
  input.addEventListener('blur', () => finish(true));
}

function onNetworkListClick(event) {
  const button = event.target.closest('button[data-act]');
  if (!button) return;
  const { act, id } = button.dataset;
  if (act === 'rename') startRename(button.closest('.net-item'));
  else if (act === 'select') networkAction('select', id);
  else if (act === 'archive') {
    const net = state.networks.find((n) => n.id === id);
    networkAction('archive', id, { archived: !(net && net.archived) });
  } else if (act === 'delete') {
    const net = state.networks.find((n) => n.id === id);
    const name = net ? net.title : 'this network';
    if (window.confirm(`Delete ${name} and its ${net ? plural(net.devices, 'saved device') : 'devices'}? This cannot be undone.`)) {
      networkAction('delete', id);
    }
  }
}

/* ------------------------------------------------------------------ */
/* preferences, auto scan, event stream                                */
/* ------------------------------------------------------------------ */

function loadPrefs() {
  try {
    const stored = JSON.parse(localStorage.getItem(PREFS_KEY) || '{}');
    Object.assign(state.prefs, stored || {});
  } catch (_) {
    /* ignore corrupt prefs */
  }
  state.prefs.showOffline = state.prefs.showOffline !== false;
  state.prefs.sort = ['ip', 'name', 'latency', 'seen', 'services'].includes(state.prefs.sort) ? state.prefs.sort : 'ip';
  state.prefs.autoInterval = [30, 60, 300, 900].includes(Number(state.prefs.autoInterval)) ? Number(state.prefs.autoInterval) : 60;
  state.prefs.autoScan = !!state.prefs.autoScan;
  state.prefs.trustFilter = ['all', 'trusted', 'unknown', 'ignored'].includes(state.prefs.trustFilter)
    ? state.prefs.trustFilter
    : 'all';
}

function savePrefs() {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(state.prefs));
  } catch (_) {
    /* private mode */
  }
}

function applyPrefs() {
  $('#show-offline').checked = state.prefs.showOffline;
  $('#trust-filter').value = state.prefs.trustFilter;
  $('#sort').value = state.prefs.sort;
  $('#auto-scan').checked = state.prefs.autoScan;
  $('#auto-interval').value = String(state.prefs.autoInterval);
  $('#auto-interval').disabled = !state.prefs.autoScan;
}

function setupAutoScan() {
  if (state.autoTimer) {
    clearInterval(state.autoTimer);
    state.autoTimer = null;
  }
  if (!state.prefs.autoScan) return;
  const interval = Math.max(15, state.prefs.autoInterval) * 1000;
  state.autoTimer = setInterval(() => {
    if (!state.scan.running) startScan({});
  }, interval);
}

function connectEvents() {
  if (!window.EventSource) return;
  const source = new EventSource('/api/events');
  source.onopen = () => setSync(true);
  source.onerror = () => setSync(false);
  source.onmessage = (message) => {
    let payload;
    try {
      payload = JSON.parse(message.data);
    } catch (_) {
      return;
    }
    handleEvent(payload);
  };
}

/* ------------------------------------------------------------------ */
/* events                                                              */
/* ------------------------------------------------------------------ */

function bindEvents() {
  $('#scan-btn').addEventListener('click', () => startScan({}));
  $('#stop-btn').addEventListener('click', stopScan);
  $('#empty-scan').addEventListener('click', (event) => {
    if (event.currentTarget.dataset.action === 'clear') {
      state.search = '';
      $('#search').value = '';
      state.prefs.showOffline = true;
      $('#show-offline').checked = true;
      state.prefs.trustFilter = 'all';
      $('#trust-filter').value = 'all';
      savePrefs();
      renderTable();
    } else {
      startScan({});
    }
  });

  $('#export-btn').addEventListener('click', (event) => {
    event.stopPropagation();
    const menu = $('#export-menu');
    const open = menu.hidden;
    menu.hidden = !open;
    $('#export-btn').setAttribute('aria-expanded', String(open));
  });
  document.addEventListener('click', () => {
    $('#export-menu').hidden = true;
    $('#export-btn').setAttribute('aria-expanded', 'false');
  });

  $('#settings-btn').addEventListener('click', openSettings);
  $('#net-chip').addEventListener('click', openNetworks);
  $('#networks-close').addEventListener('click', closeNetworks);
  $('#networks-done').addEventListener('click', closeNetworks);
  $('#networks-settings').addEventListener('click', () => {
    closeNetworks();
    openSettings();
  });
  $('#net-list').addEventListener('click', onNetworkListClick);
  $('#net-show-archived').addEventListener('change', (event) => {
    state.showArchived = event.target.checked;
    renderNetworks();
  });
  $('#settings-close').addEventListener('click', closeSettings);
  $('#settings-cancel').addEventListener('click', closeSettings);
  $('#settings-form').addEventListener('submit', submitSettings);
  $('#opt-target').addEventListener('change', syncSubnetField);

  $('#events-btn').addEventListener('click', openEventCenter);
  $('#events-close').addEventListener('click', closeEventCenter);
  $('#events-done').addEventListener('click', closeEventCenter);
  $('#events-mark-read').addEventListener('click', markAllEventsRead);
  $('#events-load-more').addEventListener('click', () => loadEvents(false));
  $('#event-list').addEventListener('click', onEventListClick);
  $('#event-list').addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const item = event.target.closest('.event-item[data-id]');
    if (!item) return;
    event.preventDefault();
    onEventListClick({ target: item });
  });
  $('#event-severity').addEventListener('change', (event) => {
    state.events.severity = event.target.value;
    loadEvents(true, true);
  });
  $('#event-unread').addEventListener('change', (event) => {
    state.events.unreadOnly = event.target.checked;
    loadEvents(true, true);
  });

  $('#search').addEventListener('input', (event) => {
    state.search = event.target.value;
    renderTable();
  });
  $('#show-offline').addEventListener('change', (event) => {
    state.prefs.showOffline = event.target.checked;
    savePrefs();
    renderTable();
  });
  $('#trust-filter').addEventListener('change', (event) => {
    state.prefs.trustFilter = event.target.value;
    savePrefs();
    renderTable();
  });
  $('#sort').addEventListener('change', (event) => {
    state.prefs.sort = event.target.value;
    savePrefs();
    renderTable();
  });
  $('#auto-scan').addEventListener('change', (event) => {
    state.prefs.autoScan = event.target.checked;
    $('#auto-interval').disabled = !state.prefs.autoScan;
    savePrefs();
    setupAutoScan();
    toast(state.prefs.autoScan ? `Auto-scan every ${state.prefs.autoInterval}s` : 'Auto-scan off');
  });
  $('#auto-interval').addEventListener('change', (event) => {
    state.prefs.autoInterval = Number(event.target.value) || 60;
    savePrefs();
    setupAutoScan();
  });

  $('#device-rows').addEventListener('click', (event) => {
    const row = event.target.closest('tr[data-ip]');
    if (row) openDrawer(row.dataset.ip);
  });
  $('#device-rows').addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const row = event.target.closest('tr[data-ip]');
    if (!row) return;
    event.preventDefault();
    openDrawer(row.dataset.ip);
  });

  $('#drawer-close').addEventListener('click', closeDrawer);
  $('#backdrop').addEventListener('click', closeDrawer);
  $('#drawer-save').addEventListener('click', saveDrawer);
  $('#drawer-probe').addEventListener('click', probeDrawer);
  $('#drawer-forget').addEventListener('click', forgetDrawer);
  $('#drawer-ip').addEventListener('click', async () => {
    const ip = state.drawerIp;
    if (!ip) return;
    try {
      await navigator.clipboard.writeText(ip);
      toast('IP address copied');
    } catch (_) {
      toast(ip);
    }
  });
  $('#drawer-label').addEventListener('input', () => {
    state.drawerDirty = true;
  });
  $('#drawer-notes').addEventListener('input', () => {
    state.drawerDirty = true;
  });
  $('#drawer-trust').addEventListener('change', () => {
    state.drawerDirty = true;
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      if ($('#drawer').classList.contains('open')) closeDrawer();
      return;
    }
    const tag = (document.activeElement && document.activeElement.tagName) || '';
    if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(tag)) {
      event.preventDefault();
      $('#search').focus();
      $('#search').select();
    }
  });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      loadState();
      loadHistory();
      loadLatestDiff();
      if ($('#event-center') && $('#event-center').open) loadEvents(true, true);
    }
  });
}

/* ------------------------------------------------------------------ */
/* boot                                                                */
/* ------------------------------------------------------------------ */

async function loadState() {
  try {
    const data = await api('/api/state');
    applySnapshot(data);
  } catch (error) {
    setSync(false);
    toast(`Cannot reach lanwatch: ${error.message}`, 'error');
  }
}

async function loadHistory() {
  try {
    const data = await api('/api/history?limit=12');
    state.history.scans = data.scans || [];
    state.history.path = data.path || state.history.path;
    state.history.error = data.error || null;
  } catch (error) {
    state.history.error = error.message || 'unavailable';
  }
  renderHistory();
}

function tick() {
  $$('[data-ts]').forEach((element) => {
    const timestamp = Number(element.dataset.ts);
    if (timestamp) element.textContent = ago(timestamp);
  });
  if (document.activeElement) {
    const tag = document.activeElement.tagName;
    if (['INPUT', 'TEXTAREA'].includes(tag)) return;
  }
  renderScan();
  renderStats();
}

async function init() {
  loadPrefs();
  applyPrefs();
  bindEvents();
  setupAutoScan();
  await Promise.all([loadState(), loadHistory()]);
  loadLatestDiff();
  connectEvents();
  setInterval(tick, 1000);
}

document.addEventListener('DOMContentLoaded', init);
