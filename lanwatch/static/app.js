'use strict';

/* lanwatch dashboard
 * Plain ES2020, no build step.  The server is the source of truth; SSE events
 * arrive for every device change and the UI re-renders from the local map.
 */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const PREFS_KEY = 'lanwatch.prefs.v1';
const TRUST_GUIDE_KEY = 'lanwatch.trustGuideDismissed.v1';
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

const EVENT_ICONS = {
  'device.new': '<circle cx="12" cy="12" r="8.5" opacity=".28"/><path d="M12 8v8M8 12h8"/>',
  'device.online': '<path d="M4.5 12.5a7.5 7.5 0 0 1 15 0"/><path d="M8 15.5a4 4 0 0 1 8 0"/><circle cx="12" cy="19" r="1.2" fill="currentColor" stroke="none"/>',
  'device.offline': '<path d="M5 5l14 14"/><path d="M4.5 12.5a7.5 7.5 0 0 1 13.2-4.9M19.5 12.5a7.5 7.5 0 0 1-9.8 7.1"/><circle cx="12" cy="19" r="1.2" fill="currentColor" stroke="none"/>',
  'device.hostname_changed': '<path d="M4 7h9a4 4 0 0 1 0 8H9"/><path d="M7 4L4 7l3 3"/><path d="M17 20h3"/>',
  'device.vendor_changed': '<path d="M4 5h16v14H4z"/><path d="M8 9h8M8 13h5"/>',
  'device.kind_changed': '<rect x="3" y="5" width="8" height="8" rx="1.5"/><rect x="13" y="11" width="8" height="8" rx="1.5"/><path d="M6 17h6M15 7h6"/>',
  'port.opened': '<path d="M8 12H3M8 8v8M16 8v8M8 12h8"/><path d="M16 9.5l4 2.5-4 2.5"/>',
  'port.closed': '<path d="M8 12H3M8 8v8M16 8v8M8 12h5"/><path d="M17 9.5l3 2.5-3 2.5" opacity=".45"/>',
  'scan.completed': '<circle cx="12" cy="12" r="8.5"/><path d="M7.8 12.2l2.8 2.8 5.6-5.8"/>',
  'scan.failed': '<path d="M12 3.5L21 20H3z"/><path d="M12 9v5"/><circle cx="12" cy="17.3" r=".9" fill="currentColor" stroke="none"/>',
  'device.ip_changed': '<path d="M4 8h14M15 5l3 3-3 3M20 16H6M9 13l-3 3 3 3"/>',
  'device.replaced': '<path d="M12 3l7 3v5c0 4.7-3 8.2-7 10-4-1.8-7-5.3-7-10V6z"/><path d="M9 9.5l6 5M15 9.5l-6 5"/>',
  'device.trust_changed': '<path d="M12 3l7 3v5c0 4.7-3 8.2-7 10-4-1.8-7-5.3-7-10V6z"/><path d="M8.7 12.2l2.2 2.2 4.4-4.6"/>',
};
const PANEL_EVENT_LIMIT = 6;
const EVENT_SEVERITIES = ['all', 'info', 'warning', 'critical'];
const EVENT_TYPE_LABELS = {
  'device.new': 'New device',
  'device.online': 'Back online',
  'device.offline': 'Went offline',
  'device.hostname_changed': 'Name changed',
  'device.vendor_changed': 'Vendor changed',
  'device.kind_changed': 'Device type changed',
  'port.opened': 'Service opened',
  'port.closed': 'Service closed',
  'scan.completed': 'Scan completed',
  'scan.failed': 'Scan failed',
  'device.ip_changed': 'Address changed',
  'device.replaced': 'Identity changed',
  'device.trust_changed': 'Trust changed',
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
  helloSeen: false,
  stateRequestId: 0,
  diffRequestId: 0,
  drawerIp: null,
  drawerDirty: false,
  autoTimer: null,
  renderQueued: false,
  search: '',
  latestDiff: null,
  diffError: null,
  newDevices: new Set(),
  prefsWarned: false,
  history: { scans: [], path: '', error: null },
  events: {
    items: [],
    unread: 0,
    path: '',
    error: null,
    loading: true,
    severity: 'all',
    device: '',
    unreadOnly: false,
    hasMore: false,
    requestId: 0,
    retention: { max_events: 0, max_event_age_days: 0 },
  },
  prefs: { showOffline: true, sort: 'ip', autoScan: false, autoInterval: 60, trustFilter: 'all' },
};

const TRUST_LABELS = { trusted: 'Trusted', unknown: 'Unknown', ignored: 'Ignored' };
const TRUST_HELP = {
  trusted: 'A device you recognize and expect on this network. If it goes offline, the change is treated as a warning.',
  unknown: 'Seen on this network but not reviewed yet. New devices start here; changes are recorded normally.',
  ignored: 'Kept in the inventory, but its changes are left out of events and alerts.',
};
const SEVERITY_LABELS = { info: 'Info', warning: 'Warning', critical: 'Critical' };

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

function eventIcon(type) {
  const body = EVENT_ICONS[type] || EVENT_ICONS['scan.completed'];
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
}

function normalizeSeverity(value) {
  return value === 'warning' || value === 'critical' ? value : 'info';
}

function setNewDevices(diff) {
  const next = new Set();
  if (diff && !diff.baseline && !diff.partial) {
    (diff.new_ips || []).forEach((ip) => {
      if (ip) next.add(String(ip));
    });
  }
  state.newDevices = next;
}

function deviceLabel(device, ip) {
  if (device) return device.name || device.hostname || device.label || ip;
  const known = state.devices.get(ip);
  return known ? known.name || known.hostname || known.label || ip : ip;
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

function trustBadge(trust) {
  const level = TRUST_LABELS[trust] ? trust : 'unknown';
  return `<span class="badge ${esc(level)}" title="${esc(TRUST_HELP[level])}">${esc(TRUST_LABELS[level])}</span>`;
}

function eventTypeLabel(type) {
  return EVENT_TYPE_LABELS[type] || String(type || 'event').replace(/[._]/g, ' ');
}

function retentionText() {
  const retention = state.events.retention || {};
  const maxEvents = Number(retention.max_events) || 0;
  const maxDays = Number(retention.max_event_age_days) || 0;
  const limits = [];
  if (maxEvents > 0) limits.push(`up to ${maxEvents.toLocaleString()} events`);
  if (maxDays > 0) limits.push(`${maxDays} days`);
  return limits.length ? `Kept on this device: ${limits.join(' or ')}.` : 'Events are kept on this device.';
}

function readTrustGuideDismissed() {
  try {
    return localStorage.getItem(TRUST_GUIDE_KEY) === '1';
  } catch (error) {
    console.warn('lanwatch: could not read local preferences', error);
    return false;
  }
}

function setTrustGuideVisible(visible, scroll = false) {
  const guide = $('#trust-guide');
  if (!guide) return;
  guide.hidden = !visible;
  if (visible && scroll) {
    const target = $('#trust-guide-title');
    if (target) target.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
}

function dismissTrustGuide() {
  setTrustGuideVisible(false);
  try {
    localStorage.setItem(TRUST_GUIDE_KEY, '1');
  } catch (error) {
    console.warn('lanwatch: could not remember the trust guide was dismissed', error);
  }
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
  } catch (error) {
    if (response.ok) console.warn('lanwatch: server returned an unreadable response', error);
    data = null;
  }
  if (!response.ok) {
    const error = new Error((data && data.error) || `Request failed (${response.status})`);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data || {};
}

function toast(message, kind = '') {
  const host = $('#toasts');
  if (!host) return;
  const element = document.createElement('div');
  element.className = 'toast' + (kind ? ` ${kind}` : '');
  element.setAttribute('role', kind === 'error' ? 'alert' : 'status');
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

function activeNetworkId() {
  return state.activeNetwork && state.activeNetwork.id ? String(state.activeNetwork.id) : '';
}

function eventMatchesActiveNetwork(event) {
  const active = activeNetworkId();
  const network = event && event.network_id;
  return !active || !network || String(network) === active;
}

function applySnapshot(data) {
  const previousActive = activeNetworkId();
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
  if (previousActive !== activeNetworkId() && state.drawerIp) closeDrawer();
  if (data.history) {
    state.history.path = data.history.path || '';
    state.history.error = data.history.error || null;
  }
  if (data.events) {
    state.events.path = data.events.path || state.events.path;
    state.events.error = data.events.error || null;
    state.events.unread = Number(data.events.unread) || 0;
    if (data.events.retention) state.events.retention = data.events.retention;
  }
  const latestDiff = data.latest_diff || null;
  state.latestDiff = latestDiff && eventMatchesActiveNetwork(latestDiff) ? latestDiff : null;
  if (state.latestDiff) state.diffError = null;
  setNewDevices(state.latestDiff);
  renderAll();
}

function handleEvent(event) {
  switch (event.type) {
    case 'hello': {
      const reconnected = state.helloSeen;
      state.helloSeen = true;
      if (event.state) state.scan = event.state;
      if (event.unread != null) state.events.unread = Number(event.unread) || 0;
      if (event.latest_diff && eventMatchesActiveNetwork(event.latest_diff)) {
        state.latestDiff = event.latest_diff;
        setNewDevices(state.latestDiff);
      }
      setSync(true);
      if (reconnected) {
        // The stream may have been down while another tab switched networks or
        // a scan finished.  Reload everything the snapshot owns.
        loadHistory();
        loadState().then(() => {
          loadLatestDiff();
          loadEvents(true, true);
        });
      }
      break;
    }
    case 'scan.started':
      if (event.state) state.scan = event.state;
      if (event.network) state.network = event.network;
      if (event.options) state.options = event.options;
      state.latestDiff = null;
      state.newDevices = new Set();
      state.diffError = null;
      state.diffRequestId += 1;
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
    case 'network.changed': {
      const previousActive = state.activeNetwork ? state.activeNetwork.id : null;
      state.networks = event.networks || state.networks;
      const nextActive = event.active || null;
      if (previousActive !== nextActive) {
        // Update the active id before reloading so event and diff responses are
        // filtered against the network that is actually active now.
        state.activeNetwork = state.networks.find((network) => network.id === nextActive) || null;
        if (state.network && state.network.network_id !== nextActive) state.network = null;
        if (state.drawerIp) closeDrawer();
        state.devices = new Map();
        state.events.device = '';
        state.events.items = [];
        state.events.unread = 0;
        state.events.hasMore = false;
        state.events.error = null;
        state.latestDiff = null;
        state.diffError = null;
        state.newDevices = new Set();
        loadState();
        loadLatestDiff();
        loadEvents(true, true);
      }
      renderNetworks();
      break;
    }
    case 'device':
      upsertDevice(event.device);
      if (state.drawerIp === (event.device && event.device.ip)) renderDrawerStats();
      break;
    case 'device.removed':
      state.devices.delete(event.ip);
      state.newDevices.delete(event.ip);
      if (state.drawerIp === event.ip) closeDrawer();
      break;
    case 'scan.diff': {
      const diff = event.diff || event;
      if (!eventMatchesActiveNetwork(diff)) break;
      state.latestDiff = diff;
      state.diffError = null;
      setNewDevices(state.latestDiff);
      announceDiff(state.latestDiff);
      if ($('#event-center') && $('#event-center').open) loadEvents(true, true);
      break;
    }
    case 'event.new': {
      // Event files are already persisted server-side.  Update just the event
      // panel and dialog instead of repainting the whole dashboard.
      const incoming = event.event || event;
      if (!eventMatchesActiveNetwork(incoming)) return;
      acceptEvent(incoming);
      return;
    }
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
  renderEventViews();
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
  else if (state.scan.phase === 'error') dot.classList.add('error');
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
  const failed = !running && (phase === 'error' || !!scan.error);
  const pulse = $('#scan-pulse');
  const bar = $('#progress-bar');
  const track = bar.parentElement;
  const panel = $('#scan-panel');

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
  else if (failed) pulse.classList.add('error');
  if (panel) panel.classList.toggle('scan-panel--error', failed);

  const errorBox = $('#scan-error');
  if (errorBox) {
    errorBox.hidden = !failed;
    if (failed) {
      const text = scan.error || scan.message || 'The scan stopped before it could finish.';
      const target = $('#scan-error-text');
      if (target && target.textContent !== text) target.textContent = text;
      errorBox.title = text;
    }
  }

  track.classList.remove('indeterminate');
  let percent = phase === 'done' ? 100 : 0;
  if (running) {
    if (scan.total > 0 && scan.done > 0) {
      percent = Math.max(2, Math.min(100, (scan.done / scan.total) * 100));
      bar.style.width = `${percent}%`;
    } else {
      track.classList.add('indeterminate');
      bar.style.width = '';
    }
  } else {
    bar.style.width = `${percent}%`;
  }
  track.setAttribute('aria-valuenow', String(Math.round(percent)));
  track.setAttribute('aria-valuetext', running ? 'scan in progress' : phase === 'done' ? 'scan complete' : 'scan idle');

  $('#scan-btn').hidden = running;
  $('#stop-btn').hidden = !running;
}

function diffParts(diff) {
  const counts = (diff && diff.counts) || {};
  const parts = [];
  const add = (key, singular, pluralLabel, value) => {
    const number = Number(value) || 0;
    if (number > 0) parts.push({ key, label: number === 1 ? singular : pluralLabel, value: number });
  };

  add('new', 'new device', 'new devices', counts.new);
  add('returned', 'back online', 'back online', counts.returned);
  add('offline', 'went offline', 'went offline', counts.offline);

  let portsAdded = 0;
  let portsRemoved = 0;
  let infoChanges = 0;
  (diff && diff.changes ? diff.changes : []).forEach((change) => {
    const details = (change && change.details) || {};
    portsAdded += Array.isArray(details.ports_added) ? details.ports_added.length : 0;
    portsRemoved += Array.isArray(details.ports_removed) ? details.ports_removed.length : 0;
    const fields = Array.isArray(details.fields) ? details.fields : [];
    if (
      fields.some((field) => ['hostname', 'vendor', 'type'].includes(field)) ||
      ['device.ip_changed', 'device.replaced'].includes(change.event_type)
    ) {
      infoChanges += 1;
    }
  });
  add('ports_added', 'new service', 'new services', portsAdded);
  add('ports_removed', 'closed service', 'closed services', portsRemoved);
  if (!portsAdded && !portsRemoved && !infoChanges) {
    // Older or partial comparison payloads may not carry details.
    infoChanges = Number(counts.changed) || 0;
  }
  add('info', 'detail changed', 'details changed', infoChanges);
  return parts;
}

function diffSummary(diff) {
  const parts = diffParts(diff);
  if (!parts.length) return 'No changes since the previous scan.';
  return `Since the last scan: ${parts.map((part) => `${part.value} ${part.label}`).join(', ')}.`;
}

function renderDiff() {
  const host = $('#scan-diff');
  if (!host) return;
  const diff = state.latestDiff;
  if (!diff || state.scan.running) {
    if (!diff && state.diffError && !state.scan.running) {
      host.hidden = false;
      host.className = 'scan-diff partial';
      host.innerHTML = `<span class="diff-tag">comparison</span><span class="diff-copy">Could not load the latest changes · ${esc(state.diffError)}</span>`;
      return;
    }
    host.hidden = true;
    host.innerHTML = '';
    host.removeAttribute('title');
    host.removeAttribute('aria-label');
    return;
  }
  host.hidden = false;
  host.className = 'scan-diff';
  host.title = '';
  host.setAttribute('aria-label', diffSummary(diff));
  if (diff.baseline) {
    host.classList.add('baseline');
    host.innerHTML = `<span class="diff-tag">baseline</span><span class="diff-copy">${plural(Number(diff.current_devices) || 0, 'device')} recorded. The next scan will show what changed.</span>`;
    return;
  }
  if (diff.partial) {
    host.classList.add('partial');
    host.innerHTML = '<span class="diff-tag">partial</span><span class="diff-copy">Scan stopped early, so no comparison was saved.</span>';
    return;
  }
  const parts = diffParts(diff);
  if (!parts.length) {
    host.classList.add('quiet');
    host.innerHTML = '<span class="diff-tag">unchanged</span><span class="diff-copy">No changes — the devices and services look the same as the previous scan.</span>';
    return;
  }
  const titles = (diff.changes || []).map((change) => change.title).filter(Boolean).slice(0, 6).join('\n');
  host.title = titles || diffSummary(diff);
  host.innerHTML = `<span class="diff-tag">since last scan</span>${parts
    .map((part) => `<span class="diff-pill ${esc(part.key)}"><b>${part.value}</b> ${esc(part.label)}</span>`)
    .join('')}`;
}

function announceDiff(diff) {
  if (!diff || !diff.counts || diff.baseline || diff.partial) return;
  const newIps = (diff.new_ips || []).map(String).filter(Boolean);
  if (newIps.length) {
    if (newIps.length === 1) {
      const ip = newIps[0];
      const label = deviceLabel(null, ip);
      toast(`New device detected · ${label}${label === ip ? '' : ` (${ip})`}`, 'new');
    } else {
      toast(`${plural(newIps.length, 'new device')} detected on this network`, 'new');
    }
    return;
  }
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
  badge.setAttribute('aria-hidden', 'true');
  const button = $('#events-btn');
  if (button) {
    button.title = unread ? `Event center · ${plural(unread, 'unread event')}` : 'Event center';
    button.setAttribute('aria-label', unread ? `Event center, ${plural(unread, 'unread event')}` : 'Event center');
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
  if (trustFilter !== 'all') {
    list = list.filter((device) => (device.trust || 'unknown') === trustFilter);
  }
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
          ? `No ${TRUST_LABELS[trustFilter] || trustFilter} devices right now. ${TRUST_HELP[trustFilter] || ''}`.trim()
          : 'Offline devices are hidden. Turn on “Offline” to show them.';
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
        const statusLabel = { ok: 'complete', stopped: 'stopped', error: 'failed' }[status];
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
          : `${Number(scan.new_devices) || 0} new · ${Number(scan.returned_devices) || 0} back online · ${Number(scan.offline_devices) || 0} offline · ${Number(scan.changed_devices) || 0} changed`;
        return `<tr title="${esc(absolute(scan.finished_at))}">
          <td><span data-ts="${Number(scan.finished_at) || 0}">${ago(scan.finished_at)}</span></td>
          <td class="mono col-history-network">${esc(scan.subnet || '—')}</td>
          <td class="num">${found}</td>
          <td class="num col-history-up">${up}</td>
          <td class="col-history-duration">${formatDuration(scan.duration_s)}</td>
          <td class="num col-history-changes" title="${esc(changeTitle)}">${changeText}</td>
          <td><span class="status ${status}">${statusLabel}</span></td>
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

  const isNew = state.newDevices.has(device.ip);
  const badges = [];
  if (isNew) badges.push('<span class="badge new">new</span>');
  if (device.is_gateway) badges.push('<span class="badge gw">gateway</span>');
  if (device.is_self) badges.push('<span class="badge self">this device</span>');
  badges.push(trustBadge(device.trust || 'unknown'));
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

  return `<tr class="device-row ${online ? '' : 'is-offline'} ${isNew ? 'is-new' : ''}" data-ip="${esc(device.ip)}" tabindex="0">
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

function eventSeverity(event) {
  return normalizeSeverity(event && event.severity);
}

function eventMatches(event) {
  const selected = EVENT_SEVERITIES.includes(state.events.severity) ? state.events.severity : 'all';
  if (selected !== 'all' && eventSeverity(event) !== selected) return false;
  if (state.events.device && String(event.device_ip || '') !== state.events.device) return false;
  if (state.events.unreadOnly && event.read) return false;
  return true;
}

function filteredEvents() {
  return (state.events.items || []).filter(eventMatches);
}

function eventDeviceText(event) {
  const ip = event.device_ip ? String(event.device_ip) : '';
  const name = event.device_name ? String(event.device_name) : ip ? deviceLabel(null, ip) : '';
  if (name && ip && name !== ip) return `${name} (${ip})`;
  return name || ip;
}

function eventHtml(event) {
  const severity = eventSeverity(event);
  const ip = event.device_ip ? String(event.device_ip) : '';
  const clickable = ip && state.devices.has(ip);
  const title = event.title || event.type || 'Event';
  const description = event.message || event.description || '';
  const type = event.type || 'event';
  const device = eventDeviceText(event);
  const meta = [];
  if (device) meta.push(`<span class="event-device">${esc(device)}</span>`);
  meta.push(`<span class="event-time" data-ts="${Number(event.ts) || 0}">${esc(ago(event.ts))}</span>`);
  if (type) meta.push(`<span class="event-type" title="${esc(type)}">${esc(eventTypeLabel(type))}</span>`);
  return `<li class="event-item sev-${severity} ${event.read ? 'read' : 'unread'}" data-id="${esc(event.id || '')}"${clickable ? ` data-ip="${esc(ip)}"` : ''} tabindex="0" title="${esc(description || title)}">
      <span class="event-icon sev-${severity}" aria-hidden="true">${eventIcon(event.type)}</span>
      <span class="event-main">
        <span class="event-top">
          <span class="event-title">${esc(title)}</span>
          <span class="event-sev sev-${severity}">${esc(SEVERITY_LABELS[severity] || severity)}</span>
        </span>
        ${description ? `<span class="event-message">${esc(description)}</span>` : ''}
        <span class="event-meta">${meta.join('<span class="event-meta-sep" aria-hidden="true">·</span>')}</span>
      </span>
    </li>`;
}

function eventStatusHtml(visibleCount) {
  if (state.events.loading) {
    return `<span class="spinner" aria-hidden="true"></span><span>${state.events.items.length ? 'Refreshing events…' : 'Loading events…'}</span>`;
  }
  if (state.events.error) {
    return `<div class="event-empty"><strong>Event log unavailable</strong><span>${esc(state.events.error)}</span><button class="btn ghost small" type="button" data-act="refresh-events">Retry</button></div>`;
  }
  const filtering = state.events.severity !== 'all' || !!state.events.device || state.events.unreadOnly;
  if (!state.events.items.length) {
    if (filtering) {
      return '<div class="event-empty"><strong>No events match these filters</strong><span>Try “All” or choose another device.</span><button class="btn ghost small" type="button" data-act="clear-event-filters">Clear filters</button></div>';
    }
    if (state.scan.running) {
      return '<div class="event-empty"><strong>Scanning…</strong><span>Changes appear after the scan finishes and is compared with the previous one.</span></div>';
    }
    return `<div class="event-empty"><strong>No events yet</strong><span>lanwatch records changes after each completed scan. Run a scan, then run another one to see what changed.</span><span class="event-empty-note">${esc(retentionText())}</span><button class="btn ghost small" type="button" data-act="scan-now">Scan now</button></div>`;
  }
  if (!visibleCount) {
    return '<div class="event-empty"><strong>No events match these filters</strong><span>Your event log has other entries. Try “All” or clear the device filter.</span><button class="btn ghost small" type="button" data-act="clear-event-filters">Clear filters</button></div>';
  }
  return '';
}

function updateEventDeviceFilter(select) {
  if (!select) return;
  const selected = state.events.device || '';
  const devices = deviceList().sort(comparator('name'));
  const signature = [selected, ...devices.map((device) => `${device.ip}:${device.name || ''}:${device.hostname || ''}:${device.label || ''}`)].join('|');
  if (select.dataset.signature !== signature) {
    const options = ['<option value="">All devices</option>'];
    if (selected && !devices.some((device) => device.ip === selected)) {
      options.push(`<option value="${esc(selected)}">${esc(selected)} (not in inventory)</option>`);
    }
    devices.forEach((device) => {
      const name = device.name || device.hostname || device.label || device.ip;
      const label = name === device.ip ? name : `${name} · ${device.ip}`;
      options.push(`<option value="${esc(device.ip)}">${esc(label)}</option>`);
    });
    select.innerHTML = options.join('');
    select.dataset.signature = signature;
  }
  select.value = selected;
}

function syncEventControls() {
  const selected = EVENT_SEVERITIES.includes(state.events.severity) ? state.events.severity : 'all';
  state.events.severity = selected;
  $$('#event-severity-chips [data-severity]').forEach((button) => {
    const active = button.dataset.severity === selected;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  });
  const severitySelect = $('#event-severity');
  if (severitySelect) severitySelect.value = selected;
  const unread = $('#event-unread');
  if (unread) unread.checked = !!state.events.unreadOnly;
  updateEventDeviceFilter($('#event-device-filter'));
  updateEventDeviceFilter($('#event-device-filter-modal'));
}

function renderEventPanel() {
  const list = $('#events-panel-list');
  const status = $('#events-panel-status');
  const hint = $('#events-panel-hint');
  const sub = $('#events-panel-sub');
  if (!list || !status || !hint) return;
  const visible = filteredEvents();
  const shown = visible.slice(0, PANEL_EVENT_LIMIT);
  list.innerHTML = shown.map(eventHtml).join('');
  list.hidden = shown.length === 0;
  list.setAttribute('aria-busy', state.events.loading ? 'true' : 'false');
  const statusHtml = eventStatusHtml(visible.length);
  status.innerHTML = statusHtml;
  status.hidden = !statusHtml;
  const unread = Number(state.events.unread) || 0;
  if (sub) {
    sub.textContent = unread
      ? `${plural(unread, 'unread event')} · latest activity`
      : 'Recent network activity';
  }
  const bits = [`${plural(visible.length, 'event')} loaded`, `${unread} unread`];
  if (state.events.unreadOnly) bits.push('unread only');
  if (visible.length > shown.length) bits.push(`showing latest ${PANEL_EVENT_LIMIT}`);
  if (!visible.length && !state.events.loading && !state.events.error) bits.push(retentionText());
  hint.textContent = bits.join(' · ');
}

function renderEvents() {
  const list = $('#event-list');
  const status = $('#event-status');
  const hint = $('#event-hint');
  if (!list || !status || !hint) return;
  const visible = filteredEvents();
  list.innerHTML = visible.map(eventHtml).join('');
  list.hidden = visible.length === 0;
  list.setAttribute('aria-busy', state.events.loading ? 'true' : 'false');
  const statusHtml = eventStatusHtml(visible.length);
  status.innerHTML = statusHtml;
  status.hidden = !statusHtml;
  const unread = Number(state.events.unread) || 0;
  const bits = [`${plural(visible.length, 'event')} shown`, `${unread} unread`];
  if (state.events.path) bits.push(`log ${state.events.path}`);
  if (!visible.length && !state.events.loading && !state.events.error) bits.push(retentionText());
  hint.textContent = bits.join(' · ');
  const more = $('#events-load-more');
  if (more) more.hidden = !state.events.hasMore;
  const mark = $('#events-mark-read');
  if (mark) mark.disabled = unread === 0;
}

function renderEventViews() {
  syncEventControls();
  renderEventPanel();
  const dialog = $('#event-center');
  if (dialog && dialog.open) renderEvents();
  renderEventBadge();
}

function acceptEvent(event) {
  if (!event) return;
  const incoming = { ...event, severity: eventSeverity(event) };
  const items = state.events.items || [];
  const index = items.findIndex((item) => item.id != null && incoming.id != null && item.id === incoming.id);
  if (index >= 0) {
    items[index] = { ...items[index], ...incoming };
  } else {
    items.unshift(incoming);
    if (!incoming.read) state.events.unread = (Number(state.events.unread) || 0) + 1;
  }
  state.events.items = items.slice(0, 100);
  renderEventViews();
}

async function loadEvents(reset = true, quiet = false) {
  const requestId = ++state.events.requestId;
  const params = new URLSearchParams();
  params.set('limit', '50');
  const selected = EVENT_SEVERITIES.includes(state.events.severity) ? state.events.severity : 'all';
  if (selected !== 'all') params.set('severity', selected);
  if (state.events.device) params.set('device', state.events.device);
  if (state.events.unreadOnly) params.set('unread', '1');
  if (state.activeNetwork && state.activeNetwork.id) {
    params.set('network_id', state.activeNetwork.id);
  }
  if (!reset && state.events.items.length) {
    const last = state.events.items[state.events.items.length - 1];
    if (last && last.id) params.set('before_id', String(last.id));
  }
  state.events.loading = true;
  renderEventViews();
  try {
    const data = await api(`/api/event-log?${params.toString()}`);
    if (requestId !== state.events.requestId) return;
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
    if (data.retention) state.events.retention = data.retention;
  } catch (error) {
    if (requestId !== state.events.requestId) return;
    state.events.error = error.message || 'unavailable';
    console.warn('lanwatch: event log could not be loaded', error);
    if (!quiet) toast(`Event log unavailable: ${state.events.error}`, 'error');
  } finally {
    if (requestId === state.events.requestId) {
      state.events.loading = false;
      renderEventViews();
    }
  }
}

function openEventCenter() {
  const dialog = $('#event-center');
  if (!dialog || dialog.open) return;
  if (typeof dialog.showModal === 'function') dialog.showModal();
  else dialog.setAttribute('open', '');
  renderEvents();
  loadEvents(true, true);
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
    renderEventViews();
    toast('Event log marked read');
  } catch (error) {
    toast(error.message || 'Could not update events', 'error');
  }
}

async function markEventRead(id) {
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
    renderEventViews();
  } catch (error) {
    console.warn('lanwatch: could not mark an event as read', error);
    toast(error.message || 'Could not mark the event as read', 'error');
  }
}

function onEventListClick(event) {
  const item = event.target.closest('.event-item[data-id]');
  if (!item) return;
  markEventRead(item.dataset.id);
  const ip = item.dataset.ip;
  if (ip && state.devices.has(ip)) {
    closeEventCenter();
    openDrawer(ip);
  }
}

function onEventStatusClick(event) {
  const action = event.target.closest('[data-act]');
  if (!action) return;
  if (action.dataset.act === 'refresh-events') {
    loadEvents(true);
  } else if (action.dataset.act === 'clear-event-filters') {
    state.events.severity = 'all';
    state.events.device = '';
    state.events.unreadOnly = false;
    loadEvents(true);
  } else if (action.dataset.act === 'scan-now') {
    if (state.scan.running) {
      toast('A scan is already running');
    } else {
      startScan({});
    }
  }
}

async function loadLatestDiff() {
  if (state.scan.running) return;
  const requestId = ++state.diffRequestId;
  try {
    const data = await api('/api/scan/diff');
    if (requestId !== state.diffRequestId || state.scan.running) return;
    state.latestDiff = data;
    state.diffError = null;
    setNewDevices(data);
    renderDiff();
    renderTable();
  } catch (error) {
    if (requestId !== state.diffRequestId || state.scan.running) return;
    if (error && error.status === 404) {
      // No completed scan to compare yet; this is not a dashboard error.
      state.diffError = null;
      renderDiff();
      return;
    }
    state.diffError = (error && error.message) || 'comparison unavailable';
    console.warn('lanwatch: latest scan comparison could not be loaded', error);
    renderDiff();
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
  const acknowledgedNew = state.newDevices.delete(ip);
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
  if (acknowledgedNew) renderTable();
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

  const trust = device.trust || 'unknown';
  const badges = [];
  if (state.newDevices.has(device.ip)) badges.push('<span class="badge new">new</span>');
  if (device.online) badges.push('<span class="badge self">online</span>');
  else badges.push('<span class="badge off">offline</span>');
  if (device.is_gateway) badges.push('<span class="badge gw">gateway</span>');
  if (device.is_self) badges.push('<span class="badge self">this device</span>');
  badges.push(trustBadge(trust));
  badges.push(`<span class="badge">${esc(KIND_LABELS[device.kind] || device.kind || 'device')}${confidenceHtml(device)}</span>`);
  $('#drawer-badges').innerHTML = badges.join('');

  if (document.activeElement !== $('#drawer-label')) $('#drawer-label').value = device.label || '';
  if (document.activeElement !== $('#drawer-notes')) $('#drawer-notes').value = device.notes || '';
  if (document.activeElement !== $('#drawer-trust')) $('#drawer-trust').value = device.trust || 'unknown';
  renderTrustHelp(device.trust || 'unknown');
  renderDrawerStats(device);
}

function renderTrustHelp(value) {
  const level = TRUST_LABELS[value] ? value : 'unknown';
  const host = $('#drawer-trust-help');
  const select = $('#drawer-trust');
  if (host) host.textContent = `${TRUST_LABELS[level]}: ${TRUST_HELP[level]}`;
  if (select) select.setAttribute('title', TRUST_HELP[level]);
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
  const confirmed = window.confirm(
    `Forget ${name} (${ip})?\n\nThis removes the device from the saved inventory. The next scan will add it back if it is still online.`
  );
  if (!confirmed) return;
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
    const title = esc(net.title);
    const actions = [];
    if (!net.active) {
      actions.push(`<button class="btn primary" data-act="select" data-id="${id}" title="Make ${title} the active network" ${busy ? 'disabled' : ''}>Switch to</button>`);
    }
    actions.push(`<button class="btn ghost" data-act="rename" data-id="${id}" title="Rename ${title}">Rename</button>`);
    if (!net.active) {
      actions.push(`<button class="btn ghost" data-act="archive" data-id="${id}" title="${net.archived ? `Restore ${title}` : `Hide ${title}; its history and events stay saved`}">${net.archived ? 'Restore' : 'Archive'}</button>`);
      actions.push(`<button class="btn ghost danger-text" data-act="delete" data-id="${id}" title="Delete ${title} and its saved devices">Delete</button>`);
    }
    return `<li class="net-item ${net.active ? 'active' : ''} ${net.archived ? 'archived' : ''}" data-id="${id}">
        <span class="net-title">${title}</span>
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
      state.events.device = '';
      state.latestDiff = null;
      state.diffError = null;
      state.newDevices = new Set();
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
    const devices = net ? plural(net.devices, 'saved device') : 'saved devices';
    if (window.confirm(`Delete ${name} and its ${devices}?\n\nScan history and events are shared and stay saved. This cannot be undone.`)) {
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
  } catch (error) {
    console.warn('lanwatch: saved preferences could not be read', error);
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
  } catch (error) {
    console.warn('lanwatch: preferences could not be saved locally', error);
    if (!state.prefsWarned) {
      state.prefsWarned = true;
      toast('Preferences could not be saved in this browser', 'warn');
    }
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
  source.onerror = () => {
    if (state.connected) console.warn('lanwatch: live event stream disconnected; retrying');
    setSync(false);
  };
  source.onmessage = (message) => {
    let payload;
    try {
      payload = JSON.parse(message.data);
    } catch (error) {
      console.warn('lanwatch: ignored an unreadable live event', error);
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
  $('#scan-retry').addEventListener('click', () => startScan({}));
  $('#trust-help').addEventListener('click', () => setTrustGuideVisible(true, true));
  $('#trust-guide-close').addEventListener('click', dismissTrustGuide);
  $('#trust-guide-done').addEventListener('click', dismissTrustGuide);
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
  $('#events-view-all').addEventListener('click', openEventCenter);
  $('#events-close').addEventListener('click', closeEventCenter);
  $('#events-done').addEventListener('click', closeEventCenter);
  $('#events-mark-read').addEventListener('click', markAllEventsRead);
  $('#events-load-more').addEventListener('click', () => loadEvents(false));
  $('#events-refresh').addEventListener('click', () => loadEvents(true));
  $('#events-refresh-modal').addEventListener('click', () => loadEvents(true));
  $('#event-list').addEventListener('click', onEventListClick);
  $('#events-panel-list').addEventListener('click', onEventListClick);
  $('#event-list').addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const item = event.target.closest('.event-item[data-id]');
    if (!item) return;
    event.preventDefault();
    onEventListClick({ target: item });
  });
  $('#events-panel-list').addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const item = event.target.closest('.event-item[data-id]');
    if (!item) return;
    event.preventDefault();
    onEventListClick({ target: item });
  });
  $('#events-panel').addEventListener('click', (event) => {
    if (event.target.closest('.event-item')) return;
    onEventStatusClick(event);
  });
  $('#event-center').addEventListener('click', onEventStatusClick);
  $('#event-severity-chips').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-severity]');
    if (!button || button.dataset.severity === state.events.severity) return;
    state.events.severity = button.dataset.severity;
    loadEvents(true, true);
  });
  $('#event-severity').addEventListener('change', (event) => {
    state.events.severity = event.target.value;
    loadEvents(true, true);
  });
  $('#event-device-filter').addEventListener('change', (event) => {
    state.events.device = event.target.value;
    loadEvents(true, true);
  });
  $('#event-device-filter-modal').addEventListener('change', (event) => {
    state.events.device = event.target.value;
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
    } catch (error) {
      console.warn('lanwatch: clipboard is unavailable', error);
      toast(`Copy unavailable · ${ip}`, 'warn');
    }
  });
  $('#drawer-label').addEventListener('input', () => {
    state.drawerDirty = true;
  });
  $('#drawer-notes').addEventListener('input', () => {
    state.drawerDirty = true;
  });
  $('#drawer-trust').addEventListener('change', (event) => {
    renderTrustHelp(event.target.value);
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
    if (document.hidden) return;
    loadHistory();
    loadState().then(() => {
      loadLatestDiff();
      loadEvents(true, true);
    });
  });
}

/* ------------------------------------------------------------------ */
/* boot                                                                */
/* ------------------------------------------------------------------ */

async function loadState() {
  const requestId = ++state.stateRequestId;
  try {
    const data = await api('/api/state');
    if (requestId !== state.stateRequestId) return;
    applySnapshot(data);
  } catch (error) {
    if (requestId !== state.stateRequestId) return;
    setSync(false);
    console.warn('lanwatch: dashboard state could not be loaded', error);
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
    console.warn('lanwatch: scan history could not be loaded', error);
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
  setTrustGuideVisible(!readTrustGuideDismissed());
  setupAutoScan();
  await Promise.all([loadState(), loadHistory()]);
  loadEvents(true, true);
  loadLatestDiff();
  connectEvents();
  setInterval(tick, 1000);
}

document.addEventListener('DOMContentLoaded', init);
