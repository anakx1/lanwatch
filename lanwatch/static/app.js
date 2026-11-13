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
  iot:
    '<circle cx="12" cy="12" r="3"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.4 5.4l1.4 1.4M17.2 17.2l1.4 1.4M18.6 5.4l-1.4 1.4M6.8 17.2l-1.4 1.4"/>',
  device:
    '<rect x="6" y="6" width="12" height="12" rx="2.5"/><path d="M9.5 2.5v3M14.5 2.5v3M9.5 18.5v3M14.5 18.5v3M2.5 9.5h3M2.5 14.5h3M18.5 9.5h3M18.5 14.5h3"/>',
};

const ICON_ALIASES = { self: 'computer', phone: 'computer', '': 'device' };
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
  prefs: { showOffline: true, sort: 'ip', autoScan: false, autoInterval: 60 },
};

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
  state.interfaces = data.interfaces || [];
  state.options = data.options || {};
  state.host = data.host || null;
  state.version = data.version || state.version;
  state.statePath = data.state_path || '';
  renderAll();
}

function handleEvent(event) {
  switch (event.type) {
    case 'hello':
      if (event.state) state.scan = event.state;
      setSync(true);
      break;
    case 'scan.started':
      if (event.state) state.scan = event.state;
      if (event.network) state.network = event.network;
      if (event.options) state.options = event.options;
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
    case 'device':
      upsertDevice(event.device);
      if (state.drawerIp === (event.device && event.device.ip)) renderDrawerStats();
      break;
    case 'device.removed':
      state.devices.delete(event.ip);
      if (state.drawerIp === event.ip) closeDrawer();
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
  renderStats();
  renderScan();
  renderCollectors();
  renderTable();
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

  if (network) {
    cidr.textContent = network.cidr || 'unknown subnet';
    const bits = [];
    if (network.interface) bits.push(network.interface);
    if (network.address) bits.push(network.address);
    iface.textContent = bits.join(' · ');
    const bitsTitle = [`Network ${network.cidr}`];
    if (network.gateway) bitsTitle.push(`gateway ${network.gateway}`);
    if (network.host_count) bitsTitle.push(`${network.host_count} addresses`);
    bitsTitle.push('click to change scan settings');
    $('#net-chip').title = bitsTitle.join(' · ');
    $('#brand-sub').textContent = `${plural(online, 'device')} online on ${network.cidr}`;
  } else {
    cidr.textContent = 'no network yet';
    iface.textContent = '';
    $('#net-chip').title = 'Open scan settings';
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
      $('#empty-text').textContent = query
        ? `Nothing matches “${query}”${state.prefs.showOffline ? '' : ' while offline devices are hidden'}.`
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

function rowHtml(device) {
  const online = !!device.online;
  const name = device.name || device.hostname || 'Unknown device';
  const subBits = [];
  if (device.vendor) subBits.push(device.vendor);
  else if (device.hostname && device.hostname !== name) subBits.push(device.hostname);
  if (device.mac) subBits.push(device.mac);
  if (!subBits.length && (device.sources || []).length) subBits.push(`via ${device.sources.join(', ')}`);
  const sub = subBits.join(' · ');

  const badges = [];
  if (device.is_gateway) badges.push('<span class="badge gw">gateway</span>');
  if (device.is_self) badges.push('<span class="badge self">this device</span>');
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
  badges.push(`<span class="badge">${esc(device.kind || 'device')}</span>`);
  $('#drawer-badges').innerHTML = badges.join('');

  if (document.activeElement !== $('#drawer-label')) $('#drawer-label').value = device.label || '';
  if (document.activeElement !== $('#drawer-notes')) $('#drawer-notes').value = device.notes || '';
  renderDrawerStats(device);
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
  identity.push(['Category', esc(device.kind || 'device')]);
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

  const advertised = [];
  const ssdp = device.ssdp || {};
  const labels = {
    friendlyName: 'UPnP name',
    manufacturer: 'Manufacturer',
    model: 'Model',
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
      body: { ip, label: $('#drawer-label').value.trim(), notes: $('#drawer-notes').value.trim() },
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
  $('#net-chip').addEventListener('click', openSettings);
  $('#settings-close').addEventListener('click', closeSettings);
  $('#settings-cancel').addEventListener('click', closeSettings);
  $('#settings-form').addEventListener('submit', submitSettings);
  $('#opt-target').addEventListener('change', syncSubnetField);

  $('#search').addEventListener('input', (event) => {
    state.search = event.target.value;
    renderTable();
  });
  $('#show-offline').addEventListener('change', (event) => {
    state.prefs.showOffline = event.target.checked;
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
    if (!document.hidden) loadState();
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
  await loadState();
  connectEvents();
  setInterval(tick, 1000);
}

document.addEventListener('DOMContentLoaded', init);
