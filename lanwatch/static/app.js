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

const ICON_ALIASES = {
  self: 'computer',
  '': 'device',
  unknown: 'device',
  mobile: 'phone',
  tablet: 'phone',
  smartphone: 'phone',
  media_player: 'media',
  gateway: 'router',
  network: 'router',
};
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
const TOPOLOGY_NS = 'http://www.w3.org/2000/svg';
const TOPOLOGY_LIMITS = { phone: 12, tablet: 20, desktop: 32 };
const TOPOLOGY_FILTERS = ['all', 'online', 'offline', 'trusted', 'unknown', 'ignored'];
const TOPOLOGY_ZOOM_MIN = 0.6;
const TOPOLOGY_ZOOM_MAX = 2.4;
const TOPOLOGY_ZOOM_STEP = 0.2;
const TOPOLOGY_PAN_SLOP = 96;
const TOPOLOGY_PAN_SLOP_Y = 72;
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
  topology: {
    width: 0,
    frame: 0,
    model: null,
    networkId: '',
    signature: null,
    search: '',
    filter: 'all',
    selected: null,
    view: { scale: 1, x: 0, y: 0 },
    pan: null,
    bound: false,
  },
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

function topologyLimit(width) {
  const value = Number(width) || 720;
  if (value < 560) return TOPOLOGY_LIMITS.phone;
  if (value < 900) return TOPOLOGY_LIMITS.tablet;
  return TOPOLOGY_LIMITS.desktop;
}

function topologyGateway(devices, network, activeNetwork) {
  const list = Array.isArray(devices) ? devices : [];
  const flagged = list.find((device) => device && device.is_gateway);
  if (flagged) return { device: flagged, ip: String(flagged.ip || ''), missing: false };

  const candidates = [
    network && network.gateway,
    activeNetwork && activeNetwork.gateway,
  ];
  for (const candidate of candidates) {
    if (!candidate) continue;
    const ip = String(candidate);
    const match = list.find((device) => device && String(device.ip) === ip);
    return { device: match || null, ip, missing: !match };
  }
  return null;
}

const TOPOLOGY_HTTP_STATUS_REASON = /^(?:continue|switching protocols|ok|created|accepted|non-authoritative information|no content|reset content|partial content|multiple choices|moved permanently|moved temporarily|found|see other|not modified|use proxy|temporary redirect|permanent redirect|bad request|unauthorized|payment required|forbidden|not found|method not allowed|not acceptable|proxy authentication required|request timeout|conflict|gone|length required|precondition failed|payload too large|uri too long|unsupported media type|range not satisfiable|expectation failed|i'?m a teapot|misdirected request|unprocessable entity|locked|failed dependency|too early|upgrade required|precondition required|too many requests|request header fields too large|unavailable for legal reasons|internal server error|not implemented|bad gateway|service unavailable|gateway timeout|http version not supported|variant also negotiates|insufficient storage|loop detected|not extended|network authentication required|redirect(?:ed)?|temporarily unavailable)$/i;

function topologyIsGenericHttpStatusName(value) {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim();
  if (!text) return false;
  if (TOPOLOGY_HTTP_STATUS_REASON.test(text)) return true;
  const match = text.match(/^(?:http\s*)?[1-5]\d{2}(?:\s+(.*))?$/i);
  if (!match) return false;
  const reason = String(match[1] || '').trim();
  return !reason || TOPOLOGY_HTTP_STATUS_REASON.test(reason);
}

function topologyName(device, ip, options = {}) {
  if (!device) return options.gateway ? 'Gateway' : String(ip || 'Unknown device');
  const candidates = [
    [device.label, true],
    [device.name, false],
    [device.hostname, true],
    [device.nbns_name, true],
  ];
  for (const [value, explicit] of candidates) {
    const text = String(value ?? '').trim();
    if (!text) continue;
    if (options.gateway && !explicit && topologyIsGenericHttpStatusName(text)) continue;
    return text;
  }
  if (options.gateway) return 'Gateway';
  return String(ip || device.ip || 'Unknown device');
}

function topologyLookup(map, key) {
  return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
}

function topologyTrust(device) {
  const trust = device && device.trust;
  return topologyLookup(TRUST_LABELS, trust) ? trust : 'unknown';
}

function topologyKindLabel(kind) {
  const key = String(kind || 'device');
  const label = topologyLookup(KIND_LABELS, key);
  if (label) return label;
  if (key === 'device') return 'Device';
  return key.replace(/[_-]+/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

function topologySearchText(node) {
  if (!node) return '';
  return [
    node.name,
    node.hostname,
    node.label,
    node.vendor,
    node.ip,
    node.kindLabel,
    node.networkLabel,
    node.networkCidr,
    node.interfaceName,
    node.mac,
  ]
    .filter((value) => value != null && String(value).trim() !== '')
    .map((value) => String(value).toLowerCase())
    .join(' ');
}

function topologyMatchesSearch(node, query) {
  const tokens = String(query || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!tokens.length) return true;
  const text = topologySearchText(node);
  return tokens.every((token) => text.includes(token));
}

function topologyMatchesFilter(node, filter) {
  if (!node || !filter || filter === 'all') return true;
  if (filter === 'online') return !!node.online;
  if (filter === 'offline') return !node.online;
  if (filter === 'trusted' || filter === 'unknown' || filter === 'ignored') {
    return node.trust === filter;
  }
  return true;
}

function topologyNodeDisplayState(node, filter, query) {
  const search = String(query || '').trim();
  const filterMatch = topologyMatchesFilter(node, filter);
  const searchMatch = topologyMatchesSearch(node, search);
  return {
    filterMatch,
    searchMatch,
    filtered: !filterMatch,
    dimmed: !!search && !searchMatch,
    matched: !!search && searchMatch,
  };
}

function topologyClampScale(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return 1;
  return Math.min(TOPOLOGY_ZOOM_MAX, Math.max(TOPOLOGY_ZOOM_MIN, number));
}

function topologyZoomScale(scale, direction) {
  const step = Number(direction) < 0 ? -TOPOLOGY_ZOOM_STEP : TOPOLOGY_ZOOM_STEP;
  return topologyClampScale(Number(scale || 1) + step);
}

function topologyFitView() {
  return { scale: 1, x: 0, y: 0 };
}

function topologyPanView(view, nextX, nextY, width, height) {
  const scale = topologyClampScale(view && view.scale);
  const limitX = Math.max(
    TOPOLOGY_PAN_SLOP,
    ((scale - 1) * Math.max(1, Number(width) || 1)) / 2 + TOPOLOGY_PAN_SLOP,
  );
  const limitY = Math.max(
    TOPOLOGY_PAN_SLOP_Y,
    ((scale - 1) * Math.max(1, Number(height) || 1)) / 2 + TOPOLOGY_PAN_SLOP_Y,
  );
  return {
    scale,
    x: Math.max(-limitX, Math.min(limitX, Number(nextX) || 0)),
    y: Math.max(-limitY, Math.min(limitY, Number(nextY) || 0)),
  };
}

function topologyTransform(view, model) {
  const scale = topologyClampScale(view && view.scale);
  const x = Number(view && view.x) || 0;
  const y = Number(view && view.y) || 0;
  const width = Math.max(1, Number(model && model.width) || 720);
  const height = Math.max(1, Number(model && model.height) || 420);
  const centerX = width / 2;
  const centerY = height / 2;
  const round = (value) => Math.round(value * 1000) / 1000;
  return `translate(${round(centerX + x)} ${round(centerY + y)}) scale(${round(scale)}) translate(${round(-centerX)} ${round(-centerY)})`;
}

function truncateTopologyText(value, max) {
  const chars = Array.from(String(value ?? ''));
  const limit = Math.max(1, Number(max) || 1);
  if (chars.length <= limit) return chars.join('');
  return `${chars.slice(0, Math.max(1, limit - 1)).join('')}…`;
}

function topologyNameLines(value, maxChars, maxLines = 2) {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim();
  if (!text) return [''];
  const limit = Math.max(4, Math.floor(Number(maxChars) || 12));
  const lineLimit = Math.max(1, Math.floor(Number(maxLines) || 1));
  const splitWord = (word) => {
    if (word.length <= limit) return [word];
    const parts = [];
    let rest = word;
    while (rest.length > limit) {
      let cut = rest.lastIndexOf('-', limit - 1);
      if (cut >= Math.floor(limit * 0.5)) cut += 1;
      else cut = limit;
      parts.push(rest.slice(0, cut));
      rest = rest.slice(cut);
    }
    if (rest) parts.push(rest);
    return parts;
  };
  const words = text.split(' ').flatMap(splitWord);
  const lines = [];
  let current = '';
  words.forEach((word) => {
    if (!current) {
      current = word;
    } else if (`${current} ${word}`.length <= limit) {
      current = `${current} ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  });
  if (current) lines.push(current);
  if (lines.length <= lineLimit) return lines;
  const kept = lines.slice(0, lineLimit);
  const remainder = lines.slice(lineLimit).join(' ');
  kept[lineLimit - 1] = truncateTopologyText(
    `${kept[lineLimit - 1]} ${remainder}`.trim(),
    limit,
  );
  return kept;
}

function topologyNodeLabelMetrics(nodeRadius, lineCount) {
  const radius = Math.max(0, Number(nodeRadius) || 18);
  const lines = Math.max(1, Math.min(2, Math.floor(Number(lineCount) || 1)));
  const lineHeight = 10.5;
  const nameY = radius + 14;
  const ipY = nameY + lines * lineHeight + 1.5;
  return { lineCount: lines, lineHeight, nameY, ipY, bottom: ipY + 3 };
}

function topologyHubLabelMetrics(hubRadius, lineCount, missing) {
  const radius = Math.max(0, Number(hubRadius) || 30);
  const lines = Math.max(0, Math.min(2, Math.floor(Number(lineCount) || 0)));
  const lineHeight = 10.5;
  const kickerY = radius + 13;
  const nameY = radius + 25;
  const ipY = lines > 0 ? nameY + lines * lineHeight + 1.5 : radius + 27;
  const missingY = ipY + 12;
  return {
    lineCount: lines,
    lineHeight,
    kickerY,
    nameY,
    ipY,
    missingY,
    bottom: (missing ? missingY : ipY) + 3,
  };
}

function topologyTreeColumns(count) {
  const safeCount = Math.max(0, Math.floor(Number(count) || 0));
  if (safeCount <= 1) return 1;
  if (safeCount === 2) return 2;
  return 3;
}

function topologyNameLimit(width, columns, mode) {
  if (mode === 'radial') return 20;
  const safeWidth = Math.max(1, Number(width) || 720);
  const safeColumns = Math.max(1, Math.floor(Number(columns) || 1));
  const margin = safeWidth < 360 ? 12 : 16;
  const columnWidth = Math.max(1, (safeWidth - margin * 2) / safeColumns);
  return Math.max(10, Math.min(24, Math.floor((columnWidth - 10) / 5.9)));
}

function topologyHubNameLimit() {
  return 24;
}

function topologyTreeLayout(count, width, metrics = {}) {
  const margin = width < 360 ? 12 : 16;
  const columns = topologyTreeColumns(count);
  const nodeRadius = width < 360 ? 17 : 18;
  const labelMetrics = topologyNodeLabelMetrics(nodeRadius, metrics.lineCount);
  const rowHeight = Math.max(70, labelMetrics.bottom + nodeRadius + 6);
  const hubRadius = width < 360 ? 28 : 30;
  const hubY = width < 360 ? 38 : 40;
  const hubMetrics = topologyHubLabelMetrics(
    hubRadius,
    Math.max(0, Number(metrics.hubLineCount) || 0),
    !!metrics.hubMissing,
  );
  const startY = Math.max(
    hubY + hubRadius + 54,
    hubY + hubMetrics.bottom + nodeRadius + 10,
  );
  const rows = Math.max(1, Math.ceil(count / columns));
  const contentWidth = width - margin * 2;
  const columnWidth = contentWidth / columns;
  const hub = { x: width / 2, y: hubY, r: hubRadius };
  const nodes = [];
  for (let index = 0; index < count; index += 1) {
    const col = index % columns;
    const row = Math.floor(index / columns);
    const inRow = Math.min(columns, count - row * columns);
    const rowWidth = inRow * columnWidth;
    const startX = margin + (contentWidth - rowWidth) / 2 + columnWidth / 2;
    nodes.push({
      x: startX + col * columnWidth,
      y: startY + row * rowHeight,
      r: nodeRadius,
    });
  }
  const height = count === 0
    ? 200
    : startY + (rows - 1) * rowHeight + labelMetrics.bottom + 10;
  return {
    mode: 'tree',
    width,
    height: Math.max(200, Math.round(height)),
    hub,
    nodes,
    columns,
    rowHeight,
  };
}

function topologyRadialLayout(count, width) {
  const hubRadius = width < 720 ? 38 : 44;
  const nodeRadius = width < 720 ? 20 : 24;
  let rings;
  if (count <= 8) {
    rings = [count];
  } else if (count <= 18) {
    const inner = Math.max(2, Math.ceil(count * 0.36));
    rings = [inner, count - inner];
  } else {
    const inner = Math.max(3, Math.ceil(count * 0.2));
    const middle = Math.max(4, Math.ceil(count * 0.33));
    rings = [inner, middle, count - inner - middle];
  }
  rings = rings.filter((ring) => ring > 0);

  let radii;
  if (rings.length <= 1) {
    const factor = count <= 3 ? 0.2 : count <= 6 ? 0.27 : 0.33;
    radii = [Math.min(width * factor, 300)];
  } else {
    // At the widest supported size the extra ring spacing keeps labels clear
    // of neighbouring nodes on dense maps.
    const outer = Math.min(width * 0.41, 330);
    radii = rings.length === 2
      ? [outer * 0.6, outer]
      : [outer * 0.48, outer * 0.74, outer];
  }
  const outer = radii[radii.length - 1] || 180;
  const height = Math.max(260, Math.round(outer * 2 + nodeRadius * 2 + 80));
  const hub = { x: width / 2, y: height / 2, r: hubRadius };
  const nodes = [];
  rings.forEach((ringCount, ringIndex) => {
    const radius = radii[ringIndex];
    const phase = -Math.PI / 2 + (ringIndex % 2 === 0 ? 0 : Math.PI / ringCount);
    for (let index = 0; index < ringCount; index += 1) {
      const angle = phase + (Math.PI * 2 * index) / ringCount;
      nodes.push({
        x: hub.x + Math.cos(angle) * radius,
        y: hub.y + Math.sin(angle) * radius,
        r: nodeRadius,
      });
    }
  });
  return {
    mode: 'radial',
    width,
    height,
    hub,
    nodes,
  };
}

function topologyLayout(count, width, metrics = {}) {
  const safeWidth = Math.max(280, Math.min(Number(width) || 720, 960));
  const safeCount = Math.max(0, Math.floor(Number(count) || 0));
  return safeWidth < 900
    ? topologyTreeLayout(safeCount, safeWidth, metrics)
    : topologyRadialLayout(safeCount, safeWidth);
}

function topologyLink(hub, node) {
  const dx = node.x - hub.x;
  const dy = node.y - hub.y;
  const distance = Math.hypot(dx, dy) || 1;
  const start = hub.r + 2;
  const end = node.r + 2;
  return {
    x1: hub.x + (dx / distance) * start,
    y1: hub.y + (dy / distance) * start,
    x2: node.x - (dx / distance) * end,
    y2: node.y - (dy / distance) * end,
  };
}

function buildTopologyView({
  devices = [],
  network = null,
  activeNetwork = null,
  width = 720,
} = {}) {
  const safeWidth = Math.max(280, Math.min(Number(width) || 720, 960));
  const list = (Array.isArray(devices) ? devices : []).filter((device) => device && device.ip);
  const gateway = topologyGateway(list, network, activeNetwork);
  const limit = topologyLimit(safeWidth);
  const sorted = list.slice().sort((a, b) => (
    ipNumber(a.ip) - ipNumber(b.ip) || String(a.ip).localeCompare(String(b.ip))
  ));
  const children = gateway
    ? sorted.filter((device) => String(device.ip) !== gateway.ip)
    : [];
  const shown = children.slice(0, limit);
  const networkLabel = String(
    (activeNetwork && (activeNetwork.label || activeNetwork.title))
    || (network && (network.label || network.title))
    || '',
  );
  const networkCidr = String(
    (network && network.cidr)
    || (activeNetwork && activeNetwork.cidr)
    || '',
  );
  const interfaceName = String((network && network.interface) || '');
  const networkGatewayMac = String(
    (network && network.gateway_mac)
    || (activeNetwork && activeNetwork.gateway_mac)
    || '',
  );

  const layoutMode = safeWidth < 900 ? 'tree' : 'radial';
  const columns = layoutMode === 'tree' ? topologyTreeColumns(shown.length) : 0;
  const nameLimit = topologyNameLimit(safeWidth, columns, layoutMode);
  const gatewayDevice = gateway && gateway.device ? gateway.device : null;
  const gatewayTrust = gatewayDevice ? topologyTrust(gatewayDevice) : 'unknown';
  const gatewayMac = networkGatewayMac || String((gatewayDevice && gatewayDevice.mac) || '');
  const hubName = gatewayDevice
    ? topologyName(gatewayDevice, gateway.ip, { gateway: true })
    : 'Gateway';
  const hubNameLines = topologyNameLines(hubName, topologyHubNameLimit(), 2);
  const hubShowName = !!(
    gatewayDevice
    && hubName
    && hubName !== gateway.ip
    && hubName !== 'Gateway'
  );
  const nodeNames = shown.map((device) => topologyName(device, device.ip));
  const nodeNameLines = nodeNames.map((name) => topologyNameLines(
    name,
    nameLimit,
    layoutMode === 'tree' ? 2 : 1,
  ));
  const maxNameLines = nodeNameLines.reduce(
    (max, lines) => Math.max(max, lines.length),
    1,
  );
  const layout = topologyLayout(gateway ? shown.length : 0, safeWidth, {
    lineCount: maxNameLines,
    hubLineCount: hubShowName ? hubNameLines.length : 0,
    hubMissing: !!(gateway && gateway.missing),
  });

  const nodes = shown.map((device, index) => {
    const position = layout.nodes[index] || { x: layout.hub.x, y: layout.hub.y, r: 18 };
    const name = nodeNames[index];
    const trust = topologyTrust(device);
    const kind = device.kind || 'device';
    return {
      ip: String(device.ip),
      name,
      hostname: String(device.hostname || ''),
      label: String(device.label || ''),
      vendor: String(device.vendor || ''),
      shortName: truncateTopologyText(name, nameLimit),
      nameLines: nodeNameLines[index],
      kind,
      kindLabel: topologyKindLabel(kind),
      online: !!device.online,
      trust,
      trustLabel: TRUST_LABELS[trust],
      statusLabel: device.online ? 'Online' : 'Offline',
      x: position.x,
      y: position.y,
      r: position.r,
    };
  });

  const online = list.filter((device) => device.online).length;
  let empty = null;
  if (!list.length) {
    empty = {
      reason: 'no-devices',
      title: 'No devices to map yet',
      text: 'Run a scan to discover this network and identify its gateway.',
    };
  } else if (!gateway) {
    empty = {
      reason: 'no-gateway',
      title: 'Gateway not identified',
      text: 'Devices were found, but no gateway could be identified. Run another scan while connected to this network.',
    };
  }

  const hub = gateway && list.length ? {
    ip: gateway.ip,
    name: hubName,
    nameLines: hubNameLines,
    showName: hubShowName,
    hostname: String((gatewayDevice && gatewayDevice.hostname) || ''),
    label: String((gatewayDevice && gatewayDevice.label) || ''),
    vendor: String((gatewayDevice && gatewayDevice.vendor) || ''),
    mac: gatewayMac,
    kind: 'router',
    kindLabel: 'Gateway',
    missing: !!gateway.missing,
    online: gatewayDevice ? !!gatewayDevice.online : null,
    trust: gatewayTrust,
    trustLabel: TRUST_LABELS[gatewayTrust],
    statusLabel: gateway.missing ? 'Not in inventory' : gatewayDevice && gatewayDevice.online ? 'Online' : 'Offline',
    networkLabel,
    networkCidr,
    interfaceName,
    x: layout.hub.x,
    y: layout.hub.y,
    r: layout.hub.r,
  } : null;

  return {
    width: layout.width,
    height: layout.height,
    mode: layout.mode,
    columns,
    nameLimit,
    rowHeight: layout.rowHeight || 0,
    hub,
    nodes,
    links: hub ? nodes.map((node) => ({
      ...topologyLink(hub, node),
      ip: node.ip,
      offline: !node.online,
    })) : [],
    total: list.length,
    childTotal: children.length,
    shown: nodes.length,
    hidden: Math.max(0, children.length - nodes.length),
    online,
    gatewayMissing: !!(gateway && gateway.missing),
    empty,
  };
}

function topologyIconBody(kind) {
  const key = topologyLookup(ICON_ALIASES, kind) || kind;
  return topologyLookup(ICONS, key) || ICONS.device;
}

function createTopologySvgElement(doc, tag, attributes = {}) {
  const element = doc.createElementNS(TOPOLOGY_NS, tag);
  Object.entries(attributes).forEach(([name, value]) => {
    element.setAttribute(name, String(value));
  });
  return element;
}

function appendTopologyText(doc, parent, value, attributes = {}) {
  const text = createTopologySvgElement(doc, 'text', attributes);
  text.textContent = String(value);
  parent.appendChild(text);
  return text;
}

function appendTopologyTitle(doc, parent, value) {
  const title = doc.createElementNS(TOPOLOGY_NS, 'title');
  title.textContent = String(value);
  parent.appendChild(title);
  return title;
}

function createTopologyIcon(doc, kind, size) {
  const iconElement = createTopologySvgElement(doc, 'svg', {
    x: -size / 2,
    y: -size / 2,
    width: size,
    height: size,
    viewBox: '0 0 24 24',
    class: 'topology-kind-icon',
    'aria-hidden': 'true',
    focusable: 'false',
  });
  // ICONS is fixed developer-authored markup selected through an allowlist.
  // Device, host, and vendor data never enters this string.
  iconElement.innerHTML = topologyIconBody(kind);
  return iconElement;
}

function createTopologySvg(doc, view, options = {}) {
  const hiddenNote = view.hidden ? ` ${view.hidden} more devices are not shown.` : '';
  const gatewayNote = view.hub && view.hub.missing
    ? ` Gateway ${view.hub.ip} is not in the inventory.`
    : '';
  const summary = view.hub
    ? `Logical network topology. Gateway ${view.hub.ip} with ${view.shown} of ${view.childTotal} devices shown.${gatewayNote}${hiddenNote} Connections are logical, not confirmed physical links.`
    : 'Logical network topology.';
  const selected = options.selected || null;
  const isSelected = (kind, ip) => !!(
    selected
    && selected.kind === kind
    && String(selected.ip || '') === String(ip || '')
  );
  const svg = createTopologySvgElement(doc, 'svg', {
    viewBox: `0 0 ${view.width} ${view.height}`,
    class: `topology-svg topology-svg--${view.mode}`,
    role: 'group',
    'aria-label': summary,
    preserveAspectRatio: 'xMidYMid meet',
  });
  appendTopologyTitle(doc, svg, 'Network topology');

  const viewport = createTopologySvgElement(doc, 'g', {
    class: 'topology-viewport',
    transform: 'translate(0 0) scale(1)',
  });
  svg.appendChild(viewport);

  const links = createTopologySvgElement(doc, 'g', {
    class: 'topology-links',
    'aria-hidden': 'true',
  });
  view.links.forEach((link) => {
    const selectedLink = isSelected('device', link.ip);
    links.appendChild(createTopologySvgElement(doc, 'line', {
      class: `topology-link${link.offline ? ' is-offline' : ''}${selectedLink ? ' is-selected' : ''}`,
      x1: link.x1,
      y1: link.y1,
      x2: link.x2,
      y2: link.y2,
      'data-ip': link.ip || '',
    }));
  });
  viewport.appendChild(links);

  if (view.hub) {
    const hub = view.hub;
    const selectedHub = isSelected('gateway', hub.ip);
    const hubClass = [
      'topology-hub',
      `trust-${hub.trust}`,
      hub.missing ? 'is-missing' : '',
      hub.online === false ? 'is-offline' : '',
      hub.online === true ? 'is-online' : '',
      selectedHub ? 'is-selected' : '',
    ].filter(Boolean).join(' ');
    const hubNameLines = Array.isArray(hub.nameLines)
      ? hub.nameLines
      : topologyNameLines(hub.name, topologyHubNameLimit(), 2);
    const showHubName = hub.showName !== false
      && !!(hub.name && hub.name !== hub.ip && hub.name !== 'Gateway');
    const hubMetrics = topologyHubLabelMetrics(
      hub.r,
      showHubName ? hubNameLines.length : 0,
      hub.missing,
    );
    const hubNameLabel = showHubName ? hub.name : '';
    const hubLabel = [
      hubNameLabel,
      'Gateway',
      `IP ${hub.ip}`,
      hub.statusLabel,
      `${hub.trustLabel} trust`,
      hub.networkCidr ? `Network ${hub.networkCidr}` : '',
      'Press Enter for gateway details',
    ].filter(Boolean).join('. ');
    const group = createTopologySvgElement(doc, 'g', {
      class: hubClass,
      transform: `translate(${hub.x} ${hub.y})`,
      'data-ip': hub.ip,
      'data-role': 'gateway',
      role: 'button',
      tabindex: '0',
      'aria-label': hubLabel,
    });
    if (selectedHub) group.setAttribute('aria-current', 'true');
    const status = hub.missing ? 'gateway not in inventory' : hub.online ? 'online' : 'offline';
    appendTopologyTitle(
      doc,
      group,
      `${hubNameLabel ? `${hubNameLabel}, ` : ''}Gateway ${hub.ip}, ${status}, ${hub.trustLabel}`,
    );
    group.appendChild(createTopologySvgElement(doc, 'circle', {
      class: 'topology-hub-halo',
      r: hub.r + 10,
    }));
    group.appendChild(createTopologySvgElement(doc, 'circle', {
      class: 'topology-hub-ring',
      r: hub.r,
    }));
    group.appendChild(createTopologySvgElement(doc, 'circle', {
      class: 'topology-hub-surface',
      r: hub.r - 6,
    }));
    group.appendChild(createTopologyIcon(doc, 'router', hub.r * 0.82));
    group.appendChild(createTopologySvgElement(doc, 'circle', {
      class: `topology-status-dot ${hub.missing ? 'missing' : hub.online ? 'online' : 'offline'}`,
      cx: hub.r * 0.72,
      cy: -hub.r * 0.72,
      r: 5,
    }));
    appendTopologyText(doc, group, 'GATEWAY', {
      class: 'topology-hub-kicker',
      y: hubMetrics.kickerY,
    });
    if (showHubName) {
      hubNameLines.forEach((line, index) => {
        appendTopologyText(doc, group, line, {
          class: 'topology-hub-name',
          y: hubMetrics.nameY + index * hubMetrics.lineHeight,
        });
      });
    }
    appendTopologyText(doc, group, hub.ip, {
      class: 'topology-hub-ip',
      y: hubMetrics.ipY,
    });
    if (hub.missing) {
      appendTopologyText(doc, group, 'not in inventory', {
        class: 'topology-hub-missing',
        y: hubMetrics.missingY,
      });
    }
    viewport.appendChild(group);
  }

  const nodes = createTopologySvgElement(doc, 'g', { class: 'topology-nodes' });
  view.nodes.forEach((node) => {
    const selectedNode = isSelected('device', node.ip);
    const group = createTopologySvgElement(doc, 'g', {
      class: `topology-node trust-${node.trust} ${node.online ? 'is-online' : 'is-offline'}${selectedNode ? ' is-selected' : ''}`,
      transform: `translate(${node.x} ${node.y})`,
      'data-ip': node.ip,
      'data-role': 'device',
      role: 'button',
      tabindex: '0',
      'aria-label': `${node.name}. ${node.kindLabel}. IP ${node.ip}. ${node.statusLabel}. ${node.trustLabel} trust. Press Enter for details.`,
    });
    if (selectedNode) group.setAttribute('aria-current', 'true');
    appendTopologyTitle(
      doc,
      group,
      `${node.name}, ${node.kindLabel}, ${node.ip}, ${node.online ? 'online' : 'offline'}, ${node.trustLabel}`,
    );
    group.appendChild(createTopologySvgElement(doc, 'circle', {
      class: 'topology-node-halo',
      r: node.r + 5,
    }));
    group.appendChild(createTopologySvgElement(doc, 'circle', {
      class: 'topology-node-surface',
      r: node.r,
    }));
    group.appendChild(createTopologyIcon(doc, node.kind, node.r * 1.05));
    group.appendChild(createTopologySvgElement(doc, 'circle', {
      class: `topology-status-dot ${node.online ? 'online' : 'offline'}`,
      cx: node.r * 0.68,
      cy: -node.r * 0.68,
      r: 4,
    }));
    const nodeNameLines = Array.isArray(node.nameLines)
      ? node.nameLines
      : [node.shortName || node.name];
    const nodeMetrics = topologyNodeLabelMetrics(node.r, nodeNameLines.length);
    nodeNameLines.forEach((line, index) => {
      appendTopologyText(doc, group, line, {
        class: 'topology-node-name',
        y: nodeMetrics.nameY + index * nodeMetrics.lineHeight,
      });
    });
    appendTopologyText(doc, group, node.ip, {
      class: 'topology-node-ip',
      y: nodeMetrics.ipY,
    });
    nodes.appendChild(group);
  });
  viewport.appendChild(nodes);
  return svg;
}

function topologyModelNode(model, ip) {
  if (!model || !Array.isArray(model.nodes)) return null;
  return model.nodes.find((node) => String(node.ip) === String(ip)) || null;
}

function topologyNodeFromTarget(target) {
  if (!target || typeof target.closest !== 'function') return null;
  return target.closest('.topology-node[data-ip], .topology-hub[data-role="gateway"]');
}

function syncTopologySelection() {
  const host = $('#topology-svg-host');
  if (!host) return;
  const selected = state.topology.selected;
  $$('.topology-node[data-ip], .topology-hub[data-role="gateway"]', host).forEach((element) => {
    const isGateway = element.classList.contains('topology-hub');
    const ip = element.getAttribute('data-ip');
    const active = !!(
      selected
      && selected.kind === (isGateway ? 'gateway' : 'device')
      && String(selected.ip || '') === String(ip || '')
    );
    element.classList.toggle('is-selected', active);
    if (active) element.setAttribute('aria-current', 'true');
    else element.removeAttribute('aria-current');
  });
  $$('.topology-link[data-ip]', host).forEach((element) => {
    const active = !!(
      selected
      && selected.kind === 'device'
      && String(selected.ip || '') === String(element.getAttribute('data-ip') || '')
    );
    element.classList.toggle('is-selected', active);
  });
}

function hideTopologySelection() {
  const panel = $('#topology-selection');
  if (!panel) return;
  panel.hidden = true;
}

function clearTopologySelection() {
  state.topology.selected = null;
  syncTopologySelection();
  hideTopologySelection();
}

function renderTopologySelection(hub) {
  const panel = $('#topology-selection');
  const title = $('#topology-selection-title');
  const body = $('#topology-selection-body');
  if (!panel || !title || !body) return;
  if (!hub) {
    panel.hidden = true;
    return;
  }
  const parts = [
    hub.ip,
    hub.statusLabel,
    `${hub.trustLabel} trust`,
  ];
  if (hub.networkLabel && hub.networkLabel !== hub.networkCidr) parts.push(hub.networkLabel);
  if (hub.networkCidr) parts.push(`Network ${hub.networkCidr}`);
  if (hub.interfaceName) parts.push(`Interface ${hub.interfaceName}`);
  if (hub.mac) parts.push(`MAC ${hub.mac}`);
  if (hub.vendor) parts.push(`Vendor ${hub.vendor}`);
  if (hub.missing) {
    parts.push('Not in the device inventory. Run another scan while connected to this network.');
  }
  title.textContent = `Gateway${hub.name && hub.name !== 'Gateway' ? ` · ${hub.name}` : ''}`;
  body.textContent = parts.filter(Boolean).join(' · ');
  panel.hidden = false;
}

function selectTopologyGateway() {
  const model = state.topology.model;
  const hub = model && model.hub;
  if (!hub) return false;
  state.topology.selected = { kind: 'gateway', ip: String(hub.ip || '') };
  if (state.drawerIp) closeDrawer();
  hideTopologyTooltip();
  syncTopologySelection();
  renderTopologySelection(hub);
  return true;
}

function selectTopologyDevice(ip) {
  const key = String(ip || '');
  if (!key || !state.devices.has(key)) return false;
  state.topology.selected = { kind: 'device', ip: key };
  hideTopologySelection();
  hideTopologyTooltip();
  syncTopologySelection();
  openDrawer(key);
  return true;
}

function activateTopologyNode(element) {
  if (!element) return null;
  const role = element.getAttribute ? element.getAttribute('data-role') : '';
  if (role === 'gateway' || (element.classList && element.classList.contains('topology-hub'))) {
    return selectTopologyGateway() ? 'gateway' : null;
  }
  const ip = element.getAttribute ? element.getAttribute('data-ip') : '';
  if (!ip || !state.devices.has(ip)) return null;
  return selectTopologyDevice(ip) ? 'device' : null;
}

function updateTopologyViewStatus(model, visible, matches) {
  const status = $('#topology-view-status');
  if (!status) return;
  const query = String(state.topology.search || '').trim();
  const filter = state.topology.filter || 'all';
  if (!model || (!query && filter === 'all')) {
    status.hidden = true;
    status.textContent = '';
    return;
  }
  const nodeCount = Array.isArray(model.nodes) ? model.nodes.length : 0;
  const bits = [
    visible
      ? `Showing ${visible} of ${nodeCount} device node${nodeCount === 1 ? '' : 's'}`
      : 'No device nodes match this view; the gateway stays visible',
  ];
  if (query) {
    bits.push(`${matches} match${matches === 1 ? '' : 'es'} for “${truncateTopologyText(query, 36)}”`);
  }
  status.textContent = bits.join(' · ');
  status.hidden = false;
}

function applyTopologyVisibility() {
  const host = $('#topology-svg-host');
  const model = state.topology.model;
  if (!host || !model || host.hidden) {
    updateTopologyViewStatus(null, 0, 0);
    return;
  }
  const query = String(state.topology.search || '').trim();
  const filter = state.topology.filter || 'all';
  let visible = 0;
  let matches = 0;

  $$('.topology-node[data-ip]', host).forEach((element) => {
    const node = topologyModelNode(model, element.getAttribute('data-ip'));
    if (!node) return;
    const stateForNode = topologyNodeDisplayState(node, filter, query);
    element.classList.toggle('is-filtered', stateForNode.filtered);
    element.classList.toggle('is-dimmed', stateForNode.dimmed);
    element.classList.toggle('is-search-match', stateForNode.matched);
    if (stateForNode.filterMatch) visible += 1;
    if (stateForNode.searchMatch) matches += 1;
  });

  $$('.topology-link[data-ip]', host).forEach((element) => {
    const node = topologyModelNode(model, element.getAttribute('data-ip'));
    if (!node) return;
    const stateForNode = topologyNodeDisplayState(node, filter, query);
    element.classList.toggle('is-filtered', stateForNode.filtered);
    element.classList.toggle('is-dimmed', stateForNode.dimmed);
  });

  const hubElement = $('.topology-hub[data-role="gateway"]', host);
  if (hubElement && model.hub) {
    const stateForHub = topologyNodeDisplayState(model.hub, 'all', query);
    hubElement.classList.toggle('is-dimmed', stateForHub.dimmed);
    hubElement.classList.toggle('is-search-match', stateForHub.matched);
  }

  updateTopologyViewStatus(model, visible, matches);
}

function applyTopologyTransform() {
  const host = $('#topology-svg-host');
  const model = state.topology.model;
  if (!host || !model) return;
  const viewport = $('.topology-viewport', host);
  if (viewport) viewport.setAttribute('transform', topologyTransform(state.topology.view, model));
  const scale = topologyClampScale(state.topology.view.scale);
  const label = $('#topology-zoom-label');
  if (label) label.textContent = `${Math.round(scale * 100)}%`;
  const zoomIn = $('#topology-zoom-in');
  const zoomOut = $('#topology-zoom-out');
  if (zoomIn) zoomIn.disabled = scale >= TOPOLOGY_ZOOM_MAX - 0.001;
  if (zoomOut) zoomOut.disabled = scale <= TOPOLOGY_ZOOM_MIN + 0.001;
}

function topologySetScale(nextScale) {
  const model = state.topology.model;
  if (!model) return;
  const current = state.topology.view;
  const scale = topologyClampScale(nextScale);
  state.topology.view = topologyPanView(
    { scale },
    current.x,
    current.y,
    model.width,
    model.height,
  );
  applyTopologyTransform();
}

function zoomTopology(direction) {
  topologySetScale(topologyZoomScale(state.topology.view.scale, direction));
}

function fitTopologyViewport() {
  if (!state.topology.model) return;
  state.topology.view = topologyFitView();
  applyTopologyTransform();
}

function setTopologyFilter(filter) {
  const next = String(filter || 'all');
  if (!TOPOLOGY_FILTERS.includes(next)) return;
  state.topology.filter = next;
  const filters = $('#topology-filters');
  if (filters) {
    $$('[data-topology-filter]', filters).forEach((button) => {
      const active = button.getAttribute('data-topology-filter') === next;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
    });
  }
  applyTopologyVisibility();
}

function syncTopologyFilterButtons() {
  const filters = $('#topology-filters');
  if (!filters) return;
  const filter = state.topology.filter || 'all';
  $$('[data-topology-filter]', filters).forEach((button) => {
    const active = button.getAttribute('data-topology-filter') === filter;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  });
}

function topologyTooltipData(element) {
  const model = state.topology.model;
  if (!element || !model) return null;
  const isGateway = element.getAttribute('data-role') === 'gateway'
    || (element.classList && element.classList.contains('topology-hub'));
  const node = isGateway
    ? model.hub
    : topologyModelNode(model, element.getAttribute('data-ip'));
  if (!node) return null;
  return { node, isGateway: !!isGateway };
}

function topologyTooltipFields(node, isGateway) {
  if (!node) return [];
  const fields = [];
  if (node.kindLabel) fields.push(['Type', node.kindLabel]);
  if (node.ip) fields.push(['IP', node.ip]);
  if (node.statusLabel) fields.push(['Status', node.statusLabel]);
  if (node.trustLabel) fields.push(['Trust', node.trustLabel]);
  if (isGateway) {
    if (node.networkCidr) fields.push(['Network', node.networkCidr]);
    if (node.interfaceName) fields.push(['Interface', node.interfaceName]);
    if (node.mac) fields.push(['Gateway MAC', node.mac]);
  } else {
    if (node.hostname && node.hostname !== node.name) fields.push(['Hostname', node.hostname]);
    if (node.vendor) fields.push(['Vendor', node.vendor]);
  }
  return fields;
}

function hideTopologyTooltip() {
  const tooltip = $('#topology-tooltip');
  if (tooltip) tooltip.hidden = true;
}

function showTopologyTooltip(element) {
  const tooltip = $('#topology-tooltip');
  const map = $('#topology-map');
  const data = topologyTooltipData(element);
  if (!tooltip || !map || !data) return;
  tooltip.replaceChildren();
  const title = document.createElement('strong');
  title.className = 'topology-tip-title';
  title.textContent = data.node.name || data.node.ip || 'Device';
  tooltip.appendChild(title);
  topologyTooltipFields(data.node, data.isGateway).forEach(([label, value]) => {
    const row = document.createElement('span');
    row.className = 'topology-tip-row';
    const labelElement = document.createElement('span');
    labelElement.className = 'topology-tip-label';
    labelElement.textContent = label;
    const valueElement = document.createElement('span');
    valueElement.className = 'topology-tip-value';
    valueElement.textContent = String(value);
    row.appendChild(labelElement);
    row.appendChild(valueElement);
    tooltip.appendChild(row);
  });
  tooltip.hidden = false;

  if (typeof element.getBoundingClientRect !== 'function') return;
  if (typeof map.getBoundingClientRect !== 'function') return;
  const nodeRect = element.getBoundingClientRect();
  const mapRect = map.getBoundingClientRect();
  const tipRect = typeof tooltip.getBoundingClientRect === 'function'
    ? tooltip.getBoundingClientRect()
    : { width: 0, height: 0 };
  let left = nodeRect.left - mapRect.left + nodeRect.width / 2 - tipRect.width / 2;
  let top = nodeRect.top - mapRect.top - tipRect.height - 8;
  if (top < 4) top = nodeRect.bottom - mapRect.top + 8;
  const maxLeft = Math.max(4, mapRect.width - tipRect.width - 4);
  left = Math.max(4, Math.min(maxLeft, left));
  if (mapRect.height - top < tipRect.height + 4) top = Math.max(4, mapRect.height - tipRect.height - 4);
  tooltip.style.left = `${Math.round(left)}px`;
  tooltip.style.top = `${Math.round(top)}px`;
}

function onTopologySearchInput(event) {
  state.topology.search = String((event.target && event.target.value) || '');
  applyTopologyVisibility();
}

function onTopologyFilterClick(event) {
  const button = event.target && typeof event.target.closest === 'function'
    ? event.target.closest('[data-topology-filter]')
    : null;
  if (!button) return;
  setTopologyFilter(button.getAttribute('data-topology-filter'));
}

function onTopologyMapClick(event) {
  const node = topologyNodeFromTarget(event.target);
  if (node) {
    if (event.preventDefault) event.preventDefault();
    activateTopologyNode(node);
    return;
  }
  const target = event.target;
  if (target && typeof target.closest === 'function'
    && target.closest('.topology-controls, .topology-zoom, .topology-tooltip, .topology-empty, button, input, select, a')) {
    return;
  }
  if (state.topology.selected) clearTopologySelection();
}

function onTopologyMapKeydown(event) {
  const node = topologyNodeFromTarget(event.target);
  if (!node) return;
  if (event.key !== 'Enter' && event.key !== ' ') return;
  if (event.preventDefault) event.preventDefault();
  activateTopologyNode(node);
}

function onTopologyMapPointerOver(event) {
  const node = topologyNodeFromTarget(event.target);
  if (!node) return;
  const related = event.relatedTarget;
  if (related && typeof node.contains === 'function' && node.contains(related)) return;
  showTopologyTooltip(node);
}

function onTopologyMapPointerOut(event) {
  const node = topologyNodeFromTarget(event.target);
  if (!node) return;
  const related = event.relatedTarget;
  if (related && typeof node.contains === 'function' && node.contains(related)) return;
  if (document.activeElement === node) return;
  hideTopologyTooltip();
}

function onTopologyMapFocusIn(event) {
  const node = topologyNodeFromTarget(event.target);
  if (node) showTopologyTooltip(node);
}

function onTopologyMapFocusOut(event) {
  const node = topologyNodeFromTarget(event.target);
  if (!node) return;
  const related = event.relatedTarget;
  if (related && typeof node.contains === 'function' && node.contains(related)) return;
  hideTopologyTooltip();
}

function onTopologyPanStart(event) {
  if (!state.topology.model || state.topology.pan) return;
  const target = event.target;
  if (target && typeof target.closest === 'function'
    && target.closest('.topology-node, .topology-hub, .topology-controls, .topology-zoom, .topology-tooltip, .topology-empty, button, input, select, a')) {
    return;
  }
  if (event.pointerType === 'mouse' && event.button !== 0) return;
  const map = $('#topology-map');
  const current = state.topology.view;
  state.topology.pan = {
    id: event.pointerId,
    pointerType: event.pointerType || 'mouse',
    startX: event.clientX,
    startY: event.clientY,
    originX: current.x,
    originY: current.y,
    moved: false,
  };
  if (map) {
    map.classList.add('is-panning');
    if (typeof map.setPointerCapture === 'function') {
      try {
        map.setPointerCapture(event.pointerId);
      } catch (error) {
        state.topology.pan = null;
        map.classList.remove('is-panning');
      }
    }
  }
  hideTopologyTooltip();
  if (event.pointerType !== 'touch' && event.preventDefault) event.preventDefault();
}

function onTopologyPanMove(event) {
  const pan = state.topology.pan;
  if (!pan || event.pointerId !== pan.id) return;
  const dx = event.clientX - pan.startX;
  const dy = event.clientY - pan.startY;
  if (!pan.moved) {
    if (Math.hypot(dx, dy) < 3) return;
    if (pan.pointerType === 'touch' && Math.abs(dy) > Math.abs(dx)) {
      state.topology.pan = null;
      releaseTopologyPanCapture($('#topology-map'), event.pointerId);
      return;
    }
    pan.moved = true;
  }
  const model = state.topology.model;
  if (!model) return;
  state.topology.view = topologyPanView(
    { scale: state.topology.view.scale },
    pan.originX + dx,
    pan.originY + dy,
    model.width,
    model.height,
  );
  applyTopologyTransform();
  if (event.preventDefault) event.preventDefault();
}

function releaseTopologyPanCapture(map, pointerId) {
  if (!map) return;
  map.classList.remove('is-panning');
  if (typeof map.hasPointerCapture === 'function' && map.hasPointerCapture(pointerId)) {
    try {
      map.releasePointerCapture(pointerId);
    } catch (error) {
      // The pointer may already have been released by the browser.
    }
  }
}

function onTopologyPanEnd(event) {
  const pan = state.topology.pan;
  if (!pan || event.pointerId !== pan.id) return;
  state.topology.pan = null;
  releaseTopologyPanCapture($('#topology-map'), event.pointerId);
}

function bindTopologyEvents() {
  if (state.topology.bound) return;
  const map = $('#topology-map');
  if (!map) return;
  state.topology.bound = true;
  map.addEventListener('click', onTopologyMapClick);
  map.addEventListener('keydown', onTopologyMapKeydown);
  map.addEventListener('pointerover', onTopologyMapPointerOver);
  map.addEventListener('pointerout', onTopologyMapPointerOut);
  map.addEventListener('focusin', onTopologyMapFocusIn);
  map.addEventListener('focusout', onTopologyMapFocusOut);
  map.addEventListener('pointerdown', onTopologyPanStart);
  map.addEventListener('pointermove', onTopologyPanMove);
  map.addEventListener('pointerup', onTopologyPanEnd);
  map.addEventListener('pointercancel', onTopologyPanEnd);
  map.addEventListener('lostpointercapture', onTopologyPanEnd);

  const search = $('#topology-search');
  if (search) search.addEventListener('input', onTopologySearchInput);
  const filters = $('#topology-filters');
  if (filters) filters.addEventListener('click', onTopologyFilterClick);
  const zoomIn = $('#topology-zoom-in');
  if (zoomIn) zoomIn.addEventListener('click', () => zoomTopology(1));
  const zoomOut = $('#topology-zoom-out');
  if (zoomOut) zoomOut.addEventListener('click', () => zoomTopology(-1));
  const fit = $('#topology-fit');
  if (fit) fit.addEventListener('click', fitTopologyViewport);
  const close = $('#topology-selection-close');
  if (close) close.addEventListener('click', clearTopologySelection);
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
      // Keep the active summary current for switches and metadata-only changes
      // such as renaming the active network.
      state.activeNetwork = state.networks.find((network) => network.id === nextActive) || null;
      if (previousActive !== nextActive) {
        // Update the active id before reloading so event and diff responses are
        // filtered against the network that is actually active now.
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
  renderTopology();
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

function topologySignatureValue(value) {
  return value == null ? '' : String(value);
}

function topologyDeviceSignature(device) {
  return [
    device.ip,
    device.name,
    device.hostname,
    device.nbns_name,
    device.label,
    device.vendor,
    device.kind,
    device.online ? 'online' : 'offline',
    device.trust,
    device.is_gateway ? 'gateway' : '',
    device.mac,
  ].map(topologySignatureValue);
}

function topologyRenderSignature(width) {
  const network = state.network;
  const active = state.activeNetwork;
  const devices = deviceList()
    .slice()
    .sort((left, right) => String(left.ip || '').localeCompare(String(right.ip || '')));
  return JSON.stringify({
    width: Math.round(Number(width) || 0),
    networkId: activeNetworkId(),
    network: network
      ? [
        network.id,
        network.network_id,
        network.cidr,
        network.gateway,
        network.label,
        network.title,
        network.interface,
        network.gateway_mac,
      ]
      : null,
    active: active
      ? [
        active.id,
        active.cidr,
        active.gateway,
        active.label,
        active.title,
        active.interface,
        active.gateway_mac,
      ]
      : null,
    devices: devices.map(topologyDeviceSignature),
  });
}

function topologyFocusedNode(host) {
  const active = document.activeElement;
  if (!active || active === document.body || typeof active.closest !== 'function') return null;
  if (!host.contains(active)) return null;
  const node = active.closest('.topology-node[data-ip], .topology-hub[data-role="gateway"]');
  if (!node) return null;
  return {
    role: node.getAttribute('data-role') || '',
    ip: node.getAttribute('data-ip') || '',
  };
}

function restoreTopologyFocus(host, focus) {
  if (!focus) return;
  const selector = focus.role === 'gateway'
    ? '.topology-hub[data-role="gateway"]'
    : '.topology-node[data-ip]';
  const target = $$(selector, host).find(
    (element) => String(element.getAttribute('data-ip') || '') === focus.ip,
  );
  if (!target || target.classList.contains('is-filtered')) return;
  if (typeof target.focus === 'function') target.focus({ preventScroll: true });
}

function topologyContextText() {
  const active = state.activeNetwork;
  const network = state.network;
  const bits = [];
  if (active) {
    const label = active.label || active.title;
    if (label) bits.push(String(label));
  }
  const cidr = (network && network.cidr) || (active && active.cidr);
  if (cidr && !bits.includes(String(cidr))) bits.push(String(cidr));
  return bits.join(' · ') || 'No active network yet';
}

function renderTopologyAccessibleList(view) {
  const list = $('#topology-accessible-list');
  if (!list) return;
  const items = [];
  if (view.hub) {
    const status = view.hub.missing
      ? 'not in inventory'
      : view.hub.online ? 'online' : 'offline';
    const name = view.hub.missing || view.hub.name === 'Gateway'
      ? 'Gateway'
      : `Gateway ${view.hub.name}`;
    items.push(`${name}, ${view.hub.ip}, ${status}, ${view.hub.trustLabel}`);
  }
  view.nodes.forEach((node) => {
    items.push(`${node.name}, ${node.ip}, ${node.online ? 'online' : 'offline'}, ${node.trustLabel}`);
  });
  if (view.hidden) {
    items.push(`${view.hidden} more devices are not shown in the map.`);
  }
  list.replaceChildren(...items.map((text) => {
    const item = document.createElement('li');
    item.textContent = text;
    return item;
  }));
}

function renderTopology() {
  const map = $('#topology-map');
  const svgHost = $('#topology-svg-host');
  const empty = $('#topology-empty');
  if (!map || !svgHost || !empty) return;

  const networkId = activeNetworkId();
  const networkChanged = state.topology.networkId !== networkId;
  if (networkChanged) {
    state.topology.networkId = networkId;
    state.topology.selected = null;
    state.topology.view = topologyFitView();
    state.topology.pan = null;
    state.topology.signature = null;
  }

  const measured = Math.round(svgHost.clientWidth || map.clientWidth || 720);
  const width = Math.max(280, Math.min(measured, 960));
  const signature = topologyRenderSignature(width);
  if (signature === state.topology.signature) return;
  const focusedNode = networkChanged ? null : topologyFocusedNode(svgHost);
  state.topology.signature = signature;
  state.topology.pan = null;
  map.classList.remove('is-panning');

  const view = buildTopologyView({
    devices: deviceList(),
    network: state.network,
    activeNetwork: state.activeNetwork,
    width,
  });
  state.topology.width = width;
  state.topology.model = view;

  $('#topology-context').textContent = topologyContextText();
  let countText = `${plural(view.total, 'device')} · ${view.online} online`;
  if (view.gatewayMissing) countText += ' · gateway not in inventory';
  $('#topology-count').textContent = countText;

  const controls = $('#topology-controls');
  const zoom = $('#topology-zoom');
  const viewStatus = $('#topology-view-status');

  if (view.empty) {
    state.topology.selected = null;
    svgHost.hidden = true;
    empty.hidden = false;
    if (controls) controls.hidden = true;
    if (zoom) zoom.hidden = true;
    if (viewStatus) {
      viewStatus.hidden = true;
      viewStatus.textContent = '';
    }
    hideTopologyTooltip();
    hideTopologySelection();
    $('#topology-empty-title').textContent = view.empty.title;
    $('#topology-empty-text').textContent = view.empty.text;
    $('#topology-more').hidden = true;
    renderTopologyAccessibleList(view);
    return;
  }

  if (controls) controls.hidden = false;
  if (zoom) zoom.hidden = false;
  empty.hidden = true;
  svgHost.hidden = false;
  hideTopologyTooltip();

  const selected = state.topology.selected;
  if (selected) {
    const exists = selected.kind === 'gateway'
      ? !!(view.hub && String(view.hub.ip || '') === String(selected.ip || ''))
      : view.nodes.some((node) => String(node.ip) === String(selected.ip || ''));
    if (!exists) state.topology.selected = null;
  }

  svgHost.replaceChildren(createTopologySvg(document, view, {
    selected: state.topology.selected,
  }));
  syncTopologyFilterButtons();
  applyTopologyTransform();
  applyTopologyVisibility();
  syncTopologySelection();
  if (state.topology.selected && state.topology.selected.kind === 'gateway') {
    renderTopologySelection(view.hub);
  } else {
    hideTopologySelection();
  }
  restoreTopologyFocus(svgHost, focusedNode);

  const more = $('#topology-more');
  if (view.hidden) {
    more.hidden = false;
    more.textContent = `Showing ${view.shown} of ${view.childTotal} devices around the gateway. Use the device list below for the rest.`;
  } else {
    more.hidden = true;
    more.textContent = '';
  }
  renderTopologyAccessibleList(view);
}

function setupTopologyResize() {
  const map = $('#topology-map');
  if (!map) return;
  const schedule = () => {
    if (state.topology.frame) return;
    state.topology.frame = requestAnimationFrame(() => {
      state.topology.frame = 0;
      const svgHost = $('#topology-svg-host');
      const width = Math.round((svgHost && svgHost.clientWidth) || map.clientWidth || 0);
      if (width && Math.abs(width - state.topology.width) >= 12) renderTopology();
    });
  };
  if (typeof ResizeObserver === 'function') {
    new ResizeObserver(schedule).observe(map);
  } else {
    window.addEventListener('resize', schedule);
  }
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
  $('#topology-scan').addEventListener('click', () => startScan({}));
  bindTopologyEvents();
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
  setupTopologyResize();
  setTrustGuideVisible(!readTrustGuideDismissed());
  setupAutoScan();
  await Promise.all([loadState(), loadHistory()]);
  loadEvents(true, true);
  loadLatestDiff();
  connectEvents();
  setInterval(tick, 1000);
}

document.addEventListener('DOMContentLoaded', init);
