'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

class FakeElement {
  constructor(namespaceURI, tagName) {
    this.namespaceURI = namespaceURI;
    this.tagName = tagName;
    this.attributes = Object.create(null);
    this.children = [];
    this.parentElement = null;
    this.html = '';
    this.text = '';
    this.hidden = false;
    this.value = '';
    this.disabled = false;
    this.style = {};
    this.listeners = Object.create(null);
  }

  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }

  getAttribute(name) {
    return this.attributes[name];
  }

  removeAttribute(name) {
    delete this.attributes[name];
  }

  get classList() {
    const element = this;
    const current = () => String(element.attributes.class || '').split(/\s+/).filter(Boolean);
    const write = (values) => {
      element.attributes.class = Array.from(new Set(values)).join(' ');
    };
    return {
      add(...names) {
        write([...current(), ...names]);
      },
      remove(...names) {
        write(current().filter((name) => !names.includes(name)));
      },
      toggle(name, force) {
        const has = current().includes(name);
        const next = force === undefined ? !has : Boolean(force);
        if (next && !has) write([...current(), name]);
        if (!next && has) write(current().filter((value) => value !== name));
        return next;
      },
      contains(name) {
        return current().includes(name);
      },
    };
  }

  appendChild(child) {
    child.parentElement = this;
    this.children.push(child);
    return child;
  }

  replaceChildren(...children) {
    this.children = children;
    children.forEach((child) => {
      child.parentElement = this;
    });
  }

  remove() {
    if (!this.parentElement) return;
    this.parentElement.children = this.parentElement.children.filter((child) => child !== this);
    this.parentElement = null;
  }

  get firstElementChild() {
    return this.children[0] || null;
  }

  set innerHTML(value) {
    this.html = String(value);
  }

  get innerHTML() {
    return this.html;
  }

  set textContent(value) {
    this.text = String(value);
    this.children = [];
  }

  get textContent() {
    if (this.children.length) {
      return this.children.map((child) => child.textContent).join('');
    }
    return this.text;
  }

  matches(selector) {
    return String(selector).split(',').some((raw) => {
      let part = raw.trim();
      if (!part) return false;
      const tagMatch = part.match(/^([a-zA-Z][\w-]*)/);
      if (tagMatch && String(this.tagName).toLowerCase() !== tagMatch[1].toLowerCase()) {
        return false;
      }
      if (tagMatch) part = part.slice(tagMatch[0].length);
      const classNames = Array.from(part.matchAll(/\.([\w-]+)/g)).map((match) => match[1]);
      if (classNames.some((name) => !this.classList.contains(name))) return false;
      const attributes = Array.from(part.matchAll(/\[([\w-]+)(?:=(?:"([^"]*)"|'([^']*)'|([^\]]+)))?\]/g));
      for (const match of attributes) {
        const name = match[1];
        const expected = match[2] ?? match[3] ?? match[4];
        if (this.getAttribute(name) == null) return false;
        if (expected != null && String(this.getAttribute(name)) !== String(expected)) return false;
      }
      return true;
    });
  }

  closest(selector) {
    let node = this;
    while (node) {
      if (typeof node.matches === 'function' && node.matches(selector)) return node;
      node = node.parentElement;
    }
    return null;
  }

  contains(other) {
    let node = other;
    while (node) {
      if (node === this) return true;
      node = node.parentElement;
    }
    return false;
  }

  querySelectorAll(selector) {
    const found = [];
    const visit = (node) => {
      node.children.forEach((child) => {
        if (typeof child.matches === 'function' && child.matches(selector)) found.push(child);
        visit(child);
      });
    };
    visit(this);
    return found;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }

  addEventListener(type, listener) {
    if (!this.listeners[type]) this.listeners[type] = [];
    this.listeners[type].push(listener);
  }

  dispatch(type, event = {}) {
    const payload = { target: this, preventDefault() {}, ...event };
    (this.listeners[type] || []).forEach((listener) => listener(payload));
    return payload;
  }

  focus() {
    documentStub.activeElement = this;
  }

  setPointerCapture() {}
  releasePointerCapture() {}
  hasPointerCapture() { return false; }

  getBoundingClientRect() {
    return { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 };
  }
}

function classesOf(element) {
  return String(element.getAttribute('class') || '').split(/\s+/).filter(Boolean);
}

const documentStub = {
  activeElement: null,
  body: new FakeElement(null, 'body'),
  elements: new Map(),
  addEventListener() {},
  createElement(tagName) {
    return new FakeElement(null, tagName);
  },
  createElementNS(namespaceURI, tagName) {
    return new FakeElement(namespaceURI, tagName);
  },
  querySelector(selector) {
    if (!this.elements.has(selector)) {
      this.elements.set(selector, new FakeElement(null, 'div'));
    }
    return this.elements.get(selector);
  },
  querySelectorAll() {
    return [];
  },
};

function resetDashboardDom() {
  documentStub.elements.clear();
  documentStub.activeElement = null;
  documentStub.body = new FakeElement(null, 'body');
}

function resetTopologyState() {
  resetDashboardDom();
  vm.runInContext(`
    state.devices = new Map();
    state.newDevices = new Set();
    state.search = '';
    state.network = null;
    state.activeNetwork = null;
    state.drawerIp = null;
    state.topology.model = null;
    state.topology.networkId = '';
    state.topology.signature = null;
    state.topology.search = '';
    state.topology.filter = 'all';
    state.topology.selected = null;
    state.topology.view = { scale: 1, x: 0, y: 0 };
    state.topology.pan = null;
  `, app);
}

function setDashboardDevices(devices) {
  app.__testDevices = devices;
  vm.runInContext('state.devices = new Map(__testDevices.map((device) => [device.ip, device]))', app);
  delete app.__testDevices;
}

function setTopologyModel(view) {
  app.__testTopologyView = view;
  vm.runInContext('state.topology.model = __testTopologyView', app);
  delete app.__testTopologyView;
}

function setTopologyNetwork(net) {
  app.__testNetwork = net;
  vm.runInContext('state.network = __testNetwork; state.activeNetwork = __testNetwork', app);
  delete app.__testNetwork;
}

function dashboardValue(expression) {
  return vm.runInContext(expression, app);
}

function loadDashboard() {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'lanwatch', 'static', 'app.js'),
    'utf8',
  );
  const context = {
    console,
    document: documentStub,
    window: {},
    localStorage: {
      getItem() { return null; },
      setItem() {},
      removeItem() {},
    },
    setTimeout,
    clearTimeout,
    requestAnimationFrame() { return 1; },
    cancelAnimationFrame() {},
    fetch: async () => ({ ok: true, json: async () => ({}) }),
  };
  vm.createContext(context);
  vm.runInContext(source, context, { filename: 'app.js' });
  return context;
}

const app = loadDashboard();

function device(ip, overrides = {}) {
  return {
    ip,
    name: `Device ${ip}`,
    hostname: null,
    label: null,
    kind: 'device',
    online: true,
    trust: 'unknown',
    is_gateway: false,
    ...overrides,
  };
}

function walk(root, output = []) {
  output.push(root);
  root.children.forEach((child) => walk(child, output));
  return output;
}

function classes(element) {
  return String(element.getAttribute('class') || '').split(/\s+/).filter(Boolean);
}

function byClass(root, className) {
  return walk(root).filter((element) => classes(element).includes(className));
}

function allText(root) {
  return walk(root)
    .filter((element) => element.tagName === 'text' || element.tagName === 'title')
    .map((element) => element.textContent)
    .join('\n');
}

function network(gateway = '192.168.1.1') {
  return { id: 'net-a', cidr: '192.168.1.0/24', gateway };
}

function build(devices, options = {}) {
  return app.buildTopologyView({
    devices,
    network: options.network === undefined ? network() : options.network,
    activeNetwork: options.activeNetwork === undefined ? network() : options.activeNetwork,
    width: options.width || 800,
  });
}

function assertNoOverlap(nodes) {
  for (let left = 0; left < nodes.length; left += 1) {
    for (let right = left + 1; right < nodes.length; right += 1) {
      const a = nodes[left];
      const b = nodes[right];
      const distance = Math.hypot(a.x - b.x, a.y - b.y);
      assert.ok(
        distance > a.r + b.r,
        `nodes ${left} and ${right} overlap (${distance.toFixed(1)}px apart)`,
      );
    }
  }
}

function testGatewayIsRenderedOnce() {
  const devices = [
    device('192.168.1.1', { name: 'Home Router', kind: 'router', trust: 'trusted', is_gateway: true }),
    device('192.168.1.20', { name: 'Living Room TV', kind: 'tv' }),
    device('192.168.1.5', { name: 'Laptop', kind: 'computer', trust: 'trusted' }),
  ];
  const view = build(devices);
  assert.strictEqual(view.hub.ip, '192.168.1.1');
  assert.strictEqual(view.hub.kind, 'router');
  assert.deepStrictEqual(view.nodes.map((node) => node.ip), ['192.168.1.5', '192.168.1.20']);
  assert.ok(!view.nodes.some((node) => node.ip === view.hub.ip));

  const svg = app.createTopologySvg(documentStub, view);
  assert.strictEqual(svg.getAttribute('role'), 'group');
  assert.ok(svg.getAttribute('aria-label').includes('Logical network topology'));
  assert.strictEqual(byClass(svg, 'topology-hub').length, 1);
  assert.strictEqual(byClass(svg, 'topology-node').length, 2);
  assert.strictEqual(byClass(svg, 'topology-link').length, 2);
}

function testNodeContentStatusAndTrust() {
  const devices = [
    device('10.0.0.1', { name: 'Router', kind: 'router', is_gateway: true }),
    device('10.0.0.2', { name: 'Living Room TV', kind: 'tv', trust: 'trusted' }),
    device('10.0.0.3', { name: 'Old Printer', kind: 'printer', trust: 'ignored', online: false }),
  ];
  const view = build(devices, { network: network('10.0.0.1'), activeNetwork: network('10.0.0.1') });
  assert.strictEqual(view.nodes.length, 2);
  assert.strictEqual(view.nodes[0].trust, 'trusted');
  assert.strictEqual(view.nodes[1].online, false);
  assert.strictEqual(view.nodes[1].trust, 'ignored');
  assert.strictEqual(view.links[1].offline, true);

  const svg = app.createTopologySvg(documentStub, view);
  const nodes = byClass(svg, 'topology-node');
  assert.ok(classes(nodes[0]).includes('trust-trusted'));
  assert.ok(classes(nodes[0]).includes('is-online'));
  assert.ok(classes(nodes[1]).includes('trust-ignored'));
  assert.ok(classes(nodes[1]).includes('is-offline'));

  const text = allText(svg);
  assert.ok(text.includes('Living Room TV'));
  assert.ok(text.includes('10.0.0.2'));
  assert.ok(text.includes('Old Printer'));
  assert.ok(text.includes('10.0.0.3'));
  assert.ok(text.includes('offline'));
  assert.ok(text.includes('Trusted'));
  assert.ok(text.includes('Ignored'));

  const nodeDots = nodes.map((node) => byClass(node, 'topology-status-dot')[0]);
  assert.ok(classes(nodeDots[0]).includes('online'));
  assert.ok(classes(nodeDots[1]).includes('offline'));
  assert.strictEqual(byClass(svg, 'topology-link').filter((line) => classes(line).includes('is-offline')).length, 1);

  const icons = byClass(svg, 'topology-kind-icon');
  assert.ok(icons[0].innerHTML.includes('<rect'));
  assert.ok(icons[1].innerHTML.includes('<rect'));
}

function testEmptyAndMissingGatewayStates() {
  const empty = app.buildTopologyView({
    devices: [],
    network: network(),
    activeNetwork: network(),
    width: 800,
  });
  assert.strictEqual(empty.empty.reason, 'no-devices');
  assert.strictEqual(empty.hub, null);
  assert.strictEqual(empty.nodes.length, 0);

  const noGateway = app.buildTopologyView({
    devices: [device('10.0.0.8')],
    network: { id: 'net-a', cidr: '10.0.0.0/24', gateway: null },
    activeNetwork: { id: 'net-a', cidr: '10.0.0.0/24', gateway: null },
    width: 800,
  });
  assert.strictEqual(noGateway.empty.reason, 'no-gateway');

  const placeholder = app.buildTopologyView({
    devices: [device('10.0.0.8')],
    network: network('10.0.0.1'),
    activeNetwork: network('10.0.0.1'),
    width: 800,
  });
  assert.strictEqual(placeholder.empty, null);
  assert.strictEqual(placeholder.hub.missing, true);
  assert.strictEqual(placeholder.gatewayMissing, true);
  assert.strictEqual(placeholder.nodes.length, 1);
  assert.strictEqual(placeholder.childTotal, 1);

  const svg = app.createTopologySvg(documentStub, placeholder);
  assert.strictEqual(byClass(svg, 'topology-hub').length, 1);
  assert.ok(classes(byClass(svg, 'topology-hub')[0]).includes('is-missing'));
  assert.ok(allText(svg).includes('not in inventory'));
  assert.ok(classes(byClass(svg, 'topology-status-dot')[0]).includes('missing'));

  app.renderTopologyAccessibleList(placeholder);
  const listText = documentStub.querySelector('#topology-accessible-list').textContent;
  assert.ok(listText.includes('Gateway, 10.0.0.1, not in inventory'));
  assert.ok(!listText.includes('Gateway Gateway'));
}

function testLargeNetworksAreCappedAndStable() {
  const devices = [device('10.0.0.1', { is_gateway: true })];
  for (let index = 2; index <= 45; index += 1) {
    devices.push(device(`10.0.0.${index}`, { online: index % 3 !== 0 }));
  }

  const desktop = build(devices, { width: 800 });
  assert.strictEqual(desktop.childTotal, 44);
  assert.strictEqual(desktop.shown, 20);
  assert.strictEqual(desktop.hidden, 24);
  assert.strictEqual(desktop.nodes.length, 20);
  assertNoOverlap(desktop.nodes);

  const wide = build(devices, { width: 960 });
  assert.strictEqual(wide.shown, 32);
  assert.strictEqual(wide.nodes.length, 32);
  assertNoOverlap(wide.nodes);

  const phone = build(devices, { width: 320 });
  assert.strictEqual(phone.shown, 12);
  assert.strictEqual(phone.hidden, 32);
  assert.strictEqual(phone.mode, 'tree');
  assertNoOverlap(phone.nodes);

  const tablet = build(devices, { width: 880 });
  assert.strictEqual(tablet.mode, 'tree');
  assertNoOverlap(tablet.nodes);
  const radial = build(devices, { width: 900 });
  assert.strictEqual(radial.mode, 'radial');
  assertNoOverlap(radial.nodes);

  const first = build(devices, { width: 800 });
  const second = build(devices, { width: 800 });
  assert.deepStrictEqual(
    first.nodes.map(({ x, y }) => [x, y]),
    second.nodes.map(({ x, y }) => [x, y]),
  );

  const toggledDevices = devices.map((entry, index) => (
    index === 1 ? { ...entry, online: !entry.online } : entry
  ));
  const toggled = build(toggledDevices, { width: 800 });
  assert.deepStrictEqual(
    first.nodes.map(({ x, y }) => [x, y]),
    toggled.nodes.map(({ x, y }) => [x, y]),
  );
  assert.notStrictEqual(first.nodes[0].online, toggled.nodes[0].online);

  const statusChanged = devices.map((entry, index) => (
    index === 1 ? { ...entry, trust: 'trusted', rtt_ms: 987 } : entry
  ));
  const stable = build(statusChanged, { width: 800 });
  assert.deepStrictEqual(
    first.nodes.map(({ x, y }) => [x, y]),
    stable.nodes.map(({ x, y }) => [x, y]),
  );
  assert.strictEqual(stable.nodes[0].trust, 'trusted');
}

function testNetworkSwitchingUsesOnlyCurrentDevices() {
  const netA = { id: 'net-a', cidr: '192.168.1.0/24', gateway: '192.168.1.1' };
  const netB = { id: 'net-b', cidr: '10.20.0.0/24', gateway: '10.20.0.1' };
  const devicesA = [
    device('192.168.1.1', { is_gateway: true }),
    device('192.168.1.10'),
  ];
  const devicesB = [
    device('10.20.0.1', { is_gateway: true }),
    device('10.20.0.22'),
    device('10.20.0.23'),
  ];

  const viewA = build(devicesA, { network: netA, activeNetwork: netA });
  const viewB = build(devicesB, { network: netB, activeNetwork: netB });
  assert.strictEqual(viewA.hub.ip, '192.168.1.1');
  assert.deepStrictEqual(viewA.nodes.map((node) => node.ip), ['192.168.1.10']);
  assert.strictEqual(viewB.hub.ip, '10.20.0.1');
  assert.deepStrictEqual(viewB.nodes.map((node) => node.ip), ['10.20.0.22', '10.20.0.23']);
  assert.ok(!viewB.nodes.some((node) => node.ip.startsWith('192.168.1.')));
}

function testUntrustedTextIsRenderedSafely() {
  const payload = '<img src=x onerror=alert(1)>';
  const devices = [
    device('10.0.0.1', { is_gateway: true }),
    device('10.0.0.9', {
      name: payload,
      hostname: payload,
      label: payload,
      kind: 'constructor',
      trust: 'constructor',
    }),
  ];
  const view = build(devices, { network: network('10.0.0.1'), activeNetwork: network('10.0.0.1') });
  assert.strictEqual(view.nodes[0].name, payload);
  assert.strictEqual(view.nodes[0].trust, 'unknown');
  assert.strictEqual(view.nodes[0].kindLabel, 'Constructor');

  const svg = app.createTopologySvg(documentStub, view);
  assert.ok(allText(svg).includes(payload));
  assert.strictEqual(walk(svg).filter((element) => ['img', 'script'].includes(element.tagName)).length, 0);
  walk(svg).forEach((element) => {
    assert.ok(!element.innerHTML.includes('<img'), 'untrusted text leaked into innerHTML');
    assert.ok(!element.innerHTML.includes('onerror'), 'untrusted text leaked into innerHTML');
  });

  resetTopologyState();
  setTopologyModel(view);
  const host = documentStub.querySelector('#topology-svg-host');
  const node = makeTopologyElement('topology-node', '10.0.0.9', 'device');
  host.appendChild(node);
  app.showTopologyTooltip(node);
  const tooltip = documentStub.querySelector('#topology-tooltip');
  assert.ok(tooltip.textContent.includes(payload));
  assert.strictEqual(walk(tooltip).filter((element) => ['img', 'script'].includes(element.tagName)).length, 0);
  walk(tooltip).forEach((element) => {
    assert.ok(!element.innerHTML.includes('<img'), 'untrusted tooltip text leaked into innerHTML');
    assert.ok(!element.innerHTML.includes('onerror'), 'untrusted tooltip text leaked into innerHTML');
  });
}

function testGatewayCandidatesAndTrust() {
  const devices = [
    device('10.0.0.1', { name: 'Router', is_gateway: false, trust: 'trusted' }),
    device('10.0.0.4'),
  ];
  const view = app.buildTopologyView({
    devices,
    network: { id: 'net-a', cidr: '10.0.0.0/24', gateway: '10.0.0.1' },
    activeNetwork: { id: 'net-a', cidr: '10.0.0.0/24', gateway: '10.0.0.1' },
    width: 800,
  });
  assert.strictEqual(view.hub.ip, '10.0.0.1');
  assert.strictEqual(view.hub.missing, false);
  assert.strictEqual(view.hub.trust, 'trusted');
  assert.deepStrictEqual(view.nodes.map((node) => node.ip), ['10.0.0.4']);
}

function makeTopologyElement(className, ip, role) {
  const element = new FakeElement('http://www.w3.org/2000/svg', 'g');
  element.setAttribute('class', className);
  element.setAttribute('data-ip', ip);
  if (role) element.setAttribute('data-role', role);
  return element;
}

function testDeviceClickOpensExistingDrawer() {
  resetTopologyState();
  const devices = [
    device('10.0.0.1', { name: 'Router', is_gateway: true }),
    device('10.0.0.2', { name: 'Living Room TV', kind: 'tv', trust: 'trusted' }),
  ];
  setDashboardDevices(devices);
  const host = documentStub.querySelector('#topology-svg-host');
  const node = makeTopologyElement('topology-node trust-trusted is-online', '10.0.0.2', 'device');
  host.appendChild(node);

  const action = app.activateTopologyNode(node);
  assert.strictEqual(action, 'device');
  assert.strictEqual(dashboardValue('state.drawerIp'), '10.0.0.2');
  assert.strictEqual(dashboardValue('state.topology.selected.kind'), 'device');
  assert.ok(node.classList.contains('is-selected'));
  assert.strictEqual(node.getAttribute('aria-current'), 'true');
  assert.ok(documentStub.querySelector('#drawer').classList.contains('open'));
  assert.strictEqual(documentStub.querySelector('#backdrop').hidden, false);

  vm.runInContext('state.drawerIp = null', app);
  app.onTopologyMapKeydown({
    target: node,
    key: 'Enter',
    preventDefault() {},
  });
  assert.strictEqual(dashboardValue('state.drawerIp'), '10.0.0.2');

  vm.runInContext('state.drawerIp = null', app);
  app.onTopologyMapKeydown({
    target: node,
    key: ' ',
    preventDefault() {},
  });
  assert.strictEqual(dashboardValue('state.drawerIp'), '10.0.0.2');
}

function testGatewaySelectionShowsNetworkDetailsWithoutDeviceDrawer() {
  resetTopologyState();
  const net = {
    id: 'net-a',
    label: 'Home network',
    cidr: '10.0.0.0/24',
    gateway: '10.0.0.1',
    gateway_mac: 'aa:bb:cc:dd:ee:ff',
    interface: 'wlan0',
  };
  const devices = [
    device('10.0.0.1', { name: 'Router', kind: 'router', trust: 'trusted', is_gateway: true }),
    device('10.0.0.2', { name: 'Living Room TV', kind: 'tv' }),
  ];
  setDashboardDevices(devices);
  const view = build(devices, { network: net, activeNetwork: net });
  setTopologyModel(view);
  const host = documentStub.querySelector('#topology-svg-host');
  const hub = makeTopologyElement('topology-hub trust-trusted is-online', '10.0.0.1', 'gateway');
  host.appendChild(hub);

  const action = app.activateTopologyNode(hub);
  assert.strictEqual(action, 'gateway');
  assert.strictEqual(dashboardValue('state.drawerIp'), null);
  assert.ok(!documentStub.querySelector('#drawer').classList.contains('open'));
  assert.strictEqual(dashboardValue('state.topology.selected.kind'), 'gateway');
  assert.ok(hub.classList.contains('is-selected'));
  assert.strictEqual(hub.getAttribute('aria-current'), 'true');

  const panel = documentStub.querySelector('#topology-selection');
  assert.strictEqual(panel.hidden, false);
  const body = documentStub.querySelector('#topology-selection-body').textContent;
  assert.ok(body.includes('10.0.0.0/24'));
  assert.ok(body.includes('wlan0'));
  assert.ok(body.includes('aa:bb:cc:dd:ee:ff'));
  assert.ok(body.includes('Home network'));
  assert.strictEqual(
    documentStub.querySelector('#topology-selection-title').textContent,
    'Gateway · Router',
  );
}

function testSearchAndFiltersUpdateHighlightingImmediately() {
  resetTopologyState();
  const devices = [
    device('10.0.0.1', { name: 'Router', kind: 'router', is_gateway: true }),
    device('10.0.0.2', {
      name: 'Living Room TV',
      hostname: 'tv.local',
      vendor: 'Acme',
      kind: 'tv',
      online: true,
      trust: 'trusted',
    }),
    device('10.0.0.3', {
      name: 'Old Printer',
      label: 'Office Printer',
      vendor: 'PrintCo',
      kind: 'printer',
      online: false,
      trust: 'ignored',
    }),
    device('10.0.0.4', {
      name: 'Laptop',
      hostname: 'laptop.local',
      kind: 'computer',
      online: true,
      trust: 'unknown',
    }),
  ];
  const net = network('10.0.0.1');
  const view = build(devices, { network: net, activeNetwork: net });
  setTopologyModel(view);
  const host = documentStub.querySelector('#topology-svg-host');
  host.hidden = false;
  const elements = new Map();
  view.nodes.forEach((node) => {
    const element = makeTopologyElement('topology-node', node.ip, 'device');
    host.appendChild(element);
    elements.set(node.ip, element);
    const link = new FakeElement('http://www.w3.org/2000/svg', 'line');
    link.setAttribute('class', 'topology-link');
    link.setAttribute('data-ip', node.ip);
    host.appendChild(link);
  });
  const hub = makeTopologyElement('topology-hub', '10.0.0.1', 'gateway');
  host.appendChild(hub);

  assert.ok(app.topologyMatchesSearch(view.nodes[0], 'tv.local'));
  assert.ok(app.topologyMatchesSearch(view.nodes[0], 'acme'));
  assert.ok(app.topologyMatchesSearch(view.nodes[1], 'office printer'));
  assert.ok(app.topologyMatchesSearch(view.nodes[1], 'printco'));
  assert.ok(app.topologyMatchesSearch(view.nodes[2], '10.0.0.4'));

  vm.runInContext("state.search = 'table-only'", app);
  app.onTopologySearchInput({ target: { value: 'laptop' } });
  assert.strictEqual(dashboardValue('state.topology.search'), 'laptop');
  assert.strictEqual(dashboardValue('state.search'), 'table-only');
  assert.ok(elements.get('10.0.0.4').classList.contains('is-search-match'));
  assert.ok(!elements.get('10.0.0.4').classList.contains('is-dimmed'));
  assert.ok(elements.get('10.0.0.2').classList.contains('is-dimmed'));
  assert.ok(elements.get('10.0.0.3').classList.contains('is-dimmed'));
  assert.ok(hub.classList.contains('is-dimmed'));

  app.onTopologySearchInput({ target: { value: '' } });
  app.setTopologyFilter('online');
  assert.strictEqual(dashboardValue('state.topology.filter'), 'online');
  assert.ok(!elements.get('10.0.0.2').classList.contains('is-filtered'));
  assert.ok(elements.get('10.0.0.3').classList.contains('is-filtered'));
  assert.ok(!elements.get('10.0.0.4').classList.contains('is-filtered'));
  assert.ok(!hub.classList.contains('is-filtered'));

  app.setTopologyFilter('trusted');
  assert.ok(!elements.get('10.0.0.2').classList.contains('is-filtered'));
  assert.ok(elements.get('10.0.0.3').classList.contains('is-filtered'));
  assert.ok(elements.get('10.0.0.4').classList.contains('is-filtered'));

  app.setTopologyFilter('unknown');
  assert.ok(elements.get('10.0.0.2').classList.contains('is-filtered'));
  assert.ok(elements.get('10.0.0.3').classList.contains('is-filtered'));
  assert.ok(!elements.get('10.0.0.4').classList.contains('is-filtered'));

  app.setTopologyFilter('offline');
  assert.ok(elements.get('10.0.0.2').classList.contains('is-filtered'));
  assert.ok(!elements.get('10.0.0.3').classList.contains('is-filtered'));
  assert.ok(elements.get('10.0.0.4').classList.contains('is-filtered'));

  app.setTopologyFilter('all');
  elements.forEach((element) => {
    assert.ok(!element.classList.contains('is-filtered'));
    assert.ok(!element.classList.contains('is-dimmed'));
    assert.ok(!element.classList.contains('is-search-match'));
  });
}

function testZoomPanAndFitLimits() {
  assert.strictEqual(app.topologyClampScale(99), 2.4);
  assert.strictEqual(app.topologyClampScale(-1), 0.6);
  assert.strictEqual(app.topologyZoomScale(1, 1), 1.2);
  assert.strictEqual(app.topologyZoomScale(2.4, 1), 2.4);
  assert.strictEqual(app.topologyZoomScale(0.6, -1), 0.6);
  const fitted = app.topologyFitView();
  assert.strictEqual(fitted.scale, 1);
  assert.strictEqual(fitted.x, 0);
  assert.strictEqual(fitted.y, 0);

  const flatPan = app.topologyPanView({ scale: 1 }, 5000, -5000, 720, 420);
  assert.strictEqual(flatPan.x, 96);
  assert.strictEqual(flatPan.y, -72);
  const zoomedPan = app.topologyPanView({ scale: 2 }, 5000, -5000, 800, 500);
  assert.strictEqual(zoomedPan.x, 496);
  assert.strictEqual(zoomedPan.y, -322);

  const devices = [device('10.0.0.1', { is_gateway: true }), device('10.0.0.2')];
  const view = build(devices);
  setTopologyModel(view);
  vm.runInContext('state.topology.view = { scale: 2, x: 40, y: 30 }', app);
  app.fitTopologyViewport();
  assert.strictEqual(dashboardValue('state.topology.view.scale'), 1);
  assert.strictEqual(dashboardValue('state.topology.view.x'), 0);
  assert.strictEqual(dashboardValue('state.topology.view.y'), 0);

  app.topologySetScale(99);
  assert.strictEqual(dashboardValue('state.topology.view.scale'), 2.4);
  assert.strictEqual(documentStub.querySelector('#topology-zoom-in').disabled, true);
  assert.strictEqual(documentStub.querySelector('#topology-zoom-out').disabled, false);
  app.topologySetScale(-10);
  assert.strictEqual(dashboardValue('state.topology.view.scale'), 0.6);
  assert.strictEqual(documentStub.querySelector('#topology-zoom-out').disabled, true);
  assert.strictEqual(documentStub.querySelector('#topology-zoom-in').disabled, false);

  const map = documentStub.querySelector('#topology-map');
  dashboardValue('state.topology.view = { scale: 1, x: 0, y: 0 }');
  app.onTopologyPanStart({
    target: makeTopologyElement('topology-node', '10.0.0.2', 'device'),
    pointerId: 6,
    pointerType: 'touch',
    button: 0,
    clientX: 10,
    clientY: 10,
    preventDefault() {},
  });
  assert.strictEqual(dashboardValue('state.topology.pan'), null);
  assert.ok(!map.classList.contains('is-panning'));
  app.onTopologyPanStart({
    target: new FakeElement(null, 'svg'),
    pointerId: 7,
    pointerType: 'touch',
    button: 0,
    clientX: 10,
    clientY: 10,
    preventDefault() {},
  });
  assert.ok(map.classList.contains('is-panning'));
  app.onTopologyPanMove({
    pointerId: 7,
    clientX: 40,
    clientY: 15,
    preventDefault() {},
  });
  assert.strictEqual(dashboardValue('state.topology.view.x'), 30);
  assert.strictEqual(dashboardValue('state.topology.view.y'), 5);
  app.onTopologyPanEnd({ pointerId: 7 });
  assert.strictEqual(dashboardValue('state.topology.pan'), null);
  assert.ok(!map.classList.contains('is-panning'));

  app.onTopologyPanStart({
    target: new FakeElement(null, 'svg'),
    pointerId: 8,
    pointerType: 'touch',
    button: 0,
    clientX: 10,
    clientY: 10,
    preventDefault() {},
  });
  app.onTopologyPanMove({
    pointerId: 8,
    clientX: 12,
    clientY: 70,
    preventDefault() {},
  });
  assert.strictEqual(dashboardValue('state.topology.pan'), null);
  assert.strictEqual(dashboardValue('state.topology.view.x'), 30);
  assert.strictEqual(dashboardValue('state.topology.view.y'), 5);
  assert.ok(!map.classList.contains('is-panning'));
}

function testKeyboardAndScreenReaderControls() {
  const devices = [
    device('10.0.0.1', { name: 'Router', kind: 'router', trust: 'trusted', is_gateway: true }),
    device('10.0.0.2', { name: 'Living Room TV', kind: 'tv', trust: 'trusted' }),
  ];
  const view = build(devices, { network: network('10.0.0.1'), activeNetwork: network('10.0.0.1') });
  const svg = app.createTopologySvg(documentStub, view, {
    selected: { kind: 'device', ip: '10.0.0.2' },
  });
  const hub = byClass(svg, 'topology-hub')[0];
  const node = byClass(svg, 'topology-node')[0];
  assert.strictEqual(hub.getAttribute('role'), 'button');
  assert.strictEqual(hub.getAttribute('tabindex'), '0');
  assert.ok(hub.getAttribute('aria-label').includes('Gateway'));
  assert.ok(hub.getAttribute('aria-label').includes('Press Enter'));
  assert.strictEqual(node.getAttribute('role'), 'button');
  assert.strictEqual(node.getAttribute('tabindex'), '0');
  assert.ok(node.getAttribute('aria-label').includes('Living Room TV'));
  assert.ok(node.getAttribute('aria-label').includes('10.0.0.2'));
  assert.ok(node.getAttribute('aria-label').includes('Online'));
  assert.ok(node.getAttribute('aria-label').includes('Trusted trust'));
  assert.ok(classes(node).includes('is-selected'));
  assert.strictEqual(node.getAttribute('aria-current'), 'true');
  const link = byClass(svg, 'topology-link')
    .find((line) => line.getAttribute('data-ip') === '10.0.0.2');
  assert.ok(link);
  assert.ok(classes(link).includes('is-selected'));
}

function testVeryLargeNetworksStayBounded() {
  const devices = [device('10.0.0.1', { is_gateway: true })];
  for (let index = 2; index <= 150; index += 1) {
    devices.push(device(`10.0.0.${index}`, { online: index % 4 !== 0 }));
  }
  const widths = [
    [320, 12, 137],
    [360, 12, 137],
    [430, 12, 137],
    [600, 20, 129],
    [768, 20, 129],
    [800, 20, 129],
    [960, 32, 117],
  ];
  widths.forEach(([width, shown, hidden]) => {
    const view = build(devices, { width });
    assert.strictEqual(view.childTotal, 149);
    assert.strictEqual(view.shown, shown);
    assert.strictEqual(view.hidden, hidden);
    assert.strictEqual(view.nodes.length, shown);
    assertNoOverlap(view.nodes);
    const svg = app.createTopologySvg(documentStub, view);
    assert.ok(svg.getAttribute('aria-label').includes(`${hidden} more devices are not shown`));
  });
}

function testTopologySkipsRedundantRenders() {
  resetTopologyState();
  const net = network('10.0.0.1');
  const devices = [
    device('10.0.0.1', { name: 'Router', is_gateway: true }),
    device('10.0.0.2', { name: 'Laptop', online: true }),
    device('10.0.0.3', { name: 'Printer', online: false }),
  ];
  setDashboardDevices(devices);
  setTopologyNetwork(net);
  app.renderTopology();
  const host = documentStub.querySelector('#topology-svg-host');
  const firstSvg = host.children[0];
  assert.ok(firstSvg);
  assert.ok(dashboardValue('state.topology.signature'));

  app.renderTopology();
  assert.strictEqual(host.children[0], firstSvg, 'unchanged data rebuilt the SVG');

  vm.runInContext("state.devices.get('10.0.0.2').online = false", app);
  app.renderTopology();
  assert.notStrictEqual(host.children[0], firstSvg, 'online change did not rebuild the SVG');
  const onlineNode = host.querySelectorAll('.topology-node')
    .find((node) => node.getAttribute('data-ip') === '10.0.0.2');
  assert.ok(onlineNode);
  assert.ok(classesOf(onlineNode).includes('is-offline'));
}

function testTopologyRendersPreserveKeyboardFocus() {
  resetTopologyState();
  const net = network('10.0.0.1');
  const devices = [
    device('10.0.0.1', { name: 'Router', is_gateway: true }),
    device('10.0.0.2', { name: 'Laptop', online: true }),
    device('10.0.0.3', { name: 'Printer', online: true }),
  ];
  setDashboardDevices(devices);
  setTopologyNetwork(net);
  app.renderTopology();
  const host = documentStub.querySelector('#topology-svg-host');
  const firstNode = host.querySelectorAll('.topology-node')
    .find((node) => node.getAttribute('data-ip') === '10.0.0.2');
  assert.ok(firstNode);
  firstNode.focus();
  assert.strictEqual(documentStub.activeElement, firstNode);

  vm.runInContext("state.devices.get('10.0.0.2').online = false", app);
  app.renderTopology();
  const replacement = host.querySelectorAll('.topology-node')
    .find((node) => node.getAttribute('data-ip') === '10.0.0.2');
  assert.ok(replacement);
  assert.notStrictEqual(replacement, firstNode);
  assert.strictEqual(documentStub.activeElement, replacement);
}

function testTopologyNetworkChangeResetsTransientStateAndNodes() {
  resetTopologyState();
  const netA = { id: 'net-a', cidr: '10.0.0.0/24', gateway: '10.0.0.1' };
  const netB = { id: 'net-b', cidr: '10.20.0.0/24', gateway: '10.20.0.1' };
  const devicesA = [
    device('10.0.0.1', { is_gateway: true }),
    device('10.0.0.2'),
    device('10.0.0.3'),
  ];
  setDashboardDevices(devicesA);
  setTopologyNetwork(netA);
  app.renderTopology();
  const host = documentStub.querySelector('#topology-svg-host');
  const firstSvg = host.children[0];
  vm.runInContext("state.topology.view = { scale: 2, x: 40, y: 30 }; state.topology.selected = { kind: 'device', ip: '10.0.0.2' }", app);

  const devicesB = [
    device('10.20.0.1', { is_gateway: true }),
    device('10.20.0.22'),
    device('10.20.0.23'),
    device('10.20.0.24'),
  ];
  setDashboardDevices(devicesB);
  setTopologyNetwork(netB);
  app.renderTopology();
  assert.notStrictEqual(host.children[0], firstSvg);
  assert.strictEqual(dashboardValue('state.topology.networkId'), 'net-b');
  assert.strictEqual(dashboardValue('state.topology.selected'), null);
  assert.strictEqual(dashboardValue('state.topology.view.scale'), 1);
  assert.strictEqual(dashboardValue('state.topology.view.x'), 0);
  assert.strictEqual(dashboardValue('state.topology.view.y'), 0);
  const ips = host.querySelectorAll('.topology-node').map((node) => node.getAttribute('data-ip'));
  assert.deepStrictEqual(ips, ['10.20.0.22', '10.20.0.23', '10.20.0.24']);
  assert.ok(!ips.some((ip) => ip.startsWith('10.0.0.')));
}

function testCompactSmallNetworkLayout() {
  const names = [
    'Home Router',
    'Living Room Television',
    'Office Laser Printer',
    'Kitchen Speaker',
    'Bedroom Phone',
    'Work Laptop',
    'Media Console',
    'Front Door Camera',
    'Garage Sensor',
    'Guest Tablet',
    'Study Desktop',
    'Hallway Display',
  ];
  [320, 360, 390, 430].forEach((width) => {
    const devices = names.map((name, index) => device(
      index === 0 ? '10.0.0.1' : `10.0.0.${index + 1}`,
      index === 0
        ? { name, kind: 'router', is_gateway: true }
        : { name, kind: index % 2 ? 'computer' : 'phone' },
    ));
    const view = build(devices, {
      width,
      network: network('10.0.0.1'),
      activeNetwork: network('10.0.0.1'),
    });
    assert.strictEqual(view.mode, 'tree');
    assert.strictEqual(view.nodes.length, 11);
    assert.strictEqual(view.columns, 3);
    assertNoOverlap(view.nodes);
    assert.ok(view.height <= 480, `height ${view.height} at ${width}px`);
    assert.ok(
      view.nodes[0].y - view.hub.y < 120,
      `oversized gateway gap at ${width}px`,
    );
    const rows = new Set(view.nodes.map((node) => node.y));
    assert.ok(rows.size <= 4, `${rows.size} rows at ${width}px`);
    view.nodes.forEach((node) => {
      assert.ok(node.nameLines.length <= 2);
      node.nameLines.forEach((line) => {
        assert.ok(line.length <= view.nameLimit);
      });
      assert.ok(node.x - node.r >= 0);
      assert.ok(node.x + node.r <= width);
    });
  });

  const small = build([
    device('10.0.0.1', { name: 'Router', is_gateway: true }),
    device('10.0.0.2', { name: 'Laptop', kind: 'computer' }),
    device('10.0.0.3', { name: 'Phone', kind: 'phone' }),
  ], {
    width: 320,
    network: network('10.0.0.1'),
    activeNetwork: network('10.0.0.1'),
  });
  assert.ok(small.height <= 240, `small network height ${small.height}`);
  assert.strictEqual(small.nodes[0].y, small.nodes[1].y);
}

function testResponsiveLayoutBounds() {
  const widths = [320, 360, 390, 430, 600, 768, 899, 900, 960, 1280];
  const counts = [0, 1, 2, 3, 6, 11, 20, 40];
  widths.forEach((width) => {
    counts.forEach((count) => {
      const devices = [];
      if (count > 0) {
        devices.push(device('10.0.0.1', {
          name: 'Gateway',
          kind: 'router',
          is_gateway: true,
        }));
        for (let index = 1; index < count; index += 1) {
          devices.push(device(`10.0.0.${index + 1}`, {
            name: index % 3 === 0
              ? 'A very long device name for wrapping'
              : `Device ${index}`,
            kind: index % 2 ? 'computer' : 'phone',
          }));
        }
      }
      const view = build(devices, {
        width,
        network: network('10.0.0.1'),
        activeNetwork: network('10.0.0.1'),
      });
      assert.ok(view.width <= 960);
      if (count === 0) {
        assert.strictEqual(view.hub, null);
      } else {
        assert.ok(view.hub);
        assert.ok(view.hub.x - view.hub.r >= 0);
        assert.ok(view.hub.x + view.hub.r <= view.width);
        assert.ok(view.hub.y - view.hub.r >= 0);
        assert.ok(view.hub.y + view.hub.r <= view.height);
        assert.ok(view.hub.nameLines.length <= 2);
        view.hub.nameLines.forEach((line) => assert.ok(line.length <= 24));
      }
      view.nodes.forEach((node, index) => {
        assert.ok(node.x - node.r >= 0, `node ${index} left overflow at ${width}px`);
        assert.ok(node.x + node.r <= view.width, `node ${index} right overflow at ${width}px`);
        assert.ok(node.y - node.r >= 0, `node ${index} top overflow at ${width}px`);
        assert.ok(node.y + node.r <= view.height, `node ${index} bottom overflow at ${width}px`);
        assert.ok(node.nameLines.length <= (view.mode === 'tree' ? 2 : 1));
        node.nameLines.forEach((line) => {
          assert.ok(line.length <= view.nameLimit);
        });
      });
      view.links.forEach((link) => {
        assert.ok(link.x1 >= 0 && link.x1 <= view.width);
        assert.ok(link.x2 >= 0 && link.x2 <= view.width);
        assert.ok(link.y1 >= 0 && link.y1 <= view.height);
        assert.ok(link.y2 >= 0 && link.y2 <= view.height);
      });
      assert.strictEqual(
        view.columns,
        view.mode === 'tree' ? app.topologyTreeColumns(view.nodes.length) : 0,
      );
    });
  });
}

function testGatewayNameFallbackAndWrapping() {
  const statusDevices = [
    device('192.168.1.1', {
      name: '302 Moved Temporarily',
      kind: 'router',
      is_gateway: true,
    }),
    device('192.168.1.2', { name: 'Laptop' }),
  ];
  const statusView = build(statusDevices, {
    network: network('192.168.1.1'),
    activeNetwork: network('192.168.1.1'),
  });
  assert.strictEqual(statusView.hub.name, 'Gateway');
  assert.strictEqual(statusView.hub.nameLines.join('|'), 'Gateway');
  const statusSvg = app.createTopologySvg(documentStub, statusView);
  const statusText = allText(statusSvg);
  assert.ok(!statusText.includes('302 Moved Temporarily'));
  assert.ok(statusText.includes('192.168.1.1'));
  assert.ok(statusText.includes('GATEWAY'));
  assert.ok(!statusText.includes('Gateway Gateway'));

  const bandwidthView = build([
    device('192.168.1.1', {
      name: '500 Mbps Router',
      kind: 'router',
      is_gateway: true,
    }),
    device('192.168.1.2', { name: 'Laptop' }),
  ], {
    network: network('192.168.1.1'),
    activeNetwork: network('192.168.1.1'),
  });
  assert.strictEqual(bandwidthView.hub.name, '500 Mbps Router');
  assert.strictEqual(bandwidthView.hub.showName, true);

  const longHost = 'very-long-living-room-router.example.lan';
  const longDevices = [
    device('192.168.1.1', {
      name: longHost,
      hostname: longHost,
      kind: 'router',
      is_gateway: true,
    }),
    device('192.168.1.2', { name: 'Laptop' }),
  ];
  const longView = build(longDevices, {
    network: network('192.168.1.1'),
    activeNetwork: network('192.168.1.1'),
    width: 320,
  });
  assert.strictEqual(longView.hub.name, longHost);
  assert.strictEqual(longView.hub.nameLines.length, 2);
  longView.hub.nameLines.forEach((line) => assert.ok(line.length <= 24));
  const longSvg = app.createTopologySvg(documentStub, longView);
  const longText = allText(longSvg);
  assert.ok(longText.includes('192.168.1.1'));
  assert.ok(longText.includes(longHost));
  assert.strictEqual(byClass(longSvg, 'topology-hub-name').length, 2);
}

function testDeviceIconsUseDistinctExistingKinds() {
  const required = ['computer', 'phone', 'tv', 'media', 'printer', 'iot', 'device'];
  const bodies = required.map((kind) => app.topologyIconBody(kind));
  assert.strictEqual(new Set(bodies).size, required.length);
  assert.strictEqual(app.topologyIconBody('mobile'), app.topologyIconBody('phone'));
  assert.strictEqual(app.topologyIconBody('tablet'), app.topologyIconBody('phone'));
  assert.strictEqual(app.topologyIconBody('unknown'), app.topologyIconBody('device'));
  assert.strictEqual(app.topologyIconBody('gateway'), app.topologyIconBody('router'));

  const devices = [device('10.0.0.1', { is_gateway: true })];
  required.forEach((kind, index) => {
    devices.push(device(`10.0.0.${index + 2}`, {
      name: `${kind} node`,
      kind,
    }));
  });
  const view = build(devices, {
    network: network('10.0.0.1'),
    activeNetwork: network('10.0.0.1'),
  });
  const svg = app.createTopologySvg(documentStub, view);
  const iconBodies = byClass(svg, 'topology-kind-icon')
    .slice(1)
    .map((element) => element.innerHTML);
  assert.strictEqual(new Set(iconBodies).size, required.length);
}

function testSelectedDeviceHighlightsConnection() {
  resetTopologyState();
  const devices = [
    device('10.0.0.1', { name: 'Router', is_gateway: true }),
    device('10.0.0.2', { name: 'Laptop', trust: 'trusted' }),
    device('10.0.0.3', { name: 'Printer', trust: 'ignored' }),
  ];
  const view = build(devices, {
    network: network('10.0.0.1'),
    activeNetwork: network('10.0.0.1'),
  });
  const svg = app.createTopologySvg(documentStub, view, {
    selected: { kind: 'device', ip: '10.0.0.2' },
  });
  const links = byClass(svg, 'topology-link');
  const selectedLink = links.find((line) => line.getAttribute('data-ip') === '10.0.0.2');
  const otherLink = links.find((line) => line.getAttribute('data-ip') === '10.0.0.3');
  assert.ok(classes(selectedLink).includes('is-selected'));
  assert.ok(!classes(otherLink).includes('is-selected'));
  const node = byClass(svg, 'topology-node')
    .find((item) => item.getAttribute('data-ip') === '10.0.0.2');
  assert.ok(classes(node).includes('is-selected'));
  assert.strictEqual(node.getAttribute('aria-current'), 'true');

  setTopologyModel(view);
  const host = documentStub.querySelector('#topology-svg-host');
  host.replaceChildren(svg);
  vm.runInContext(
    "state.topology.selected = { kind: 'device', ip: '10.0.0.3' }",
    app,
  );
  app.syncTopologySelection();
  const nextLink = links.find((line) => line.getAttribute('data-ip') === '10.0.0.3');
  assert.ok(classes(nextLink).includes('is-selected'));
  assert.ok(!classes(selectedLink).includes('is-selected'));
  assert.ok(!classes(node).includes('is-selected'));
}

function testGatewaySelectionUsesSafeTextForUntrustedData() {
  resetTopologyState();
  const payload = '<svg onload=alert(1)>&hostile</svg>';
  const net = network('10.0.0.1');
  const devices = [
    device('10.0.0.1', {
      name: payload,
      label: payload,
      hostname: 'router.local',
      vendor: payload,
      is_gateway: true,
    }),
    device('10.0.0.2'),
  ];
  const view = build(devices, { network: net, activeNetwork: net });
  setTopologyModel(view);
  const action = app.activateTopologyNode(makeTopologyElement('topology-hub', '10.0.0.1', 'gateway'));
  assert.strictEqual(action, 'gateway');
  const title = documentStub.querySelector('#topology-selection-title');
  const body = documentStub.querySelector('#topology-selection-body');
  assert.ok(title.textContent.includes(payload));
  assert.ok(body.textContent.includes(payload));
  assert.strictEqual(walk(title).filter((element) => ['svg', 'script'].includes(element.tagName)).length, 0);
  assert.strictEqual(walk(body).filter((element) => ['svg', 'script'].includes(element.tagName)).length, 0);
  assert.strictEqual(title.innerHTML, '');
  assert.strictEqual(body.innerHTML, '');
}

const tests = [
  testGatewayIsRenderedOnce,
  testNodeContentStatusAndTrust,
  testEmptyAndMissingGatewayStates,
  testLargeNetworksAreCappedAndStable,
  testNetworkSwitchingUsesOnlyCurrentDevices,
  testUntrustedTextIsRenderedSafely,
  testGatewayCandidatesAndTrust,
  testDeviceClickOpensExistingDrawer,
  testGatewaySelectionShowsNetworkDetailsWithoutDeviceDrawer,
  testSearchAndFiltersUpdateHighlightingImmediately,
  testZoomPanAndFitLimits,
  testKeyboardAndScreenReaderControls,
  testVeryLargeNetworksStayBounded,
  testTopologySkipsRedundantRenders,
  testTopologyRendersPreserveKeyboardFocus,
  testTopologyNetworkChangeResetsTransientStateAndNodes,
  testCompactSmallNetworkLayout,
  testResponsiveLayoutBounds,
  testGatewayNameFallbackAndWrapping,
  testDeviceIconsUseDistinctExistingKinds,
  testSelectedDeviceHighlightsConnection,
  testGatewaySelectionUsesSafeTextForUntrustedData,
];

tests.forEach((test) => {
  test();
  process.stdout.write(`ok ${test.name}\n`);
});
