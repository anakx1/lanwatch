# lanwatch

Discover the devices on your LAN and watch them live in a browser.

`lanwatch` is a **zero-dependency** Python tool: one process, one JSON
inventory, a SQLite history and event log, and a small web dashboard served by
the standard library. It combines active probing (ICMP sweep, TCP port scan, web
fingerprinting) with passive sources (ARP/neighbour table, mDNS, SSDP/UPnP,
NetBIOS, reverse DNS) and tells you honestly which of them actually worked on
your network. Devices can be marked trusted or ignored, and each completed scan
is compared with the previous one to record new, returned, offline and changed
devices in the dashboard's Event Center.

```
$ lanwatch
  IP             NAME                      SERVICES              SEEN
  192.168.1.1    router.home               21,53,80,443          0s
  192.168.1.9    —                         —                     now
  192.168.1.24   living-room-tv            8009,9100,32400       0s
```

## Quick start

Requires Python 3.9+. No packages to install.

```bash
cd ~/lanwatch

./bin/lanwatch                    # scan the detected LAN once
./bin/lanwatch web                # live dashboard at http://localhost:8765/
./bin/lanwatch watch -i 60        # rescan every minute in the terminal
```

Or install the `lanwatch` command (needs `setuptools`; Termux's Python often
does not ship it, in which case use `./bin/lanwatch` or `python3 -m lanwatch`):

```bash
pip install -e . --no-build-isolation
lanwatch --version
```

Scan a specific subnet, port list, or interface:

```bash
lanwatch 192.168.1.0/24
lanwatch wlan0
lanwatch scan -p 22,80,443,8009 --deep --verbose
```

## What a scan does

A scan runs in three phases: a fast ICMP **sweep** finds live hosts, a **probe**
port-scans them (plus silent hosts in `--deep` mode), and a **names** phase
enriches what was found. Every collector reports its own status (`ok`, `empty`,
`skipped`, `unavailable`, `error`) so an empty result is never confused with a
working one.

| Collector | What it does | Notes |
| --- | --- | --- |
| ICMP sweep | Parallel `ping` across the subnet, records RTT and reply TTL (an OS hint) | Main liveness signal; uses the system `ping` |
| ARP / neighbour | Reads MAC addresses from `/proc/net/arp`, `ip neigh`, or `arp -an` | Usually blocked on Android; often empty there |
| TCP probe | Connects to `DEFAULT_PORTS` (22, 53, 80, 443, 8009, 9100, 32400, …) | `--deep` also probes hosts that ignore ICMP |
| Web fingerprint | `GET /` on open web ports: page title, `Server` header, login realm, TLS certificate name | Unverified TLS (LAN gear is self-signed); reads identity hints only. `--no-http` disables it |
| Banner grab | Reads a short greeting from FTP/SSH/Telnet/SMTP/IMAP/POP3 ports | Best effort, only when the port is open |
| mDNS-SD | Browses `_services._dns-sd._udp.local` and resolves hostnames | Needs multicast; often filtered on Android |
| SSDP / UPnP | Sends `M-SEARCH`, fetches device descriptions for friendly names | Needs multicast |
| NetBIOS (NBNS) | Sends a node-status query for Windows/Samba names | Unicast, so it often works where multicast does not |
| Reverse DNS | `socket.gethostbyaddr` for each live IP | Uses the configured resolver |
| Vendor lookup | Maps MAC OUI to a vendor | Embedded table + lazy read of `nmap-mac-prefixes` if present |

Hostname priority when several sources answer:
**mDNS (5) > SSDP (4) > NBNS (3) > reverse DNS (2)**.

"Online" means the host answered **in the current process**. Every stored
device is marked offline at startup, so the dashboard never shows yesterday's
results as live.

## Fingerprinting: "what is this device?"

Android hides MAC addresses from ordinary apps, so many devices arrive with no
vendor. `lanwatch/fingerprint.py` identifies them from every other signal:
hostnames, mDNS service types, UPnP descriptions, web titles and `Server`
headers, TLS certificate names, open ports and the ICMP TTL.

Each signal casts a weighted vote for a kind (router, printer, TV, NAS, camera,
phone, speaker, console, smart device, computer, media). The winner becomes the
device kind; its margin over the runner-up becomes a confidence score, and every
vote keeps a human-readable reason ("web page looks like a printer", "JetDirect
port 9100 open") shown in the device drawer under **Why we think so**. Weak or
conflicting evidence stays "Unknown device" instead of guessing. Names fall back
to the fingerprint (`TP-Link Archer AX50`, a clean page title, or
`Brother printer`) only after your label, the hostname and the UPnP name.

TTL hints (64 → Linux/Android/Apple, 128 → Windows, 255 → network gear) are
deliberately weak. The module is pure: it never touches the network.

## Networks

Each network gets its own inventory, so the same `192.168.1.0/24` at home and at
the office never mix and a stale router from another Wi-Fi is not shown next to
today's. A network is identified by its CIDR plus, when readable, the gateway's
MAC (same CIDR with a different gateway MAC is a different network).

- On startup the dashboard shows the inventory of the network you are on, if known.
- Scanning a new network creates it; nothing is created merely by opening the UI.
- Tap the network chip to switch, rename, archive/restore or delete networks.
  Switching is refused while a scan runs; the active network cannot be deleted.
- The default gateway is read from `/proc/net/route` or `ip route` when possible
  (not on most Android builds, where the previous guess is used), and only one
  device per network carries the gateway badge.
- Old flat `devices.json` files (schema 1) are migrated automatically on first
  load: devices are grouped by their /24.

## The dashboard

`lanwatch web` serves a single-page dashboard (HTML/CSS/JS, no build step):

- Live device table over Server-Sent Events (`/api/events`) — no polling.
- Collector status chips: see at a glance what worked on this network.
- Filters (offline visibility, trust level), sorting, and search.
- Network switcher with per-network inventories (see [Networks](#networks)).
- Device kind icons, confidence, and the evidence behind each guess.
- Device drawer: rename, set trust, add notes, run an on-demand port probe,
  forget.
- Scan comparison banner: new, returned, offline and changed devices.
- Event Center: durable, filterable history of changes with unread counts.
- Scan settings dialog: subnet, ports, timeout, concurrency, deep mode,
  per-collector toggles — applied to the next scan.
- Scan history: a live trend bar chart and recent-scan table backed by SQLite.
- Auto-scan interval, CSV/JSON export, dark/light-friendly responsive layout.

The server binds to `127.0.0.1` by default. Use `--host 0.0.0.0` only on a
network you trust; see [Security](#security).

## CLI

```
lanwatch [--state PATH] <command> ...

  scan [subnet]     discover devices once
  watch             scan repeatedly (-i SECONDS, default 30)
  devices           list the saved inventory (--trust LEVEL)
  history           show recent scans (--limit, --device IP, --json)
  events            show the persistent Event Center log
  web               serve the web dashboard
  label IP [NAME]   give a device a friendly name (--notes)
  trust IP LEVEL    mark a device trusted, unknown or ignored
  forget IP         remove a device
  version           print the version
```

Useful flags:

```bash
lanwatch scan --json > snapshot.json     # full snapshot
lanwatch scan --csv                      # inventory as CSV
lanwatch scan --all                      # include offline devices
lanwatch devices --online --verbose
lanwatch devices --trust ignored
lanwatch history --limit 10              # recent scans
lanwatch history --device 192.168.1.24   # one device's presence history
lanwatch events --unread                 # durable change log
lanwatch trust 192.168.1.24 trusted
lanwatch web --port 8799 --no-open --scan
```

`--state PATH` (or `LANWATCH_STATE`) overrides the inventory file. The default
is `$XDG_STATE_HOME/lanwatch/devices.json`, i.e.
`~/.local/state/lanwatch/devices.json`. Scan history is stored next to it as
`<inventory>-history.db` (default `devices-history.db`); `LANWATCH_HISTORY`
overrides that path.

## HTTP API

All responses are JSON unless noted. `GET` endpoints are read-only.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/state` | Full snapshot: devices, scan status, collectors, settings |
| GET | `/api/events` | SSE stream of live events (`text/event-stream`) |
| GET | `/api/health` | `{ok, version, time}` |
| GET | `/api/network` | Detected interfaces and current network |
| GET | `/api/networks` | Saved networks and the active one |
| GET | `/api/history?limit=N` | Recent scans (1–200, default 12) |
| GET | `/api/event-log` | Durable events (`limit`, `before_id`, `severity`, `type`, `network_id`, `device`, `unread`) |
| GET | `/api/scan/diff?scan_id=N` | Comparison for a scan, or the latest completed scan |
| GET | `/api/export.csv` | Inventory as CSV |
| GET | `/api/export.json` | Inventory as JSON |
| POST | `/api/scan` | Start a scan; body may contain scan options |
| POST | `/api/stop` | Cancel the running scan |
| POST | `/api/device` | Update `{ip, label?, notes?, trust?}` |
| POST | `/api/event-log/read` | Mark `{ids}` or `{all: true}` events read (`network_id` optional) |
| POST | `/api/probe` | Probe `{ip, ports?}` on demand |
| POST | `/api/forget` | Remove `{ip}` |
| POST | `/api/interfaces` | Re-detect interfaces |
| POST | `/api/network/select` | Switch the active network `{id}` (409 while scanning) |
| POST | `/api/network/rename` | `{id, label}` (blank clears) |
| POST | `/api/network/archive` | `{id, archived?}` (not the active network) |
| POST | `/api/network/delete` | `{id}` (not the active network) |

Scan options accepted by `/api/scan`:

```json
{
  "subnet": "192.168.1.0/24",
  "ports": [22, 80, 443],
  "ping_timeout": 1.0,
  "concurrency": 64,
  "max_hosts": 1024,
  "deep": false,
  "http": true,
  "mdns": true,
  "ssdp": true,
  "nbns": true,
  "rdns": true
}
```

`ports` may also be a comma-separated string. Invalid or missing fields fall
back to the server defaults; out-of-range values are clamped.

Every `/api/scan` response is followed by an SSE `scan.finished` event once the
snapshot is saved and the history row is written. A 202 response means the
scan started, not that it finished.

## Scan history

Each completed or stopped scan is appended to a local SQLite database
(`<inventory>-history.db` next to the inventory). The dashboard shows the last
12 scans as a bar chart plus a table; the CLI exposes the same data:

```bash
lanwatch history
lanwatch history --device 192.168.1.24 --limit 50
lanwatch history --json
```

The `scans` table stores the network, start/finish times, duration, host and
device counts, a stopped/error flag, and the comparison counts. `scan_devices`
stores the snapshot of each device seen in that scan, so per-device presence
and services are available even after the device disappears from the inventory.
History is shared across networks — each row records its scanned network and
subnet — and is capped at the newest 500 scans to keep the database small.
SQLite is part of the Python standard library, so this adds no dependency.

## Trust and change detection

Trust is user-assigned and stored with the device in its network inventory:

- **trusted** — expected gear; offline and service changes are warnings.
- **unknown** — the default. Changes are recorded, but with a lower severity.
- **ignored** — still scanned and kept in the inventory, but hidden from the
  default device list and excluded from change events and alerts.

Set it in the device drawer or with `lanwatch trust IP trusted|unknown|ignored`.
Collectors never overwrite trust, and the dashboard's trust filter can show
ignored devices when you need them.

After every completed scan, `lanwatch` compares the snapshot with the previous
completed scan on the same network. The first completed scan is a **baseline**
and deliberately does not emit one “new device” event per host. Later scans
record:

- devices that are genuinely new, or that were seen in an older scan and
  returned after an absence;
- devices that went offline;
- the same IP with a different MAC (possible replacement);
- the same MAC on a new IP (DHCP move);
- hostname and open-service changes.

Stopped scans are recorded but never used as a comparison baseline. Failed
scans do not create a history row; they add a `scan.failed` event instead.
Comparison logic lives in `lanwatch/changes.py` and does no I/O.

## Event Center

Durable events share the history database (`events` table) and survive browser
reloads and process restarts. The dashboard bell shows unread counts; the Event
Center can filter by severity and unread state, open the related device, and
mark events read. Events can also be read from the CLI and API:

```bash
lanwatch events
lanwatch events --severity warning,critical --unread
lanwatch events --device 192.168.1.24 --json
```

Events are capped at the newest 5,000 and pruned after 180 days. `scan.failed`
events are recorded without a scan row and are not used for comparison.

## Running on Android / Termux

`lanwatch` was built with Termux in mind and degrades instead of failing:

- **Netlink and `/proc/net/arp` are blocked.** Interface addresses come from
  `ioctl`/`ifconfig`; MAC/vendor data is usually unavailable.
- **Multicast is filtered by the kernel/Wi-Fi driver.** mDNS and SSDP typically
  report `empty`. That is a platform limitation, not a bug — the dashboard
  shows the collector status so you can see it.
- **ICMP works** through the system `ping`; TCP probing works unprivileged.
- Interface detection accepts `wlan0`; loopback and point-to-point `rmnet`
  interfaces are filtered out.

On a normal Linux machine all collectors usually work, with or without root.

## Security

- Binds to loopback by default.
- State-changing `POST`s require the header `X-Lanwatch: 1`, which forces a
  CORS preflight from browsers on other origins.
- If an `Origin` header is present it must match `Host`; no CORS headers are
  sent.
- The dashboard sends a restrictive `Content-Security-Policy`.
- No authentication: if you bind to a LAN address, anyone who can reach the
  port can scan and edit labels. Don't expose it to the internet.

## Tests and development

```bash
python3 -m unittest discover -s tests -t .   # 165 tests
ruff check .
mypy
```

The tests mock the network layer, so they run offline and on Android.

Layout:

```
bin/lanwatch          launcher for a checkout
lanwatch/
  changes.py          pure scan-to-scan comparison
  cli.py              argparse commands and table rendering
  discovery.py        scan engine, options, event bus
  events.py           durable event model and event builders
  history.py          SQLite scan history, events and migrations
  collectors.py       ICMP, ARP, TCP, HTTP, mDNS, SSDP, NBNS, rDNS primitives
  dnsparse.py         minimal DNS packet codec (no dnspython)
  fingerprint.py      device kind, confidence and evidence from signals
  netif.py            interface detection, gateways and subnet resolution
  model.py            Device model, merge rules, port names
  oui.py              MAC normalization and vendor database
  store.py            per-network JSON persistence, offline marking, CSV export
  web.py              stdlib HTTP server, routes, SSE
  static/             dashboard HTML/CSS/JS
tests/                unittest suite with a mocked scan fixture
```

## License

MIT — see [LICENSE](LICENSE).
