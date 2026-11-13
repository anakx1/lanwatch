# lanwatch

Discover the devices on your LAN and watch them live in a browser.

`lanwatch` is a **zero-dependency** Python tool: one process, one JSON state
file, and a small web dashboard served by the standard library. It combines
active probing (ICMP sweep, TCP port scan) with passive sources (ARP/neighbour
table, mDNS, SSDP/UPnP, NetBIOS, reverse DNS) and tells you honestly which of
them actually worked on your network.

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
| ICMP sweep | Parallel `ping` across the subnet, records RTT | Main liveness signal; uses the system `ping` |
| ARP / neighbour | Reads MAC addresses from `/proc/net/arp`, `ip neigh`, or `arp -an` | Usually blocked on Android; often empty there |
| TCP probe | Connects to `DEFAULT_PORTS` (22, 53, 80, 443, 8009, 9100, 32400, …) | `--deep` also probes hosts that ignore ICMP |
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

## The dashboard

`lanwatch web` serves a single-page dashboard (HTML/CSS/JS, no build step):

- Live device table over Server-Sent Events (`/api/events`) — no polling.
- Collector status chips: see at a glance what worked on this network.
- Filters (all / online / named / known vendor), sorting, and search.
- Device drawer: rename, add notes, run an on-demand port probe, forget.
- Scan settings dialog: subnet, ports, timeout, concurrency, deep mode,
  per-collector toggles — applied to the next scan.
- Auto-scan interval, CSV/JSON export, dark/light-friendly responsive layout.

The server binds to `127.0.0.1` by default. Use `--host 0.0.0.0` only on a
network you trust; see [Security](#security).

## CLI

```
lanwatch [--state PATH] <command> ...

  scan [subnet]     discover devices once
  watch             scan repeatedly (-i SECONDS, default 30)
  devices           list the saved inventory
  web               serve the web dashboard
  label IP [NAME]   give a device a friendly name (--notes)
  forget IP         remove a device
  version           print the version
```

Useful flags:

```bash
lanwatch scan --json > snapshot.json     # full snapshot
lanwatch scan --csv                      # inventory as CSV
lanwatch scan --all                      # include offline devices
lanwatch devices --online --verbose
lanwatch web --port 8799 --no-open --scan
```

`--state PATH` (or `LANWATCH_STATE`) overrides the inventory file. The default
is `$XDG_STATE_HOME/lanwatch/devices.json`, i.e.
`~/.local/state/lanwatch/devices.json`.

## HTTP API

All responses are JSON unless noted. `GET` endpoints are read-only.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/state` | Full snapshot: devices, scan status, collectors, settings |
| GET | `/api/events` | SSE stream of snapshots (`text/event-stream`) |
| GET | `/api/health` | `{ok, version, time}` |
| GET | `/api/network` | Detected interfaces and current network |
| GET | `/api/export.csv` | Inventory as CSV |
| GET | `/api/export.json` | Inventory as JSON |
| POST | `/api/scan` | Start a scan; body may contain scan options |
| POST | `/api/stop` | Cancel the running scan |
| POST | `/api/device` | Update `{ip, label?, notes?}` |
| POST | `/api/probe` | Probe `{ip, ports?}` on demand |
| POST | `/api/forget` | Remove `{ip}` |
| POST | `/api/interfaces` | Re-detect interfaces |

Scan options accepted by `/api/scan`:

```json
{
  "subnet": "192.168.1.0/24",
  "ports": [22, 80, 443],
  "ping_timeout": 1.0,
  "concurrency": 64,
  "max_hosts": 1024,
  "deep": false,
  "mdns": true,
  "ssdp": true,
  "nbns": true,
  "rdns": true
}
```

`ports` may also be a comma-separated string. Invalid or missing fields fall
back to the server defaults; out-of-range values are clamped.

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
python3 -m unittest discover -s tests -t .   # 61 tests
ruff check .
mypy
```

The tests mock the network layer, so they run offline and on Android.

Layout:

```
bin/lanwatch          launcher for a checkout
lanwatch/
  cli.py              argparse commands and table rendering
  discovery.py        scan engine, options, event bus
  collectors.py       ICMP, ARP, TCP, mDNS, SSDP, NBNS, rDNS primitives
  dnsparse.py         minimal DNS packet codec (no dnspython)
  netif.py            interface detection and subnet resolution
  model.py            Device model, merge rules, port names
  oui.py              MAC normalization and vendor database
  store.py            JSON persistence, offline marking, CSV export
  web.py              stdlib HTTP server, routes, SSE
  static/             dashboard HTML/CSS/JS
tests/                unittest suite with a mocked scan fixture
```

## License

MIT — see [LICENSE](LICENSE).
