# ArgusIDS

A minimal functional network intrusion detection system (IDS) for Linux. ArgusIDS captures live traffic, parses IPv4 packets, and raises real alerts for port scans, SYN/UDP/ICMP floods, and connections to high-risk destination ports.

Designed to deploy anywhere Linux runs — from legacy bare-metal servers to modern cloud VMs — with zero runtime dependencies, a tiny footprint, and a single binary.

## Why ArgusIDS

Most IDS platforms pull in large dependency trees, rule databases, and services that are hard to maintain on older or resource-constrained hosts. ArgusIDS takes the opposite approach: a small C program that does one job well.

- **No libpcap, no databases, no interpreters** — only libc and standard Linux APIs
- **Low overhead** — single-threaded loop, fixed in-memory state, suitable for old hardware
- **Broad Linux support** — built on `AF_PACKET` raw sockets (available since Linux 2.2) and a plain Makefile
- **Deploy and forget** — compile once, run under `sudo` or as a systemd service, log to a file

ArgusIDS is not a drop-in replacement for Snort or Suricata when you need deep packet inspection, thousands of signatures, or IPv6. It is a working IDS for hosts and networks that need reliable, low-maintenance threat detection without the operational weight of a full IDS stack.

## Features

- **Live packet capture** via raw `AF_PACKET` sockets on one interface or all interfaces
- **IPv4 parsing** for Ethernet (including 802.1Q VLAN), IP, TCP, and UDP headers
- **Five active detection rules** with sliding time windows and per-source tracking
- **Dual output** — alerts to the terminal and append-only log file (`-q` for log-only)
- **Graceful shutdown** — responds to SIGTERM within one second (no hang waiting for traffic)
- **Host table eviction** — recycles stale entries when tracking 256+ sources
- **Tunable thresholds** in one header (`include/config.h`), rebuild to apply

## Detection Rules

| Alert | Trigger | Default threshold |
|-------|---------|-------------------|
| **Port scan** | One source probes many distinct destination ports | 15 unique ports within 60 seconds |
| **SYN flood** | High rate of TCP SYN packets (no ACK) from one host | 40 SYN packets within 10 seconds |
| **UDP flood** | High rate of UDP packets from one host | 80 packets within 10 seconds |
| **ICMP flood** | High rate of ICMP from one host | 50 packets within 10 seconds |
| **Suspicious port** | Traffic to a known high-risk destination port | One alert per source every 30 seconds |

Suspicious ports monitored by default: 21 (FTP), 23 (Telnet), 25 (SMTP), 135/139/445 (Windows/SMB), 1433 (MSSQL), 3306 (MySQL), 3389 (RDP), 5900 (VNC), 6379 (Redis).

## Requirements

| | |
|---|---|
| **OS** | Linux (kernel 2.2+; tested workflow on legacy and current distros) |
| **Toolchain** | gcc or clang |
| **Privileges** | `CAP_NET_RAW` — run as root or grant the capability to the binary |
| **Runtime deps** | None beyond glibc/musl |

ArgusIDS is Linux-only. It does not run on Windows or macOS.

### Legacy and modern builds

The default build uses C11 (`-std=c11`). On older distributions with an aging compiler, use C99:

```bash
make CFLAGS="-Wall -Wextra -O2 -std=c99 -Iinclude -Isrc"
```

Cross-compile for a target server from a build host:

```bash
make CC=aarch64-linux-gnu-gcc
```

Static linking for minimal/container or air-gapped targets (glibc):

```bash
make LDFLAGS="-static"
```

## Build

```bash
git clone https://github.com/vaxarez/ArgusIDS.git
cd ArgusIDS
make
```

Binary output: `build/argusids`

```bash
make clean        # remove build/ artifacts
make install      # install to /usr/local/bin (use sudo)
make uninstall    # remove installed binary
make help         # list targets and options
```

Custom install prefix:

```bash
sudo PREFIX=/opt/argus make install
```

## Usage

```bash
sudo ./build/argusids [options]
```

| Option | Description |
|--------|-------------|
| `-i <iface>` | Capture on a specific interface (e.g. `eth0`, `enp0s3`). Omit for all interfaces. |
| `-l <file>` | Alert log path (default: `alerts.log`) |
| `-q` | Quiet mode — write alerts to log file only (recommended for systemd) |
| `-V` | Print version and exit |
| `-h` | Show help |

### Examples

Monitor all interfaces:

```bash
sudo ./build/argusids
```

Bind to one interface and log to `/var/log`:

```bash
sudo ./build/argusids -i eth0 -l /var/log/argusids.log
```

Run quietly under systemd (alerts go to log file only):

```bash
sudo ./build/argusids -i eth0 -l /var/log/argusids.log -q
```

Run without full root by granting capture capability once:

```bash
sudo setcap cap_net_raw+ep ./build/argusids
./build/argusids -i eth0
```

Press **Ctrl+C** to stop. Shutdown prints session stats: packets analyzed, alerts raised, tracked hosts.

### Sample output

```
ArgusIDS 1.1.0 — Linux IDS
Interface: eth0
Alert log: alerts.log
Rules: port scan, SYN flood, UDP flood, ICMP flood, suspicious ports
Press Ctrl+C to stop.

[!] ALERT [PORT_SCAN] 2026-06-17 14:32:01
    Port scan from 192.168.1.50 (15 ports / 60s)

--- ArgusIDS Stats ---
Packets analyzed: 12847
Alerts raised:    3
Tracked hosts:    12
```

Log file format (suitable for `grep`, log rotation, or forwarding to syslog/ELK):

```
[PORT_SCAN] 2026-06-17 14:32:01 | Port scan from 192.168.1.50 (15 ports / 60s)
```

## Deployment

### systemd service

Create `/etc/systemd/system/argusids.service`:

```ini
[Unit]
Description=ArgusIDS network intrusion detection
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/argusids -i eth0 -l /var/log/argusids.log -q
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now argusids
sudo journalctl -u argusids -f
```

Adjust `ExecStart` interface and log path for the host. Use `logrotate` on the alert log file as needed.

## Configuration

Edit `include/config.h` and rebuild:

```c
#define ARGUS_PORT_SCAN_THRESHOLD   15   /* unique ports before alert */
#define ARGUS_PORT_SCAN_WINDOW      60   /* in seconds */
#define ARGUS_SYN_FLOOD_THRESHOLD   40
#define ARGUS_SYN_FLOOD_WINDOW      10
#define ARGUS_UDP_FLOOD_THRESHOLD   80
#define ARGUS_UDP_FLOOD_WINDOW      10
#define ARGUS_ICMP_FLOOD_THRESHOLD  50
#define ARGUS_ICMP_FLOOD_WINDOW     10
#define ARGUS_SUSP_COOLDOWN         30   /* seconds between suspicious-port alerts */
#define ARGUS_MAX_TRACKED_HOSTS     256
#define ARGUS_MAX_PORTS_PER_HOST    64
#define ARGUS_RECV_TIMEOUT_SEC      1    /* shutdown responsiveness */
#define ARGUS_DEFAULT_LOG           "alerts.log"
```

Add or remove entries in `ARGUS_SUSPICIOUS_PORTS` (terminate with `0`).

Lower thresholds increase sensitivity (more alerts, more false positives). Raise them on busy networks or when alerting into a SIEM with rate limits.

## Architecture

```
src/
├── main.c           Entry point, CLI, capture loop
├── capture/         Raw socket open/recv/close
├── parse/           Ethernet → IP → TCP/UDP header parsing
├── detect/          Rule engine and per-host state tracking
└── log/             Console and file alert output
include/
└── config.h         Thresholds and suspicious port list
```

**Data flow:** `capture_recv` → `packet_parse` → `detector_analyze` → `alert_log`

The detector tracks up to 256 source hosts in memory, evicting the least-recently-seen host when the table is full. VLAN-tagged frames (802.1Q) are parsed. Non-IPv4 traffic and non-TCP/UDP/ICMP IPv4 packets are skipped after parse.

## Design scope

ArgusIDS is deliberately minimal. These are architectural choices, not missing features:

| In scope | Out of scope (use a full IDS if required) |
|----------|-------------------------------------------|
| IPv4 port scan, flood, and suspicious-port detection | IPv6 |
| Per-source rate and port tracking | Payload / signature matching |
| File and console alerting | TLS inspection |
| Single-binary, low-resource operation | Distributed sensor management |
| Tunable thresholds via `config.h` | Built-in firewall blocking |

For a server or edge node that needs dependable baseline IDS coverage without maintaining a rule corpus, ArgusIDS is meant to run continuously in production.

## License

See the repository for license information.

## Contributing

Pull requests and issues are welcome. When changing detection logic or defaults, update `include/config.h` and document behavior here.
