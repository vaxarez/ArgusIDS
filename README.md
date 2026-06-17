# ArgusIDS

Basic network intrusion detection system for **Linux only**. Captures live traffic with raw sockets and applies simple signature-based rules.

## Requirements

- Linux with `AF_PACKET` support
- `gcc` and `make`
- Root privileges to capture packets (`CAP_NET_RAW`)

No external libraries — only standard C and Linux headers.

## Quick start

```bash
git clone <repo-url>
cd ArgusIDS

make
sudo ./build/argusids
```

## Build

```bash
make          # compile → build/argusids
make clean    # remove all compiled files
make help     # show targets and options
```

Cross-compiler example:

```bash
CC=clang make
```

## Install

Install system-wide (default: `/usr/local/bin/argusids`):

```bash
make
sudo make install
argusids -i eth0
```

Custom prefix:

```bash
sudo make install PREFIX=/opt/argus
```

Uninstall:

```bash
sudo make uninstall
```

## Run

```bash
sudo ./build/argusids                  # all interfaces
sudo ./build/argusids -i eth0          # single interface
sudo ./build/argusids -l alerts.log    # custom alert log
./build/argusids -h                    # help
```

## Project layout

```
ArgusIDS/
├── include/config.h      # thresholds and suspicious ports
├── src/
│   ├── main.c            # entry point, CLI
│   ├── capture/          # raw socket packet capture
│   ├── parse/            # Ethernet / IP / TCP / UDP parsing
│   ├── detect/           # detection rules engine
│   └── log/              # console + file alerting
├── Makefile
└── README.md
```

The `build/` directory is created by `make` and removed by `make clean`. Only source files are shipped in the repo.

## Detection rules

| Rule | Description |
|------|-------------|
| Port scan | Same source probes many destination ports in a time window |
| SYN flood | High rate of SYN-only TCP packets from one host |
| ICMP flood | High rate of ICMP from one host |
| Suspicious port | Traffic to commonly targeted ports (SSH, RDP, SMB, etc.) |

Tune thresholds in `include/config.h`.
