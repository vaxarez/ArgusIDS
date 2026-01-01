# Argus-IDS

**Argus-IDS** is a lightweight Intrusion Detection System (IDS) written in C, combining both signature-based and anomaly-based detection.  
The name refers to Argus Panoptes, a mythical giant with one hundred eyes who never slept — the perfect metaphor for a vigilant network guardian.

---

## Description

> This project was created as a graduation project to demonstrate core IDS concepts using the C programming language.  
> It features packet sniffing, detection by known attack signatures, and simple anomaly heuristics.

---

## Features

- Captures live network traffic using `libpcap`
- Signature-based detection from a local database (`signatures.db`)
- Basic anomaly detection (suspicious sizes, uncommon protocols, etc.)
- Responds to detections with logging and console alerts
- Configurable via `config.ini`

---

## Project Structure
```text
argus-ids/
├── main.c
├── network_monitor.c
├── network_monitor.h
├── signature_detection.c
├── signature_detection.h
├── anomaly_detection.c
├── anomaly_detection.h
├── response_handler.c
├── response_handler.h
├── utils.c
├── utils.h
├── signatures.db
├── config.ini
├── log.txt
├── Makefile
└── README.md
```
---

## Dependencies

- GCC compiler
- `libpcap` development library

---

## Installation & Build

### Install libpcap (Arch Linux)

```bash
sudo pacman -Syu
sudo pacman -S libpcap-dev
```
Or Debian (and debian based distro's)
```bash
sudo apt update
sudo apt upgrade
sudo apt install libpcap-dev
```
---

## Build the project
```bash
make
```
