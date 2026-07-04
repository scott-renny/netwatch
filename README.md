# NET-WATCH — Homelab Network Monitoring Dashboard

> **Real-time network visibility for a home SOC lab.**  
> Built on Ubuntu Server · Python Flask · nmap · vnstat · Pi-hole v6 · Wazuh · Nginx

---

## The Story

It started because I wanted to manage my kids' internet time.

I wanted something that would let me see which devices were online, set schedules per kid, cut their internet with one button when homework time started, and enforce daily time limits automatically. I figured I'd build it myself — it would be a fun weekend project.

Halfway through I looked at what I had actually built:

- **Network segmentation** — grouping devices by profile and controlling access per group
- **DNS-layer access control** — using Pi-hole's group management API to block internet access without touching the global configuration
- **Real-time network monitoring** — continuous nmap scanning, device discovery, status tracking
- **Security event correlation** — pulling Wazuh SIEM alerts into the same dashboard
- **Bandwidth monitoring** — per-interface traffic tracking via vnstat

That's three CompTIA Security+ exam domains in one project. What started as a parenting tool turned into one of the most hands-on security labs I've built.

---

## What It Does

- **Device discovery** — nmap scans your network continuously and maps every device by IP and MAC address
- **Profiles and schedules** — group devices into profiles (Kids, Gaming, Guest, Work) with per-day allowed hours and daily time budgets in minutes
- **Kill switch** — one button cuts internet access for an entire profile group via Pi-hole's group management API — without pausing ad-blocking for the rest of the network
- **Per-profile site blocking** — add specific domains to a profile's blocklist; they're blocked at the DNS level for that group only
- **Real-time bandwidth chart** — 24-hour traffic chart from vnstat showing actual Mbps
- **Wazuh integration** — security alerts with MITRE ATT&CK tags pulled from the SIEM
- **Auto-start** — runs as a systemd service, restarts on crash, survives reboots

---

## Screenshots

### Overview — Live on real hardware
> 35 devices discovered · Real bandwidth data · Pi-hole connected · Uptime from /proc/uptime

![NET-WATCH Overview](screenshots/overview.png)

### Schedule Editor
> Per-profile daily schedules with time limits — blocks automatically when the budget runs out

![Schedule Editor](screenshots/schedule.png)

---

## Stack

| Layer | Technology |
|---|---|
| Backend API | Python 3 / Flask |
| Network scanning | nmap (`-sn -T3 --host-timeout 5s`) |
| Bandwidth tracking | vnstat |
| DNS access control | Pi-hole v6 REST API |
| Security alerts | Wazuh REST API |
| Web server | Nginx (reverse proxy) |
| Process management | systemd |
| Frontend | Vanilla JS / Chart.js / HTML+CSS |
| Platform | Ubuntu Server 22.04 |

---

## Security+ Domain Mapping

| Domain | Coverage |
|---|---|
| **D2 — Network Architecture** | Network segmentation via Pi-hole groups, VLAN-ready SCAN_SUBNETS config, per-profile DNS isolation |
| **D3 — Implementation** | nmap scanning, vnstat bandwidth monitoring, Nginx reverse proxy, UFW firewall rules |
| **D4 — Security Operations** | Wazuh SIEM integration, MITRE ATT&CK event tagging, real-time alert dashboard, kill switch access control |

---

## Project Structure

```
netwatch/
├── setup.sh                  # One-command installer
├── netwatch.service          # systemd service definition
├── nginx-netwatch.conf       # Nginx reverse proxy config
├── netwatch_buildguide_v3.html  # Complete build guide (open in browser)
├── api/
│   └── netwatch_api.py       # Flask backend — 26 endpoints
├── web/
│   └── index.html            # Dashboard — single self-contained file
└── config/
    ├── devices.json          # Device registry (auto-populated by scanner)
    └── profiles.json         # Profiles, schedules, blocked sites
```

---

## Quick Install

**Prerequisites:** Ubuntu Server 22.04+, nmap, Python 3, Nginx

```bash
# 1. Copy the netwatch folder to your server
scp -r netwatch/ your_username@YOUR_SERVER_IP:~/

# 2. SSH in and run the installer
ssh your_username@YOUR_SERVER_IP
cd ~/netwatch
chmod +x setup.sh
sudo ./setup.sh

# 3. Edit your network config
sudo nano /opt/netwatch/api/netwatch_api.py
# Set SCAN_SUBNETS to your real subnet and interface name

# 4. Open the dashboard
# http://YOUR_SERVER_IP in any browser on your network
```

Full step-by-step instructions with zero-knowledge explanations are in `netwatch_buildguide_v3.html` — open it in any browser.

---

## API Endpoints (26 total)

```
GET  /api/status              — Primary poll: devices, profiles, bandwidth, alerts
POST /api/scan                — Trigger manual network scan
GET  /api/devices             — Full device list
GET  /api/profiles            — Profiles with access state and budget
POST /api/profiles/<id>/killswitch     — Toggle internet kill switch
GET  /api/profiles/<id>/blocklist      — Per-profile blocked domains
POST /api/profiles/<id>/blocklist      — Add blocked domain
DELETE /api/profiles/<id>/blocklist/<domain>  — Remove blocked domain
GET  /api/traffic             — vnstat hourly bandwidth data
GET  /api/pihole/probe        — Test Pi-hole connectivity
GET  /api/alerts/wazuh        — Recent Wazuh security events
```

---

## Pi-hole Integration

NET-WATCH uses Pi-hole's **group management API** — not the global disable button. This means:

- Kill switch disables **only that profile's Pi-hole group** — ad-blocking continues for everyone else
- Per-profile site blocking adds domains to the **group's denylist only** — other devices unaffected
- Requires Pi-hole v6 for full kill switch and per-group domain management support

---

## Planned

- [ ] VLAN support (SCAN_SUBNETS multi-subnet scanning is already implemented)
- [ ] Wazuh vulnerability scan integration
- [ ] Per-device bandwidth tracking (requires ntopng or Zeek)
- [ ] Email/webhook alerts when kill switch triggers or budget runs out
- [ ] Optional login screen (code is present, disabled by default)

---

## Build Guide

The full build guide (`netwatch_buildguide_v3.html`) includes:

- 18 sections with zero-knowledge explanations
- 42 interactive checkboxes that save progress in the browser
- 4 portfolio snapshot moments with exact screenshot guidance and LinkedIn captions
- VLAN transition guide for when you're ready to segment the network
- Troubleshooting section for every common failure mode

Open it in any browser — no internet required.

---

*Built as part of an active homelab SOC portfolio targeting Security+ SY0-701 and SOC analyst roles.*
