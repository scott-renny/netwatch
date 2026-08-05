# NET-WATCH

![Status](https://img.shields.io/badge/status-Phase%206%20complete-success)
![Version](https://img.shields.io/badge/version-3.1-blue)
![Platform](https://img.shields.io/badge/platform-Ubuntu%20Server-orange)
![DNS](https://img.shields.io/badge/Pi--hole-v6-red)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-005571)

> **Operational network visibility and profile-based DNS access control for the Cyber Operations Center Engineering Program.**

NET-WATCH began as a family screen-time project and evolved into an integrated network operations platform. The maintained v3.1 deployment combines real device discovery, device inventory, access schedules, daily budgets, Pi-hole group policy, and Wazuh security visibility in one dashboard.

## Project status

**Phase 6 is complete.** The production deployment has been validated with real devices and the Matthew and Sophia profiles. The platform is stable and will remain in service until its next planned version update.

NET-WATCH is also documented as [Phase 6 of the Cyber Operations Center Engineering Program](https://github.com/scott-renny/cyber-operations-center-engineering-program/tree/main/phases/phase-06-netwatch).

## Capabilities

- Continuous device discovery with ARP scanning and Nmap enrichment
- Device naming, device-type classification, and profile assignment
- Views for all, assigned, unassigned, and device-type groupings
- Per-profile schedules and daily usage budgets
- Manual profile kill switches
- Pi-hole v6 group-based DNS enforcement
- Per-profile blocked-domain policies
- Wazuh alerts with MITRE ATT&CK context
- vnStat bandwidth visibility
- Optional dashboard authentication
- Health and Pi-hole enforcement diagnostics
- Automatic startup and restart through systemd

## Production architecture

```text
LAN devices
     |
ARP scan / Nmap / vnStat
     |
NET-WATCH API
Gunicorn on 127.0.0.1:8082
     |-- Pi-hole v6 group API
     |-- Wazuh local alert data or API
     |-- JSON device/profile state
     |
Caddy private HTTPS
     |
Browser dashboard
```

The installer preserves an active Caddy deployment and adds NET-WATCH to the existing private HTTPS management plane. Nginx remains available as a supported fallback for systems that do not already use Caddy.

## Pi-hole safety model

NET-WATCH does **not** disable Pi-hole globally.

Access control uses one managed deny-all expression and an empty safety group named `NETWATCH-Control`. When a profile must be blocked, NET-WATCH associates only that profile's Pi-hole group with the managed rule. Other profiles and normal ad blocking remain active.

The reconciliation layer rejects unsafe configurations, including:

- the Pi-hole default group;
- missing or disabled profile groups;
- a control group containing clients;
- foreign rules or control groups; and
- ambiguous group ownership.

Diagnostics are available from `GET /api/pihole/enforcement`, and an explicit reconciliation can be requested with `POST /api/pihole/enforcement/reconcile`.

## Wazuh integration

NET-WATCH can read the local Wazuh alert stream when installed on the Wazuh host, or use configured API access. The dashboard presents alert severity, rule details, agent context, and MITRE ATT&CK mappings where available.

## Repository structure

```text
netwatch/
├── api/
│   └── netwatch_api.py
├── config/
│   ├── devices.json
│   └── profiles.json
├── web/
│   └── index.html
├── setup.sh
├── netwatch.service
└── nginx-netwatch.conf
```

Runtime configuration is installed separately at `/etc/netwatch/netwatch.env`. Secrets must never be committed to this repository.

## Installation

Requirements:

- Ubuntu or Debian
- Python 3
- root access for installation
- a reachable local network interface
- optional Pi-hole v6 and Wazuh deployments

Clone the repository and run the installer:

```bash
git clone https://github.com/scott-renny/netwatch.git
cd netwatch
sudo bash setup.sh
```

The installer:

1. validates required project files;
2. installs missing scanning, bandwidth, and Python prerequisites;
3. creates an isolated Python environment;
4. deploys the application to `/opt/netwatch`;
5. creates protected runtime configuration;
6. installs and starts the hardened Gunicorn/systemd service;
7. integrates with active Caddy or configures Nginx as a fallback; and
8. applies the required local firewall access.

Review and configure `/etc/netwatch/netwatch.env`, then restart NET-WATCH.

## Runtime configuration

Common settings include:

```ini
SCAN_SUBNETS_JSON=[{"subnet":"YOUR_SUBNET","interface":"YOUR_INTERFACE"}]
TZ=America/Toronto

NETWATCH_AUTH_ENABLED=true
NETWATCH_PASSWORD=SET_A_STRONG_PASSWORD
NETWATCH_SECRET=SET_A_RANDOM_SECRET
NETWATCH_HTTPS=true

PIHOLE_ENABLED=true
PIHOLE_HOST=YOUR_PIHOLE_HOST
PIHOLE_PORT=YOUR_PIHOLE_PORT
PIHOLE_HTTPS=false
PIHOLE_V6_PASSWORD=SET_OUTSIDE_GIT

WAZUH_ENABLED=true
WAZUH_ALERTS_FILE=/var/ossec/logs/alerts/alerts.json

# Active-use budgets count one minute only when assigned devices produce
# this many new Pi-hole DNS queries during a usage tick.
USAGE_MIN_DNS_QUERIES_PER_TICK=3

# Persistent access-event retention.
ACCESS_LOG_RETENTION_DAYS=90
ACCESS_LOG_MAX_RECORDS=5000
```

Use one occurrence of each setting. Do not place real passwords, tokens, addresses, device identifiers, or private certificate data in public documentation.

Authentication may be disabled temporarily on a trusted management network, but it must be enabled before the dashboard is reachable from less-trusted segments.

## Verification

```bash
systemctl is-active netwatch
curl -sS http://127.0.0.1:8082/api/health
curl -sS http://127.0.0.1:8082/api/pihole/enforcement | python3 -m json.tool
```

A healthy deployment reports:

- the service as active;
- `{"ok":true,"service":"netwatch"}`; and
- Pi-hole enforcement with `"enabled": true`, `"ok": true`, and no warnings.

A profile listed with a reason such as `after_window` is being blocked intentionally by its schedule.

## Operations

```bash
sudo systemctl status netwatch
sudo systemctl restart netwatch
sudo journalctl -u netwatch -f
```

Configuration and profile data are preserved when the installer is rerun. Back them up before upgrades.

## Security notes

- The API binds to localhost and should be exposed only through the configured reverse proxy.
- The systemd unit applies filesystem and kernel hardening controls.
- Runtime secrets live in a root-managed environment file.
- Pi-hole policy changes are profile-scoped and reconciled continuously.
- Public evidence must be sanitized.
- A single Pi-hole instance remains a DNS availability dependency; resilient DNS filtering requires a second independent Pi-hole host.

## Technology stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Production server | Gunicorn |
| Discovery | arp-scan, Nmap |
| Bandwidth | vnStat |
| DNS policy | Pi-hole v6 REST API |
| Security monitoring | Wazuh |
| Reverse proxy | Caddy in the validated deployment; Nginx fallback |
| Service management | systemd |
| Frontend | HTML, CSS, JavaScript, Chart.js |
| Platform | Ubuntu Server 24.04 |

## Security+ domain mapping

| Domain | Demonstrated coverage |
|---|---|
| D2 — Network Architecture | Segmentation readiness, DNS policy, profile groups, network discovery |
| D3 — Implementation | Linux services, reverse proxy, firewall, systemd, Gunicorn |
| D4 — Security Operations | Wazuh alerts, MITRE ATT&CK mapping, monitoring, access-control validation |

## Usage accounting and access history

Daily budgets are based on per-client Pi-hole DNS counter deltas, not device discovery status. A device merely appearing online does not consume time. The first sample after service startup establishes a baseline without charging a minute.

DNS activity is an activity proxy rather than literal screen time. Tune `USAGE_MIN_DNS_QUERIES_PER_TICK` for the network: increase it to ignore more background chatter, or decrease it for light browsing workloads.

Access transitions, manual kill-switch changes, counter resets, and budget exhaustion are persisted in `config/access_log.json`. The dashboard reads the latest events from `GET /api/access-log`; retention is controlled by `ACCESS_LOG_RETENTION_DAYS` and `ACCESS_LOG_MAX_RECORDS`.

## Known limitations and next improvements

- Multi-VLAN discovery requires the server to have a valid interface and route for each scanned network.
- High-availability DNS requires a second independent Pi-hole host.
- Authentication should be enabled before less-trusted VLAN access.
- Future work may add deeper Wazuh vulnerability data, notifications, and richer bandwidth attribution.

## Author

**Scott Renny**  
Aspiring SOC Analyst · Infrastructure Engineer · Home Lab Builder
