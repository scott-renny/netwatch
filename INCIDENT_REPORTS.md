# NET-WATCH — Incident Response Write-Ups

*Documentation of issues encountered during deployment and how they were resolved.*
*Included as part of the homelab portfolio to demonstrate real troubleshooting methodology.*

---

## IR-001 — arp-scan Causing Wi-Fi Interface Drop

**Date:** 2026-07-02
**Severity:** High — resulted in complete SSH lockout, required physical access to server

### What Happened
After installing NET-WATCH on a Wi-Fi-only Ubuntu Server, the background scan loop ran `arp-scan` against the `wlp2s0` (Wi-Fi) interface every 30 seconds. This caused the wireless interface to drop, terminating SSH sessions and making the server unreachable from the network. The issue recurred on every reboot because the netwatch systemd service started automatically.

### Root Cause
`arp-scan` sends raw ARP broadcasts at the Layer 2 level and puts the network interface into promiscuous mode. On Wi-Fi interfaces, this disrupts the normal 802.11 association state and can cause the driver to drop the connection to the access point. Ethernet interfaces handle this safely; Wi-Fi interfaces do not.

### Resolution
**Immediate:** Physical access to server was required to bring the interface back up:
```bash
sudo wpa_cli -i wlp2s0 reconnect
sudo dhclient wlp2s0
sudo reboot
```

**Permanent fix — switched from arp-scan to nmap:**
The `_scan_subnet()` function in `netwatch_api.py` was updated to use:
```python
subprocess.run(["nmap", "-sn", "-T3", "--host-timeout", "5s", subnet])
```
nmap's ping sweep (`-sn`) uses ICMP and does not disrupt Wi-Fi associations. The interface remained stable across all subsequent scans.

**Additional mitigation:**
- `AUTO_SCAN_INTERVAL` increased from 30s to 300s (5 minutes)
- Auto-scan background thread disabled; manual scan-on-demand via dashboard button only
- Scan timeout increased from 30s to 120s to allow nmap sufficient time

### Lessons Learned
- arp-scan is appropriate for wired/ethernet environments only
- Wi-Fi-only server setups require nmap or similar ICMP-based discovery
- Always test scanner tools manually before enabling background threads
- Having a physical keyboard/monitor connected to a headless server is essential for recovery

---

## IR-002 — Port Conflict on Port 80 (Docker vs Nginx)

**Date:** 2026-07-02
**Severity:** Medium — prevented dashboard from loading at root URL

### What Happened
After running `setup.sh`, Nginx failed to start with the error: `nginx.service is not active, cannot reload`. The service kept failing to bind to port 80.

### Root Cause
An existing Docker container (Pi-hole) was already listening on port 80. `sudo lsof -i :80` confirmed:
```
COMMAND     PID   USER  TYPE
docker-pr  1840   root  TCP  *:http (LISTEN)
docker-pr  1847   root  TCP  *:http (LISTEN)
```

### Resolution
Changed the NET-WATCH Nginx config to listen on port 8082 instead of port 80:
```bash
sudo nano /etc/nginx/sites-available/netwatch
# Changed: listen 80; → listen 8082;
sudo ufw allow 8082/tcp
sudo systemctl start nginx
```
The dashboard URL changed from `http://SERVER_IP` to `http://SERVER_IP:8082`. The `API_BASE` constant in `index.html` was updated to match.

### Lessons Learned
- Always audit which ports are in use before deploying (`sudo lsof -i :80`)
- Docker port bindings persist across reboots and block system services
- The setup script should check for port conflicts before configuring Nginx

---

## IR-003 — API_BASE Reverting to Placeholder on Every File Update

**Date:** 2026-07-03
**Severity:** Low — dashboard showed "Backend Offline" after every file update

### What Happened
Every time `index.html` was copied from the development machine to the server, the `API_BASE` constant reverted from `http://192.168.1.103:8082` back to the placeholder `http://127.0.0.1:5000`, causing the dashboard to show "Backend Offline" immediately after update.

### Root Cause
The source file on the development machine retained the placeholder value. Each file copy overwrote the server's edited version. There was no persistent mechanism to inject the server-specific IP into the file.

### Resolution
Two-part fix:
1. Updated the source file's `API_BASE` to `http://192.168.1.103:8082` permanently — it is now baked in
2. Added a post-copy `sed` command as standard procedure after every file update:
```bash
sudo sed -i 's|const API_BASE = "http://127.0.0.1:5000";|const API_BASE = "http://192.168.1.103:8082";|' /opt/netwatch/web/index.html
```

### Lessons Learned
- Environment-specific configuration should be injected at deploy time, not hardcoded in source
- A proper CI/CD pipeline or deployment script would handle this automatically
- The `setup.sh` script was updated to run the sed substitution as part of installation

---

## IR-004 — vnstat Tracking Wrong Interface (Docker Bridge Instead of Wi-Fi)

**Date:** 2026-07-04
**Severity:** Medium — Total Bandwidth and traffic chart showed zeros despite real traffic

### What Happened
The Network Traffic chart and Total Bandwidth stat card displayed zeros or "— MB" despite the network being active. The `/api/traffic` endpoint returned `"source": "unavailable"`.

### Root Cause
vnstat was tracking the Docker bridge interface (`br-05419816dcc2`) as its primary interface because it was listed first in the vnstat database. The `_default_interface()` function in the backend selected the first non-loopback interface from vnstat's database, which happened to be the Docker bridge — not the actual Wi-Fi interface (`wlp2s0`) used for real network traffic.

### Resolution
Rewrote `_default_interface()` to prefer the interface specified in `SCAN_SUBNETS`:
```python
def _default_interface():
    preferred = SCAN_SUBNETS[0].get("interface", "wlp2s0")
    # ... checks vnstat database, returns preferred if tracked
    # Falls back to first non-loopback non-docker interface
```
Also fixed a JSON key mismatch: vnstat's output uses `"hour"` (singular) but the parser was looking for `"hours"` (plural), causing a KeyError that silently fell through to the unavailable fallback.

### Lessons Learned
- Always verify which interface a bandwidth tracking tool is monitoring
- Docker creates multiple virtual interfaces that can confuse interface auto-detection
- Log the selected interface on startup so mismatches are immediately visible

---

## IR-005 — Pi-hole Probe Returning Unreachable Despite Valid Credentials

**Date:** 2026-07-04
**Severity:** Medium — Pi-hole integration showing unreachable despite correct password

### What Happened
After setting `PIHOLE_ENABLED = True` and the correct Pi-hole v6 password, `/api/pihole/probe` returned `"reachable": false, "version": null`.

### Root Cause
The `detect_version()` function attempted to reach `/api/info/version` without authentication. Pi-hole v6 returns HTTP 401 (Unauthorized) for all API endpoints without a valid session token — including the version endpoint. The function interpreted the 401 as "not Pi-hole v6" and fell through to the v5 check, which also failed, returning `null`.

### Resolution
Updated `detect_version()` to authenticate first using `_v6_auth()` before probing the version endpoint:
```python
def detect_version(self):
    try:
        self._v6_auth()  # authenticate first
        if self._sid:
            r = self._req("get", "/api/info/version", headers={"sid": self._sid})
            if r.status_code == 200:
                self.ver = 6; return 6
    except Exception:
        pass
    # fallback checks...
```
After this fix, `/api/pihole/probe` returned `"reachable": true, "version": 6` on the first attempt.

### Lessons Learned
- Pi-hole v6's API requires authentication for all endpoints, including informational ones
- Authentication must happen before any API probe, not after version detection
- Testing API authentication manually with `curl` before integrating is essential

---

*All incidents were resolved without data loss. The homelab remained operational throughout, as all issues were isolated to the NET-WATCH monitoring layer rather than the underlying network infrastructure.*
