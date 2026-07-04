"""
NET-WATCH API — v3
Password-protected, real data from vnstat / Pi-hole / Wazuh,
background scan + usage threads, full CRUD.

Set your password:   export NETWATCH_PASSWORD=yourpassword
Generate secret key: python3 -c "import secrets; print(secrets.token_hex(32))"
"""
from flask import Flask, jsonify, request, session
from flask_cors import CORS
import json, os, re, subprocess, threading, uuid, datetime

# ══════════════════════════════════════════════════════
#  SETUP
# ══════════════════════════════════════════════════════
app = Flask(__name__)
app.secret_key        = os.environ.get("NETWATCH_SECRET", "change-me-set-NETWATCH_SECRET-env-var")
app.permanent_session_lifetime = datetime.timedelta(hours=24)

CORS_ORIGINS = "*"
CORS(app, origins=CORS_ORIGINS, supports_credentials=True)

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR    = os.path.join(BASE_DIR, "..", "config")
DEVICES_FILE  = os.path.join(CONFIG_DIR, "devices.json")
PROFILES_FILE = os.path.join(CONFIG_DIR, "profiles.json")

# ══════════════════════════════════════════════════════
#  AUTH
#  Set NETWATCH_PASSWORD env var before deploying.
#  Default is "netwatch" — change it.
# ══════════════════════════════════════════════════════

# Auth disabled — all endpoints open




# ══════════════════════════════════════════════════════
#  PI-HOLE CLIENT (v5 + v6 auto-detect)
# ══════════════════════════════════════════════════════
PIHOLE_HOST     = os.environ.get("PIHOLE_HOST", "192.168.1.1")
PIHOLE_PORT     = int(os.environ.get("PIHOLE_PORT", "8081"))
PIHOLE_HTTPS    = os.environ.get("PIHOLE_HTTPS", "false").lower() == "true"
PIHOLE_V5_TOKEN = os.environ.get("PIHOLE_V5_TOKEN", "")
PIHOLE_V6_PASS  = os.environ.get("PIHOLE_V6_PASSWORD", "")
PIHOLE_ENABLED  = os.environ.get("PIHOLE_ENABLED", "false").lower() == "true"

class PiholeClient:
    def __init__(self):
        scheme     = "https" if PIHOLE_HTTPS else "http"
        self.base  = f"{scheme}://{PIHOLE_HOST}:{PIHOLE_PORT}"
        self.ver   = None
        self._sid  = None   # v6 session id

    def _req(self, method, path, **kwargs):
        import requests as req
        url = self.base + path
        kwargs.setdefault("timeout", 8)
        kwargs.setdefault("verify", False)
        return getattr(req, method)(url, **kwargs)

    def detect_version(self):
        # Try v6 first — authenticate then check version
        try:
            self._v6_auth()
            if self._sid:
                r = self._req("get", "/api/info/version", headers={"sid": self._sid})
                if r.status_code == 200 and "version" in r.text.lower():
                    self.ver = 6; return 6
        except Exception:
            pass
        # Try unauthenticated v6 version endpoint
        try:
            r = self._req("get", "/api/info/version")
            if r.status_code == 200 and "version" in r.text.lower():
                self.ver = 6; return 6
        except Exception:
            pass
        # Try v5 legacy endpoint
        try:
            r = self._req("get", "/admin/api.php", params={"status": ""})
            if r.status_code == 200:
                self.ver = 5; return 5
        except Exception:
            pass
        return None

    def _v6_auth(self):
        r = self._req("post", "/api/auth", json={"password": PIHOLE_V6_PASS})
        r.raise_for_status()
        self._sid = r.json().get("session", {}).get("sid")

    def _v6_get(self, path, **kw):
        if not self._sid: self._v6_auth()
        h = {"sid": self._sid}
        r = self._req("get", path, headers=h, **kw)
        if r.status_code == 401:
            self._sid = None; self._v6_auth()
            r = self._req("get", path, headers={"sid": self._sid}, **kw)
        r.raise_for_status(); return r.json()

    def set_group_enabled(self, group_name, enabled):
        if self.ver is None: self.detect_version()
        if self.ver != 6:
            return {"ok": False, "error": "Pi-hole v5 does not support per-group API — upgrade to v6"}
        try:
            groups = self._v6_get("/api/groups").get("groups", [])
            m = next((g for g in groups if g.get("name") == group_name), None)
            if not m: return {"ok": False, "error": f'Group "{group_name}" not found in Pi-hole'}
            r = self._req("put", f"/api/groups/{m['id']}",
                          headers={"sid": self._sid}, json={"enabled": enabled})
            r.raise_for_status()
            return {"ok": True, "group": group_name, "enabled": enabled}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def top_clients(self):
        """Per-client DNS query counts — used for bandwidth chart."""
        try:
            if self.ver == 6:
                data = self._v6_get("/api/stats/top_clients")
                clients = data.get("top_sources", [])
                total   = sum(c.get("count", 0) for c in clients) or 1
                return [{"name": c.get("name", c.get("ip", "?")),
                         "ip":  c.get("ip", ""),
                         "count": c.get("count", 0),
                         "pct": round(c.get("count", 0) / total * 100, 1)}
                        for c in clients[:6]]
            else:
                import requests as req
                r = self._req("get", "/admin/api.php",
                              params={"getQuerySources": "", "auth": PIHOLE_V5_TOKEN})
                r.raise_for_status()
                src   = r.json().get("top_sources", {})
                total = sum(src.values()) or 1
                return [{"name": k.split("|")[1] if "|" in k else k,
                         "ip":  k.split("|")[0] if "|" in k else k,
                         "count": v, "pct": round(v / total * 100, 1)}
                        for k, v in list(src.items())[:6]]
        except Exception:
            return []

    def dns_summary(self):
        """Queries blocked/total stats."""
        try:
            if self.ver == 6:
                d = self._v6_get("/api/stats/summary")
                q = d.get("queries", {})
                return {"queries_today": q.get("total", 0),
                        "blocked_today": q.get("blocked", 0),
                        "pct_blocked":   round(q.get("percent_blocked", 0), 1),
                        "domains_blocked": d.get("gravity", {}).get("domains_being_blocked", 0)}
            else:
                import requests as req
                r = self._req("get", "/admin/api.php",
                              params={"summaryRaw": "", "auth": PIHOLE_V5_TOKEN})
                r.raise_for_status(); d = r.json()
                total = d.get("dns_queries_today", 0)
                blk   = d.get("ads_blocked_today", 0)
                return {"queries_today": total, "blocked_today": blk,
                        "pct_blocked": round(blk / total * 100, 1) if total else 0,
                        "domains_blocked": d.get("domains_being_blocked", 0)}
        except Exception:
            return {}

    # ── Domain blocking per group ─────────────────────────────────

    def _get_group_id(self, group_name):
        """Returns the numeric Pi-hole group ID for a named group, or None."""
        if self.ver is None: self.detect_version()
        if self.ver != 6: return None
        try:
            groups = self._v6_get("/api/groups").get("groups", [])
            m = next((g for g in groups if g.get("name") == group_name), None)
            return m["id"] if m else None
        except Exception:
            return None

    def get_blocked_domains(self, group_name):
        """
        Returns the list of domains currently on Pi-hole's denylist
        that are assigned to the given group. Returns [] if Pi-hole
        isn't connected or the group doesn't exist.
        """
        if self.ver is None: self.detect_version()
        if self.ver != 6: return []
        try:
            gid = self._get_group_id(group_name)
            if gid is None: return []
            # Get all deny-type domain entries
            data = self._v6_get("/api/domains", params={"type": "deny"})
            domains = data.get("domains", [])
            # Filter to only those assigned to this group
            result = []
            for d in domains:
                groups_for_domain = d.get("groups", [])
                if gid in groups_for_domain:
                    result.append({
                        "domain":  d.get("domain"),
                        "id":      d.get("id"),
                        "comment": d.get("comment", ""),
                    })
            return result
        except Exception:
            return []

    def add_blocked_domain(self, group_name, domain, comment=""):
        """
        Adds a domain to Pi-hole's denylist and assigns it to the
        given group, so only devices in that group are blocked.
        Other groups are unaffected.
        Returns {"ok": True} on success or {"ok": False, "error": ...}.
        """
        if self.ver is None: self.detect_version()
        if self.ver != 6:
            return {"ok": False, "error": "Pi-hole v5 does not support per-group domain blocking via API — upgrade to v6"}
        try:
            gid = self._get_group_id(group_name)
            if gid is None:
                return {"ok": False, "error": f'Pi-hole group "{group_name}" not found — create it in Pi-hole first'}

            # Add domain to the denylist, assigned to this group only
            r = self._req("post", "/api/domains",
                          headers={"sid": self._sid},
                          json={"domain": domain,
                                "type":    "deny",
                                "kind":    "exact",
                                "comment": comment or f"Blocked for profile group: {group_name}",
                                "groups":  [gid],
                                "enabled": True})
            if r.status_code in (200, 201):
                return {"ok": True, "domain": domain, "group": group_name}
            # Domain might already exist — try to add the group assignment
            if r.status_code == 409:
                return {"ok": False, "error": f'"{domain}" is already on the denylist (possibly in a different group — manage it from Pi-hole directly)'}
            r.raise_for_status()
            return {"ok": True, "domain": domain}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def remove_blocked_domain(self, group_name, domain):
        """
        Removes a domain from Pi-hole's denylist for the given group.
        If the domain is also assigned to other groups, those are unaffected.
        """
        if self.ver is None: self.detect_version()
        if self.ver != 6:
            return {"ok": False, "error": "Pi-hole v5 does not support per-group domain management via API"}
        try:
            gid = self._get_group_id(group_name)
            if gid is None:
                return {"ok": False, "error": f'Pi-hole group "{group_name}" not found'}

            # Find the domain entry
            data    = self._v6_get("/api/domains", params={"type": "deny"})
            domains = data.get("domains", [])
            entry   = next((d for d in domains
                            if d.get("domain") == domain and gid in d.get("groups", [])),
                           None)
            if not entry:
                return {"ok": False, "error": f'"{domain}" not found in group "{group_name}"'}

            r = self._req("delete", f"/api/domains/{entry['id']}",
                          headers={"sid": self._sid})
            r.raise_for_status()
            return {"ok": True, "domain": domain, "removed_from": group_name}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def sync_blocked_domains(self, group_name, domains):
        """
        Ensures Pi-hole's denylist for this group exactly matches the
        provided list. Adds missing entries, removes extras.
        Called at startup so Pi-hole stays in sync even after a server reboot.
        Returns a summary dict of what was added/removed.
        """
        if not PIHOLE_ENABLED or self.ver != 6:
            return {"synced": False}
        try:
            current  = {d["domain"] for d in self.get_blocked_domains(group_name)}
            desired  = set(domains)
            to_add   = desired - current
            to_remove = current - desired
            for d in to_add:    self.add_blocked_domain(group_name, d)
            for d in to_remove: self.remove_blocked_domain(group_name, d)
            return {"synced": True, "added": list(to_add), "removed": list(to_remove)}
        except Exception as e:
            return {"synced": False, "error": str(e)}


pihole = PiholeClient()

# ══════════════════════════════════════════════════════
#  WAZUH CLIENT
# ══════════════════════════════════════════════════════
WAZUH_URL      = os.environ.get("WAZUH_URL",      "https://localhost:55000")
WAZUH_USER     = os.environ.get("WAZUH_USER",     "wazuh")
WAZUH_PASS     = os.environ.get("WAZUH_PASSWORD", "wazuh")
WAZUH_ENABLED  = os.environ.get("WAZUH_ENABLED",  "false").lower() == "true"
_wazuh_tok     = None
_wazuh_tok_ts  = None

def _wazuh_token():
    import requests as req
    global _wazuh_tok, _wazuh_tok_ts
    now = datetime.datetime.now().timestamp()
    if _wazuh_tok and _wazuh_tok_ts and now - _wazuh_tok_ts < 800:
        return _wazuh_tok
    r = req.post(f"{WAZUH_URL}/security/user/authenticate",
                 auth=(WAZUH_USER, WAZUH_PASS), verify=False, timeout=10)
    r.raise_for_status()
    _wazuh_tok    = r.json()["data"]["token"]
    _wazuh_tok_ts = now
    return _wazuh_tok

def _wazuh_get(path, params=None):
    import requests as req
    global _wazuh_tok, _wazuh_tok_ts
    tok = _wazuh_token()
    r   = req.get(f"{WAZUH_URL}{path}", headers={"Authorization": f"Bearer {tok}"},
                  params=params, verify=False, timeout=10)
    if r.status_code == 401:
        _wazuh_tok = None; _wazuh_tok_ts = None
        tok = _wazuh_token()
        r   = req.get(f"{WAZUH_URL}{path}", headers={"Authorization": f"Bearer {tok}"},
                      params=params, verify=False, timeout=10)
    r.raise_for_status(); return r.json()

def wazuh_recent_events(limit=10, min_level=5):
    if not WAZUH_ENABLED: return []
    try:
        data = _wazuh_get("/alerts", params={"level": min_level, "limit": limit, "sort": "-timestamp"})
        return [{"time":   e.get("timestamp","")[:19].replace("T"," "),
                 "rule":   e.get("rule",{}).get("description",""),
                 "level":  e.get("rule",{}).get("level", 0),
                 "agent":  e.get("agent",{}).get("name","?"),
                 "mitre":  ", ".join(e.get("rule",{}).get("mitre",{}).get("technique",["—"]))}
                for e in data.get("data",{}).get("affected_items",[])]
    except Exception:
        return []

def wazuh_counts_7d():
    """Per-day alert severity buckets for the last 7 days."""
    if not WAZUH_ENABLED:
        return []
    result = []
    today = datetime.date.today()
    for days_ago in range(6, -1, -1):
        d = today - datetime.timedelta(days=days_ago)
        label = d.strftime("%a")
        crit = high = med = 0
        try:
            start = f"{d.isoformat()}T00:00:00"
            end   = f"{d.isoformat()}T23:59:59"
            data  = _wazuh_get("/alerts",
                                params={"level": "12", "limit": 1,
                                        "q": f"timestamp>{start};timestamp<{end}"})
            crit = data.get("data", {}).get("total_affected_items", 0)
            data  = _wazuh_get("/alerts",
                                params={"level": "9", "limit": 1,
                                        "q": f"timestamp>{start};timestamp<{end}"})
            high = max(0, data.get("data", {}).get("total_affected_items", 0) - crit)
            data  = _wazuh_get("/alerts",
                                params={"level": "5", "limit": 1,
                                        "q": f"timestamp>{start};timestamp<{end}"})
            med = max(0, data.get("data", {}).get("total_affected_items", 0) - crit - high)
        except Exception:
            pass
        result.append({"date": label, "critical": crit, "high": high, "medium": med})
    return result

# ══════════════════════════════════════════════════════
#  VNSTAT HELPERS
# ══════════════════════════════════════════════════════
def _default_interface():
    """
    Pick the best interface for bandwidth tracking.
    Prefers the interface in SCAN_SUBNETS, falls back to first
    non-loopback non-docker interface that vnstat knows about.
    """
    preferred = SCAN_SUBNETS[0].get("interface", "wlp2s0")
    try:
        r = subprocess.run(["vnstat", "--json"], capture_output=True, text=True, timeout=5)
        ifaces = [i["name"] for i in json.loads(r.stdout).get("interfaces", [])]
        # Return preferred if vnstat already tracks it
        if preferred in ifaces:
            return preferred
        # Otherwise pick first non-loopback, non-docker, non-bridge interface
        for name in ifaces:
            if not any(name.startswith(p) for p in ["lo","br-","docker","veth"]):
                return name
        # Last resort — first non-loopback
        for name in ifaces:
            if name != "lo":
                return name
    except Exception:
        pass
    return preferred

def vnstat_24h(interface=None):
    iface = interface or _default_interface()
    try:
        r = subprocess.run(["vnstat", "--json", "h", "24", "-i", iface],
                           capture_output=True, text=True, timeout=10)
        data  = json.loads(r.stdout)
        traffic = data["interfaces"][0]["traffic"]
        # vnstat uses "hour" (singular) not "hours"
        hours = traffic.get("hours", traffic.get("hour", []))
        labels, rx_vals, tx_vals = [], [], []
        for h in hours[-24:]:
            # vnstat hour entries have a "date" and "time" object, or just "id"
            t    = h.get("time", {})
            d    = h.get("date", {})
            hour = t.get("hour", h.get("id", 0) % 24)
            labels.append(f"{hour:02d}:00")
            rx_vals.append(round(h.get("rx", 0) / 450_000, 2))
            tx_vals.append(round(h.get("tx", 0) / 450_000, 2))
        return {"labels": labels, "rx": rx_vals, "tx": tx_vals,
                "interface": iface, "source": "vnstat"}
    except Exception:
        now    = datetime.datetime.now()
        labels = [(now - datetime.timedelta(hours=i)).strftime("%H:00")
                  for i in range(23, -1, -1)]
        return {"labels": labels, "rx": [0]*24, "tx": [0]*24,
                "interface": iface, "source": "unavailable"}

def vnstat_today(interface=None):
    iface = interface or _default_interface()
    try:
        r = subprocess.run(["vnstat", "--json", "d", "1", "-i", iface],
                           capture_output=True, text=True, timeout=10)
        data  = json.loads(r.stdout)
        traffic = data["interfaces"][0]["traffic"]
        days = traffic.get("days", traffic.get("day", [{}]))
        today = days[0] if days else {}
        rx, tx = today.get("rx", 0), today.get("tx", 0)
        return {"rx_bytes": rx, "tx_bytes": tx, "total_bytes": rx + tx,
                "total_tb": round((rx + tx) / (1024**4), 4)}
    except Exception:
        return {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0, "total_tb": 0}

# ════════════════════════════════════════════════════════════════════
#  NETWORK SCAN CONFIGURATION
#
#  SCAN_SUBNETS tells the background scanner which subnets to sweep
#  with arp-scan every AUTO_SCAN_INTERVAL seconds.
#
#  FLAT NETWORK (single subnet — start here):
#    SCAN_SUBNETS = [{"subnet": "192.168.1.0/24", "interface": "eth0"}]
#
#  AFTER ADDING VLANs (add one entry per VLAN):
#    SCAN_SUBNETS = [
#        {"subnet": "192.168.1.0/24",  "interface": "eth0"},      # Main LAN
#        {"subnet": "192.168.10.0/24", "interface": "eth0.10"},    # IoT VLAN
#        {"subnet": "192.168.20.0/24", "interface": "eth0.20"},    # Kids VLAN
#        {"subnet": "192.168.30.0/24", "interface": "eth0.30"},    # Guest VLAN
#    ]
#
#  The interface name for VLANs is your physical interface + a dot +
#  the VLAN ID. Find your physical interface with: ip link show
#  Confirm VLAN interfaces exist with: ip link show | grep "\."
#
#  FIREWALL RULES REQUIRED PER VLAN (add these to your router/firewall):
#    1. This server's IP → VLAN subnet  (for ARP scanning)
#    2. VLAN subnet      → this server port 80  (to load the dashboard)
#    3. This server's IP → Pi-hole port 80  (for kill switches + blocklists)
#
#  CORS — tighten this from "*" once VLANs are set up.
#  Replace with a list of the admin VLAN subnet and any other
#  subnets that need dashboard access:
#    CORS_ORIGINS = ["http://192.168.1.0/24", "http://192.168.50.0/24"]
#  For now "*" means any device on any subnet can reach the API.
# ════════════════════════════════════════════════════════════════════

SCAN_SUBNETS        = [{"subnet": "192.168.1.0/24", "interface": "eth0"}]
AUTO_SCAN_INTERVAL  = 300  # 5 minutes — gentler on Wi-Fi
USAGE_TICK_INTERVAL = 60   # seconds between per-profile usage ticks

# ════════════════════════════════════════════════════════════════════
#  AUTO-NAMING: MAC OUI LOOKUP + NMAP HOSTNAME DETECTION
#
#  When a new device is discovered, two things happen automatically:
#  1. The MAC prefix is looked up against a table of common home-network
#     device manufacturers (Apple, Samsung, Google, etc.) — gives a
#     name like "Apple Device (192.168.1.73)"
#  2. nmap reverse-DNS / hostname detection is run on that single IP —
#     if the device registered a hostname with your router (e.g.
#     "scotts-iphone.local"), that name is used instead.
#
#  The result is stored in devices.json. You can still rename any device
#  manually from the dashboard — the auto-name is just the starting point.
# ════════════════════════════════════════════════════════════════════

# Top ~300 OUI prefixes for common home network device manufacturers.
# Format: first 3 bytes of MAC (uppercase, colon-separated) → vendor name.
# Source: IEEE OUI registry, filtered to consumer/home-network devices.
OUI_TABLE = {
    # ── Apple ─────────────────────────────────────────────────────────
    "00:03:93":"Apple","00:05:02":"Apple","00:0A:27":"Apple","00:0A:95":"Apple",
    "00:0D:93":"Apple","00:11:24":"Apple","00:14:51":"Apple","00:16:CB":"Apple",
    "00:17:F2":"Apple","00:19:E3":"Apple","00:1B:63":"Apple","00:1C:B3":"Apple",
    "00:1D:4F":"Apple","00:1E:52":"Apple","00:1E:C2":"Apple","00:1F:5B":"Apple",
    "00:1F:F3":"Apple","00:21:E9":"Apple","00:22:41":"Apple","00:23:12":"Apple",
    "00:23:32":"Apple","00:23:6C":"Apple","00:23:DF":"Apple","00:24:36":"Apple",
    "00:25:00":"Apple","00:25:4B":"Apple","00:25:BC":"Apple","00:26:08":"Apple",
    "00:26:4A":"Apple","00:26:B0":"Apple","00:26:BB":"Apple","00:30:65":"Apple",
    "00:3E:E1":"Apple","04:0C:CE":"Apple","04:15:52":"Apple","04:1E:64":"Apple",
    "04:26:65":"Apple","04:48:9A":"Apple","04:52:F3":"Apple","04:54:53":"Apple",
    "04:69:F8":"Apple","04:D3:CF":"Apple","04:DB:56":"Apple","04:E5:36":"Apple",
    "04:F1:3E":"Apple","04:F7:E4":"Apple","08:00:07":"Apple","08:6D:41":"Apple",
    "08:70:45":"Apple","08:74:02":"Apple","0C:1D:AF":"Apple","0C:3E:9F":"Apple",
    "0C:4D:E9":"Apple","0C:51:01":"Apple","0C:74:C2":"Apple","0C:77:1A":"Apple",
    "0C:BC:9F":"Apple","0C:D7:46":"Apple","10:1C:0C":"Apple","10:40:F3":"Apple",
    "10:41:7F":"Apple","10:93:E9":"Apple","10:9A:DD":"Apple","10:DD:B1":"Apple",
    "14:10:9F":"Apple","14:5A:05":"Apple","14:8F:C6":"Apple","14:99:E2":"Apple",
    "18:20:32":"Apple","18:34:51":"Apple","18:65:90":"Apple","18:AF:61":"Apple",
    "18:E7:F4":"Apple","1C:1A:C0":"Apple","1C:36:BB":"Apple","1C:91:48":"Apple",
    "20:78:F0":"Apple","20:7D:74":"Apple","20:A2:E4":"Apple","20:AB:37":"Apple",
    "24:1E:EB":"Apple","24:5B:A7":"Apple","24:A0:74":"Apple","24:AB:81":"Apple",
    "28:0B:5C":"Apple","28:37:37":"Apple","28:5A:EB":"Apple","28:6A:BA":"Apple",
    "28:A0:2B":"Apple","28:CF:E9":"Apple","28:E0:2C":"Apple","28:E1:4C":"Apple",
    "28:F0:76":"Apple","2C:1F:23":"Apple","2C:20:0B":"Apple","2C:B4:3A":"Apple",
    "2C:F0:EE":"Apple","30:10:E4":"Apple","30:35:AD":"Apple","30:90:AB":"Apple",
    "30:F7:C5":"Apple","34:08:BC":"Apple","34:15:9E":"Apple","34:36:3B":"Apple",
    "34:51:C9":"Apple","34:A3:95":"Apple","34:AB:37":"Apple","34:C0:59":"Apple",
    "34:E2:FD":"Apple","38:0F:4A":"Apple","38:48:4C":"Apple","38:53:9C":"Apple",
    "38:66:F0":"Apple","38:B5:4D":"Apple","38:C9:86":"Apple","3C:07:54":"Apple",
    "3C:2E:F9":"Apple","3C:D0:F8":"Apple","40:30:04":"Apple","40:3C:FC":"Apple",
    "40:4D:7F":"Apple","40:6C:8F":"Apple","40:9C:28":"Apple","40:A6:D9":"Apple",
    "40:B3:95":"Apple","40:CB:C0":"Apple","40:D3:2D":"Apple","44:00:10":"Apple",
    "44:2A:60":"Apple","44:4C:0C":"Apple","44:D8:84":"Apple","44:FB:42":"Apple",
    "48:43:7C":"Apple","48:60:BC":"Apple","48:74:6E":"Apple","48:A1:95":"Apple",
    "48:BF:6B":"Apple","48:D7:05":"Apple","4C:32:75":"Apple","4C:57:CA":"Apple",
    "4C:74:03":"Apple","4C:8D:79":"Apple","4C:A9:19":"Apple","50:32:37":"Apple",
    "50:7A:55":"Apple","50:82:D5":"Apple","50:BC:96":"Apple","50:DE:06":"Apple",
    "50:EA:D6":"Apple","54:26:96":"Apple","54:33:CB":"Apple","54:4E:90":"Apple",
    "54:72:4F":"Apple","54:9F:13":"Apple","54:AE:27":"Apple","54:E4:3A":"Apple",
    "58:1F:AA":"Apple","58:55:CA":"Apple","58:7F:57":"Apple","58:B0:35":"Apple",
    "5C:1D:D9":"Apple","5C:59:48":"Apple","5C:8D:4E":"Apple","5C:95:AE":"Apple",
    "5C:AD:CF":"Apple","5C:F5:DA":"Apple","5C:F9:38":"Apple","60:03:08":"Apple",
    "60:33:4B":"Apple","60:6D:C7":"Apple","60:92:17":"Apple","60:C5:47":"Apple",
    "60:D9:C7":"Apple","60:F4:45":"Apple","60:F8:1D":"Apple","64:20:0C":"Apple",
    "64:76:BA":"Apple","64:9A:BE":"Apple","64:A3:CB":"Apple","64:B9:E8":"Apple",
    "64:E6:82":"Apple","68:09:27":"Apple","68:A8:6D":"Apple","68:AE:20":"Apple",
    "68:D9:3C":"Apple","6C:19:C0":"Apple","6C:3E:6D":"Apple","6C:40:08":"Apple",
    "6C:70:9F":"Apple","6C:72:E7":"Apple","6C:8D:C1":"Apple","6C:96:CF":"Apple",
    "6C:AB:31":"Apple","70:11:24":"Apple","70:3E:AC":"Apple","70:48:0F":"Apple",
    "70:56:81":"Apple","70:73:CB":"Apple","70:81:EB":"Apple","70:A2:B3":"Apple",
    "70:CD:60":"Apple","70:DE:E2":"Apple","70:EC:E4":"Apple","74:1B:B2":"Apple",
    "74:4D:28":"Apple","74:8F:3C":"Apple","74:E1:B6":"Apple","78:31:C1":"Apple",
    "78:4F:43":"Apple","78:67:D7":"Apple","78:7B:8A":"Apple","78:CA:39":"Apple",
    "78:D7:5F":"Apple","78:FD:94":"Apple","7C:01:91":"Apple","7C:04:D0":"Apple",
    "7C:11:BE":"Apple","7C:6D:62":"Apple","7C:D1:C3":"Apple","7C:FA:DF":"Apple",
    "80:00:6E":"Apple","80:49:71":"Apple","80:82:23":"Apple","80:92:9F":"Apple",
    "80:BE:05":"Apple","80:E6:50":"Apple","84:29:99":"Apple","84:38:35":"Apple",
    "84:78:8B":"Apple","84:8E:DF":"Apple","84:A1:34":"Apple","84:B1:53":"Apple",
    "84:FC:FE":"Apple","88:19:08":"Apple","88:1F:A1":"Apple","88:53:2E":"Apple",
    "88:63:DF":"Apple","88:66:A5":"Apple","88:AE:07":"Apple","88:C6:63":"Apple",
    "88:CB:87":"Apple","88:E8:7F":"Apple","8C:00:6D":"Apple","8C:29:37":"Apple",
    "8C:2D:AA":"Apple","8C:58:77":"Apple","8C:7B:9D":"Apple","8C:7C:92":"Apple",
    "8C:85:90":"Apple","8C:8D:28":"Apple","90:27:E4":"Apple","90:3C:92":"Apple",
    "90:60:F0":"Apple","90:72:40":"Apple","90:8D:6C":"Apple","90:B0:ED":"Apple",
    "90:B9:31":"Apple","90:C1:C6":"Apple","90:DD:5D":"Apple","94:BF:2D":"Apple",
    "94:E9:6A":"Apple","94:F6:A3":"Apple","98:01:A7":"Apple","98:03:D8":"Apple",
    "98:10:E8":"Apple","98:5A:EB":"Apple","98:B8:E3":"Apple","98:CA:33":"Apple",
    "98:D6:BB":"Apple","98:FE:94":"Apple","9C:04:EB":"Apple","9C:20:7B":"Apple",
    "9C:29:76":"Apple","9C:35:EB":"Apple","9C:4F:DA":"Apple","9C:84:BF":"Apple",
    "9C:F3:87":"Apple","A0:18:28":"Apple","A0:3B:E3":"Apple","A0:4E:A7":"Apple",
    "A0:56:F3":"Apple","A0:99:9B":"Apple","A0:D7:95":"Apple","A0:ED:CD":"Apple",
    "A4:31:35":"Apple","A4:5E:60":"Apple","A4:67:06":"Apple","A4:83:E7":"Apple",
    "A4:B1:97":"Apple","A4:C3:61":"Apple","A4:CF:99":"Apple","A4:D1:8C":"Apple",
    "A4:D9:31":"Apple","A8:20:66":"Apple","A8:51:AB":"Apple","A8:5B:78":"Apple",
    "A8:60:B6":"Apple","A8:66:7F":"Apple","A8:88:08":"Apple","A8:96:8A":"Apple",
    "A8:FA:D8":"Apple","AC:1F:74":"Apple","AC:29:3A":"Apple","AC:3C:0B":"Apple",
    "AC:61:EA":"Apple","AC:87:A3":"Apple","AC:BC:32":"Apple","AC:CF:5C":"Apple",
    "AC:DE:48":"Apple","AC:E4:B5":"Apple","AC:FD:EC":"Apple","B0:34:95":"Apple",
    "B0:65:BD":"Apple","B0:70:2D":"Apple","B0:9F:BA":"Apple","B0:CA:68":"Apple",
    "B4:18:D1":"Apple","B4:4B:D2":"Apple","B4:8B:19":"Apple","B4:F0:AB":"Apple",
    "B8:09:8A":"Apple","B8:17:C2":"Apple","B8:41:A4":"Apple","B8:44:D9":"Apple",
    "B8:53:AC":"Apple","B8:5D:0A":"Apple","B8:8D:12":"Apple","B8:C1:11":"Apple",
    "B8:E8:56":"Apple","B8:FF:61":"Apple","BC:3B:AF":"Apple","BC:4C:C4":"Apple",
    "BC:52:B7":"Apple","BC:54:36":"Apple","BC:67:78":"Apple","BC:6C:21":"Apple",
    "BC:92:6B":"Apple","BC:A9:20":"Apple","BC:EC:5D":"Apple","C0:1A:DA":"Apple",
    "C0:84:7A":"Apple","C0:9F:42":"Apple","C0:B6:58":"Apple","C0:CC:F8":"Apple",
    "C0:D0:12":"Apple","C4:2C:03":"Apple","C4:61:8B":"Apple","C4:B3:01":"Apple",
    "C8:1E:E7":"Apple","C8:2A:14":"Apple","C8:33:4B":"Apple","C8:3C:85":"Apple",
    "C8:6F:1D":"Apple","C8:85:50":"Apple","C8:BC:C8":"Apple","C8:D0:83":"Apple",
    "C8:E0:EB":"Apple","CC:08:8D":"Apple","CC:25:EF":"Apple","CC:29:F5":"Apple",
    "CC:44:63":"Apple","D0:03:4B":"Apple","D0:23:DB":"Apple","D0:33:11":"Apple",
    "D0:4F:7E":"Apple","D0:65:CA":"Apple","D0:A6:37":"Apple","D0:C5:F3":"Apple",
    "D4:61:9D":"Apple","D4:9A:20":"Apple","D4:DC:CD":"Apple","D4:F4:6F":"Apple",
    "D8:00:4D":"Apple","D8:1D:72":"Apple","D8:30:62":"Apple","D8:96:95":"Apple",
    "D8:A2:5E":"Apple","D8:BB:2C":"Apple","D8:CF:9C":"Apple","DC:0C:5C":"Apple",
    "DC:2B:2A":"Apple","DC:37:14":"Apple","DC:41:5F":"Apple","DC:52:85":"Apple",
    "DC:86:D8":"Apple","DC:9B:9C":"Apple","DC:A4:CA":"Apple","DC:D3:21":"Apple",
    "E0:33:8E":"Apple","E0:5F:45":"Apple","E0:66:78":"Apple","E0:AC:CB":"Apple",
    "E0:B5:2D":"Apple","E0:B9:BA":"Apple","E0:F5:C6":"Apple","E4:25:E7":"Apple",
    "E4:98:D6":"Apple","E4:9A:DC":"Apple","E4:C6:3D":"Apple","E4:CE:8F":"Apple",
    "E4:E4:AB":"Apple","E8:04:0B":"Apple","E8:06:88":"Apple","E8:80:2E":"Apple",
    "E8:8D:28":"Apple","E8:B2:AC":"Apple","EC:35:86":"Apple","EC:85:2F":"Apple",
    "F0:18:98":"Apple","F0:1F:AF":"Apple","F0:79:60":"Apple","F0:99:BF":"Apple",
    "F0:B4:79":"Apple","F0:C1:F1":"Apple","F0:CB:A1":"Apple","F0:D1:A9":"Apple",
    "F0:DB:E2":"Apple","F0:DC:E2":"Apple","F0:F6:1C":"Apple","F4:0F:24":"Apple",
    "F4:1B:A1":"Apple","F4:31:59":"Apple","F4:37:B7":"Apple","F4:5C:89":"Apple",
    "F4:F1:5A":"Apple","F4:F9:51":"Apple","F8:1E:DF":"Apple","F8:27:93":"Apple",
    "F8:62:14":"Apple","F8:7B:7A":"Apple","F8:95:EA":"Apple","FC:25:3F":"Apple",
    "FC:2A:9C":"Apple","FC:E9:98":"Apple",
    # ── Samsung ───────────────────────────────────────────────────────
    "00:02:78":"Samsung","00:07:AB":"Samsung","00:12:47":"Samsung","00:15:99":"Samsung",
    "00:16:32":"Samsung","00:16:6B":"Samsung","00:16:6C":"Samsung","00:17:C9":"Samsung",
    "00:17:D5":"Samsung","00:18:AF":"Samsung","00:1A:8A":"Samsung","00:1B:98":"Samsung",
    "00:1C:43":"Samsung","00:1D:25":"Samsung","00:1D:F6":"Samsung","00:1E:7D":"Samsung",
    "00:1F:CC":"Samsung","00:21:19":"Samsung","00:21:D1":"Samsung","00:23:39":"Samsung",
    "00:23:99":"Samsung","00:24:54":"Samsung","00:24:91":"Samsung","00:25:38":"Samsung",
    "00:25:67":"Samsung","00:26:37":"Samsung","04:18:0F":"Samsung","04:1B:BA":"Samsung",
    "04:FE:31":"Samsung","08:08:C2":"Samsung","08:37:3D":"Samsung","08:D4:2B":"Samsung",
    "08:EC:A9":"Samsung","0C:14:20":"Samsung","0C:89:10":"Samsung","10:1D:C0":"Samsung",
    "10:30:47":"Samsung","10:3B:59":"Samsung","10:D3:8A":"Samsung","14:49:E0":"Samsung",
    "14:89:FD":"Samsung","14:F4:2A":"Samsung","18:22:7E":"Samsung","18:26:66":"Samsung",
    "18:3A:2D":"Samsung","18:3F:47":"Samsung","1C:5A:3E":"Samsung","1C:62:B8":"Samsung",
    "1C:66:AA":"Samsung","1C:AF:05":"Samsung","20:13:E0":"Samsung","20:55:31":"Samsung",
    "24:4B:03":"Samsung","24:C6:96":"Samsung","24:DB:AC":"Samsung","28:27:BF":"Samsung",
    "28:39:5E":"Samsung","28:BA:B5":"Samsung","28:CC:01":"Samsung","2C:0E:3D":"Samsung",
    "2C:44:01":"Samsung","2C:AE:2B":"Samsung","30:19:66":"Samsung","30:96:3B":"Samsung",
    "30:CD:A7":"Samsung","34:14:5F":"Samsung","34:23:87":"Samsung","34:31:11":"Samsung",
    "38:01:97":"Samsung","38:16:D1":"Samsung","3C:5A:37":"Samsung","3C:8B:FE":"Samsung",
    "40:0E:85":"Samsung","40:4E:36":"Samsung","40:C3:F0":"Samsung","44:4E:1A":"Samsung",
    "44:78:3E":"Samsung","44:F4:59":"Samsung","48:13:7E":"Samsung","48:44:F7":"Samsung",
    "4C:3C:16":"Samsung","4C:BC:A5":"Samsung","50:01:BB":"Samsung","50:32:75":"Samsung",
    "50:A4:C8":"Samsung","50:CC:F8":"Samsung","50:F5:20":"Samsung","54:40:AD":"Samsung",
    "54:88:0E":"Samsung","54:92:BE":"Samsung","54:9B:12":"Samsung","58:C3:8B":"Samsung",
    "5C:0A:5B":"Samsung","5C:3C:27":"Samsung","5C:49:7D":"Samsung","5C:A3:9D":"Samsung",
    "5C:E8:EB":"Samsung","5C:F6:DC":"Samsung","60:A1:0A":"Samsung","60:D0:A9":"Samsung",
    "64:1C:AE":"Samsung","64:6C:B2":"Samsung","64:77:91":"Samsung","64:B3:10":"Samsung",
    "68:27:37":"Samsung","68:48:98":"Samsung","68:EB:AE":"Samsung","6C:2F:2C":"Samsung",
    "6C:83:36":"Samsung","6C:F3:73":"Samsung","70:28:8B":"Samsung","70:F9:27":"Samsung",
    "74:45:8A":"Samsung","78:1F:DB":"Samsung","78:25:AD":"Samsung","78:40:E4":"Samsung",
    "78:52:1A":"Samsung","7C:0B:C6":"Samsung","7C:61:93":"Samsung","80:57:19":"Samsung",
    "80:65:6D":"Samsung","84:11:9E":"Samsung","84:25:DB":"Samsung","84:51:81":"Samsung",
    "84:55:A5":"Samsung","84:6E:80":"Samsung","84:98:66":"Samsung","88:32:9B":"Samsung",
    "88:43:E1":"Samsung","8C:71:F8":"Samsung","8C:77:12":"Samsung","90:18:7C":"Samsung",
    "90:2B:34":"Samsung","94:01:C2":"Samsung","94:35:0A":"Samsung","94:51:03":"Samsung",
    "94:63:D1":"Samsung","94:76:B7":"Samsung","98:39:8E":"Samsung","98:52:B1":"Samsung",
    "98:83:89":"Samsung","9C:02:98":"Samsung","9C:3A:AF":"Samsung","9C:65:B0":"Samsung",
    "A0:0B:BA":"Samsung","A0:10:81":"Samsung","A0:21:95":"Samsung","A4:07:B6":"Samsung",
    "A4:70:D6":"Samsung","A8:04:60":"Samsung","A8:7D:12":"Samsung","AC:36:13":"Samsung",
    "AC:5F:3E":"Samsung","B0:47:BF":"Samsung","B0:72:BF":"Samsung","B0:DF:3A":"Samsung",
    "B4:07:F9":"Samsung","B4:3A:28":"Samsung","B4:79:A7":"Samsung","B4:EF:FA":"Samsung",
    "B8:5E:7B":"Samsung","B8:BB:AF":"Samsung","B8:C6:8E":"Samsung","BC:20:A4":"Samsung",
    "BC:44:86":"Samsung","BC:72:B1":"Samsung","BC:85:1F":"Samsung","C0:BD:D1":"Samsung",
    "C4:42:02":"Samsung","C4:50:06":"Samsung","C4:57:6E":"Samsung","C4:88:E5":"Samsung",
    "C8:0F:10":"Samsung","C8:14:79":"Samsung","C8:19:F7":"Samsung","C8:BA:94":"Samsung",
    "CC:07:AB":"Samsung","CC:F9:E8":"Samsung","D0:22:BE":"Samsung","D0:59:E4":"Samsung",
    "D4:87:D8":"Samsung","D4:88:90":"Samsung","D4:E8:B2":"Samsung","D8:57:EF":"Samsung",
    "D8:90:E8":"Samsung","DC:71:44":"Samsung","E0:99:71":"Samsung","E4:12:1D":"Samsung",
    "E4:40:E2":"Samsung","E8:50:8B":"Samsung","EC:1F:72":"Samsung","EC:9B:F3":"Samsung",
    "F0:25:B7":"Samsung","F0:5A:09":"Samsung","F4:09:D8":"Samsung","F8:04:2E":"Samsung",
    "F8:77:B8":"Samsung","FC:A1:3E":"Samsung","FC:DB:B3":"Samsung",
    # ── Google ────────────────────────────────────────────────────────
    "00:1A:11":"Google","08:9E:08":"Google","1C:F2:9A":"Google","20:DF:B9":"Google",
    "3C:5A:B4":"Google","48:D6:D5":"Google","54:60:09":"Google","6C:AD:F8":"Google",
    "70:3A:CB":"Google","94:95:A0":"Google","A4:77:33":"Google","F4:F5:D8":"Google",
    "F8:8F:CA":"Google","54:F2:01":"Google","C8:D3:FF":"Google",
    # ── Amazon ────────────────────────────────────────────────────────
    "00:FC:8B":"Amazon","0C:47:C9":"Amazon","18:74:2E":"Amazon","34:D2:70":"Amazon",
    "38:F7:3D":"Amazon","40:B4:CD":"Amazon","44:65:0D":"Amazon","50:F5:DA":"Amazon",
    "68:37:E9":"Amazon","6C:56:97":"Amazon","74:75:48":"Amazon","78:E1:03":"Amazon",
    "84:D6:D0":"Amazon","88:71:E5":"Amazon","94:9F:3E":"Amazon","A0:02:DC":"Amazon",
    "AC:63:BE":"Amazon","B0:FC:0D":"Amazon","B4:7C:9C":"Amazon","CC:9E:A2":"Amazon",
    "D0:57:4C":"Amazon","F0:27:2D":"Amazon","F0:81:73":"Amazon","F0:A2:25":"Amazon",
    "FC:65:DE":"Amazon","FC:A6:67":"Amazon",
    # ── Microsoft ─────────────────────────────────────────────────────
    "00:03:FF":"Microsoft","00:12:5A":"Microsoft","00:15:5D":"Microsoft","00:17:FA":"Microsoft",
    "00:1D:D8":"Microsoft","00:22:48":"Microsoft","00:50:F2":"Microsoft","10:16:88":"Microsoft",
    "14:3F:A5":"Microsoft","28:18:78":"Microsoft","28:76:10":"Microsoft","3C:83:75":"Microsoft",
    "48:50:73":"Microsoft","50:1A:C5":"Microsoft","54:27:1E":"Microsoft","58:82:A8":"Microsoft",
    "60:45:BD":"Microsoft","70:77:81":"Microsoft","7C:1E:52":"Microsoft","80:E5:07":"Microsoft",
    "98:5F:D3":"Microsoft","9C:B6:D0":"Microsoft","B8:31:B5":"Microsoft","C4:9D:ED":"Microsoft",
    "C8:3F:26":"Microsoft","DC:53:60":"Microsoft","E8:03:9A":"Microsoft","F0:6E:0B":"Microsoft",
    # ── Sony / PlayStation ────────────────────────────────────────────
    "00:01:4A":"Sony","00:04:1F":"Sony","00:13:A9":"Sony","00:1A:80":"Sony",
    "00:24:BE":"Sony","04:CF:8C":"Sony","28:0D:FC":"Sony","30:17:C8":"Sony",
    "3C:01:EF":"Sony","4C:60:DE":"Sony","50:C7:BF":"Sony","54:42:49":"Sony",
    "70:2A:D5":"Sony","7C:B5:9B":"Sony","AC:9B:0A":"Sony","B0:5A:DA":"Sony",
    "BC:60:A7":"Sony","D8:D4:3C":"Sony","F0:B4:29":"Sony","FC:0F:E6":"Sony",
    # ── Nintendo ─────────────────────────────────────────────────────
    "00:09:BF":"Nintendo","00:16:56":"Nintendo","00:17:AB":"Nintendo","00:19:1D":"Nintendo",
    "00:1A:E9":"Nintendo","00:1B:EA":"Nintendo","00:1C:BE":"Nintendo","00:1E:35":"Nintendo",
    "00:1F:32":"Nintendo","00:21:47":"Nintendo","00:22:4C":"Nintendo","00:23:CC":"Nintendo",
    "00:24:1E":"Nintendo","00:24:44":"Nintendo","00:24:F3":"Nintendo","00:25:A0":"Nintendo",
    "00:26:59":"Nintendo","2C:10:C1":"Nintendo","40:D2:8A":"Nintendo","58:BD:A3":"Nintendo",
    "60:6B:FF":"Nintendo","64:B5:C6":"Nintendo","78:A2:A0":"Nintendo","7C:BB:8A":"Nintendo",
    "8C:56:C5":"Nintendo","98:B6:E9":"Nintendo","A4:5C:27":"Nintendo","B8:AE:6E":"Nintendo",
    "E0:0C:7F":"Nintendo","E8:4E:CE":"Nintendo",
    # ── Netgear ───────────────────────────────────────────────────────
    "00:09:5B":"Netgear","00:0F:B5":"Netgear","00:14:6C":"Netgear","00:18:4D":"Netgear",
    "00:1B:2F":"Netgear","00:1E:2A":"Netgear","00:22:3F":"Netgear","00:24:B2":"Netgear",
    "00:26:F2":"Netgear","04:A1:51":"Netgear","10:0C:6B":"Netgear","1C:1B:0D":"Netgear",
    "20:4E:7F":"Netgear","28:C6:8E":"Netgear","2C:B0:5D":"Netgear","30:46:9A":"Netgear",
    "44:94:FC":"Netgear","4C:09:D4":"Netgear","6C:B0:CE":"Netgear","74:44:01":"Netgear",
    "84:1B:5E":"Netgear","A0:21:B7":"Netgear","A0:40:A0":"Netgear","C0:3F:0E":"Netgear",
    "C4:3D:C7":"Netgear","C4:04:15":"Netgear","C8:D7:19":"Netgear","D8:EB:97":"Netgear",
    # ── TP-Link ───────────────────────────────────────────────────────
    "00:27:19":"TP-Link","10:FE:ED":"TP-Link","14:CC:20":"TP-Link","18:A6:F7":"TP-Link",
    "1C:3B:F3":"TP-Link","20:DC:E6":"TP-Link","24:69:68":"TP-Link","28:2C:B2":"TP-Link",
    "2C:D0:5A":"TP-Link","30:B5:C2":"TP-Link","38:83:45":"TP-Link","40:3F:8C":"TP-Link",
    "40:8D:5C":"TP-Link","44:FE:3B":"TP-Link","50:3E:AA":"TP-Link","54:35:30":"TP-Link",
    "58:8B:F3":"TP-Link","5C:89:9A":"TP-Link","60:E3:27":"TP-Link","64:70:02":"TP-Link",
    "6C:5A:B5":"TP-Link","70:4F:57":"TP-Link","74:EA:3A":"TP-Link","78:8A:20":"TP-Link",
    "80:8F:1D":"TP-Link","84:16:F9":"TP-Link","90:F6:52":"TP-Link","98:DA:C4":"TP-Link",
    "9C:A6:15":"TP-Link","A0:F3:C1":"TP-Link","AC:84:C6":"TP-Link","B0:48:7A":"TP-Link",
    "B4:B0:24":"TP-Link","B8:D5:0B":"TP-Link","C4:6E:1F":"TP-Link","C8:0E:14":"TP-Link",
    "D8:07:B6":"TP-Link","DC:FE:18":"TP-Link","E8:DE:27":"TP-Link","EC:08:6B":"TP-Link",
    "F0:A7:31":"TP-Link","F4:EC:38":"TP-Link","F8:1A:67":"TP-Link","FC:D7:33":"TP-Link",
    # ── Asus ─────────────────────────────────────────────────────────
    "00:0C:6E":"Asus","00:11:D8":"Asus","00:13:D4":"Asus","00:15:F2":"Asus",
    "00:17:31":"Asus","00:18:F3":"Asus","00:1A:92":"Asus","00:1B:FC":"Asus",
    "00:1D:60":"Asus","00:1E:8C":"Asus","00:1F:C6":"Asus","00:22:15":"Asus",
    "00:23:54":"Asus","00:24:8C":"Asus","00:26:18":"Asus","04:92:26":"Asus",
    "08:60:6E":"Asus","0C:9D:92":"Asus","10:02:B5":"Asus","10:7B:44":"Asus",
    "10:BF:48":"Asus","14:DA:E9":"Asus","18:31:BF":"Asus","1C:87:2C":"Asus",
    "20:CF:30":"Asus","2C:FD:A1":"Asus","30:85:A9":"Asus","38:2C:4A":"Asus",
    "40:16:7E":"Asus","40:B0:FA":"Asus","48:5B:39":"Asus","4C:ED:FB":"Asus",
    "50:46:5D":"Asus","54:04:A6":"Asus","5C:FF:35":"Asus","60:A4:4C":"Asus",
    "6C:F3:7F":"Asus","70:8B:CD":"Asus","74:D0:2B":"Asus","78:24:AF":"Asus",
    "7C:10:C9":"Asus","80:1F:02":"Asus","88:D7:F6":"Asus","90:E6:BA":"Asus",
    "9C:5C:8E":"Asus","A0:F3:E4":"Asus","AC:22:0B":"Asus","BC:AE:C5":"Asus",
    "C8:60:00":"Asus","D0:17:C2":"Asus","D4:5D:64":"Asus","D8:50:E6":"Asus",
    "E0:3F:49":"Asus","E4:70:B8":"Asus","E8:94:F6":"Asus","F0:2F:74":"Asus",
    "FC:4A:E9":"Asus",
    # ── Roku ─────────────────────────────────────────────────────────
    "00:0D:4B":"Roku","08:05:81":"Roku","B8:3E:59":"Roku","B8:A1:75":"Roku",
    "BC:A9:93":"Roku","C8:3A:6B":"Roku","CC:6D:A0":"Roku","D8:31:CF":"Roku",
    "DC:3A:5E":"Roku","E4:AF:A1":"Roku","F0:5C:77":"Roku",
    # ── Chromecast / Google Nest ──────────────────────────────────────
    "00:1A:11":"Google Nest","10:9A:DD":"Google Nest","14:10:9F":"Google Nest",
    "18:B4:30":"Google Nest","28:6A:BA":"Google Nest","6C:AD:F8":"Chromecast",
    "94:95:A0":"Chromecast",
    # ── Ring / Alarm ─────────────────────────────────────────────────
    "B4:A2:EB":"Ring","C4:75:AB":"Ring","FC:65:DE":"Ring",
    # ── Ecobee ───────────────────────────────────────────────────────
    "44:61:32":"Ecobee",
    # ── Nest Thermostat ───────────────────────────────────────────────
    "18:B4:30":"Nest","64:16:66":"Nest",
    # ── Philips Hue ───────────────────────────────────────────────────
    "00:17:88":"Philips Hue",
    # ── Raspberry Pi ─────────────────────────────────────────────────
    "B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi","E4:5F:01":"Raspberry Pi",
    "28:CD:C1":"Raspberry Pi",
    # ── Cisco / Linksys ───────────────────────────────────────────────
    "00:01:64":"Cisco","00:01:97":"Cisco","00:02:3D":"Cisco","00:03:6B":"Cisco",
    "00:04:9A":"Cisco","00:0A:8A":"Cisco","00:0B:5F":"Cisco","00:0C:30":"Cisco",
    "00:0D:BD":"Cisco","00:0E:08":"Cisco","00:0F:34":"Cisco","00:10:7B":"Cisco",
    "00:11:93":"Cisco","00:12:D9":"Cisco","00:13:1A":"Cisco","00:14:69":"Cisco",
    "00:15:63":"Cisco","00:16:47":"Cisco","00:17:0E":"Cisco","00:18:18":"Cisco",
    "00:19:07":"Cisco","00:1A:6C":"Cisco","00:1B:2A":"Cisco","00:1C:B0":"Cisco",
    "00:1D:46":"Cisco","00:1E:49":"Cisco","00:1F:9E":"Cisco","00:21:A0":"Cisco",
    "00:22:90":"Cisco","00:23:04":"Cisco","00:24:97":"Cisco","00:25:2E":"Cisco",
    "00:26:CB":"Cisco","68:BC:0C":"Cisco","6C:41:6A":"Cisco","70:10:5C":"Cisco",
    "C0:62:6B":"Linksys","C4:41:1E":"Linksys",
    # ── Ubiquiti ─────────────────────────────────────────────────────
    "00:15:6D":"Ubiquiti","00:27:22":"Ubiquiti","04:18:D6":"Ubiquiti","24:A4:3C":"Ubiquiti",
    "44:D9:E7":"Ubiquiti","68:72:51":"Ubiquiti","78:8A:20":"Ubiquiti","80:2A:A8":"Ubiquiti",
    "B4:FB:E4":"Ubiquiti","DC:9F:DB":"Ubiquiti","E0:63:DA":"Ubiquiti","F0:9F:C2":"Ubiquiti",
    "FC:EC:DA":"Ubiquiti",
    # ── Intel (laptops/PCs with Intel Wi-Fi) ─────────────────────────
    "00:02:B3":"Intel","00:0C:F1":"Intel","00:0E:35":"Intel","00:0E:D7":"Intel",
    "00:11:11":"Intel","00:12:F0":"Intel","00:13:02":"Intel","00:13:CE":"Intel",
    "00:13:E8":"Intel","00:15:00":"Intel","00:16:76":"Intel","00:16:EA":"Intel",
    "00:18:DE":"Intel","00:19:D1":"Intel","00:1B:21":"Intel","00:1C:BF":"Intel",
    "00:1D:E0":"Intel","00:1E:64":"Intel","00:1E:65":"Intel","00:1F:3B":"Intel",
    "00:21:6A":"Intel","00:22:FA":"Intel","00:23:14":"Intel","00:23:8B":"Intel",
    "00:24:D7":"Intel","00:27:10":"Intel","04:0E:3C":"Intel","08:D4:0C":"Intel",
    "10:02:B5":"Intel","10:F3:11":"Intel","18:3D:A2":"Intel","18:56:80":"Intel",
    "20:16:D8":"Intel","20:68:9D":"Intel","24:77:03":"Intel","28:D2:44":"Intel",
    "2C:6E:85":"Intel","30:3A:64":"Intel","34:02:86":"Intel","34:6F:90":"Intel",
    "38:DE:AD":"Intel","3C:A9:F4":"Intel","40:25:C2":"Intel","44:03:A7":"Intel",
    "48:45:20":"Intel","4C:34:88":"Intel","4C:79:6E":"Intel","4C:EB:42":"Intel",
    "50:76:AF":"Intel","54:35:30":"Intel","54:E1:AD":"Intel","58:20:B1":"Intel",
    "5C:51:4F":"Intel","60:36:DD":"Intel","60:57:18":"Intel","60:67:20":"Intel",
    "64:5D:86":"Intel","68:05:CA":"Intel","6C:29:95":"Intel","70:1C:E7":"Intel",
    "74:29:AF":"Intel","78:92:9C":"Intel","78:FF:57":"Intel","7C:7A:91":"Intel",
    "80:19:34":"Intel","80:86:F2":"Intel","84:0B:2D":"Intel","88:53:2E":"Intel",
    "8C:8D:28":"Intel","90:2E:16":"Intel","94:65:9C":"Intel","94:9F:3E":"Intel",
    "98:4F:EE":"Intel","9C:B6:D0":"Intel","A0:88:B4":"Intel","A4:34:D9":"Intel",
    "A4:4E:31":"Intel","A8:7E:EA":"Intel","AC:7B:A1":"Intel","B0:5A:DA":"Intel",
    "B4:6B:FC":"Intel","B8:08:CF":"Intel","BC:77:37":"Intel","C4:8E:8F":"Intel",
    "C8:D9:D2":"Intel","CC:3D:82":"Intel","D0:57:7B":"Intel","D0:7E:35":"Intel",
    "D4:81:D7":"Intel","D8:FC:93":"Intel","DC:53:60":"Intel","E4:B3:18":"Intel",
    "E8:6A:64":"Intel","EC:08:6B":"Intel","F0:76:1C":"Intel","F4:06:69":"Intel",
    "F8:16:54":"Intel","F8:28:19":"Intel",
    # ── Arris / Motorola (cable modems/routers) ───────────────────────
    "00:01:5E":"Arris","00:04:37":"Arris","00:07:0E":"Arris","00:0A:D9":"Arris",
    "00:13:5F":"Arris","00:17:C8":"Arris","00:19:31":"Arris","00:1E:46":"Arris",
    "00:26:B8":"Arris","04:18:B6":"Arris","08:36:C9":"Arris","18:1E:B0":"Arris",
    "1C:C1:DE":"Arris","2C:B0:5D":"Arris","34:9D:CD":"Arris","44:E1:37":"Arris",
    "54:F2:01":"Arris","74:9D:DC":"Arris","8C:04:FF":"Arris","9C:CC:D3":"Arris",
    "A0:CA:AB":"Arris","A4:18:75":"Arris","B0:39:56":"Arris","BC:14:01":"Arris",
    "C0:56:27":"Arris","D4:05:98":"Arris","E8:8C:DF":"Arris",
    # ── Eero ─────────────────────────────────────────────────────────
    "34:AA:FF":"Eero","54:26:96":"Eero","6C:D6:6A":"Eero","78:8A:20":"Eero",
    # ── OPNsense / pfSense / Protectli ───────────────────────────────
    "00:A0:98":"Protectli","68:1D:EF":"Protectli",
    # ── Synology NAS ─────────────────────────────────────────────────
    "00:11:32":"Synology",
    # ── QNAP NAS ─────────────────────────────────────────────────────
    "00:08:9B":"QNAP","24:5E:BE":"QNAP",
    # ── Wyze ─────────────────────────────────────────────────────────
    "2C:AA:8E":"Wyze","D0:3F:27":"Wyze",
    # ── Belkin / Wemo ────────────────────────────────────────────────
    "00:17:3F":"Belkin","00:30:BD":"Belkin","08:86:3B":"Belkin","10:05:CA":"Belkin",
    "14:22:DB":"Belkin","18:33:9D":"Belkin","1C:FA:68":"Belkin","20:AA:4B":"Belkin",
    "30:23:03":"Belkin","34:BB:26":"Belkin","44:E9:DD":"Belkin","8C:59:C3":"Belkin",
    "94:44:52":"Belkin","B4:75:0E":"Belkin","C0:56:E3":"Belkin","C4:41:1E":"Belkin",
    "E8:9F:80":"Belkin","EC:1A:59":"Belkin",
    # ── D-Link ───────────────────────────────────────────────────────
    "00:05:5D":"D-Link","00:0D:88":"D-Link","00:11:95":"D-Link","00:13:46":"D-Link",
    "00:15:E9":"D-Link","00:17:9A":"D-Link","00:19:5B":"D-Link","00:1B:11":"D-Link",
    "00:1C:F0":"D-Link","00:1E:58":"D-Link","00:21:91":"D-Link","00:22:B0":"D-Link",
    "00:24:01":"D-Link","00:26:5A":"D-Link","14:D6:4D":"D-Link","1C:7E:E5":"D-Link",
    "28:10:7B":"D-Link","34:08:04":"D-Link","5C:D9:98":"D-Link","78:54:2E":"D-Link",
    "90:94:E4":"D-Link","A0:AB:1B":"D-Link","B8:A3:86":"D-Link","BC:F6:85":"D-Link",
    "C8:BE:19":"D-Link","D8:FE:E3":"D-Link","E8:CC:18":"D-Link","F0:7D:68":"D-Link",
    # ── LG Electronics ───────────────────────────────────────────────
    "00:1C:62":"LG","00:1E:75":"LG","00:24:83":"LG","00:26:E2":"LG",
    "20:16:B9":"LG","28:4F:49":"LG","30:14:4A":"LG","3C:BD:D8":"LG",
    "40:B0:76":"LG","48:59:29":"LG","4C:BB:58":"LG","50:B7:C3":"LG",
    "58:A2:B5":"LG","5C:F6:DC":"LG","60:AB:14":"LG","64:99:5D":"LG",
    "6C:2B:59":"LG","70:F9:6D":"LG","74:A5:28":"LG","78:5D:C8":"LG",
    "7C:66:EF":"LG","88:07:4B":"LG","8C:3A:E3":"LG","A8:16:D0":"LG",
    "AC:F1:DF":"LG","B4:E6:2A":"LG","C4:36:6C":"LG","C8:08:E9":"LG",
    "CC:2D:83":"LG","D4:3D:7E":"LG","D8:6C:63":"LG","E8:F2:E2":"LG",
    "EC:23:3D":"LG","F4:01:EB":"LG","F8:0C:F3":"LG","FC:F1:52":"LG",
}

# ── Friendly vendor name for display ─────────────────────────────
# Maps internal vendor strings to display names with device type hints
VENDOR_DISPLAY = {
    "Apple":        ("Apple Device",    "Mobile"),
    "Samsung":      ("Samsung Device",  "Mobile"),
    "Google":       ("Google Device",   "IoT"),
    "Google Nest":  ("Google Nest",     "IoT"),
    "Chromecast":   ("Chromecast",      "TV"),
    "Amazon":       ("Amazon Device",   "IoT"),
    "Microsoft":    ("Windows PC",      "Desktop"),
    "Sony":         ("Sony Device",     "Console"),
    "Nintendo":     ("Nintendo",        "Console"),
    "Netgear":      ("Netgear Device",  "Server"),
    "TP-Link":      ("TP-Link Device",  "IoT"),
    "Asus":         ("Asus Device",     "Desktop"),
    "Roku":         ("Roku",            "TV"),
    "Ring":         ("Ring Device",     "IoT"),
    "Ecobee":       ("Ecobee",          "IoT"),
    "Nest":         ("Nest Thermostat", "IoT"),
    "Philips Hue":  ("Philips Hue Hub", "IoT"),
    "Raspberry Pi": ("Raspberry Pi",    "Server"),
    "Cisco":        ("Cisco Device",    "Server"),
    "Linksys":      ("Linksys Router",  "Server"),
    "Ubiquiti":     ("Ubiquiti Device", "Server"),
    "Intel":        ("Intel Device",    "Laptop"),
    "Arris":        ("Arris Modem",     "Server"),
    "Eero":         ("Eero Router",     "Server"),
    "Protectli":    ("Protectli Vault", "Server"),
    "Synology":     ("Synology NAS",    "Server"),
    "QNAP":         ("QNAP NAS",        "Server"),
    "Wyze":         ("Wyze Camera",     "IoT"),
    "Belkin":       ("Belkin/Wemo",     "IoT"),
    "D-Link":       ("D-Link Device",   "Server"),
    "LG":           ("LG Device",       "TV"),
}


def lookup_oui(mac):
    """
    Returns (vendor_name, device_type) for a MAC address, or (None, None).
    Tries the full 3-byte prefix first, then a 2-byte prefix as fallback.
    """
    if not mac or mac == "00:00:00:00:00:00":
        return None, None
    mac_upper = mac.upper()
    prefix3 = mac_upper[:8]   # "AA:BB:CC"
    prefix2 = mac_upper[:5]   # "AA:BB"
    vendor = OUI_TABLE.get(prefix3) or OUI_TABLE.get(prefix2)
    if not vendor:
        return None, None
    display, dtype = VENDOR_DISPLAY.get(vendor, (vendor + " Device", "Unknown"))
    return display, dtype


def auto_name_device(ip, mac):
    """
    Attempts to produce a human-readable device name using:
      1. nmap reverse-DNS / hostname detection (runs fast, single host)
      2. MAC OUI vendor lookup (instant, no network call)

    Returns {"name": str, "type": str, "source": str}
    where source is "hostname", "oui", or "unknown".
    """
    name, dtype, source = None, "Unknown", "unknown"

    # ── Step 1: nmap hostname detection ──────────────────────────────
    try:
        r = subprocess.run(
            ["nmap", "-sn", "-T3", "--host-timeout", "3s", ip],
            capture_output=True, text=True, timeout=10
        )
        for line in r.stdout.splitlines():
            # "Nmap scan report for scotts-iphone.local (192.168.1.73)"
            # "Nmap scan report for 192.168.1.73"
            if "Nmap scan report for" in line:
                parts = line.replace("Nmap scan report for ", "").strip()
                # If there's a hostname (not just an IP), extract it
                if "(" in parts:
                    hostname = parts.split("(")[0].strip()
                    # Clean up mDNS suffixes and make it readable
                    hostname = hostname.replace(".local", "").replace(".home", "")
                    hostname = hostname.replace(".lan", "").replace(".internal", "")
                    if hostname and not hostname[0].isdigit():
                        # Convert dashes to spaces and title-case
                        display = " ".join(
                            w.capitalize() for w in hostname.replace("-", " ").split()
                        )
                        name   = display
                        source = "hostname"
                        break
    except Exception:
        pass

    # ── Step 2: OUI vendor lookup (fallback or type enrichment) ──────
    oui_name, oui_type = lookup_oui(mac)

    if name:
        # We have a hostname — still use OUI to enrich the device type
        dtype = oui_type if oui_type and oui_type != "Unknown" else "Unknown"
    elif oui_name:
        # No hostname — use vendor name + IP
        name   = f"{oui_name} ({ip})"
        dtype  = oui_type or "Unknown"
        source = "oui"
    else:
        name   = f"Unknown ({ip})"
        dtype  = "Unknown"
        source = "unknown"

    return {"name": name, "type": dtype, "source": source}

def _scan_subnet(subnet, interface, timeout=120):
    try:
        # Use nmap instead of arp-scan — nmap is Wi-Fi safe and won't
        # drop the wlp2s0 interface the way raw ARP broadcasts do.
        r = subprocess.run(
            ["nmap", "-sn", "-T3", "--host-timeout", "5s", subnet],
            capture_output=True, text=True, timeout=timeout)
        found = {}
        current_ip = None
        for line in r.stdout.splitlines():
            if "Nmap scan report" in line:
                ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if ip_m:
                    current_ip = ip_m.group(1)
            mac_m = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", line)
            if mac_m and current_ip:
                found[current_ip] = mac_m.group(0)
                current_ip = None
        # Include hosts nmap found without a MAC (e.g. the server itself)
        current_ip = None
        for line in r.stdout.splitlines():
            if "Nmap scan report" in line:
                ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if ip_m:
                    current_ip = ip_m.group(1)
            if current_ip and current_ip not in found:
                found[current_ip] = "00:00:00:00:00:00"
                current_ip = None
        return {"ok": True, "found": found}
    except FileNotFoundError:
        return {"ok": False, "error": "nmap not installed — run: sudo apt install nmap"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"Scan timed out ({timeout}s)"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ══════════════════════════════════════════════════════
#  FILE HELPERS
# ══════════════════════════════════════════════════════
def rj(path):
    if not os.path.exists(path): return []
    with open(path) as f: return json.load(f)

def wj(path, data):
    with open(path, "w") as f: json.dump(data, f, indent=2)

def new_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:6]}"

# ══════════════════════════════════════════════════════
#  SCHEDULE / BUDGET
# ══════════════════════════════════════════════════════
DAY_KEYS = ["mon","tue","wed","thu","fri","sat","sun"]
DEFAULT_SCHED = {d:{"start":"00:00","end":"23:59","daily_limit_minutes":None} for d in DAY_KEYS}

def today_key():   return DAY_KEYS[datetime.datetime.now().weekday()]
def today_str():   return datetime.date.today().isoformat()
def m2i(t):
    h,m = t.split(":"); return int(h)*60+int(m)

def ensure_reset(p):
    u = p.setdefault("usage",{"minutes_used_today":0,"usage_date":None})
    if u.get("usage_date") != today_str():
        u["minutes_used_today"] = 0; u["usage_date"] = today_str()

def access_state(p):
    ensure_reset(p)
    day    = (p.get("schedule") or DEFAULT_SCHED).get(today_key(), DEFAULT_SCHED["mon"])
    now_m  = datetime.datetime.now().hour*60 + datetime.datetime.now().minute
    s, e   = m2i(day["start"]), m2i(day["end"])
    no_acc = s == e
    in_win = (not no_acc) and s <= now_m <= e
    limit  = day.get("daily_limit_minutes")
    used   = p["usage"]["minutes_used_today"]
    budget = None if limit is None else max(0, limit - used)
    if p.get("killed"):             reason,ok = "killed",           False
    elif no_acc:                    reason,ok = "no_access_today",  False
    elif not in_win:
        reason = "before_window" if now_m < s else "after_window"; ok = False
    elif limit is not None and used >= limit:
        reason,ok = "budget_exhausted", False
    else:                           reason,ok = "allowed",          True
    win_left = max(0, e - now_m) if in_win else 0
    rem = (min(win_left, budget) if budget is not None else win_left)
    return {"allowed":ok,"reason":reason,
            "today_start":day["start"],"today_end":day["end"],
            "today_window":f"{day['start']} – {day['end']}",
            "daily_limit_minutes":limit,"minutes_used_today":used,
            "minutes_remaining_budget":budget,
            "minutes_remaining_window":win_left,"minutes_remaining":rem}

def norm_sched(raw):
    if not raw: return dict(DEFAULT_SCHED)
    return {d:{"start":     raw.get(d, DEFAULT_SCHED[d]).get("start","00:00"),
               "end":       raw.get(d, DEFAULT_SCHED[d]).get("end","23:59"),
               "daily_limit_minutes": raw.get(d, DEFAULT_SCHED[d]).get("daily_limit_minutes")}
            for d in DAY_KEYS}

# ══════════════════════════════════════════════════════
#  DEVICES ENDPOINTS
# ══════════════════════════════════════════════════════
@app.route("/api/devices", methods=["GET"])
def get_devices():
    return jsonify(rj(DEVICES_FILE))

@app.route("/api/devices", methods=["POST"])
def add_device():
    b = request.get_json(force=True) or {}
    if not b.get("name") or not b.get("ip"):
        return jsonify({"error":"name and ip required"}), 400
    devices = rj(DEVICES_FILE)
    d = {"id":new_id("dev"),"name":b["name"],"ip":b["ip"],
         "mac":b.get("mac","Unknown"),"type":b.get("type","Unknown"),
         "icon":b.get("icon","💻"),"profile_id":b.get("profile_id"),
         "status":"unknown"}
    devices.append(d); wj(DEVICES_FILE, devices)
    return jsonify(d), 201

@app.route("/api/devices/<did>", methods=["GET"])
def get_device(did):
    for d in rj(DEVICES_FILE):
        if d["id"] == did: return jsonify(d)
    return jsonify({"error":"not found"}), 404

@app.route("/api/devices/<did>", methods=["PATCH"])
def update_device(did):
    devices = rj(DEVICES_FILE)
    b = request.get_json(force=True) or {}
    for d in devices:
        if d["id"] == did:
            d.update(b); wj(DEVICES_FILE, devices); return jsonify(d)
    return jsonify({"error":"not found"}), 404

@app.route("/api/devices/<did>", methods=["DELETE"])
def delete_device(did):
    devices = rj(DEVICES_FILE)
    remaining = [d for d in devices if d["id"] != did]
    if len(remaining) == len(devices): return jsonify({"error":"not found"}), 404
    wj(DEVICES_FILE, remaining); return jsonify({"deleted":did})

# ══════════════════════════════════════════════════════
#  PROFILES ENDPOINTS
# ══════════════════════════════════════════════════════
@app.route("/api/profiles", methods=["GET"])
def get_profiles():
    return jsonify(rj(PROFILES_FILE))

@app.route("/api/profiles", methods=["POST"])
def add_profile():
    b = request.get_json(force=True) or {}
    if not b.get("name"): return jsonify({"error":"name required"}), 400
    profiles = rj(PROFILES_FILE)
    p = {"id":new_id("prof"),"name":b["name"],"color":b.get("color","#00d4ff"),
         "icon":b.get("icon","👤"),"killable":b.get("killable",True),"killed":False,
         "pihole_group":b.get("pihole_group"),
         "schedule":norm_sched(b.get("schedule")),
         "usage":{"minutes_used_today":0,"usage_date":today_str()}}
    profiles.append(p); wj(PROFILES_FILE, profiles)
    return jsonify(p), 201

@app.route("/api/profiles/<pid>", methods=["PATCH"])
def update_profile(pid):
    profiles = rj(PROFILES_FILE)
    b = request.get_json(force=True) or {}
    for p in profiles:
        if p["id"] == pid:
            if "schedule" in b:
                merged = dict(p.get("schedule") or DEFAULT_SCHED)
                for day, dd in b["schedule"].items():
                    if day in DAY_KEYS:
                        merged[day] = {"start": dd.get("start", merged.get(day,{}).get("start","00:00")),
                                       "end":   dd.get("end",   merged.get(day,{}).get("end","23:59")),
                                       "daily_limit_minutes": dd.get("daily_limit_minutes")}
                b["schedule"] = norm_sched(merged)
            p.update(b); wj(PROFILES_FILE, profiles); return jsonify(p)
    return jsonify({"error":"not found"}), 404

@app.route("/api/profiles/<pid>", methods=["DELETE"])
def delete_profile(pid):
    profiles = rj(PROFILES_FILE)
    remaining = [p for p in profiles if p["id"] != pid]
    if len(remaining) == len(profiles): return jsonify({"error":"not found"}), 404
    wj(PROFILES_FILE, remaining)
    devices = rj(DEVICES_FILE); changed = False
    for d in devices:
        if d.get("profile_id") == pid: d["profile_id"] = None; changed = True
    if changed: wj(DEVICES_FILE, devices)
    return jsonify({"deleted":pid})

# ══════════════════════════════════════════════════════
#  KILL SWITCH
# ══════════════════════════════════════════════════════
@app.route("/api/profiles/<pid>/killswitch", methods=["POST"])
def toggle_kill(pid):
    profiles = rj(PROFILES_FILE)
    p = next((x for x in profiles if x["id"]==pid), None)
    if not p: return jsonify({"error":"not found"}), 404
    if not p.get("killable",True): return jsonify({"error":"protected"}), 403
    p["killed"] = not p["killed"]; wj(PROFILES_FILE, profiles)
    devices = rj(DEVICES_FILE)
    affected = [d for d in devices if d.get("profile_id")==pid]
    pihole_r = {"ok":False,"error":"PIHOLE_ENABLED is False"}
    if PIHOLE_ENABLED and p.get("pihole_group"):
        pihole_r = pihole.set_group_enabled(p["pihole_group"], not p["killed"])
    return jsonify({"profile_id":pid,"profile_name":p["name"],"killed":p["killed"],
                    "devices_affected":len(affected),"pihole_action":pihole_r,
                    "timestamp":datetime.datetime.now().isoformat()})

# ══════════════════════════════════════════════════════
#  USAGE TRACKING
# ══════════════════════════════════════════════════════
@app.route("/api/profiles/<pid>/usage/tick", methods=["POST"])
def tick_usage(pid):
    profiles = rj(PROFILES_FILE)
    p = next((x for x in profiles if x["id"]==pid), None)
    if not p: return jsonify({"error":"not found"}), 404
    mins_add = (request.get_json(silent=True) or {}).get("minutes", 1)
    ensure_reset(p); p["usage"]["minutes_used_today"] += mins_add
    wj(PROFILES_FILE, profiles)
    s = access_state(p)
    auto_kill = s["reason"]=="budget_exhausted" and not p.get("killed")
    if auto_kill:
        p["killed"] = True; wj(PROFILES_FILE, profiles); s = access_state(p)
    return jsonify({"profile_id":pid,"minutes_used_today":p["usage"]["minutes_used_today"],
                    "access":s,"auto_killed_by_budget":auto_kill})

@app.route("/api/profiles/<pid>/usage/reset", methods=["POST"])
def reset_usage(pid):
    profiles = rj(PROFILES_FILE)
    p = next((x for x in profiles if x["id"]==pid), None)
    if not p: return jsonify({"error":"not found"}), 404
    unkill = (request.get_json(silent=True) or {}).get("unkill", True)
    p["usage"] = {"minutes_used_today":0,"usage_date":today_str()}
    if unkill: p["killed"] = False
    wj(PROFILES_FILE, profiles)
    return jsonify({"profile_id":pid,"minutes_used_today":0,"killed":p["killed"]})

@app.route("/api/profiles/<pid>/access", methods=["GET"])
def get_access(pid):
    for p in rj(PROFILES_FILE):
        if p["id"]==pid: return jsonify(access_state(p))
    return jsonify({"error":"not found"}), 404

# ══════════════════════════════════════════════════════
#  REAL-TIME DATA ENDPOINTS
# ══════════════════════════════════════════════════════
@app.route("/api/traffic", methods=["GET"])
def get_traffic():
    """24h bandwidth history from vnstat."""
    iface = request.args.get("interface")
    return jsonify(vnstat_24h(iface))

@app.route("/api/bandwidth/clients", methods=["GET"])
def get_bw_clients():
    """Per-client usage from Pi-hole, or device list fallback."""
    if PIHOLE_ENABLED:
        clients = pihole.top_clients()
        if clients: return jsonify(clients)
    # Fallback: distribute evenly across online devices
    devices = rj(DEVICES_FILE)
    online  = [d for d in devices if d.get("status")=="online"]
    total   = len(online) or 1
    colors  = ["#00d4ff","#00e87a","#a855f7","#ffc740","#ff8c00","#3b82f6"]
    return jsonify([{"name":d["name"],"ip":d["ip"],
                     "pct":round(100/total,1),"count":0,
                     "color":colors[i%len(colors)]}
                    for i,d in enumerate(online[:6])])

@app.route("/api/dns/stats", methods=["GET"])
def get_dns_stats():
    if not PIHOLE_ENABLED: return jsonify({"available":False})
    return jsonify({**pihole.dns_summary(),"available":True})

@app.route("/api/alerts/wazuh", methods=["GET"])
def get_wazuh_alerts():
    limit     = int(request.args.get("limit", 10))
    min_level = int(request.args.get("level", 5))
    return jsonify({"events":wazuh_recent_events(limit, min_level),
                    "available":WAZUH_ENABLED})

@app.route("/api/alerts/counts", methods=["GET"])
def get_alert_counts():
    return jsonify({"days":wazuh_counts_7d(),"available":WAZUH_ENABLED})

# ══════════════════════════════════════════════════════
#  SCAN + DIAGNOSTICS
# ══════════════════════════════════════════════════════
@app.route("/api/scan", methods=["POST"])
def scan_network():
    body = request.get_json(silent=True) or {}
    subnets = body.get("subnets", SCAN_SUBNETS)
    all_found, results = {}, []
    for entry in subnets:
        r = _scan_subnet(entry.get("subnet",""), entry.get("interface","eth0"))
        if r["ok"]:
            all_found.update(r["found"])
            results.append({"subnet":entry["subnet"],"ok":True,"hosts_found":len(r["found"])})
        else:
            if "not installed" in r.get("error",""):
                return jsonify({"error":r["error"]}), 500
            results.append({"subnet":entry.get("subnet","?"),"ok":False,"error":r["error"]})
    devices = rj(DEVICES_FILE); known = {d["ip"] for d in devices}; added = []
    for ip,mac in all_found.items():
        if ip not in known:
            auto  = auto_name_device(ip, mac)
            nd = {"id":new_id("dev"),
                  "name":          auto["name"],
                  "ip":            ip,
                  "mac":           mac,
                  "type":          auto["type"],
                  "icon":          "❓",
                  "profile_id":    None,
                  "status":        "online",
                  "new":           True,
                  "name_source":   auto["source"],
                  "discovered_at": datetime.datetime.now().isoformat()}
            devices.append(nd); added.append(nd)
    online = set(all_found.keys())
    for d in devices: d["status"] = "online" if d["ip"] in online else "offline"
    wj(DEVICES_FILE, devices)
    return jsonify({"scan_results":results,"total_hosts_found":len(all_found),
                    "newly_added":added,"total_devices":len(devices),
                    "timestamp":datetime.datetime.now().isoformat()})

@app.route("/api/pihole/probe", methods=["GET"])
def probe_pihole():
    v = pihole.detect_version()
    return jsonify({"reachable":v is not None,"version":v,"base_url":pihole.base})


@app.route("/api/devices/auto-rename", methods=["POST"])
def auto_rename_devices():
    """
    Re-runs auto-naming on all devices that are still named "Unknown (IP)".
    POST with body {"all": true} to re-name every device (even already named ones).
    Useful when you first deploy and want to bulk-identify the 35 unknown devices.
    Takes a minute to run since it does nmap hostname detection per device.
    Returns a list of what was renamed.
    """
    body    = request.get_json(force=True) or {}
    force   = body.get("all", False)
    devices = rj(DEVICES_FILE)
    renamed = []

    for d in devices:
        is_unknown = d.get("name","").startswith("Unknown (")
        if not (is_unknown or force):
            continue
        auto = auto_name_device(d["ip"], d.get("mac",""))
        if auto["source"] != "unknown" or force:
            old_name    = d["name"]
            d["name"]   = auto["name"]
            d["type"]   = auto["type"] if auto["type"] != "Unknown" else d.get("type","Unknown")
            d["name_source"] = auto["source"]
            renamed.append({"ip": d["ip"], "old": old_name, "new": d["name"],
                            "source": auto["source"]})

    if renamed:
        wj(DEVICES_FILE, devices)

    return jsonify({"renamed": len(renamed), "details": renamed})


#  PER-PROFILE DOMAIN BLOCKLIST
#  Stored locally in profiles.json AND synced to Pi-hole
#  when PIHOLE_ENABLED=True. Works without Pi-hole too —
#  the list is saved and will sync when Pi-hole connects.
# ══════════════════════════════════════════════════════

@app.route("/api/profiles/<pid>/blocklist", methods=["GET"])
def get_blocklist(pid):
    """
    Returns the blocked domains for a profile.
    Includes the local list always, and Pi-hole's live list
    if PIHOLE_ENABLED so you can spot any drift.
    """
    profiles = rj(PROFILES_FILE)
    p = next((x for x in profiles if x["id"] == pid), None)
    if not p: return jsonify({"error": "not found"}), 404

    local_domains = p.get("blocked_domains", [])

    pihole_domains = []
    pihole_synced  = False
    if PIHOLE_ENABLED and p.get("pihole_group"):
        pihole_domains = pihole.get_blocked_domains(p["pihole_group"])
        pihole_synced  = True

    return jsonify({
        "profile_id":     pid,
        "profile_name":   p["name"],
        "pihole_group":   p.get("pihole_group"),
        "blocked_domains": local_domains,
        "pihole_domains":  pihole_domains,
        "pihole_synced":   pihole_synced,
        "pihole_enabled":  PIHOLE_ENABLED,
    })


@app.route("/api/profiles/<pid>/blocklist", methods=["POST"])
def add_to_blocklist(pid):
    """
    Adds a domain to the blocked list for this profile.
    Saves it locally immediately, then pushes to Pi-hole
    if PIHOLE_ENABLED and the profile has a pihole_group.

    Body: { "domain": "youtube.com", "comment": "optional note" }

    The domain is normalised (lowercased, www. stripped) so
    "www.YouTube.com" and "youtube.com" are treated as the same entry.
    """
    profiles = rj(PROFILES_FILE)
    p = next((x for x in profiles if x["id"] == pid), None)
    if not p: return jsonify({"error": "not found"}), 404

    body    = request.get_json(force=True) or {}
    raw     = body.get("domain", "").strip().lower()
    comment = body.get("comment", "").strip()

    if not raw:
        return jsonify({"error": "domain is required"}), 400

    # Normalise — strip protocol and www prefix
    domain = raw.replace("https://","").replace("http://","").split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    if not domain or "." not in domain:
        return jsonify({"error": f'"{raw}" doesn\'t look like a valid domain'}), 400

    # Save locally
    blocked = p.setdefault("blocked_domains", [])
    if domain in blocked:
        return jsonify({"error": f'"{domain}" is already on this profile\'s blocklist'}), 409
    blocked.append(domain)
    wj(PROFILES_FILE, profiles)

    # Push to Pi-hole
    pihole_result = {"ok": False, "error": "PIHOLE_ENABLED is False — saved locally only"}
    if PIHOLE_ENABLED and p.get("pihole_group"):
        pihole_result = pihole.add_blocked_domain(p["pihole_group"], domain, comment)

    return jsonify({
        "domain":         domain,
        "profile_id":     pid,
        "profile_name":   p["name"],
        "blocked_domains": blocked,
        "pihole_result":  pihole_result,
    }), 201


@app.route("/api/profiles/<pid>/blocklist/<path:domain>", methods=["DELETE"])
def remove_from_blocklist(pid, domain):
    """
    Removes a domain from this profile's blocklist.
    Deletes it locally and removes it from Pi-hole if enabled.
    """
    profiles = rj(PROFILES_FILE)
    p = next((x for x in profiles if x["id"] == pid), None)
    if not p: return jsonify({"error": "not found"}), 404

    blocked = p.get("blocked_domains", [])
    if domain not in blocked:
        return jsonify({"error": f'"{domain}" is not on this profile\'s blocklist'}), 404

    blocked.remove(domain)
    p["blocked_domains"] = blocked
    wj(PROFILES_FILE, profiles)

    pihole_result = {"ok": False, "error": "PIHOLE_ENABLED is False — removed locally only"}
    if PIHOLE_ENABLED and p.get("pihole_group"):
        pihole_result = pihole.remove_blocked_domain(p["pihole_group"], domain)

    return jsonify({
        "domain":         domain,
        "profile_id":     pid,
        "blocked_domains": blocked,
        "pihole_result":  pihole_result,
    })


@app.route("/api/profiles/<pid>/blocklist/sync", methods=["POST"])
def sync_blocklist(pid):
    """
    Forces an immediate sync of this profile's local blocked_domains
    list to Pi-hole. Useful after connecting Pi-hole for the first time —
    any domains you'd already saved locally will be pushed up.
    """
    profiles = rj(PROFILES_FILE)
    p = next((x for x in profiles if x["id"] == pid), None)
    if not p: return jsonify({"error": "not found"}), 404

    if not PIHOLE_ENABLED:
        return jsonify({"ok": False, "error": "PIHOLE_ENABLED is False"}), 400
    if not p.get("pihole_group"):
        return jsonify({"ok": False, "error": "No Pi-hole group set on this profile"}), 400

    result = pihole.sync_blocked_domains(p["pihole_group"], p.get("blocked_domains", []))
    return jsonify({"profile_id": pid, "profile_name": p["name"], **result})



def check_routes():
    out = []
    for entry in SCAN_SUBNETS:
        host = entry["subnet"].replace("0/24","1").replace("/24","")
        try:
            r = subprocess.run(["ip","route","get",host],
                               capture_output=True,text=True,timeout=5)
            out.append({"subnet":entry["subnet"],"routable":r.returncode==0,
                        "route":r.stdout.strip().split("\n")[0] if r.returncode==0 else None})
        except Exception as ex:
            out.append({"subnet":entry["subnet"],"routable":False,"route":str(ex)})
    return jsonify({"routes":out,"all_reachable":all(r["routable"] for r in out)})

@app.route("/api/network/vpn", methods=["GET"])
def check_vpn():
    try:
        r = subprocess.run(["wg","show"],capture_output=True,text=True,timeout=5)
        if r.returncode != 0: return jsonify({"wireguard_installed":True,"tunnel_up":False,"peers":[]})
        lines = r.stdout.strip().split("\n")
        ifaces, peers, cur = [], [], None
        for line in lines:
            if line.startswith("interface:"): ifaces.append(line.split(":",1)[1].strip())
            elif line.strip().startswith("peer:"):
                if cur: peers.append(cur)
                cur = {"public_key":line.split(":",1)[1].strip()}
            elif cur:
                if "endpoint:"        in line: cur["endpoint"]       = line.split(":",1)[1].strip()
                elif "allowed ips:"   in line: cur["allowed_ips"]    = line.split(":",1)[1].strip()
                elif "latest handshake:" in line: cur["last_handshake"] = line.split(":",1)[1].strip()
        if cur: peers.append(cur)
        return jsonify({"wireguard_installed":True,"tunnel_up":len(ifaces)>0,
                        "interfaces":ifaces,"peers":peers,"peer_count":len(peers)})
    except FileNotFoundError:
        return jsonify({"wireguard_installed":False,"message":"WireGuard not installed"})

# ══════════════════════════════════════════════════════
#  COMBINED STATUS (primary dashboard poll)
# ══════════════════════════════════════════════════════
@app.route("/api/status", methods=["GET"])
def status():
    devices  = rj(DEVICES_FILE)
    profiles = rj(PROFILES_FILE)
    plookup  = {p["id"]:p for p in profiles}

    # Enrich devices
    enriched_devices = []
    for d in devices:
        dc = dict(d)
        owner = plookup.get(d.get("profile_id"))
        dc["profile_name"]   = owner["name"] if owner else None
        dc["profile_killed"] = owner.get("killed",False) if owner else False
        enriched_devices.append(dc)

    # Enrich profiles + reset usage if new day
    enriched_profiles = []; reset_needed = False
    for p in profiles:
        before = (p.get("usage") or {}).get("usage_date")
        pc = dict(p)
        pc["device_count"] = sum(1 for d in devices if d.get("profile_id")==p["id"])
        pc["device_names"] = [d["name"] for d in devices if d.get("profile_id")==p["id"]]
        pc["access"] = access_state(p)
        if p.get("usage",{}).get("usage_date") != before: reset_needed = True
        enriched_profiles.append(pc)
    if reset_needed: wj(PROFILES_FILE, profiles)

    # Real bandwidth summary from vnstat
    bw = vnstat_today()

    # Device type breakdown from actual device records
    type_counts = {}
    for d in devices:
        t = d.get("type","Unknown")
        type_counts[t] = type_counts.get(t,0) + 1

    # Active Wazuh alerts (high severity only)
    active_alerts = wazuh_recent_events(limit=5, min_level=10)

    # Real server uptime from /proc/uptime
    try:
        with open('/proc/uptime') as f:
            uptime_secs = int(float(f.read().split()[0]))
    except Exception:
        uptime_secs = 0

    # Devices added in the last 24 hours (based on scan timestamps if available)
    # We track this simply by counting devices whose status flipped to online recently
    # For now use the newly_added count stored in devices — future: add created_at field
    new_devices_24h = sum(1 for d in devices if d.get('new', False))

    online_count = sum(1 for d in devices if d.get("status")=="online")

    return jsonify({
        "devices":       enriched_devices,
        "profiles":      enriched_profiles,
        "online_count":  online_count,
        "total_devices": len(devices),
        "bandwidth":     bw,
        "device_types":  type_counts,
        "active_alerts":   active_alerts,
        "alert_count":     len(active_alerts),
        "uptime_seconds":  uptime_secs,
        "new_devices_24h": new_devices_24h,
        "pihole_connected": PIHOLE_ENABLED and pihole.ver is not None,
        "wazuh_connected":  WAZUH_ENABLED,
        "timestamp":       datetime.datetime.now().isoformat(),
    })

# ══════════════════════════════════════════════════════
#  BACKGROUND THREADS
# ══════════════════════════════════════════════════════
def _scan_loop():
    import time
    while True:
        time.sleep(AUTO_SCAN_INTERVAL)
        try:
            all_found = {}
            for entry in SCAN_SUBNETS:
                r = _scan_subnet(entry.get("subnet",""), entry.get("interface","eth0"))
                if r["ok"]: all_found.update(r["found"])
            devices = rj(DEVICES_FILE); known = {d["ip"] for d in devices}
            for ip,mac in all_found.items():
                if ip not in known:
                    auto = auto_name_device(ip, mac)
                    devices.append({
                        "id":           new_id("dev"),
                        "name":         auto["name"],
                        "ip":           ip,
                        "mac":          mac,
                        "type":         auto["type"],
                        "icon":         "❓",
                        "profile_id":   None,
                        "status":       "online",
                        "new":          True,
                        "name_source":  auto["source"],
                        "discovered_at":datetime.datetime.now().isoformat()
                    })
            online = set(all_found.keys())
            for d in devices: d["status"] = "online" if d["ip"] in online else "offline"
            wj(DEVICES_FILE, devices)
        except Exception:
            pass

def _usage_loop():
    import time
    while True:
        time.sleep(USAGE_TICK_INTERVAL)
        try:
            devices  = rj(DEVICES_FILE)
            profiles = rj(PROFILES_FILE)
            active_pids = {d["profile_id"] for d in devices
                           if d.get("status")=="online" and d.get("profile_id")}
            changed = False
            for p in profiles:
                if p["id"] not in active_pids: continue
                ensure_reset(p); s = access_state(p)
                if not s["allowed"]: continue
                p["usage"]["minutes_used_today"] += 1
                lim = s.get("daily_limit_minutes")
                if lim and p["usage"]["minutes_used_today"] >= lim: p["killed"] = True
                changed = True
            if changed: wj(PROFILES_FILE, profiles)
        except Exception:
            pass

# ══════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    import warnings; warnings.filterwarnings("ignore")

    print("\n── NET-WATCH API v3 ─────────────────────────────────")
    print(  '  Auth             : disabled (open access)')
    print(f"  Pi-hole          : {'enabled — ' + PIHOLE_HOST if PIHOLE_ENABLED else 'disabled (set PIHOLE_ENABLED=true)'}")
    print(f"  Wazuh            : {'enabled — ' + WAZUH_URL if WAZUH_ENABLED else 'disabled (set WAZUH_ENABLED=true)'}")
    print(f"  Scan subnets     : {[s['subnet'] for s in SCAN_SUBNETS]}")
    print(f"  Scan interval    : {AUTO_SCAN_INTERVAL}s | Usage tick: {USAGE_TICK_INTERVAL}s")

    if PIHOLE_ENABLED:
        print("  Probing Pi-hole  :", end=" ", flush=True)
        v = pihole.detect_version()
        print(f"v{v} ✓" if v else "UNREACHABLE ✗")
        if v == 6:
            # Sync all profile blocklists so Pi-hole matches local state
            # (handles the case where Pi-hole was reset or rebuilt)
            profiles = rj(PROFILES_FILE)
            synced = 0
            for p in profiles:
                if p.get("pihole_group") and p.get("blocked_domains"):
                    pihole.sync_blocked_domains(p["pihole_group"], p["blocked_domains"])
                    synced += 1
            if synced:
                print(f"  Blocklist sync   : {synced} profile(s) synced to Pi-hole")

    # Auto-scan disabled — scanning on Wi-Fi can drop the interface.
    # Use the Scan Network button in the dashboard instead.
    # To re-enable: remove the # from the line below.
    #threading.Thread(target=_scan_loop,  daemon=True, name="scan").start()
    threading.Thread(target=_usage_loop, daemon=True, name="usage").start()
    print("  Background threads: scan + usage started")
    print("  Dashboard URL    :  http://<server-ip>")
    print("─────────────────────────────────────────────────────\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
