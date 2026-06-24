"""
TP-Link Switch Metrics Scraper
================================
Scrapes port metrics from a TP-Link managed switch web UI and exposes
them via a Prometheus-compatible HTTP interface.

Endpoints discovered from sys_portsetting.html JS source:
  - Actual port state : GET /portCur.xml          (polled live)
  - Config state      : GET /port_setting.cgi      (embedded in HTML at load)
  - Login             : POST /logon.cgi

Response format (/portCur.xml):
  "<st0>,<st1>,...,&<sp0>,<sp1>,...,&<dp0>,<dp1>,...,&<fc0>,<fc1>,...,&"
  Group 0 → state   : 0=Disabled, 1=Enabled
  Group 1 → speed   : 0=LinkDown, 1=10M, 2=100M, 3=1000M
  Group 2 → duplex  : 0=Full,     1=Half, 2=LinkDown/Auto
  Group 3 → flowctl : 0=Off,      1=On,   2=LinkDown (only when port disabled)

Disabled-port rule (mirrors JS curState()):
  If state==0 (Disabled) → speed="link_down", duplex="link_down", fc="off"
  regardless of what groups 1-3 say.

Usage:
  # One-shot table print:
  python tplink_scraper.py --host 192.168.31.138

  # Prometheus exporter on :9100:
  pip install prometheus_client requests
  python tplink_scraper.py --host 192.168.31.138 --serve --port 9100
"""

import argparse
import logging
import time
from dataclasses import dataclass
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Optional prometheus_client – only required for --serve mode
# ---------------------------------------------------------------------------
try:
    from prometheus_client import start_http_server
    from prometheus_client.core import GaugeMetricFamily, REGISTRY
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tplink_scraper")

# ---------------------------------------------------------------------------
# Switch defaults
# ---------------------------------------------------------------------------
DEFAULT_HOST     = "1.1.1.1"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"

# Discovered from JS source: xmlReq.open("GET", "/portCur.xml", true)
PORT_STATE_URL   = "/portCur.xml"

# Login endpoint (TP-Link TL-SG10xx series)
LOGIN_PATH       = "/logon.cgi"

# Proactive re-auth interval (seconds). Tune to your switch's session timeout.
COOKIE_TTL       = 300  # 5 minutes

# ---------------------------------------------------------------------------
# Value maps  — derived directly from the JS arrays in sys_portsetting.html
#
# state_info  = [opt_disabled, opt_enabled]
# speed_info  = [ary_spdinfo0, ary_spdinfo1, ary_spdinfo2, ary_spdinfo3]
# duplex_info = [ary_duplexinfo1, ary_duplexinfo2, ary_duplexinfo0]
#   NOTE: duplex_info is a *re-ordering* of mode_info — Full/Half/Auto, not Auto/Full/Half
# flow_info   = [ary_flowinfo0, ary_flowinfo1, ary_spdinfo0]
#   index 2 is "link_down" but only relevant when port is disabled (handled in code)
# ---------------------------------------------------------------------------
STATE_MAP = {
    "0": "disabled",
    "1": "enabled",
}

SPEED_MAP = {
    "0": "link_down",   # ary_spdinfo0 (also used as "Auto" in config context)
    "1": "10M",         # ary_spdinfo1
    "2": "100M",        # ary_spdinfo2
    "3": "1000M",       # ary_spdinfo3
}

# duplex_info array in JS: [duplexinfo1=Full, duplexinfo2=Half, duplexinfo0=Auto/LinkDown]
DUPLEX_MAP = {
    "0": "full",        # ary_duplexinfo1
    "1": "half",        # ary_duplexinfo2
    "2": "link_down",   # ary_duplexinfo0 (Auto / Link Down)
}

# flow_info array in JS: [flowinfo0=Off, flowinfo1=On, spdinfo0=LinkDown]
FLOW_MAP = {
    "0": "off",
    "1": "on",
    "2": "link_down",   # sent when port disabled; we normalise to "off" below
}

SPEED_MBPS = {
    "link_down": 0,
    "10M":       10,
    "100M":      100,
    "1000M":     1000,
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class PortMetrics:
    port:             int           # 1-based
    state_actual:     str = "unknown"
    speed_actual:     str = "unknown"
    duplex_actual:    str = "unknown"
    flow_ctrl_actual: str = "unknown"
    link_up:          int = 0       # convenience gauge: 1 = link active


# ---------------------------------------------------------------------------
# Session / auth lifecycle
# ---------------------------------------------------------------------------
class SwitchSession:
    """
    Manages an HTTP session with cookie-based auth to a TP-Link switch.

    Auth flow:
        POST /logon.cgi  username=<u>&password=<p>&logon=Login
        → switch sets   Set-Cookie: Cookies=<base64-token>
        All subsequent requests carry that cookie automatically.

    Cookie expiry is handled two ways:
        1. Proactive: re-auth after COOKIE_TTL seconds
        2. Reactive:  re-auth if response looks like a login redirect (HTTP 302
           or HTML body containing "logon")
    """

    def __init__(self, host: str, username: str, password: str,
                 cookie_ttl: int = COOKIE_TTL):
        self.base_url   = f"http://{host}"
        self.username   = username
        self.password   = password
        self.cookie_ttl = cookie_ttl

        self._session:   Optional[requests.Session] = None
        self._authed_at: float = 0.0

    def _cookie_fresh(self) -> bool:
        return (time.time() - self._authed_at) < self.cookie_ttl

    def login(self) -> None:
        log.info("Authenticating with %s …", self.base_url)
        s = requests.Session()
        s.headers.update({
            "User-Agent":      ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) "
                                "Chrome/148.0.0.0 Safari/537.36"),
            "Accept":          "*/*",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "DNT":             "1",
        })
        resp = s.post(
            self.base_url + LOGIN_PATH,
            data={"username": self.username, "password": self.password, "logon": "Login"},
            timeout=10,
            allow_redirects=True,
        )
        if "Cookies" not in s.cookies:
            raise RuntimeError(
                f"Login failed (HTTP {resp.status_code}) — 'Cookies' not set. "
                "Check credentials or LOGIN_PATH."
            )
        self._session   = s
        self._authed_at = time.time()
        log.info("Authenticated OK  cookie=%s", s.cookies.get("Cookies"))

    def _ensure_auth(self) -> None:
        if self._session is None or not self._cookie_fresh():
            self.login()

    def get(self, path: str) -> requests.Response:
        self._ensure_auth()
        resp = self._session.get(
            self.base_url + path,
            headers={"Referer": self.base_url + "/homepage.html"},
            timeout=10,
        )
        # Detect mid-session expiry
        if resp.status_code in (302, 401) or _is_login_page(resp):
            log.warning("Session expired — re-authenticating …")
            self.login()
            resp = self._session.get(
                self.base_url + path,
                headers={"Referer": self.base_url + "/homepage.html"},
                timeout=10,
            )
        resp.raise_for_status()
        return resp


def _is_login_page(resp: requests.Response) -> bool:
    """Heuristic: HTML body containing 'logon' means we got bounced to login."""
    if "text/html" in resp.headers.get("Content-Type", ""):
        return b"logon" in resp.content.lower()
    return False


# ---------------------------------------------------------------------------
# Parser — mirrors curState() in sys_portsetting.html
# ---------------------------------------------------------------------------
def parse_portcur(raw: str, num_ports: int = 8) -> list[PortMetrics]:
    """
    Parse /portCur.xml response.

    Format:  "v,v,v,...,&v,v,v,...,&v,v,v,...,&v,v,v,...,&"
    Groups:   [0]=state  [1]=speed  [2]=duplex  [3]=flow_ctrl
    """
    groups = [g.strip() for g in raw.strip().split("&") if g.strip()]
    if len(groups) < 4:
        raise ValueError(f"Expected ≥4 data groups, got {len(groups)!r} from: {raw!r}")

    def vals(group_idx: int) -> list[str]:
        return [v.strip() for v in groups[group_idx].split(",") if v.strip()]

    states  = vals(0)
    speeds  = vals(1)
    duplexs = vals(2)
    flows   = vals(3)

    ports = []
    for i in range(num_ports):
        st_raw = states[i]
        state  = STATE_MAP.get(st_raw, st_raw)

        # Mirror JS disabled-port logic:
        # if (state_info[st[i]] == opt_disabled) → sp=link_down, dp=link_down, fc=off
        if state == "disabled":
            speed  = "link_down"
            duplex = "link_down"
            fc     = "off"
        else:
            speed  = SPEED_MAP.get(speeds[i],  speeds[i])
            duplex = DUPLEX_MAP.get(duplexs[i], duplexs[i])
            fc_raw = FLOW_MAP.get(flows[i], flows[i])
            fc     = "off" if fc_raw == "link_down" else fc_raw

        link_up = 1 if state == "enabled" and speed != "link_down" else 0

        ports.append(PortMetrics(
            port             = i + 1,
            state_actual     = state,
            speed_actual     = speed,
            duplex_actual    = duplex,
            flow_ctrl_actual = fc,
            link_up          = link_up,
        ))

    return ports


# ---------------------------------------------------------------------------
# Scrape
# ---------------------------------------------------------------------------
def scrape(session: SwitchSession, num_ports: int = 8) -> list[PortMetrics]:
    resp = session.get(PORT_STATE_URL)
    log.debug("Raw /portCur.xml: %s", resp.text)
    return parse_portcur(resp.text, num_ports=num_ports)


# ---------------------------------------------------------------------------
# Prometheus collector
# ---------------------------------------------------------------------------
class TPLinkCollector:
    """Custom Prometheus collector. Register once with REGISTRY.register(...)."""

    def __init__(self, session: SwitchSession, num_ports: int = 8):
        self.session   = session
        self.num_ports = num_ports

    def collect(self):
        try:
            ports = scrape(self.session, self.num_ports)
        except Exception as exc:
            log.error("Scrape error: %s", exc)
            return

        link_up = GaugeMetricFamily(
            "tplink_port_link_up",
            "1 if port has an active link, 0 otherwise",
            labels=["port"],
        )
        speed = GaugeMetricFamily(
            "tplink_port_speed_mbps",
            "Actual link speed in Mbps (0 = link down)",
            labels=["port"],
        )
        info = GaugeMetricFamily(
            "tplink_port_info",
            "Port state info (value always 1; read labels for state details)",
            labels=["port", "state", "duplex", "flow_ctrl"],
        )

        for p in ports:
            lbl = [str(p.port)]
            link_up.add_metric(lbl, p.link_up)
            speed.add_metric(lbl, SPEED_MBPS.get(p.speed_actual, 0))
            info.add_metric(
                [str(p.port), p.state_actual, p.duplex_actual, p.flow_ctrl_actual], 1
            )

        yield link_up
        yield speed
        yield info


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="TP-Link switch Prometheus exporter")
    ap.add_argument("--host",       default=DEFAULT_HOST)
    ap.add_argument("--username",   default=DEFAULT_USERNAME)
    ap.add_argument("--password",   default=DEFAULT_PASSWORD)
    ap.add_argument("--num-ports",  type=int, default=8,    dest="num_ports")
    ap.add_argument("--cookie-ttl", type=int, default=COOKIE_TTL, dest="cookie_ttl",
                    help="Seconds before proactive re-auth (default: 300)")
    ap.add_argument("--serve",      action="store_true",
                    help="Run as Prometheus HTTP exporter")
    ap.add_argument("--port",       type=int, default=9100,
                    help="HTTP port for Prometheus exporter (default: 9100)")
    ap.add_argument("--debug",      action="store_true")
    args = ap.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    session = SwitchSession(
        host       = args.host,
        username   = args.username,
        password   = args.password,
        cookie_ttl = args.cookie_ttl,
    )

    if args.serve:
        if not PROMETHEUS_AVAILABLE:
            raise SystemExit("prometheus_client not installed. Run: pip install prometheus_client")
        REGISTRY.register(TPLinkCollector(session, num_ports=args.num_ports))
        start_http_server(args.port)
        log.info("Prometheus exporter listening on http://0.0.0.0:%d/metrics", args.port)
        while True:
            time.sleep(60)
    else:
        ports = scrape(session, num_ports=args.num_ports)
        w = 10
        print(f"{'Port':<8} {'Link':<6} {'State':<10} {'Speed':<{w}} {'Duplex':<{w}} {'Flow Ctrl'}")
        print("-" * 56)
        for p in ports:
            print(
                f"Port {p.port:<3} {'UP' if p.link_up else 'DOWN':<6} "
                f"{p.state_actual:<10} {p.speed_actual:<{w}} "
                f"{p.duplex_actual:<{w}} {p.flow_ctrl_actual}"
            )


if __name__ == "__main__":
    main()
    