#!/usr/bin/env python3
"""
Network Guardian
=================
A DEFENSIVE tool for detecting ARP spoofing / Man-in-the-Middle activity
on a local network you own or are authorized to monitor.

It does NOT intercept, redirect, or harvest any traffic. It only listens
to ARP broadcasts and compares them against a trusted baseline you build
yourself, alerting you when something inconsistent shows up.

Usage:
    sudo python network_guardian.py      # Linux / macOS
    python network_guardian.py           # Windows (run as Administrator)

Requires: scapy, colorama  (see requirements.txt)
"""

import sys
import os
import json
import time
import ipaddress
import threading
import logging
from datetime import datetime
from collections import defaultdict, deque

try:
    from scapy.all import ARP, Ether, srp, sniff, sendp, AsyncSniffer, conf
except ImportError:
    print("[!] Scapy is not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR_OK = Fore.GREEN
    COLOR_WARN = Fore.YELLOW
    COLOR_ALERT = Fore.RED + Style.BRIGHT
    COLOR_INFO = Fore.CYAN
    COLOR_RESET = Style.RESET_ALL
except ImportError:
    COLOR_OK = COLOR_WARN = COLOR_ALERT = COLOR_INFO = COLOR_RESET = ""

BASELINE_FILE = "trusted_hosts.json"
ALERT_LOG_FILE = "alerts.log"
GRATUITOUS_ARP_WINDOW_SECONDS = 10
GRATUITOUS_ARP_THRESHOLD = 15  # unsolicited replies from one MAC in the window = flood
PROBE_INTERVAL_SECONDS = 5     # how often to actively re-check known hosts
SNIFF_CHUNK_SECONDS = 2        # how long each passive-sniff pass runs before looping
HEARTBEAT_INTERVAL_SECONDS = 10  # reassure the user the monitor is alive

logging.basicConfig(
    filename=ALERT_LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
)

# Shared between monitor() and the web dashboard thread so the dashboard can
# show live stats while the CLI monitor runs. Simple dict assignment is fine
# here (no lock needed) since we're only ever doing atomic single-key updates.
SHARED_STATE = {
    "status": "inactive",
    "iface": None,
    "replies_seen": 0,
    "verified_ok": 0,
}


def divider(width=70):
    print(COLOR_INFO + ("=" * width) + COLOR_RESET)


def check_pcap_driver():
    """Mirrors the friendly libpcap/Npcap availability notice seen in similar tools."""
    if sys.platform == "win32" and not has_l2_capability():
        print(COLOR_WARN + "[!] No libpcap provider detected. Install Npcap (Windows) for best results." + COLOR_RESET)


def has_l2_capability():
    """
    Returns True only if Scapy can actually do raw Layer 2 (Ethernet/ARP) I/O.
    On Windows this requires Npcap; without it Scapy silently falls back to an
    L3-only socket that cannot send/receive ARP frames, and options 2/3 will
    appear to run but never see or send real traffic.
    """
    try:
        from scapy.config import conf as _conf
    except Exception:
        return False

    if sys.platform != "win32":
        # libpcap ships with Linux/macOS; raw L2 sockets work natively
        return True

    return bool(getattr(_conf, "use_pcap", False))


def require_l2_or_warn():
    """Call before any scan/monitor action. Returns False (and prints guidance) if
    Layer 2 capture isn't actually available, so we don't run a useless loop."""
    if has_l2_capability():
        return True
    print()
    print(COLOR_ALERT + "  [!] Raw Layer 2 (ARP/Ethernet) access is not available — this action "
                         "would silently do nothing." + COLOR_RESET)
    print(COLOR_WARN + "  [!] On Windows this means Npcap isn't installed/active correctly. Fix:" + COLOR_RESET)
    print(COLOR_WARN + "      1. Install Npcap from https://npcap.com/#download" + COLOR_RESET)
    print(COLOR_WARN + "      2. During setup, check 'Install Npcap in WinPcap API-compatible Mode'" + COLOR_RESET)
    print(COLOR_WARN + "      3. Reboot" + COLOR_RESET)
    print(COLOR_WARN + "      4. Run this tool from an Administrator terminal" + COLOR_RESET)
    print()
    return False


def shield_icon():
    print(Fore.CYAN + Style.BRIGHT + r"""
  ▄▄▄▄▄▄▄▄▄▄▄
 █           █
  ▀▄▄▄▄▄▄▄▄▄▀
   █       █
    ▀▄▄▄▄▄▀
     █   █
      ▀▄▀
""" + COLOR_RESET)


def banner():
    check_pcap_driver()
    shield_icon()
    print(Fore.BLUE + Style.BRIGHT + r"""
 ███╗   ██╗███████╗████████╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
 ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
 ██╔██╗ ██║█████╗     ██║       ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
 ██║╚██╗██║██╔══╝     ██║       ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
 ██║ ╚████║███████╗   ██║       ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝        ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
""" + COLOR_RESET)
    print(COLOR_INFO + "  Defensive ARP Spoofing / MITM Detector" + COLOR_RESET)
    print(COLOR_INFO + "  For monitoring networks you own or are authorized to test.\n" + COLOR_RESET)


def list_interfaces():
    from scapy.all import get_if_list, get_if_addr, get_if_hwaddr

    print()
    print(COLOR_INFO + "  Available interfaces:" + COLOR_RESET)
    print(COLOR_INFO + "  ----------------------" + COLOR_RESET)

    names = get_if_list()
    if not names:
        print(COLOR_WARN + "  [!] No interfaces found." + COLOR_RESET)
        print()
        return []

    for i, name in enumerate(names, 1):
        try:
            ip = get_if_addr(name)
        except Exception:
            ip = None
        if not ip or ip == "0.0.0.0":
            ip = "unassigned"

        try:
            mac = get_if_hwaddr(name)
        except Exception:
            mac = "?"

        tag = ""
        if ip == "127.0.0.1" or name in ("lo", "Loopback"):
            tag = COLOR_WARN + "  (loopback — not useful for LAN scanning)" + COLOR_RESET

        print(f"    {i}) {name:<10} IP: {ip:<15} MAC: {mac}{tag}")

    print()
    return names


def choose_interface():
    names = list_interfaces()
    while True:
        choice = input(COLOR_INFO + "  [*] Select interface number: " + COLOR_RESET).strip()
        if choice.isdigit() and 1 <= int(choice) <= len(names):
            print()
            return names[int(choice) - 1]
        print(COLOR_WARN + "  [!] Invalid selection, try again." + COLOR_RESET)


def get_local_subnet(iface_name):
    """Best-effort guess of the local /24 subnet based on the chosen interface's IP."""
    try:
        from scapy.all import get_if_addr
        ip = get_if_addr(iface_name)
        if ip and ip != "0.0.0.0":
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(network)
    except Exception:
        pass
    return None


def build_baseline(iface_name):
    """Actively ARP-scan the subnet and save a trusted IP -> MAC table."""
    if not require_l2_or_warn():
        return {}

    subnet = get_local_subnet(iface_name)
    if not subnet:
        subnet = input(COLOR_INFO + "  [*] Could not auto-detect subnet. Enter it manually (e.g. 192.168.1.0/24): " + COLOR_RESET).strip()

    print()
    print(COLOR_INFO + f"  [*] Scanning network on {iface_name} ..." + COLOR_RESET)
    print(COLOR_INFO + f"  [*] Scanning {subnet} on {iface_name} ..." + COLOR_RESET)

    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    try:
        answered, _ = srp(packet, timeout=4, iface=iface_name, verbose=False)
    except PermissionError:
        print(COLOR_ALERT + "  [!] Permission denied. Run this tool as root/Administrator." + COLOR_RESET)
        return {}
    except Exception as e:
        print(COLOR_ALERT + f"  [!] Scan failed: {e}" + COLOR_RESET)
        return {}

    trusted = {}
    for _, received in answered:
        trusted[received.psrc] = received.hwsrc.lower()

    if not trusted:
        print(COLOR_WARN + "  [!] No hosts responded. Baseline is empty." + COLOR_RESET)
        if subnet.startswith("127."):
            print(COLOR_WARN + "  [!] You scanned the loopback interface (127.0.0.1), which only "
                                "sees this machine." + COLOR_RESET)
            print(COLOR_WARN + "      Go back to option [1] and pick your real network interface "
                                "(e.g. eth0, wlan0, en0)." + COLOR_RESET)
        print()
        return trusted

    with open(BASELINE_FILE, "w") as f:
        json.dump(trusted, f, indent=2)

    print(COLOR_OK + f"  [+] Discovered {len(trusted)} device(s):" + COLOR_RESET)
    print()
    print_devices_table(trusted)
    print()

    return trusted


def print_devices_table(trusted):
    """Bordered # | IP | MAC table with margin, matching the tool's visual style."""
    rows = sorted(trusted.items(), key=lambda x: ipaddress.ip_address(x[0]))
    ip_w, mac_w = 15, 17
    sep = f"  +---+{'-' * (ip_w + 2)}+{'-' * (mac_w + 2)}+"
    print(COLOR_INFO + sep + COLOR_RESET)
    print(COLOR_INFO + f"  | # | {'IP':<{ip_w}} | {'MAC Address':<{mac_w}} |" + COLOR_RESET)
    print(COLOR_INFO + sep + COLOR_RESET)
    for i, (ip, mac) in enumerate(rows, 1):
        print(f"  | {i} | {ip:<{ip_w}} | {mac:<{mac_w}} |")
    print(COLOR_INFO + sep + COLOR_RESET)


def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return {}
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def log_alert(message):
    print(COLOR_ALERT + f"  [ALERT] {message}" + COLOR_RESET)
    logging.info(message)


def monitor(iface_name):
    if not require_l2_or_warn():
        return

    trusted = load_baseline()
    if not trusted:
        print(COLOR_WARN + "  [!] No baseline found. Build one first (menu option 2)." + COLOR_RESET)
        print()
        return

    print()
    print(COLOR_INFO + f"  [*] Monitoring ARP traffic on {iface_name}. Press Ctrl+C to stop." + COLOR_RESET)
    print(COLOR_INFO + f"  [*] This runs continuously in the background — it's normal for it to "
                        f"keep going with no alerts if nothing is wrong." + COLOR_RESET)
    print(COLOR_INFO + f"  [*] Actively re-checking {len(trusted)} known host(s) every "
                        f"{PROBE_INTERVAL_SECONDS}s so spoofing is caught quickly, "
                        f"not just when traffic happens to occur." + COLOR_RESET)
    print()

    # Tracks recent unsolicited ARP replies per source MAC, for flood/gratuitous detection
    recent_replies = defaultdict(lambda: deque())
    stop_event = threading.Event()
    stats = SHARED_STATE
    stats.update({"status": "active", "iface": iface_name, "replies_seen": 0, "verified_ok": 0})

    def check_flood(src_mac):
        now = time.time()
        dq = recent_replies[src_mac]
        dq.append(now)
        while dq and now - dq[0] > GRATUITOUS_ARP_WINDOW_SECONDS:
            dq.popleft()
        if len(dq) > GRATUITOUS_ARP_THRESHOLD:
            log_alert(
                f"Possible ARP flood / gratuitous ARP spam from {src_mac} "
                f"({len(dq)} replies in {GRATUITOUS_ARP_WINDOW_SECONDS}s)"
            )
            dq.clear()

    def handle_packet(pkt):
        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        if arp.op != 2:  # only interested in "is-at" replies
            return

        src_ip = arp.psrc
        src_mac = arp.hwsrc.lower()

        check_flood(src_mac)
        stats["replies_seen"] += 1

        known_mac = trusted.get(src_ip)
        if known_mac is None:
            # New host not in baseline — informational, not necessarily malicious
            print(COLOR_WARN + f"  [NEW] Unrecognized host joined: {src_ip} -> {src_mac} "
                                f"(not in baseline; rescan if this is expected)" + COLOR_RESET)
            return

        if known_mac != src_mac:
            log_alert(
                f"ARP spoofing suspected! {src_ip} is claimed by {src_mac}, "
                f"but baseline says it should be {known_mac}."
            )
        else:
            stats["verified_ok"] += 1

    def prober():
        """
        Passive sniffing alone depends on ARP traffic happening to occur, which can
        make the monitor look stuck on a quiet network. This actively re-requests
        every known host on a short interval so we get a fresh, timely reply to
        verify against the baseline instead of waiting indefinitely.
        """
        while not stop_event.is_set():
            for ip in list(trusted.keys()):
                try:
                    frame = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
                    sendp(frame, iface=iface_name, verbose=False)
                except Exception:
                    pass
            stop_event.wait(PROBE_INTERVAL_SECONDS)

    probe_thread = threading.Thread(target=prober, daemon=True)
    probe_thread.start()

    # AsyncSniffer runs the actual packet capture on its own thread and exposes
    # .stop(). Ctrl+C is much more reliable this way: the blocking C-level capture
    # call inside sniff() doesn't always hand control back to Python promptly
    # (especially on Windows/Npcap), so instead we keep the main thread in a plain
    # time.sleep() loop, which Python *always* interrupts cleanly on Ctrl+C.
    async_sniffer = AsyncSniffer(iface=iface_name, filter="arp", prn=handle_packet, store=False)

    try:
        async_sniffer.start()
    except PermissionError:
        print(COLOR_ALERT + "  [!] Permission denied. Run this tool as root/Administrator." + COLOR_RESET)
        stop_event.set()
        print()
        return
    except Exception as e:
        print(COLOR_ALERT + f"  [!] Could not start capture: {e}" + COLOR_RESET)
        stop_event.set()
        print()
        return

    last_heartbeat = time.time()
    try:
        while True:
            time.sleep(0.5)
            now = time.time()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL_SECONDS:
                stamp = datetime.now().strftime("%H:%M:%S")
                print(COLOR_INFO + f"  [*] Still monitoring... ({stamp}) "
                                    f"— {stats['replies_seen']} ARP replies checked, "
                                    f"{stats['verified_ok']} verified OK, "
                                    f"press Ctrl+C to stop." + COLOR_RESET)
                last_heartbeat = now
    except KeyboardInterrupt:
        print(COLOR_INFO + "\n  [*] Stopping... please wait." + COLOR_RESET)
    finally:
        stop_event.set()
        try:
            async_sniffer.stop()
        except Exception:
            pass
        SHARED_STATE["status"] = "inactive"
        print(COLOR_INFO + "  [*] Monitoring stopped." + COLOR_RESET)
    print()


def view_alert_log():
    print()
    if not os.path.exists(ALERT_LOG_FILE) or os.path.getsize(ALERT_LOG_FILE) == 0:
        print(COLOR_INFO + "  [i] No alerts logged yet." + COLOR_RESET)
        print()
        return
    print(COLOR_INFO + f"  --- {ALERT_LOG_FILE} ---" + COLOR_RESET)
    with open(ALERT_LOG_FILE) as f:
        for line in f.read().splitlines():
            print("  " + line)
    print()


def tail_alert_log(n=50):
    """Most recent alert lines first, for the dashboard feed."""
    if not os.path.exists(ALERT_LOG_FILE):
        return []
    with open(ALERT_LOG_FILE) as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    return lines[-n:][::-1]


DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Network Guardian Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#080b10; --bg-grid: rgba(79,209,255,0.035);
    --panel:#0e141c; --panel-2:#0c1119; --border:#1c2733; --border-soft:#141c26;
    --cyan:#4fd1ff; --cyan-dim:#1c6f8c; --blue:#3a86ff;
    --green:#2ee6a6; --amber:#ffc857; --red:#ff5c6c;
    --text:#c7d5e0; --text-dim:#5c7286; --text-faint:#38495a;
  }
  * { box-sizing: border-box; }
  body {
    background:
      linear-gradient(var(--bg-grid) 1px, transparent 1px) 0 0 / 100% 28px,
      linear-gradient(90deg, var(--bg-grid) 1px, transparent 1px) 0 0 / 28px 100%,
      var(--bg);
    color: var(--text); font-family: 'JetBrains Mono', 'Consolas', monospace;
    margin: 0; padding: 28px 32px 40px; min-height: 100vh;
  }

  .topbar { display:flex; align-items:center; justify-content:space-between; margin-bottom: 22px;
             padding-bottom: 18px; border-bottom: 1px solid var(--border); }
  .brand { display:flex; align-items:center; gap: 12px; }
  .brand-icon { width: 34px; height: 34px; border: 1.5px solid var(--cyan); border-radius: 8px;
                display:flex; align-items:center; justify-content:center; color: var(--cyan);
                font-size: 16px; box-shadow: 0 0 14px rgba(79,209,255,0.25); }
  h1 { color: var(--cyan); font-size: 19px; margin: 0; letter-spacing: 2px; font-weight: 700; }
  .sub { color: var(--text-dim); font-size: 11px; margin-top: 2px; letter-spacing: 0.5px; }
  .clock { text-align: right; }
  .clock .time { color: var(--text); font-size: 15px; letter-spacing: 1px; }
  .clock .date { color: var(--text-dim); font-size: 10px; margin-top: 2px; letter-spacing: 0.5px; }

  .status-row { display:grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-bottom: 24px; }
  @media (max-width: 900px) { .status-row { grid-template-columns: repeat(2, 1fr); } }
  .stat {
    background: var(--panel); border: 1px solid var(--border); border-left: 3px solid var(--border);
    border-radius: 6px; padding: 14px 16px; position: relative; overflow: hidden;
  }
  .stat.accent-cyan { border-left-color: var(--cyan); }
  .stat.accent-blue { border-left-color: var(--blue); }
  .stat.accent-green { border-left-color: var(--green); }
  .stat .label { color: var(--text-dim); font-size: 10px; text-transform: uppercase;
                 letter-spacing: 1.5px; margin-bottom: 8px; }
  .stat .value { font-size: 22px; font-weight: 700; color: var(--blue); line-height: 1;
                 white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .stat .value.on { color: var(--green); }
  .stat .value.off { color: var(--text-faint); }
  .pulse { display:inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 8px;
           position: relative; top: -1px; }
  .pulse.on { background: var(--green); box-shadow: 0 0 8px var(--green); animation: blink 1.4s infinite; }
  .pulse.off { background: var(--text-faint); }
  @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.35; } }

  .grid { display: grid; grid-template-columns: 1.1fr 1fr; gap: 18px; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
           padding: 0; overflow: hidden; }
  .panel-head { display:flex; align-items:center; justify-content:space-between;
                padding: 12px 16px; border-bottom: 1px solid var(--border); background: var(--panel-2); }
  .panel-head h2 { color: var(--cyan); font-size: 12px; margin: 0; letter-spacing: 1.5px;
                   text-transform: uppercase; font-weight: 700; }
  .count-badge { background: rgba(79,209,255,0.08); color: var(--cyan); border: 1px solid var(--cyan-dim);
                 font-size: 10px; padding: 2px 9px; border-radius: 20px; letter-spacing: 0.5px; }
  .panel-body { padding: 6px 0; max-height: 420px; overflow-y: auto; }

  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { text-align: left; color: var(--text-dim); font-weight: 700; padding: 8px 16px;
       border-bottom: 1px solid var(--border); font-size: 10px; letter-spacing: 1px; text-transform: uppercase; }
  td { padding: 9px 16px; border-bottom: 1px solid var(--border-soft); color: var(--text); }
  tr:hover td { background: rgba(79,209,255,0.03); }
  td.idx { color: var(--text-faint); width: 30px; }
  td.mac { color: var(--cyan); letter-spacing: 0.5px; }

  .alert-item { padding: 10px 16px; border-bottom: 1px solid var(--border-soft);
                border-left: 3px solid var(--red); font-size: 11.5px; color: #ffb3ba; line-height: 1.5; }
  .alert-item .tag { color: var(--red); font-weight: 700; letter-spacing: 1px; font-size: 10px;
                      display:block; margin-bottom: 3px; }

  .empty { color: var(--text-faint); font-style: italic; padding: 22px 16px; font-size: 12px; text-align: center; }
</style>
</head>
<body>

  <div class="topbar">
    <div class="brand">
      <div class="brand-icon">&#9737;</div>
      <div>
        <h1>NETWORK GUARDIAN</h1>
        <div class="sub">ARP SPOOFING / MITM DETECTION &mdash; LIVE FEED</div>
      </div>
    </div>
    <div class="clock">
      <div class="time" id="clock-time">--:--:--</div>
      <div class="date" id="clock-date">-- --- ----</div>
    </div>
  </div>

  <div class="status-row" id="stats"></div>

  <div class="grid">
    <div class="panel">
      <div class="panel-head">
        <h2>Trusted Devices</h2>
        <span class="count-badge" id="device-count">0</span>
      </div>
      <div class="panel-body">
        <table id="devices"><thead><tr><th>#</th><th>IP Address</th><th>MAC Address</th></tr></thead>
        <tbody></tbody></table>
      </div>
    </div>
    <div class="panel">
      <div class="panel-head">
        <h2>Alert Feed</h2>
        <span class="count-badge" id="alert-count">0</span>
      </div>
      <div class="panel-body" id="alerts"></div>
    </div>
  </div>

<script>
function tickClock() {
  const now = new Date();
  document.getElementById('clock-time').textContent = now.toLocaleTimeString('en-GB');
  document.getElementById('clock-date').textContent = now.toLocaleDateString('en-US',
    { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' });
}
tickClock();
setInterval(tickClock, 1000);

async function refresh() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();

    const statusOn = data.status === 'active';
    document.getElementById('stats').innerHTML = `
      <div class="stat accent-${statusOn ? 'green' : 'cyan'}">
        <div class="label">Spoof Detection</div>
        <div class="value ${statusOn ? 'on' : 'off'}">
          <span class="pulse ${statusOn ? 'on' : 'off'}"></span>${statusOn ? 'ACTIVE' : 'INACTIVE'}
        </div>
      </div>
      <div class="stat accent-cyan">
        <div class="label">Interface</div>
        <div class="value" style="font-size:13px" title="${data.iface || ''}">${data.iface || '\u2014'}</div>
      </div>
      <div class="stat accent-blue">
        <div class="label">Replies Checked</div>
        <div class="value">${data.replies_seen}</div>
      </div>
      <div class="stat accent-blue">
        <div class="label">Verified OK</div>
        <div class="value">${data.verified_ok}</div>
      </div>
      <div class="stat accent-cyan">
        <div class="label">Known Devices</div>
        <div class="value">${data.devices.length}</div>
      </div>
    `;

    document.getElementById('device-count').textContent = data.devices.length;
    const tbody = document.querySelector('#devices tbody');
    tbody.innerHTML = data.devices.length
      ? data.devices.map((d,i) => `<tr><td class="idx">${i+1}</td><td>${d.ip}</td><td class="mac">${d.mac}</td></tr>`).join('')
      : '<tr><td colspan="3" class="empty">No baseline yet &mdash; run a scan first.</td></tr>';

    document.getElementById('alert-count').textContent = data.alerts.length;
    const alertsDiv = document.getElementById('alerts');
    alertsDiv.innerHTML = data.alerts.length
      ? data.alerts.map(a => `<div class="alert-item"><span class="tag">&#9888; ALERT</span>${a}</div>`).join('')
      : '<div class="empty">No alerts yet. All quiet.</div>';
  } catch (e) {
    console.error(e);
  }
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


def start_dashboard(port=5000):
    try:
        from flask import Flask, jsonify, Response
    except ImportError:
        print(COLOR_ALERT + "  [!] Flask is not installed. Run: pip install flask" + COLOR_RESET)
        print()
        return

    app = Flask(__name__)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # keep Flask's request log out of the CLI

    @app.route("/")
    def index():
        return Response(DASHBOARD_HTML, mimetype="text/html")

    @app.route("/api/status")
    def api_status():
        trusted = load_baseline()
        devices = [
            {"ip": ip, "mac": mac}
            for ip, mac in sorted(trusted.items(), key=lambda x: ipaddress.ip_address(x[0]))
        ]
        return jsonify({
            "status": SHARED_STATE.get("status", "inactive"),
            "iface": SHARED_STATE.get("iface"),
            "replies_seen": SHARED_STATE.get("replies_seen", 0),
            "verified_ok": SHARED_STATE.get("verified_ok", 0),
            "devices": devices,
            "alerts": tail_alert_log(50),
        })

    def run():
        try:
            app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
        except Exception as e:
            print(COLOR_ALERT + f"  [!] Dashboard failed to start: {e}" + COLOR_RESET)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    time.sleep(0.3)  # give Flask a moment to bind before printing success

    print()
    print(COLOR_OK + f"  [+] Dashboard running at http://127.0.0.1:{port}" + COLOR_RESET)
    print(COLOR_INFO + "  [*] It keeps running in the background — open that URL in your browser." + COLOR_RESET)
    print(COLOR_INFO + "  [*] It'll show live data once you scan (option 2) and/or monitor (option 3)." + COLOR_RESET)
    print()


def main_menu():
    banner()
    iface_name = None

    monitoring_status = "inactive"

    while True:
        baseline = load_baseline()
        print()
        divider()
        print(COLOR_WARN + f"  [*] Spoof Detection: {monitoring_status}" + COLOR_RESET)
        divider()
        print(f"  [1]  Select network interface")
        print(f"  [2]  Scan network (build trusted baseline)")
        print(f"  [3]  Start ARP spoofing / MITM monitor")
        print(f"  [4]  View alert log")
        print(f"  [5]  Launch web dashboard")
        print(f"  [6]  Exit")
        divider()
        print()
        choice = input(COLOR_INFO + "  [>] Select an option: " + COLOR_RESET).strip()
        print()

        if choice == "1":
            iface_name = choose_interface()
        elif choice == "2":
            if not iface_name:
                print(COLOR_WARN + "  [!] Select an interface first (option 1)." + COLOR_RESET)
                print()
                continue
            build_baseline(iface_name)
        elif choice == "3":
            if not iface_name:
                print(COLOR_WARN + "  [!] Select an interface first (option 1)." + COLOR_RESET)
                print()
                continue
            monitoring_status = "active"
            monitor(iface_name)
            monitoring_status = "inactive"
        elif choice == "4":
            view_alert_log()
        elif choice == "5":
            start_dashboard()
        elif choice == "6":
            print(COLOR_INFO + "  Goodbye." + COLOR_RESET)
            print()
            break
        else:
            print(COLOR_WARN + "  [!] Invalid choice." + COLOR_RESET)
            print()


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(COLOR_INFO + "\nInterrupted. Exiting." + COLOR_RESET)
        sys.exit(0)
