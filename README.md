<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f2027,50:203a43,100:2c5364&height=220&section=header&text=NETWORK%20GUARDIAN&fontSize=55&fontColor=00FF9C&animation=fadeIn&desc=Real-Time%20ARP%20Spoofing%20%26%20MITM%20Detection%20Engine&descAlignY=68&descSize=18" width="100%" alt="Network Guardian banner"/>

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=22&duration=3000&pause=800&color=00FF9C&center=true&vCenter=true&width=650&lines=%F0%9F%9B%A1%EF%B8%8F+Defending+your+LAN%2C+one+ARP+packet+at+a+time;%F0%9F%94%8D+Detects+ARP+Spoofing+%7C+MITM+%7C+ARP+Floods;%E2%9A%A1+Built+with+Python+%2B+Scapy+%2B+Flask" alt="Typing SVG"/>

</div>

<br/>

```
 ▄▄▄▄▄▄▄▄▄▄▄
█           █
 ▀▄▄▄▄▄▄▄▄▄▀
  █       █
   ▀▄▄▄▄▄▀
    █   █
     ▀▄▀

███╗   ██╗███████╗████████╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║       ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
██║╚██╗██║██╔══╝     ██║       ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
██║ ╚████║███████╗   ██║       ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝        ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-Packet%20Sniffing-EE0000?style=for-the-badge&logo=wireshark&logoColor=white)](https://scapy.net/)
[![Flask](https://img.shields.io/badge/Flask-Web%20Dashboard-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Colorama](https://img.shields.io/badge/Colorama-CLI%20Styling-FFDD00?style=for-the-badge)](https://pypi.org/project/colorama/)
[![Npcap](https://img.shields.io/badge/Npcap-Windows%20Capture-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://npcap.com/)

[![License](https://img.shields.io/github/license/ANIKETCHAND/network_guardian-5-?style=for-the-badge&color=2ea44f)](LICENSE)
[![Stars](https://img.shields.io/github/stars/ANIKETCHAND/network_guardian-5-?style=for-the-badge&color=yellow)](https://github.com/ANIKETCHAND/network_guardian-5-/stargazers)
[![Forks](https://img.shields.io/github/forks/ANIKETCHAND/network_guardian-5-?style=for-the-badge&color=orange)](https://github.com/ANIKETCHAND/network_guardian-5-/network/members)
[![Issues](https://img.shields.io/github/issues/ANIKETCHAND/network_guardian-5-?style=for-the-badge&color=red)](https://github.com/ANIKETCHAND/network_guardian-5-/issues)

<sub>🐧 Linux &nbsp;|&nbsp; 🍎 macOS &nbsp;|&nbsp; 🪟 Windows &nbsp;— &nbsp;runs anywhere Python + Npcap/libpcap does</sub>

</div>

<br/>

**Network Guardian** is a **defensive**, terminal-first Python tool that watches your local network for **ARP spoofing** and **Man-in-the-Middle (MITM)** activity in real time. It builds a trusted baseline of every device on your LAN, then continuously listens for ARP traffic that doesn't match — the classic signature of an attacker trying to poison your ARP cache and hijack traffic.

> [!IMPORTANT]
> Network Guardian **only listens**. It never redirects, intercepts, injects, or harvests traffic. It is a *detector*, not an attack tool.

> [!WARNING]
> For use only on networks you **own** or are **explicitly authorized** to monitor. Unauthorized network monitoring may be illegal in your jurisdiction.

---

## 📚 Table of Contents

- [✨ Features](#-features)
- [🧠 How It Works](#-how-it-works)
- [🔁 Detection Flow](#-detection-flow)
- [🛠️ Tech Stack](#️-tech-stack)
- [📦 Installation](#-installation)
- [▶️ Usage](#️-usage)
- [🚨 Example Alert](#-example-alert)
- [🌐 Web Dashboard](#-web-dashboard)
- [🧊 Roadmap](#-roadmap)
- [⚠️ Notes & Limitations](#️-notes--limitations)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 📡 | **Baseline Scanning** | Actively ARP-scans your subnet and records a trusted `IP → MAC` table |
| 👁️ | **Live ARP Monitoring** | Continuously sniffs ARP replies on the wire, comparing every claim to the baseline |
| 🚨 | **Spoofing Detection** | Flags an IP that suddenly claims a *different* MAC than the baseline — classic ARP cache poisoning |
| 🌊 | **Flood Detection** | Flags a MAC sending unusually high rates of unsolicited ARP replies — a common spoofing-tool fingerprint |
| 🆕 | **New Host Alerts** | Informational flags for brand-new devices that join the network (normal, not an attack) |
| 📝 | **Persistent Alert Log** | Every alert is timestamped and written to `alerts.log` for later review |
| 🌐 | **Web Dashboard** | Optional Flask-powered browser view of live alerts |
| 🎨 | **Colorized CLI** | Colorama-powered terminal output that's easy to scan at a glance |

---

## 🧠 How It Works

1. **Baseline scan** — actively ARP-scans your subnet and records a trusted `IP → MAC` table (`trusted_hosts.json`).
2. **Live monitor** — sniffs ARP replies on the wire and compares every `IP → MAC` claim against the baseline.
   - A different MAC claiming a known IP → logged as an **`[ALERT]`** (cache poisoning).
   - Abnormally high unsolicited ARP reply rate from one MAC → logged as an **`[ALERT]`** (flood / spoofing tool).
   - A brand-new host not in the baseline → logged as **`[NEW]`** (informational — normal when devices join).
3. **Alert log** — every alert is timestamped and written to `alerts.log`.

## 🔁 Detection Flow

```mermaid
flowchart TD
    A["🔌 Select Network Interface"] --> B["📡 Baseline ARP Scan"]
    B --> C[("trusted_hosts.json")]
    C --> D["👁️ Live ARP Monitor"]
    D --> E{"IP → MAC matches baseline?"}
    E -->|✅ Match| F["Normal traffic — no action"]
    E -->|⚠️ Mismatch| G["🚨 ALERT: ARP spoofing / cache poisoning"]
    E -->|🆕 Unknown IP| H["ℹ️ NEW: unseen host notice"]
    D --> I{"Unsolicited ARP rate"}
    I -->|High volume| J["🚨 ALERT: ARP flood / MITM tool"]
    G --> K["📝 alerts.log"]
    J --> K
    H --> K
    K --> L["🖥️ CLI Console"]
    K --> M["🌐 Web Dashboard"]
```

<details>
<summary>🎬 Sequence view — a spoofing attempt getting caught</summary>

```mermaid
sequenceDiagram
    actor Attacker
    participant LAN as Local Network
    participant Guardian as Network Guardian
    participant Log as alerts.log

    Attacker->>LAN: Sends spoofed ARP reply (fake MAC for gateway IP)
    LAN->>Guardian: ARP traffic observed on the wire
    Guardian->>Guardian: Compare claimed IP → MAC vs trusted baseline
    Guardian-->>Guardian: Mismatch found!
    Guardian->>Log: Write timestamped [ALERT]
    Guardian->>Guardian: Push alert to console + dashboard
```

</details>

---

## 🛠️ Tech Stack

<div align="center">

| Technology | Role in the project |
|---|---|
| ![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) | Core language |
| ![Scapy](https://img.shields.io/badge/Scapy-EE0000?style=flat-square&logo=wireshark&logoColor=white) | ARP scanning, sniffing & packet crafting |
| ![Flask](https://img.shields.io/badge/Flask-000000?style=flat-square&logo=flask&logoColor=white) | Lightweight web dashboard |
| ![Colorama](https://img.shields.io/badge/Colorama-FFDD00?style=flat-square&logoColor=white) | Cross-platform colored terminal output |
| ![JSON](https://img.shields.io/badge/JSON-000000?style=flat-square&logo=json&logoColor=white) | `trusted_hosts.json` baseline storage |
| ![Npcap](https://img.shields.io/badge/Npcap-0078D6?style=flat-square&logo=windows&logoColor=white) | Raw packet capture driver on Windows |

</div>

---

## 📦 Installation

```bash
git clone https://github.com/ANIKETCHAND/network_guardian-5-.git
cd network_guardian-5-
pip install -r requirements.txt
```

Scapy needs raw packet access:

| Platform | Requirement |
|---|---|
| 🐧 Linux / 🍎 macOS | Run with `sudo` |
| 🪟 Windows | Install [Npcap](https://npcap.com/#download) and run the terminal **as Administrator** |

---

## ▶️ Usage

```bash
sudo python network_guardian.py      # Linux / macOS
python network_guardian.py           # Windows (as Administrator)
```

| # | Menu Option |
|---|---|
| 1 | 🔌 Select network interface |
| 2 | 📡 Scan network (build trusted baseline) |
| 3 | 👁️ Start ARP spoofing / MITM monitor |
| 4 | 📜 View alert log |
| 5 | 🌐 Launch web dashboard |
| 6 | 🚪 Exit |

**Typical session:** select your interface → build a baseline while the network is known-clean → start the monitor → leave it running → check `alerts.log` or the live console for anything suspicious.

## 🚨 Example Alert

*(illustrative format — actual fields depend on your run)*

```text
[2026-08-14 10:32:17] [ALERT] Possible ARP spoofing detected!
    IP            : 192.168.1.1
    Baseline MAC  : AA:BB:CC:11:22:33
    Current MAC   : DE:AD:BE:EF:00:11
    >>> Someone may be impersonating your gateway!
```

## 🌐 Web Dashboard

Option `[5]` launches a lightweight **Flask** web dashboard so you can watch alerts and host status from a browser instead of the terminal — handy for keeping the monitor running headless while you check in from another device on the LAN.

---

## 🧊 Roadmap

Ideas for where Network Guardian could go next — contributions welcome!

- [ ] 🧊 **3D live network topology map** — an interactive Three.js/WebGL graph rendering every host as a node in 3D space, with links that pulse red the instant spoofing is detected
- [ ] 📧 Email / Telegram / Slack alert notifications
- [ ] 🏷️ GeoIP + vendor (OUI) lookup for flagged hosts
- [ ] 🗄️ SQLite/PostgreSQL persistence for historical alerts
- [ ] 📊 Exportable PDF/CSV incident reports
- [ ] 🧠 Confidence scoring for alerts (reduce false positives on noisy DHCP networks)
- [ ] 🌐 Multi-subnet / VLAN monitoring support

> The 3D topology view above is a **planned enhancement**, not yet implemented — flagged here so it's easy to track and pick up.

---

## ⚠️ Notes & Limitations

- This detects **ARP-layer** spoofing specifically. It's a strong project piece for demonstrating LAN threat detection, but it isn't a full IDS.
- Rebuild the baseline whenever you add/replace hardware on the network, or you'll get `[NEW]` notices for legitimate devices.
- The flood threshold (`GRATUITOUS_ARP_THRESHOLD` in the script) can be tuned — busy networks with lots of DHCP churn may need a higher value.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

```bash
# 1. Fork the repo
# 2. Create your feature branch
git checkout -b feature/amazing-feature
# 3. Commit your changes
git commit -m "Add amazing feature"
# 4. Push and open a Pull Request
git push origin feature/amazing-feature
```

## 📜 License

Distributed under the **MIT License** — for educational and authorized defensive use. See [`LICENSE`](LICENSE) for details.

---

<div align="center">

### ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=ANIKETCHAND/network_guardian-5-&type=Date)](https://star-history.com/#ANIKETCHAND/network_guardian-5-&Date)

Made with 🛡️ by [**ANIKETCHAND**](https://github.com/ANIKETCHAND)

*If Network Guardian helped you learn something about network security, consider giving it a ⭐!*

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:2c5364,50:203a43,100:0f2027&height=100&section=footer" width="100%" alt="footer wave"/>

</div>
