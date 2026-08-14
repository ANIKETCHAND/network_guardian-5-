# 🛡️ Network Guardian

```text
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

A **defensive** Python tool that detects ARP spoofing and Man-in-the-Middle (MITM)
activity on your local network. It only listens — it never redirects, intercepts,
or harvests traffic.

> ⚠️ For use on networks you own or are explicitly authorized to monitor.

---

## How it works

1. **Baseline scan** — actively ARP-scans your subnet and records a trusted
   `IP -> MAC` table (`trusted_hosts.json`).
2. **Live monitor** — sniffs ARP replies on the wire and compares every
   `IP -> MAC` claim against the baseline.
   - If an IP suddenly claims a **different MAC** than the baseline says →
     classic sign of ARP cache poisoning → logged as an `[ALERT]`.
   - If one MAC address sends an unusually high rate of unsolicited ARP
     replies in a short window → possible ARP flood/spoofing tool running →
     logged as an `[ALERT]`.
   - Brand-new hosts not in the baseline are flagged as informational
     (`[NEW]`), since that's normal when devices join the network.
3. **Alert log** — every alert is timestamped and written to `alerts.log`
   for later review.

## Install

```bash
pip install -r requirements.txt
```

Scapy needs raw packet access:
- **Linux/macOS**: run with `sudo`
- **Windows**: install [Npcap](https://npcap.com/#download) and run the
  terminal as Administrator

## Usage

```bash
sudo python network_guardian.py      # Linux / macOS
python network_guardian.py           # Windows (as Administrator)
```

Menu flow:

```
[1] Select network interface
[2] Build / refresh trusted baseline (ARP scan)
[3] Start ARP spoofing / MITM monitor
[4] View alert log
[5] Exit
```

Typical session: select your interface → build a baseline while the network
is known-clean → start the monitor → leave it running → check `alerts.log`
or the live console output for anything suspicious.

## Notes & limitations

- This detects ARP-layer spoofing specifically. It's a good project piece
  for demonstrating LAN threat detection, but it isn't a full IDS.
- Rebuild the baseline whenever you add/replace hardware on the network,
  or you'll get `[NEW]` notices for legitimate devices.
- The flood threshold (`GRATUITOUS_ARP_THRESHOLD` in the script) can be
  tuned — busy networks with lots of DHCP churn may need a higher value.

## License

MIT — for educational and authorized defensive use.
