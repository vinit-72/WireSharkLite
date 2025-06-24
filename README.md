# LAN Packet Sniffer and Analyzer (Wireshark Lite)

A simplified LAN packet sniffer and analyzer built using Python and Scapy. This tool captures network packets, extracts protocol-level details (TCP, UDP, DNS), and logs them into a CSV file for further inspection — similar in concept to Wireshark.

---

## 🚀 Features

- Live packet capture using `scapy`
- Supports filters: TCP, UDP, IP, DNS (via BPF syntax)
- Extracts:
  - Source/Destination IP
  - Ports (TCP/UDP)
  - Protocol type
  - Timestamp
- Saves data to `packet_log.csv`
- Command-line interface

---

## 🛠 Requirements

- Python 3.8+
- [`scapy`](https://pypi.org/project/scapy/):
  ```bash
  pip install scapy
