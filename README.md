# 🕵️‍♂️ Packet Sniffer in Python

A lightweight network packet sniffer built in Python using raw sockets.  
It captures and analyzes Ethernet, IPv4, ICMP, TCP, and UDP traffic in real time.

## 🚀 Features
- Captures all incoming packets on the network interface
- Extracts and displays:
  - MAC addresses
  - IP headers
  - TCP/UDP ports and flags
  - ICMP message types
- Pretty-print packet data in a readable hex format

## 📦 Requirements
- Python 3.x
- Linux OS (uses `AF_PACKET`, which is Linux-specific)
- Run with root privileges (`sudo`) to capture raw packets

## 🧪 How to Run

```bash
sudo python3 python-sniffer.py
