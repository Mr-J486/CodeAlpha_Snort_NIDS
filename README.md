# 🛡️ Snort-based Network Intrusion Detection System (NIDS)

A hands-on project from my Cybersecurity Internship at CodeAlpha, showcasing how to detect real-time network threats using custom Snort v3 rules.

## ✨ Features

- Real-time packet monitoring on a live network
- Custom rules for detecting:
  - SSH, TELNET, RDP connections
  - ICMP Ping (requests/replies)
  - Nmap port scans
- Alert logging for analysis

## ⚙️ Technologies Used

- Snort v3
- Linux (Ubuntu/Kali)
- Nmap (attack simulation)

## 🕸️ Network Setup

- Attacker: `192.168.1.8` (used Nmap)
- Victim: `192.168.1.9` (running Snort)

## 🔐 Snort Rules Example

snort
```alert tcp any any -> $HOME_NET 3389 (msg:"RDP Connection Initiation"; sid:1;)
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Request"; sid:2; rev:1;)
alert icmp $HOME_NET any -> any any (msg:"ICMP Ping Reply"; sid:3; rev:1;)
alert tcp any any -> $HOME_NET 23 (msg:"TELNET Connection Attempt"; sid:4; rev:1;)
alert tcp any any -> $HOME_NET 22 (msg:"SSH Handshake"; sid:5; rev:1;)
```
🚀 How to Run
Place your rules in /etc/snort/rules/local.rules

Link the file inside /etc/snort/snort.lua

Run Snort:

bash
Copy
Edit
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast
💾 Save Alerts
bash
Copy
Edit
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast > alerts.txt
🎥 Demo
Demo video is attached showing attack simulation and alert detection.

📚 What I Learned
Writing Snort v3 rules

Simulating attacks using Nmap

Real-time traffic monitoring

Configuring and running a modern IDS

📂 Project Structure
bash
Copy
Edit
📦 Snort-NIDS
 ┣ 📄 snort.lua
 ┣ 📄 rules/local.rules
 ┣ 📄 alerts.txt
 ┣ 📄 demo.mp4
 ┗ 📄 README.md
