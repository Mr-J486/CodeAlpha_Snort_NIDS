🛡️ Snort-based Network Intrusion Detection System (NIDS)
This project demonstrates a network-based intrusion detection system using Snort, implemented as part of my Cybersecurity Internship at CodeAlpha. The system is configured to monitor traffic in real-time, detect malicious activity, and generate alerts for suspicious behavior on the network.

⚙️ Features
🔍 Live Network Monitoring using Snort

📜 Custom Rule Configuration for:

ICMP Ping detection

RDP, SSH, TELNET connection attempts

🛎️ Real-time Alerting to terminal and log files

🧠 Attack Simulation using tools like Nmap

📁 Alert Logging for incident review

📊 (Optional) Visualization of captured alerts

🧠 Detection Rules Used
snort
Copy
Edit
alert tcp any any -> $HOME_NET 3389 (msg:"RDP Connection Initiation"; sid:1;)
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Request"; sid:2; rev:1;)
alert icmp $HOME_NET any -> any any (msg:"ICMP Ping Reply"; sid:3; rev:1;)
alert tcp any any -> $HOME_NET 23 (msg:"TELNET Connection Attempt"; sid:4; rev:1;)
alert tcp any any -> $HOME_NET 22 (msg:"SSH Handshake"; sid:5; rev:1;)
These rules were saved in local.rules and included via snort.lua.

🧪 Attack Scenario
Simulated an Nmap scan from an attacker machine:

Attacker IP: 192.168.1.8

Victim IP: 192.168.1.9

Snort was run on the victim machine with:

bash
Copy
Edit
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast
🗂️ Directory Structure
bash
Copy
Edit
📦Snort-NIDS-Task
 ┣ 📁rules/
 ┃ ┗ 📄local.rules
 ┣ 📄snort.lua       # Configuration file
 ┣ 📄README.md
 ┗ 📄demo.mp4        # Optional: video demonstration
🚀 How to Run
Install Snort (Version 3.x recommended)

Update snort.lua to include the custom local.rules file

Set your HOME_NET in snort.lua (e.g., 192.168.1.9/32)

Launch Snort in alert mode:

bash
Copy
Edit
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast
Simulate an attack (e.g., using Nmap) from a second device

Monitor the terminal or /var/log/snort/alert_fast.txt

🧾 Logs & Alerts
Alerts are printed in real-time to the terminal

You can redirect output to a file using:

bash
Copy
Edit
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast > alerts.txt
🧠 Learning Outcomes
Understanding of NIDS components and Snort architecture

Rule writing for protocol-based threat detection

Real-time monitoring and threat alerting

Attack simulation and detection testing
