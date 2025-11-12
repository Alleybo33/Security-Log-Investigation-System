# 🔍 System Log Investigation System (SLIS)

[![Python](https://img.shields.io/badge/Python-3.x-blue)](https://www.python.org/)  
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)  
[![Status](https://img.shields.io/badge/Status-Stable-success)]()

A Python-based **CLI log triage tool** for incident responders and SOC analysts.  
SLIS automates the investigation of web server access logs by producing actionable reports on **top offender IPs**, **User-Agent anomalies**, and **known scanner signatures**.

---

## ✅ Features
✔ Automated full triage (`full-report`) — finds the noisiest IP and runs a deep-dive.  
✔ `top-ips` — top 20 most frequent source IPs.  
✔ `top-ua` — top 20 most frequent User-Agents.  
✔ `scanners` — detect known scanner/tool signatures (sqlmap, nikto, gobuster, etc.).  
✔ `ip-report` — detailed timeline and activity for a single IP.  
✔ Flexible output: console or saved to file.  
✔ Lightweight single-file Python script — no external dependencies.

---

## ⚠ Requirements
- **Python 3.8+**  
- Read access to the webserver access log file (e.g., `/var/log/nginx/access.log`)  
- Shell utilities (`grep`, `awk`, `sort`, `uniq`) — standard on Linux/macOS.  

> SLIS is designed to work without extra Python packages; some modules may rely on basic shell commands.

---

## ✅ Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/Alleybo33/Security-Log-Investigation-System.git
cd Security-Log-Investigation-System

2. Make the Script Executable
chmod +x slis.py

💻 Usage
./slis.py -d <logfile> -t <type> [options]

Arguments

-d, --directory — (required) path to the access log file.

-t, --type — (required) analysis type: full-report, top-ips, top-ua, scanners, ip-report.

-i, --ip — (optional) specific IP (required for ip-report).

-o, --output — (optional) file to write output to (silences console output).

Examples

Run a full automated report:

./slis.py -d /var/log/nginx/access.log -t full-report


Run a full report and save to file:

./slis.py -d /var/log/apache2/access.log -t full-report -o investigation-01.txt


Check for known scanners:

./slis.py -d access.log -t scanners


Investigate a specific suspicious IP:

./slis.py -d access.log -t ip-report -i 172.21.0.1

🔮 Future Features

 Add -t sqli module to detect common SQL injection patterns

 Add -t cmdi module for command injection detection

 Implement native Python log parsing for cross-platform portability

 Detect modern web attacks (GraphQL abuse, API fuzzing)

🧑‍💻 Author

Developed by @Alleybo33
