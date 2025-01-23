# 🕵️‍♂️ Honeypot Detection Tool

## 📌 Overview
Honeypots are decoy systems designed to detect, deflect, or study cyber attacks. This tool helps penetration testers identify whether a target system is a honeypot by using multiple detection techniques, including:

- **Banner Grabbing**: Checking for known honeypot service banners.  
- **Shodan API Lookup**: Querying Shodan for honeypot indicators.  
- **Nmap Scanning**: Identifying unusual service fingerprints.  
- **TCP Packet Analysis**: Sending SYN packets and analyzing responses.  

---

## ⚠️ Disclaimer
> **This tool is intended for educational and research purposes only.**  
> Unauthorized scanning or penetration testing of systems you do not own or have explicit permission to test may be illegal.  
> The author is not responsible for any misuse of this tool.  

---

## 🚀 Features
✔ Detects honeypot banners (Cowrie, Kippo, Dionaea, etc.).  
✔ Queries **Shodan API** for honeypot-related information.  
✔ Uses **Nmap** to scan for unusual services.  
✔ Sends **SYN packets** to analyze TCP responses.  

---

## 🛠 Installation
### 🔹 Prerequisites
- **Python 3.x**  
- **pip** installed  
- **Shodan API Key** (optional but recommended)  
- **Nmap** installed on your system  

### 🔹 Install Dependencies
```bash
pip install shodan scapy
