import socket
import shodan
import subprocess
import scapy.all as scapy

SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"

HONEYPOT_BANNERS = ["Cowrie", "Kippo", "Dionaea", "Honeyd", "Glastopf"]

def get_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner
    except:
        return None

def check_honeypot_banner(ip):
    suspicious_ports = [22, 23, 80, 443, 445, 3389]
    for port in suspicious_ports:
        banner = get_banner(ip, port)
        if banner:
            print(f"[+] Banner on {ip}:{port} -> {banner}")
            for honeypot in HONEYPOT_BANNERS:
                if honeypot.lower() in banner.lower():
                    print(f"[!] Possible honeypot detected: {honeypot} on {ip}:{port} 🚨")
                    return True
    return False

def check_shodan(ip):
    if not SHODAN_API_KEY:
        print("[!] You have not set up a Shodan API Key.")
        return None
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        result = api.host(ip)
        print(f"[+] Shodan information for {ip}:")
        print(f"    - ISP: {result.get('isp', 'N/A')}")
        print(f"    - Organization: {result.get('org', 'N/A')}")
        print(f"    - Open Ports: {result.get('ports', [])}")
        
        # Checking for honeypot indicators
        if "honeypot" in result:
            print(f"[!] Shodan reports {ip} as a honeypot! 🚨")
            return True
        return False
    except shodan.APIError as e:
        print(f"[X] Shodan Error: {e}")
        return None

def scan_nmap(ip):
    try:
        print(f"[+] Running Nmap scan on {ip}...")
        result = subprocess.run(["nmap", "-sV", "-Pn", ip], capture_output=True, text=True)
        print(result.stdout)

        # Checking for suspicious results
        if "Cowrie" in result.stdout or "Honeypot" in result.stdout:
            print(f"[!] Nmap detected a possible honeypot on {ip}! 🚨")
            return True
        return False
    except Exception as e:
        print(f"[X] Nmap scan failed: {e}")
        return None

def analyze_packets(ip):
    print(f"[+] Sending SYN packet to {ip}...")
    try:
        response = scapy.sr1(scapy.IP(dst=ip)/scapy.TCP(dport=80, flags="S"), timeout=3, verbose=False)
        if response and response.haslayer(scapy.TCP):
            if response.getlayer(scapy.TCP).flags == 0x12:  
                print(f"[+] {ip} responded with SYN-ACK (normal behavior).")
            elif response.getlayer(scapy.TCP).flags == 0x14: 
                print(f"[!] {ip} responded with RST-ACK (possible honeypot)!")
                return True
        else:
            print(f"[!] No response from {ip}, could be a honeypot!")
            return True
    except Exception as e:
        print(f"[X] Packet analysis failed: {e}")
        return None

def detect_honeypot(ip):
    print(f"[*] Starting honeypot detection for {ip}...\n")
    
    banner_result = check_honeypot_banner(ip)
    shodan_result = check_shodan(ip)
    nmap_result = scan_nmap(ip)
    packet_result = analyze_packets(ip)

    if any([banner_result, shodan_result, nmap_result, packet_result]):
        print(f"\n🚨 [ALERT] {ip} is likely a honeypot! 🚨")
    else:
        print(f"\n✅ {ip} does not appear to be a honeypot.")

target_ip = "192.168.1.1"  
detect_honeypot(target_ip)
