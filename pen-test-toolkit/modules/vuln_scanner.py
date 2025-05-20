# modules/vuln_scanner.py

import socket

# Common services and their default ports
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
}

def grab_banner(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((ip, port))
            return s.recv(1024).decode().strip()
    except:
        return None

def run_vuln_scan(target_ip):
    print(f"[*] Starting vulnerability scan on {target_ip}...\n")

    for port, service in COMMON_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    print(f"[+] Port {port} ({service}) is OPEN")
                    banner = grab_banner(target_ip, port)
                    if banner:
                        print(f"    └─ Banner: {banner}")
                        # Simple vulnerability check
                        if "vsftpd 2.3.4" in banner:
                            print("    [!] Vulnerable: vsftpd 2.3.4 has a known backdoor (CVE-2011-2523)")
        except Exception as e:
            print(f"[-] Error scanning port {port}: {e}")

    print("\n[*] Scan complete.")
