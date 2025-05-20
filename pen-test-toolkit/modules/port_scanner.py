# modules/port_scanner.py

import socket
import threading

def scan_port(target_ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"[+] Port {port} is OPEN")
    except Exception as e:
        print(f"[-] Error scanning port {port}: {e}")

def run_port_scanner(target_ip, start_port=1, end_port=1024):
    print(f"[*] Scanning {target_ip} from port {start_port} to {end_port}...\n")

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target_ip, port))
        threads.append(t)
        t.start()

    for thread in threads:
        thread.join()

    print("\n[*] Port scan complete.")
