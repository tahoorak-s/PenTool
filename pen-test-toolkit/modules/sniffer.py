# modules/sniffer.py

from scapy.all import sniff, IP, TCP, UDP, ARP
from datetime import datetime

def process_packet(packet):
    timestamp = datetime.now().strftime('%H:%M:%S')
    
    if IP in packet:
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "IP"
        print(f"[{timestamp}] {packet[IP].src} → {packet[IP].dst} | {proto}")
    elif ARP in packet:
        print(f"[{timestamp}] ARP: {packet[ARP].psrc} → {packet[ARP].pdst}")

def run_sniffer(interface, packet_count):
    print(f"[*] Sniffing on {interface} for {packet_count} packets...\n")
    try:
        sniff(iface=interface, prn=process_packet, count=packet_count)
    except Exception as e:
        print(f"[-] Error: {e}")
