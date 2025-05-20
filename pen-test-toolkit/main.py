# main.py

import argparse
from modules import port_scanner
from modules import brute_forcer
from modules import hash_cracker
from modules import vuln_scanner
from modules import sniffer

def main():
    parser = argparse.ArgumentParser(description="Penetration Testing Toolkit")
    subparsers = parser.add_subparsers(dest="command")

    # Port Scanner Command
    port_parser = subparsers.add_parser("scan", help="Run port scanner")
    port_parser.add_argument("target", help="Target IP address")
    port_parser.add_argument("--start", type=int, default=1, help="Start port")
    port_parser.add_argument("--end", type=int, default=1024, help="End port")

    # Brute Forcer Command
    brute_parser = subparsers.add_parser("brute", help="Run FTP brute-forcer")
    brute_parser.add_argument("target", help="Target FTP IP/Host")
    brute_parser.add_argument("--userfile", required=True, help="Path to username wordlist")
    brute_parser.add_argument("--passfile", required=True, help="Path to password wordlist") 

    # Hash Cracker Command
    hash_parser = subparsers.add_parser("crack", help="Crack a hashed password")
    hash_parser.add_argument("hash", help="The target hash to crack")
    hash_parser.add_argument("--type", choices=["md5", "sha1", "sha256"], required=True, help="Hash type")
    hash_parser.add_argument("--wordlist", required=True, help="Path to dictionary file")

    # Vulnerability Scanner
    vuln_parser = subparsers.add_parser("vulnscan", help="Scan for common vulnerabilities")
    vuln_parser.add_argument("target", help="Target IP address")

    # Network Sniffer
    sniff_parser = subparsers.add_parser("sniff", help="Sniff packets on a network interface")
    sniff_parser.add_argument("interface", help="Interface to sniff on (e.g., eth0)")
    sniff_parser.add_argument("--count", type=int, default=10, help="Number of packets to capture")

    # ✅ NOW parse arguments
    args = parser.parse_args()

    if args.command == "scan":
        port_scanner.run_port_scanner(args.target, args.start, args.end)
    elif args.command == "brute":
        print("[DEBUG] Brute-forcing triggered")
        brute_forcer.run_brute_force(args.target, args.userfile, args.passfile)
    elif args.command == "crack":
        hash_cracker.run_hash_cracker(args.hash, args.type, args.wordlist)
    elif args.command == "vulnscan":
        vuln_scanner.run_vuln_scan(args.target)
    elif args.command == "sniff":
        sniffer.run_sniffer(args.interface, args.count)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
