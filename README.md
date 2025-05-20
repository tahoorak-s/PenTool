# Penetration Testing Toolkit

## Description

The **Penetration Testing Toolkit** is a Python-based collection of modules designed to perform common penetration testing tasks. The toolkit includes the following functionalities:

* **Port Scanner**: Scan for open ports on a target host.
* **Brute Forcer**: Perform brute-force attacks on FTP services using username and password wordlists.
* **Hash Cracker**: Crack hashed passwords (supports MD5, SHA1, SHA256).
* **Vulnerability Scanner**: Scan a target host for common vulnerabilities.
* **Network Sniffer**: Capture and display network packets in real-time.

This toolkit is designed for penetration testers, ethical hackers, and cybersecurity enthusiasts who want to practice and automate common penetration testing tasks.

## Modules

### 1. **Port Scanner**

Scans for open ports on a target IP address. You can specify a port range to scan.

**Command:**

```bash
python main.py scan <target> --start <start_port> --end <end_port>
```

### 2. **Brute Forcer**

Performs an FTP brute-force attack, attempting to login to an FTP server using a wordlist of usernames and passwords.

**Command:**

```bash
python main.py brute <target> --userfile <username_wordlist> --passfile <password_wordlist>
```

### 3. **Hash Cracker**

Cracks a hashed password using a wordlist. Supports MD5, SHA1, and SHA256 hash types.

**Command:**

```bash
python main.py crack <hash> --type <hash_type> --wordlist <dictionary_file>
```

### 4. **Vulnerability Scanner**

Scans a target host for common vulnerabilities.

**Command:**

```bash
python main.py vulnscan <target>
```

### 5. **Network Sniffer**

Captures and displays packets on a network interface. This tool uses **Scapy** to sniff packets.

**Command:**

```bash
python main.py sniff <interface> --count <number_of_packets>
```

## Requirements

The following Python libraries are required to run this toolkit:

* `scapy`: For packet sniffing and network analysis.

To install the dependencies, run:

```bash
pip install -r requirements.txt
```

## How to Use

1. Clone or download the project repository.
2. Install the required libraries by running the command above.
3. Use the available modules via the command line interface, for example:

```bash
python main.py scan 192.168.1.1 --start 1 --end 1024
```

4. Customize the wordlists and target IPs as necessary for each tool.

## License

This project is open-source. Feel free to use and modify it for educational purposes. Always get explicit permission before conducting any penetration testing on a network or system.

---


