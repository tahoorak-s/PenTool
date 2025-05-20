# modules/hash_cracker.py

import hashlib

def hash_string(word, hash_type):
    if hash_type == "md5":
        return hashlib.md5(word.encode()).hexdigest()
    elif hash_type == "sha1":
        return hashlib.sha1(word.encode()).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(word.encode()).hexdigest()
    else:
        raise ValueError("Unsupported hash type. Choose from: md5, sha1, sha256.")

def run_hash_cracker(target_hash, hash_type, wordlist_path):
    print(f"[*] Starting hash cracking ({hash_type})...\n")

    try:
        with open(wordlist_path, 'r') as file:
            for line in file:
                word = line.strip()
                hashed_word = hash_string(word, hash_type)
                if hashed_word == target_hash:
                    print(f"[+] Match found: {word}")
                    return
    except FileNotFoundError:
        print("[-] Wordlist file not found.")
    except Exception as e:
        print(f"[-] Error: {e}")

    print("[-] No match found in wordlist.")
