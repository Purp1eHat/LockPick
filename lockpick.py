import hashlib

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def dictionary_attack(target_hash, wordlist_path):
    """Try to crack the hash using a dictionary (wordlist attack)."""
    try:
        with open(wordlist_path, "r", encoding="utf-8") as file:
            for password in file:
                password = password.strip()  # Remove newlines and spaces
                if hash_password(password) == target_hash:
                    print(f"[+] Password found: {password}")
                    return password
    except FileNotFoundError:
        print("[-] Wordlist file not found!")
    return None

if __name__ == "__main__":
    # Get user input
    user_hash = input("Enter the SHA-256 hash to crack: ").strip()
    wordlist = input("Enter path to wordlist (default: passwords.txt): ").strip() or "passwords.txt"

    print("[*] Starting dictionary attack...")
    result = dictionary_attack(user_hash, wordlist)

    if not result:
        print("[-] Password not found in wordlist.")
