import hashlib
import os
import json

HASH_FILE = "hashes.json"

def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()

def load_hashes():
    return json.load(open(HASH_FILE)) if os.path.exists(HASH_FILE) else {}

def save_hashes(hashes):
    with open(HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=4)

def check_integrity(files):
    old_hashes = load_hashes()
    new_hashes = {}
    for file in files:
        if os.path.isfile(file):
            new_hash = calculate_hash(file)
            new_hashes[file] = new_hash
            if file in old_hashes and old_hashes[file] != new_hash:
                print(f"[!] File changed: {file}")
            elif file not in old_hashes:
                print(f"[+] New file added: {file}")
    save_hashes(new_hashes)

if __name__ == "__main__":
    files_to_check = ["test.txt"]  # Add file paths here
    check_integrity(files_to_check)
