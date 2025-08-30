import hashlib
import os
import json

# File to store hashes of monitored files
HASH_FILE = "hashes.json"

def calculate_hash(file_path):
    """Calculate SHA-256 hash of a given file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read file in chunks to handle large files efficiently
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()

def load_hashes():
    """Load previously saved hashes from JSON file."""
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, "r") as f:
            return json.load(f)
    return {}

def save_hashes(hashes):
    """Save current file hashes to JSON file."""
    with open(HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=4)

def check_integrity(files):
    """
    Check integrity of files:
    - Detect new files
    - Detect modified files
    - Save updated hashes
    """
    old_hashes = load_hashes()  # Load previous hash data
    new_hashes = {}

    for file in files:
        if os.path.isfile(file):
            # Calculate hash for the current file
            new_hash = calculate_hash(file)
            new_hashes[file] = new_hash

            # Compare with previous hash values
            if file in old_hashes:
                if old_hashes[file] != new_hash:
                    print(f"[!] File changed: {file}")
            else:
                print(f"[+] New file added: {file}")

    # Save updated hashes after checking all files
    save_hashes(new_hashes)

if __name__ == "__main__":
    # Add file paths to monitor here
    files_to_check = ["test.txt"]
    check_integrity(files_to_check)
