import hashlib
import json
import time
import getpass
import os
import bcrypt
import hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv

#   LOAD / SETUP ADMIN SECRETS
load_dotenv("admin.env")

if not os.path.exists(".env"):
    # Auto-generate secure secrets
    with open(".env", "w") as f:
        f.write(f"ADMIN_ID=admin\n")
        f.write(f"ADMIN_PASSWORD={bcrypt.hashpw('changeme'.encode(), bcrypt.gensalt()).decode()}\n")
        f.write(f"ADMIN_KEY={get_random_bytes(32).hex()}\n")

load_dotenv()  # reload after auto-create

ADMIN_ID = os.getenv("ADMIN_ID")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD")
ADMIN_KEY = bytes.fromhex(os.getenv("ADMIN_KEY"))  # used for encryption + HMAC

#   GLOBALS
users = {}
blockchain = []

#   FILE I/O
def save_blockchain():
    with open("blockchain.json", "w") as f:
        json.dump(blockchain, f, indent=2)


def load_blockchain():
    global blockchain
    try:
        with open("blockchain.json") as f:
            blockchain[:] = json.load(f)
    except FileNotFoundError:
        blockchain.clear()


#   HELPER FUNCTIONS
def bcrypt_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def bcrypt_verify(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def mask_id(uid: str) -> str:
    return uid[:2] + "*" * (len(uid) - 4) + uid[-2:] if len(uid) > 4 else "****"


# ====== AES-GCM ENCRYPTION ======
def encrypt_message(msg: str) -> str:
    nonce = get_random_bytes(12)
    cipher = AES.new(ADMIN_KEY[:32], AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    return (nonce + tag + ciphertext).hex()


def decrypt_message(cipher_hex: str) -> str:
    data = bytes.fromhex(cipher_hex)
    nonce, tag, ct = data[:12], data[12:28], data[28:]
    cipher = AES.new(ADMIN_KEY[:32], AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode()


# ====== HMAC SIGNING ======
def sign_block(block: dict) -> str:
    h = hmac.new(ADMIN_KEY, digestmod="sha256")
    h.update(json.dumps(block, sort_keys=True).encode())
    return h.hexdigest()


def verify_signature(block: dict, signature: str) -> bool:
    expected = sign_block(block)
    return hmac.compare_digest(expected, signature)


#   BLOCKCHAIN

def prev_hash():
    if not blockchain:
        return "0" * 64
    return blockchain[-1]["signature"]  # chain by signature


def create_block(masked_user, encrypted_complaint):
    block = {
        "user": masked_user,
        "complaint": encrypted_complaint,
        "complaint_hash": hashlib.sha256(encrypted_complaint.encode()).hexdigest(),
        "prev_hash": prev_hash(),
        "timestamp": time.time(),
    }

    signature = sign_block(block)
    block["signature"] = signature
    return block


#   USER FUNCTIONS

def register_user():
    uid = input("Enter new User ID: ").strip()
    if uid in users:
        print("User already exists.")
        return

    pwd = getpass.getpass("Create password: ")
    users[uid] = {
        "password_hash": bcrypt_hash(pwd),
        "submitted": False
    }

    print("Registration successful!")


def login_user():
    uid = input("User ID: ").strip()
    pwd = getpass.getpass("Password: ")

    user = users.get(uid)
    if not user or not bcrypt_verify(pwd, user["password_hash"]):
        print("Invalid credentials.")
        return None

    print("Login successful.")
    return uid


def submit_complaint(uid):
    user = users[uid]

    if user["submitted"]:
        print("You already submitted a complaint.")
        return

    complaint = input("\nEnter your complaint:\n> ").strip()
    if not complaint:
        print("Complaint cannot be empty.")
        return

    pwd = getpass.getpass("Re-enter your password: ")

    if not bcrypt_verify(pwd, user["password_hash"]):
        print("Incorrect password.")
        return

    encrypted = encrypt_message(complaint)
    masked = mask_id(uid)

    block = create_block(masked, encrypted)
    blockchain.append(block)
    save_blockchain()

    user["submitted"] = True

    print("Complaint securely encrypted and added to blockchain.")


#   ADMIN
def verify_integrity():
    for i, blk in enumerate(blockchain):
        sig = blk.get("signature")
        block_copy = {k: v for k, v in blk.items() if k != "signature"}

        if not verify_signature(block_copy, sig):
            print(f"Tampering detected in block {i+1}")
            return False

        if i > 0 and blk["prev_hash"] != blockchain[i - 1]["signature"]:
            print(f"Chain broken at block {i+1}")
            return False

    print("Blockchain verified. All blocks intact.")
    return True


def review_complaints():
    print("\nAdmin access required.")
    admin_id = input("Admin ID: ").strip()
    admin_pass = getpass.getpass("Admin Password: ")

    if admin_id != ADMIN_ID or not bcrypt_verify(admin_pass, ADMIN_PASSWORD_HASH):
        print("Access denied.")
        return

    if not verify_integrity():
        print("Integrity failed. Cannot review.")
        return

    print("\n--- Decrypted Complaints ---")
    for i, blk in enumerate(blockchain, 1):
        try:
            msg = decrypt_message(blk["complaint"])
        except:
            msg = "<Decryption failed>"

        print(f"\nComplaint #{i}")
        print(f"Time: {time.ctime(blk['timestamp'])}")
        print(f"User: {blk['user']}")
        print(f"Complaint: {msg}")

#   MAIN
def main():
    load_blockchain()
    while True:
        print("\n--- Secure Complaint System ---")
        print("1. Register User")
        print("2. Login & Submit Complaint")
        print("3. Verify Blockchain")
        print("4. Review Complaints (Admin)")
        print("5. Exit")

        ch = input("Choose option: ").strip()
        if ch == "1":
            register_user()
        elif ch == "2":
            uid = login_user()
            if uid:
                submit_complaint(uid)
        elif ch == "3":
            verify_integrity()
        elif ch == "4":
            review_complaints()
        elif ch == "5":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
