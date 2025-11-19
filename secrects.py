import bcrypt
import os

admin_id = input("Admin ID: ")
password = input("Admin Password: ")

hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
key = os.urandom(32).hex()

print("\nAdd this to your .env file:\n")
print(f"ADMIN_ID={admin_id}")
print(f"ADMIN_PASSWORD={hashed}")
print(f"ADMIN_KEY={key}")
