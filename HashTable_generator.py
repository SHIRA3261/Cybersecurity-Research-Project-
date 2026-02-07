import json
import time
from datetime import datetime
import hashlib
import psutil
import os
import bcrypt
from argon2 import PasswordHasher

process = psutil.Process(os.getpid())
GROUP_SEED = "536128351"
ATTEMPTS_LOG = "attempts_stage1.log"

HASH_MODES = {
    "1": "SHA-256+salt",
    "2": "bcrypt (cost=12)",
    "3": "Argon2id"
}

HASH_FILES = {
    "1": "users1.json",
    "2": "users2.json",
    "3": "users3.json"
}

# Argon2id configuration (64MB, 1 iteration, 1 thread)
ph = PasswordHasher(
    time_cost=1,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    salt_len=16
)

class AuthSystem:
    def __init__(self):
        self.users = {}
        self.users_file = None
        self.create_users()

    def choose_hash_mode(self):
        print("Choose protection mode for this run:")
        print("1 - SHA-256+salt")
        print("2 - bcrypt (cost=12)")
        print("3 - Argon2id")
        choice = input("Enter 1/2/3: ").strip()
        while choice not in HASH_MODES:
            choice = input("Enter 1/2/3: ").strip()
        self.users_file = HASH_FILES[choice]
        return HASH_MODES[choice]

    def apply_sha256_salt(self, password, username):
        salt = f"{GROUP_SEED}:{username}"
        digest = hashlib.sha256((salt + ":" + password).encode("utf-8")).hexdigest()
        return f"sha256${salt}${digest}"

    def apply_bcrypt(self, password, username):
        combined = f"{GROUP_SEED}:{username}:{password}".encode("utf-8")
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(combined, salt)
        return hashed.decode("utf-8")

    def apply_argon2id(self, password, username):
        combined = f"{GROUP_SEED}:{username}:{password}"
        hashed = ph.hash(combined)
        return hashed

    def transform_password(self, raw_password, username, mode):
        if mode == "SHA-256+salt":
            return self.apply_sha256_salt(raw_password, username)
        if mode == "bcrypt (cost=12)":
            return self.apply_bcrypt(raw_password, username)
        if mode == "Argon2id":
            return self.apply_argon2id(raw_password, username)
        return raw_password

    def create_users(self):
        weak_passwords = [
            "123456", "password", "654321", "234567", "1111111",
            "12345678", "000339", "hello!", "000000", GROUP_SEED
        ]

        medium_passwords = [
            "all123", "abc123", "key123", "p@sw0rd", "admin123",
            "login456", "secret77", "welcome1", "cat321", "bank1234"
        ]

        strong_passwords = [
            "lklr7!hdb!", "54fc437j@j", ",sad*^WQkjd",
            "@JyyerGJnbd", "JHGjhgy32", "@" + GROUP_SEED,
            "Co6njf25", "@ikyuds", "0b6j6VHV29",
            "hkdaj906!g"
        ]

        all_passwords = weak_passwords + medium_passwords + strong_passwords
        categories = ["weak"] * 10 + ["medium"] * 10 + ["strong"] * 10

        hash_mode = self.choose_hash_mode()

        users = []
        for i, (raw_password, category) in enumerate(zip(all_passwords, categories)):
            username = f"user_{i + 1}"
            transformed = self.transform_password(raw_password, username, hash_mode)
            user = {
                "username": username,
                "password": transformed,
                "strength_category": category,
                "hash_mode": hash_mode
            }
            users.append(user)

        with open(self.users_file, "w", encoding="utf-8") as f:
            json.dump(users, f, ensure_ascii=False, indent=2)

        self.users = {u["username"]: u for u in users}

    def load_users(self):
        try:
            with open(self.users_file, "r", encoding="utf-8") as f:
                users = json.load(f)
            self.users = {u["username"]: u for u in users}
        except Exception:
            print("Error loading users file")
            self.users = {}

    def verify_password(self, user, raw_password):
        username = user["username"]
        stored = user["password"]
        mode = user.get("hash_mode", "")

        if mode == "SHA-256+salt" or stored.startswith("sha256$"):
            candidate = self.apply_sha256_salt(raw_password, username)
            return candidate == stored

        if mode == "bcrypt (cost=12)" or stored.startswith("$2b$") or stored.startswith("$2a$") or stored.startswith("$2y$"):
            combined = f"{GROUP_SEED}:{username}:{raw_password}".encode("utf-8")
            return bcrypt.checkpw(combined, stored.encode("utf-8"))

        if mode == "Argon2id" or stored.startswith("$argon2id$"):
            combined = f"{GROUP_SEED}:{username}:{raw_password}"
            try:
                ph.verify(stored, combined)
                return True
            except Exception:
                return False

        return False

    def login(self, username, password):
        start_time = time.time()
        user = self.users.get(username)
        
        if not user:
            return False, "User not found"

        is_correct = self.verify_password(user, password)
        status = "Success" if is_correct else "Failure"
        category = user["strength_category"]
        return is_correct, f"{status}:{category}"

def main():
    system = AuthSystem()

    while True:
        print("Do you want to enter a username? (enter 'n' to exit)")
        username = input("Username: ").strip()
        if username.lower() == "n":
            break

        password = input("Password: ")

        success, message = system.login(username, password)
        print(message)

        if success:
            print("Login successful!")

if __name__ == "__main__":
    main()
