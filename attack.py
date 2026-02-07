import json
import time
import itertools
from datetime import datetime, timezone
import hashlib
import bcrypt
from argon2 import PasswordHasher
import psutil
import os
import atexit

from defence import (
    RateLimitingAuthSystem,
    LockoutAuthSystem,
    CaptchaAuthSystem,
    TOTPAuthSystem,
)

process = psutil.Process(os.getpid())
GROUP_SEED = "536128351"
MAX_RUNTIME_TOTAL = 7200
ATTEMPTS_PER_PASS = 50000
MAX_RUNTIME_BRUTE = 7200
MAX_ATTEMPTS_TOTAL = 50000
TARGET_USERNAME = "user_7"

ph_baseline = PasswordHasher(
    time_cost=1,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)


class AttackLoggerJSONL:
    def __init__(self, log_file, buffer_size=500):
        self.log_file = log_file
        self.start_time = time.time()
        self.buffer_size = buffer_size
        self.buffer = []
        open(self.log_file, "w").close()
        atexit.register(self.close)  # שופך גם אם התהליך נעצר

    def _flush(self):
        if not self.buffer:
            return
        with open(self.log_file, "a", encoding="utf-8") as f:
            for record in self.buffer:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.buffer.clear()

    def log(self, event_type, data):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "runtime_seconds": round(time.time() - self.start_time, 3),
            "event_type": event_type,
            "data": data,
        }
        self.buffer.append(record)
        if len(self.buffer) >= self.buffer_size:
            self._flush()

    def close(self):
        self._flush()


class DefenceLogger:
    """באפר 500 גם להגנות ב-defence.py"""
    def __init__(self, log_file, buffer_size=500):
        self.log_file = log_file
        self.buffer = []
        self.buffer_size = buffer_size
        open(self.log_file, "w").close()

    def log(self, record):
        self.buffer.append(record)
        if len(self.buffer) >= self.buffer_size:
            self.flush()

    def flush(self):
        if self.buffer:
            with open(self.log_file, "a", encoding="utf-8") as f:
                for record in self.buffer:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
            self.buffer.clear()

    def close(self):
        self.flush()


# =========================================================
# NoDefenceAuthSystem - עם property ותמיכה בלוגר
# =========================================================
class NoDefenceAuthSystem:
    def __init__(self, users_file, logger=None):
        self.users_file = users_file
        self.logger = logger
        self._users = {}
        self.load_users()

    @property
    def users(self):
        return self._users

    def load_users(self):
        with open(self.users_file, "r", encoding="utf-8") as f:
            users = json.load(f)
            self._users = {u["username"]: u for u in users}

    def verify_password(self, user, raw_password):
        username = user["username"]
        stored = user["password"]
        mode = user.get("hash_mode", "")

        if mode == "SHA-256+salt" or stored.startswith("sha256$"):
            salt = f"{GROUP_SEED}:{username}"
            digest = hashlib.sha256((salt + ":" + raw_password).encode("utf-8")).hexdigest()
            candidate = f"sha256${salt}${digest}"
            return candidate == stored

        if (
            mode == "bcrypt (cost=12)"
            or stored.startswith("$2b$")
            or stored.startswith("$2a$")
            or stored.startswith("$2y$")
        ):
            combined = f"{GROUP_SEED}:{username}:{raw_password}".encode("utf-8")
            return bcrypt.checkpw(combined, stored.encode("utf-8"))

        if mode == "Argon2id" or stored.startswith("$argon2id$"):
            combined = f"{GROUP_SEED}:{username}:{raw_password}"
            try:
                ph_baseline.verify(stored, combined)
                return True
            except Exception:
                return False

        return False

    def login(self, username, password):
        user = self._users.get(username)
        if not user:
            if self.logger:
                self.logger.log(
                    "brute_force_attempt",
                    {
                        "username": username,
                        "password": password,
                        "success": False,
                        "message": "User not found",
                        "category": "unknown",
                    },
                )
            return False, "User not found"

        ok = self.verify_password(user, password)
        category = user.get("strength_category", "unknown")
        if self.logger:
            self.logger.log(
                "brute_force_attempt",
                {
                    "username": username,
                    "password": password,
                    "success": ok,
                    "message": "Success" if ok else "Failure:bad_password",
                    "category": category,
                },
            )
        return ok, f"Success:{category}" if ok else f"Failure:{category}"


# =========================================================
# Password Spraying (מושתק)
# =========================================================
class PasswordSprayingAttacker:
    def __init__(self, system, log_file, passwords_file="passwords.txt"):
        self.system = system
        self.passwords_file = passwords_file
        self.password_list = self.load_password_list()
        self.logger = AttackLoggerJSONL(log_file)
        self.cracked = []
        self.total_login_attempts = 0

    def load_password_list(self):
        passwords = []
        try:
            with open(self.passwords_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    password = line.strip()
                    if password:
                        passwords.append(password)
            print(f"--- Loaded {len(passwords)} passwords from {self.passwords_file} ---")
        except FileNotFoundError:
            return ["123456", "password"]
        return passwords

    def _call_login(self, username, password):
        if isinstance(self.system, CaptchaAuthSystem):
            success, msg = self.system.login(username, password)
            if not success and msg == "Captcha required":
                token = self.system.get_captcha_token(GROUP_SEED)
                self.logger.log(
                    "captcha_token_requested",
                    {"username": username, "token_obtained": token is not None},
                )
                success, msg = self.system.login(username, password)
                return success, msg
        if isinstance(self.system, TOTPAuthSystem):
            success, msg = self.system.login(username, password, totp_code=None)
            if not success and msg == "TOTP required":
                code = self.system.get_totp_code_for_user(username)
                self.logger.log(
                    "totp_code_requested",
                    {"username": username, "code_length": len(code)},
                )
                success, msg = self.system.login(username, password, totp_code=code)
                return success, msg
        return self.system.login(username, password)

    def spray_single_password(self, password, run_number, max_attempts):
        found = []
        for username, user in self.system.users.items():
            if self.total_login_attempts >= max_attempts:
                return found, True
            success, msg = self._call_login(username, password)
            self.total_login_attempts += 1
            category = user.get("strength_category", "unknown")
            self.logger.log(
                "password_spray_attempt",
                {
                    "total_attempt_id": self.total_login_attempts,
                    "tested_password": password,
                    "username": username,
                    "success": success,
                },
            )
            if success:
                print(f" SUCCESS! '{password}' -> {username}")
                self.cracked.append(
                    {"password": password, "username": username, "category": category}
                )
                found.append({"username": username, "category": category})
        return found, False

    def run_spray_attack(self, max_runtime=MAX_RUNTIME_TOTAL, max_attempts=50000):
        print(
            f"\n=== PASSWORD SPRAYING ATTACK (Limit: {max_attempts} login attempts) ==="
        )
        overall_start = time.time()
        self.total_login_attempts = 0
        for i, password in enumerate(self.password_list, 1):
            if time.time() - overall_start > max_runtime or self.total_login_attempts >= max_attempts:
                break
            found, limit_reached = self.spray_single_password(password, i, max_attempts)
            if i % 100 == 0:
                print(
                    f"Progress: {self.total_login_attempts}/{max_attempts} attempts made..."
                )
            if limit_reached:
                break
        total_time = time.time() - overall_start
        print(
            f"Spray finished. Total attempts: {self.total_login_attempts}, Time: {total_time:.1f}s"
        )
        self.logger.close()


# =========================================================
# Brute Force
# =========================================================
class BruteForceAttacker:
    def __init__(self, system, log_file):
        self.system = system
        self.logger = AttackLoggerJSONL(log_file)
        self.cracked = []
        self.cracked_passwords = set()
        self.total_successes = 0
        self.total_attempts_global = 0
        self.brute_start_time = time.time()

    def get_charset_passes(self):
        return [
            ("NUMBERS ONLY", "0123456789"),
            ("NUMBERS + lowercase", "abcdefghijk0123456789lmnopqrstuvwxyz"),
            (
                "NUMBERS + a-zA-Z",
                "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            ),
            (
                "FULL CHARSET",
                "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()",
            ),
        ]

    def generate_passwords(self, charset, length):
        return itertools.product(charset, repeat=length)

    def _call_login(self, username, password):
        success, msg = self.system.login(username, password)

        # זיהוי נעילה מיוחד ל-LockoutAuthSystem - ממשיך לנסות!
        if "Account locked" in msg:
            self.logger.log(
                "account_locked",
                {
                    "username": username,
                    "password": password,
                    "lock_detected": True,
                    "full_message": msg,
                    "continue_attack": True,
                },
            )

        # CAPTCHA/TOTP כרגיל
        if isinstance(self.system, CaptchaAuthSystem):
            if not success and msg == "Captcha required":
                token = self.system.get_captcha_token(GROUP_SEED)
                self.logger.log(
                    "captcha_token_requested",
                    {"username": username, "token_obtained": token is not None},
                )
                success, msg = self.system.login(username, password)
                return success, msg

        if isinstance(self.system, TOTPAuthSystem):
            success, msg = self.system.login(username, password, totp_code=None)
            if not success and msg == "TOTP required":
                code = self.system.get_totp_code_for_user(username)
                self.logger.log(
                    "totp_code_requested",
                    {"username": username, "code_length": len(code)},
                )
                success, msg = self.system.login(
                    username, password, totp_code=code
                )
                return success, msg

        return success, msg

    def brute_force_pass(self, pass_name, charset, length):
        print(f"PASS: {pass_name} | Length {length}")
        attempts = 0
        pass_successes = 0
        target = TARGET_USERNAME

        for password_tuple in self.generate_passwords(charset, length):
            if (
                attempts >= ATTEMPTS_PER_PASS
                or self.total_attempts_global >= MAX_ATTEMPTS_TOTAL
                or (time.time() - self.brute_start_time) > MAX_RUNTIME_BRUTE
            ):
                break

            password = "".join(password_tuple)
            attempts += 1
            self.total_attempts_global += 1

            success, msg = self._call_login(target, password)
            cpu_usage = process.cpu_percent(interval=None)
            memory_usage = process.memory_info().rss
            category = self.system.users.get(target, {}).get(
                "strength_category", "unknown"
            )

            self.logger.log(
                "brute_force_attempt",
                {
                    "pass": pass_name,
                    "length": length,
                    "attempt": attempts,
                    "total_attempts": self.total_attempts_global,
                    "username": target,
                    "password": password,
                    "success": success,
                    "message": msg,
                    "category": category,
                    "cpu_percent": cpu_usage,
                    "rss_bytes": memory_usage,
                },
            )

            if success and password not in self.cracked_passwords:
                self.cracked_passwords.add(password)
                self.total_successes += 1
                pass_successes += 1
                print(
                    f"SUCCESS #{self.total_successes}: '{password}' -> {target} ({category})"
                )
                self.logger.log(
                    "brute_force_success",
                    {
                        "pass": pass_name,
                        "length": length,
                        "password": password,
                        "username": target,
                        "category": category,
                        "attempt": attempts,
                        "total_attempts": self.total_attempts_global,
                    },
                )
                self.cracked.append(
                    {
                        "password": password,
                        "username": target,
                        "category": category,
                    }
                )
                return True, attempts

        print(f"PASS COMPLETE: {attempts:,} att, {pass_successes} found")
        return pass_successes, attempts

    def run_brute_attack(self):
        print(
            f"\n=== BRUTE FORCE ATTACK (single target: {TARGET_USERNAME}) ==="
        )
        self.logger.log(
            "attack_start",
            {
                "type": "brute_force",
                "target_username": TARGET_USERNAME,
                "max_attempts": MAX_ATTEMPTS_TOTAL,
                "max_runtime": MAX_RUNTIME_BRUTE,
            },
        )

        lengths = [6, 7]
        passes = self.get_charset_passes()
        total_attempts = 0

        for pass_idx, (pass_name, charset) in enumerate(passes, 1):
            if (
                self.total_attempts_global >= MAX_ATTEMPTS_TOTAL
                or (time.time() - self.brute_start_time) > MAX_RUNTIME_BRUTE
            ):
                break

            print(f"\nPASS {pass_idx}: {pass_name}")
            pass_total = 0

            for length in lengths:
                if (
                    self.total_attempts_global >= MAX_ATTEMPTS_TOTAL
                    or (time.time() - self.brute_start_time) > MAX_RUNTIME_BRUTE
                ):
                    break

                succ, att = self.brute_force_pass(pass_name, charset, length)
                pass_total += att
                total_attempts += att

                if succ:
                    return

            print(f"Pass total: {pass_total:,} attempts")

        total_time = time.time() - self.brute_start_time
        self.print_brute_summary(total_attempts, total_time)

    def print_brute_summary(self, total_attempts, total_time):
        print("\nBRUTE SUMMARY")
        print(f"Successes: {self.total_successes}")
        print(f"Attempts: {total_attempts:,}")
        print(f"Time: {total_time:.1f}s")

        # סטטיסטיקת נעילות מפורטת
        lock_events = []
        try:
            with open(self.logger.log_file, "r") as f:
                for line in f:
                    record = json.loads(line)
                    if record["event_type"] == "account_locked":
                        lock_events.append(record)
        except Exception:
            pass

        if lock_events:
            first_lock_time = lock_events[0]["runtime_seconds"]
            last_lock_time = lock_events[-1]["runtime_seconds"]
            lock_duration = last_lock_time - first_lock_time
            print("\nLOCKOUT STATS:")
            print(f"First lock detected: {first_lock_time:.1f}s")
            print(f"Attacker continued for: {lock_duration:.1f}s under lockout")
            print(f"Lock events logged: {len(lock_events)}")
            if lock_duration > 0:
                print(
                    f"Average attempts/sec during lock: {len(lock_events)/lock_duration:.1f}"
                )

        print("\nCracked:")
        print("Password | Length | Username | Category")
        print("-" * 40)
        for row in self.cracked:
            pw = row["password"]
            print(
                f"{pw:<10} | {len(pw):>6} | {row['username']:<10} | {row['category']}"
            )


# =========================================================
# הרצה מלאה עם flush מובטח
# =========================================================
def run_for_hash_file_with_system(users_file, hash_mode_label, system, defence_name):
    print("\n" + "=" * 60)
    print(
        f"DEFENCE: {defence_name} | STORAGE MODE: {hash_mode_label} ({users_file})"
    )
    print("=" * 60)

    # Brute Force עם flush מובטח
    brute_attacker = BruteForceAttacker(
        system, f"brute_force_{defence_name}_{users_file}.jsonl"
    )
    try:
        brute_attacker.run_brute_attack()
    finally:
        brute_attacker.logger.close()  # שופך את כל הבאפר גם אם <500!
        print(f" Logged to: brute_force_{defence_name}_{users_file}.jsonl")

    # Password Spraying עם flush מובטח
    spray_attacker = PasswordSprayingAttacker(
        system, f"password_spray_{defence_name}_{users_file}.jsonl"
    )
    try:
        spray_attacker.run_spray_attack()
    finally:
        spray_attacker.logger.close()
        print(f" Logged to: password_spray_{defence_name}_{users_file}.jsonl")


def run_for_hash_file(users_file, hash_mode_label):

    logger = AttackLoggerJSONL(
        f"brute_force_none_{users_file}.jsonl", buffer_size=500
    )
    system_none = NoDefenceAuthSystem(users_file, logger=logger)
    try:
        run_for_hash_file_with_system(users_file, hash_mode_label, system_none, "none")
    finally:
        logger.close()


    system_rate = RateLimitingAuthSystem(
        users_file=users_file, rate_limit=10, rate_window=1.0
    )
    run_for_hash_file_with_system(users_file, hash_mode_label, system_rate, "rate")

    system_lock = LockoutAuthSystem(
        users_file=users_file, lock_threshold=10, lock_duration=10.0
    )
    run_for_hash_file_with_system(users_file, hash_mode_label, system_lock, "lock")

    system_captcha = CaptchaAuthSystem(
        users_file=users_file, lock_threshold=10, lock_duration=10.0
    )
    run_for_hash_file_with_system(
        users_file, hash_mode_label, system_captcha, "captcha"
    )

    system_totp = TOTPAuthSystem(users_file=users_file)
    run_for_hash_file_with_system(users_file, hash_mode_label, system_totp, "totp")


def main():
    storage_modes = [
        
        ("users3.json", "Argon2id"),
        ("users1.json", "SHA-256+salt"),
        ("users2.json", "bcrypt (cost=12)"),
        
    ]

    for file_name, label in storage_modes:
        print(f"\n TESTING {file_name} ({label})")
        run_for_hash_file(file_name, label)


if __name__ == "__main__":
    main()
