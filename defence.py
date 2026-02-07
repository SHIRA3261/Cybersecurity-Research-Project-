import json
import time
import hashlib
from datetime import datetime, timezone
import bcrypt
from argon2 import PasswordHasher
import pyotp 

GROUP_SEED = "536128351"
PEPPER_SECRET = "X9!kLm#2025"
PEPPER = f"{GROUP_SEED}:{PEPPER_SECRET}"

ATTEMPTS_LOG_RATE = "attempts_rate_limit.log"
ATTEMPTS_LOG_LOCK = "attempts_lockout.log"
ATTEMPTS_LOG_CAPTCHA = "attempts_captcha.log"
ATTEMPTS_LOG_TOTP = "attempts_totp.log"

ph = PasswordHasher(
    time_cost=1, memory_cost=65536, parallelism=1,
    hash_len=32,
    salt_len=16
)

def now_ts():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def log_attempt(filename, record):
    with open(filename, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def verify_candidate(raw_password, user):
    username = user["username"]
    stored = user["password"]
    mode = user.get("hash_mode", "")

    if mode == "SHA-256+salt" or stored.startswith("sha256$"):
        salt = f"{GROUP_SEED}:{username}"
        digest = hashlib.sha256((salt + ":" + raw_password).encode("utf-8")).hexdigest()
        candidate = f"sha256${salt}${digest}"
        return candidate == stored

    if mode == "SHA-256+salt+pepper" or stored.startswith("pepper_sha256$"):
        salt = f"{GROUP_SEED}:{username}"
        digest = hashlib.sha256(
            (PEPPER + ":" + salt + ":" + raw_password).encode("utf-8")
        ).hexdigest()
        candidate = f"pepper_sha256${salt}${digest}"
        return candidate == stored

    if mode == "bcrypt (cost=12)" or stored.startswith("$2b$") or stored.startswith("$2a$") or stored.startswith("$2y$"):
        combined = f"{GROUP_SEED}:{username}:{raw_password}".encode("utf-8")
        return bcrypt.checkpw(combined, stored.encode("utf-8"))

    if mode == "bcrypt+pepper" or stored.startswith("pepper_bcrypt$"):
        combined = f"{PEPPER}:{GROUP_SEED}:{username}:{raw_password}".encode("utf-8")
        hash_part = stored.split("$", 1)[1].encode("utf-8")
        return bcrypt.checkpw(combined, hash_part)

    if mode == "Argon2id" or stored.startswith("$argon2id$"):
        combined = f"{GROUP_SEED}:{username}:{raw_password}"
        try:
            ph.verify(stored, combined)
            return True
        except Exception:
            return False

    if mode == "Argon2id+pepper" or stored.startswith("pepper_argon2id$"):
        combined = f"{PEPPER}:{GROUP_SEED}:{username}:{raw_password}"
        hash_part = stored.split("$", 1)[1]
        try:
            ph.verify(hash_part, combined)
            return True
        except Exception:
            return False

    return False

# =========================================================
# 1) Rate-Limiting בלבד
# =========================================================
class RateLimitingAuthSystem:
    def __init__(self, users_file, rate_limit=10, rate_window=1.0):
        self.users_file = users_file
        self.users = {}
        self.RATE_LIMIT = rate_limit
        self.RATE_WINDOW = rate_window
        self.attempt_timestamps = []
        self.load_users()

    def load_users(self):
        with open(self.users_file, "r", encoding="utf-8") as f:
            users = json.load(f)
            self.users = {u["username"]: u for u in users}

    def check_rate_limit(self):
        now = time.time()
        self.attempt_timestamps = [
            t for t in self.attempt_timestamps
            if now - t < self.RATE_WINDOW
        ]
        if len(self.attempt_timestamps) >= self.RATE_LIMIT:
            wait_time = self.RATE_WINDOW - (now - self.attempt_timestamps[0])
            if wait_time > 0:
                time.sleep(wait_time)

    def record_attempt(self):
        self.attempt_timestamps.append(time.time())

    def login(self, username, password):
        start = time.time()
        self.check_rate_limit()
        self.record_attempt()
        user = self.users.get(username)
        if not user:
            latency = int((time.time() - start) * 1000)
            log_attempt(ATTEMPTS_LOG_RATE, {
                "timestamp": now_ts(),
                "group_seed": GROUP_SEED,
                "username": username,
                "hash_mode": "no_user",
                "protection_flags": ["rate_limit"],
                "result": "fail_no_user",
                "latency_ms": latency
            })
            return False, "User not found"

        ok = verify_candidate(password, user)
        latency = int((time.time() - start) * 1000)
        result = "success" if ok else "fail_bad_password"
        log_attempt(ATTEMPTS_LOG_RATE, {
            "timestamp": now_ts(),
            "group_seed": GROUP_SEED,
            "username": username,
            "hash_mode": user.get("hash_mode", "unknown"),
            "protection_flags": ["rate_limit"],
            "result": result,
            "latency_ms": latency
        })
        status = "Success" if ok else "Failure"
        return ok, f"{status}:{user['strength_category']}"

# =========================================================
# 2) נעילת חשבון בלבד - מתוקן
# =========================================================
class LockoutAuthSystem:
    def __init__(self, users_file, lock_threshold=10, lock_duration=10.0):
        self.users_file = users_file
        self.LOCK_THRESHOLD = lock_threshold
        self.LOCK_DURATION = lock_duration
        self.failed_attempts = {}
        self.locked_until = {}
        self.users = {}
        self.load_users()

    def load_users(self):
        with open(self.users_file, "r", encoding="utf-8") as f:
            users = json.load(f)
            self.users = {u["username"]: u for u in users}

    def is_locked(self, username):
        now = time.time()
        until = self.locked_until.get(username, 0)
        if now < until:
            return True
        if username in self.locked_until:
            del self.locked_until[username]
            self.failed_attempts[username] = 0
        return False

    def register_failure(self, username):
        c = self.failed_attempts.get(username, 0) + 1
        self.failed_attempts[username] = c
        if c >= self.LOCK_THRESHOLD:
            self.locked_until[username] = time.time() + self.LOCK_DURATION

    def register_success(self, username):
        self.failed_attempts[username] = 0
        if username in self.locked_until:
            del self.locked_until[username]

    def login(self, username, password):
        start = time.time()
        user = self.users.get(username)
        if not user:
            latency = int((time.time() - start) * 1000)
            log_attempt(ATTEMPTS_LOG_LOCK, {
                "timestamp": now_ts(),
                "group_seed": GROUP_SEED,
                "username": username,
                "hash_mode": "no_user",
                "protection_flags": ["lockout"],
                "result": "fail_no_user",
                "latency_ms": latency
            })
            return False, "User not found"

        now = time.time()
        
        if self.is_locked(username):
            until = self.locked_until[username]
            remaining = max(0, until - now)
            latency = int((time.time() - start) * 1000)
            log_attempt(ATTEMPTS_LOG_LOCK, {
                "timestamp": now_ts(),
                "group_seed": GROUP_SEED,
                "username": username,
                "hash_mode": user.get("hash_mode", "unknown"),
                "protection_flags": ["lockout"],
                "result": "account_locked",
                "remaining_seconds": round(remaining, 1),
                "latency_ms": latency
            })
            return False, f"Account locked ({remaining:.1f}s remaining)"

        ok = verify_candidate(password, user)
        latency = int((time.time() - start) * 1000)

        if ok:
            self.register_success(username)
            result = "success"
        else:
            self.register_failure(username)
            result = "fail_bad_password"

        log_attempt(ATTEMPTS_LOG_LOCK, {
            "timestamp": now_ts(),
            "group_seed": GROUP_SEED,
            "username": username,
            "hash_mode": user.get("hash_mode", "unknown"),
            "protection_flags": ["lockout"],
            "result": result,
            "latency_ms": latency
        })

        status = "Success" if ok else "Failure"
        return ok, f"{status}:{user['strength_category']}"

# =========================================================
# 3) CAPTCHA token בלבד
# =========================================================
class CaptchaAuthSystem:
    def __init__(self, users_file, lock_threshold=5, lock_duration=60.0):
        self.users_file = users_file
        self.users = {}
        self.LOCK_THRESHOLD = lock_threshold
        self.LOCK_DURATION = lock_duration
        self.failed_attempts = {}
        self.locked_until = {}
        self.captcha_required = False
        self.captcha_token_valid = False
        self.load_users()

    def load_users(self):
        with open(self.users_file, "r", encoding="utf-8") as f:
            users = json.load(f)
            self.users = {u["username"]: u for u in users}

    def is_locked(self, username):
        now = time.time()
        until = self.locked_until.get(username, 0)
        if now < until:
            return True
        if username in self.locked_until:
            del self.locked_until[username]
            self.failed_attempts[username] = 0
        return False

    def register_failure(self, username):
        c = self.failed_attempts.get(username, 0) + 1
        self.failed_attempts[username] = c
        if c >= self.LOCK_THRESHOLD:
            self.locked_until[username] = time.time() + self.LOCK_DURATION
            self.captcha_required = True
            self.captcha_token_valid = False

    def register_success(self, username):
        self.failed_attempts[username] = 0
        if username in self.locked_until:
            del self.locked_until[username]

    def get_captcha_token(self, admin_secret):
        if admin_secret != GROUP_SEED:
            return None
        self.captcha_required = False
        self.captcha_token_valid = True
        return f"CAPTCHA_OK_{int(time.time())}"

    def login(self, username, password):
        start = time.time()
        if self.captcha_required and not self.captcha_token_valid:
            latency = int((time.time() - start) * 1000)
            log_attempt(ATTEMPTS_LOG_CAPTCHA, {
                "timestamp": now_ts(),
                "group_seed": GROUP_SEED,
                "username": username,
                "hash_mode": "unknown",
                "protection_flags": ["captcha"],
                "result": "captcha_required",
                "latency_ms": latency
            })
            return False, "Captcha required"

        user = self.users.get(username)
        if not user:
            latency = int((time.time() - start) * 1000)
            log_attempt(ATTEMPTS_LOG_CAPTCHA, {
                "timestamp": now_ts(),
                "group_seed": GROUP_SEED,
                "username": username,
                "hash_mode": "no_user",
                "protection_flags": ["captcha"],
                "result": "fail_no_user",
                "latency_ms": latency
            })
            return False, "User not found"

        if self.is_locked(username):
            latency = int((time.time() - start) * 1000)
            log_attempt(ATTEMPTS_LOG_CAPTCHA, {
                "timestamp": now_ts(),
                "group_seed": GROUP_SEED,
                "username": username,
                "hash_mode": user.get("hash_mode", "unknown"),
                "protection_flags": ["captcha"],
                "result": "account_locked",
                "latency_ms": latency
            })
            return False, "Account locked"

        ok = verify_candidate(password, user)
        latency = int((time.time() - start) * 1000)
        if ok:
            self.register_success(username)
            result = "success"
        else:
            self.register_failure(username)
            result = "fail_bad_password"

        log_attempt(ATTEMPTS_LOG_CAPTCHA, {
            "timestamp": now_ts(),
            "group_seed": GROUP_SEED,
            "username": username,
            "hash_mode": user.get("hash_mode", "unknown"),
            "protection_flags": ["captcha"],
            "result": result,
            "latency_ms": latency
        })
        status = "Success" if ok else "Failure"
        return ok, f"{status}:{user['strength_category']}"

# =========================================================
# 4) TOTP בלבד
# =========================================================
class TOTPAuthSystem:
    def __init__(self, users_file):
        self.users_file = users_file
        self.users = {}
        self.totp_secrets = {}
        self.load_users()
        self.load_totp_secrets()

    def load_users(self):
        with open(self.users_file, "r", encoding="utf-8") as f:
            users = json.load(f)
            self.users = {u["username"]: u for u in users}

    def load_totp_secrets(self):
        for username in self.users.keys():
            self.totp_secrets[username] = pyotp.random_base32()

    def get_totp_code_for_user(self, username):
        secret = self.totp_secrets[username]
        totp = pyotp.TOTP(secret)
        return totp.now()

    def verify_totp(self, username, code):
        secret = self.totp_secrets.get(username)
        if not secret or code is None:
            return False
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    def login(self, username, password, totp_code=None):
        start = time.time()
        user = self.users.get(username)
        if not user:
            latency = int((time.time() - start) * 1000)
            log_attempt(ATTEMPTS_LOG_TOTP, {
                "timestamp": now_ts(),
                "group_seed": GROUP_SEED,
                "username": username,
                "hash_mode": "no_user",
                "protection_flags": ["totp"],
                "result": "fail_no_user",
                "latency_ms": latency
            })
            return False, "User not found"

        ok_pw = verify_candidate(password, user)
        if not ok_pw:
            latency = int((time.time() - start) * 1000)
            log_attempt(ATTEMPTS_LOG_TOTP, {
                "timestamp": now_ts(),
                "group_seed": GROUP_SEED,
                "username": username,
                "hash_mode": user.get("hash_mode", "unknown"),
                "protection_flags": ["totp"],
                "result": "fail_bad_password",
                "latency_ms": latency
            })
            return False, "Failure:bad_password"

        if totp_code is None:
            latency = int((time.time() - start) * 1000)
            log_attempt(ATTEMPTS_LOG_TOTP, {
                "timestamp": now_ts(),
                "group_seed": GROUP_SEED,
                "username": username,
                "hash_mode": user.get("hash_mode", "unknown"),
                "protection_flags": ["totp"],
                "result": "totp_required",
                "latency_ms": latency
            })
            return False, "TOTP required"

        ok_totp = self.verify_totp(username, totp_code)
        latency = int((time.time() - start) * 1000)
        result = "success" if ok_totp else "totp_failed"
        log_attempt(ATTEMPTS_LOG_TOTP, {
            "timestamp": now_ts(),
            "group_seed": GROUP_SEED,
            "username": username,
            "hash_mode": user.get("hash_mode", "unknown"),
            "protection_flags": ["totp"],
            "result": result,
            "latency_ms": latency
        })

        if not ok_totp:
            return False, "TOTP failed"
        return True, f"Success:{user['strength_category']}"
