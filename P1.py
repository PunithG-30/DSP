import base64
import hashlib
import hmac
import os
import random
import string
import sys
from collections import deque, defaultdict
from typing import Tuple

# =========================
# Optional strong crypto
# =========================
USE_FERNET = False
try:
    from cryptography.fernet import Fernet
    USE_FERNET = True
except Exception:
    # cryptography not installed; will use a demonstrative XOR fallback (NOT secure)
    pass


# =========================
# Confidentiality
# =========================
def confidentiality_demo(plaintext: str) -> None:
    print("\n=== CONFIDENTIALITY DEMO ===")
    if USE_FERNET:
        key = Fernet.generate_key()
        f = Fernet(key)
        token = f.encrypt(plaintext.encode())
        print(f"[Fernet] Key (keep secret!): {key.decode()}")
        print(f"[Fernet] Ciphertext: {token.decode()}")
        recovered = f.decrypt(token).decode()
        print(f"[Fernet] Decrypted: {recovered}")
        print("Result: Data protected in transit/storage; readable only with the key.")
    else:
        print("⚠️ cryptography not installed; using XOR demo (NOT secure; for teaching only).")
        key = os.urandom(16)
        print(f"[XOR] Demo key (hex): {key.hex()}  (do not use in production)")
        ct = xor_encrypt(plaintext.encode(), key)
        print(f"[XOR] Ciphertext (base64): {base64.b64encode(ct).decode()}")
        recovered = xor_decrypt(ct, key).decode()
        print(f"[XOR] Decrypted: {recovered}")
        print("Result: Demonstrates that without the key, the bytes are unreadable (in real apps use strong crypto).")


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_decrypt(ct: bytes, key: bytes) -> bytes:
    return xor_encrypt(ct, key)


# =========================
# Integrity
# =========================
def integrity_demo(message: str) -> None:
    print("\n=== INTEGRITY DEMO (HMAC) ===")
    secret = os.urandom(32)  # shared secret for HMAC
    tag = hmac.new(secret, message.encode(), hashlib.sha256).hexdigest()
    print(f"Message: {message}")
    print(f"HMAC tag: {tag}")

    # Verify intact message
    ok = hmac.compare_digest(tag, hmac.new(secret, message.encode(), hashlib.sha256).hexdigest())
    print(f"Verification (untampered): {'OK' if ok else 'FAIL'}")

    # Tamper with message
    tampered = message[:-1] + ("X" if message[-1] != "X" else "Y") if message else "X"
    ok2 = hmac.compare_digest(tag, hmac.new(secret, tampered.encode(), hashlib.sha256).hexdigest())
    print(f"Tampered message: {tampered}")
    print(f"Verification (tampered): {'OK' if ok2 else 'FAIL'}")
    print("Result: Any change to the data invalidates the tag → tampering is detected.")


# =========================
# Availability
# =========================
class RateLimiter:
    """Token bucket rate limiter."""
    def __init__(self, rate_per_tick: int, burst: int):
        self.rate = rate_per_tick
        self.capacity = burst
        self.tokens = burst

    def allow(self) -> bool:
        if self.tokens > 0:
            self.tokens -= 1
            return True
        return False

    def refill(self):
        self.tokens = min(self.capacity, self.tokens + self.rate)


class Server:
    """Simple server that may fail under load; has queue and capacity per tick."""
    def __init__(self, name: str, capacity_per_tick: int, base_fail_prob: float = 0.02):
        self.name = name
        self.capacity = capacity_per_tick
        self.base_fail_prob = base_fail_prob
        self.queue = deque()
        self.processed = 0
        self.failed = 0

    def accept(self, request_id: int):
        self.queue.append(request_id)

    def process_tick(self):
        # process up to capacity
        handled = 0
        for _ in range(min(self.capacity, len(self.queue))):
            req = self.queue.popleft()
            # simulate random failure
            if random.random() < self.base_fail_prob:
                self.failed += 1
            else:
                self.processed += 1
            handled += 1
        return handled


def availability_demo(
    total_ticks: int = 50,
    legit_rps: int = 20,
    attack_rps: int = 0,
    retry_attempts: int = 2,
    servers: int = 2,
    per_server_capacity: int = 20,
    rate_limit_per_tick: int = 30,
    rate_limit_burst: int = 60,
) -> None:
    """
    Simulates availability with:
      - multiple servers (redundancy),
      - token bucket rate limiting,
      - retry policy,
      - optional attack traffic spike.
    """
    print("\n=== AVAILABILITY DEMO (Rate limit + Retries + Redundancy) ===")
    print(f"Ticks={total_ticks}, legit_rps={legit_rps}, attack_rps={attack_rps}, servers={servers}, per_server_capacity={per_server_capacity}")
    rl = RateLimiter(rate_limit_per_tick, rate_limit_burst)
    pool = [Server(f"S{i+1}", per_server_capacity) for i in range(servers)]

    stats = defaultdict(int)  # issued, dropped_rl, sent, processed, failed, retried
    next_server_idx = 0

    def dispatch(req_id: int):
        nonlocal next_server_idx
        # round-robin across servers
        pool[next_server_idx].accept(req_id)
        next_server_idx = (next_server_idx + 1) % len(pool)

    pending_retries = deque()  # (req_id, attempts_left)

    req_counter = 0
    for t in range(1, total_ticks + 1):
        # refill limiter at tick boundary
        rl.refill()

        # generate traffic (legit + attack)
        incoming = legit_rps + (attack_rps if t > total_ticks // 2 else 0)  # attack starts mid-sim
        stats["issued"] += incoming

        # process retries first (higher priority)
        retry_count_this_tick = len(pending_retries)
        for _ in range(retry_count_this_tick):
            req_id, left = pending_retries.popleft()
            if rl.allow():
                dispatch(req_id)
                stats["sent"] += 1
            else:
                stats["dropped_rl"] += 1
                pending_retries.append((req_id, left))  # couldn't send; try next tick

        # new requests through rate limiter
        for _ in range(incoming):
            req_counter += 1
            if rl.allow():
                dispatch(req_counter)
                stats["sent"] += 1
            else:
                stats["dropped_rl"] += 1
                # optionally queue a retry
                if retry_attempts > 0:
                    pending_retries.append((req_counter, retry_attempts))

        # process each server's queue
        for s in pool:
            before_processed = s.processed
            before_failed = s.failed
            s.process_tick()
            processed_now = s.processed - before_processed
            failed_now = s.failed - before_failed
            stats["processed"] += processed_now - failed_now
            stats["failed"] += failed_now

        # handle failed -> schedule retry if attempts left
        # For simplicity, we treat failures implicitly by adding retry for some portion.
        # Here we'll assume each 'failed_now' corresponds to retry entries (not tracked per id).
        # This keeps the sim simple yet illustrative.
        # You can expand this to track each request individually if desired.
        # Distribute retry tickets into the queue (bounded by attempts).
        newly_failed = stats["failed"] - stats.get("_prev_failed", 0)
        stats["_prev_failed"] = stats["failed"]
        for _ in range(newly_failed):
            # synthesize a new req_id to represent the retry attempt
            req_counter += 1
            if retry_attempts > 0:
                pending_retries.append((req_counter, retry_attempts - 1))
                stats["retried"] += 1

    processed = stats["processed"]
    dropped = stats["dropped_rl"]
    failed = stats["failed"]
    issued = stats["issued"]
    sent = stats["sent"]
    availability_pct = (processed / max(1, issued)) * 100.0

    print("\n--- SUMMARY ---")
    print(f"Issued requests:     {issued}")
    print(f"Admitted (rate OK):  {sent}")
    print(f"Dropped by rate-lim: {dropped}")
    print(f"Processed success:   {processed}")
    print(f"Server failures:     {failed}")
    print(f"Retries scheduled:   {stats['retried']}")
    print(f"Estimated availability: {availability_pct:.2f}%")
    print("Takeaway: Rate limits protect the system, retries hide transient failures, "
          "and multiple servers provide redundancy during spikes.\n")


# =========================
# Simple CLI
# =========================
def random_message(n=24):
    return "".join(random.choice(string.ascii_letters + string.digits + " ") for _ in range(n))


def main():
    print("CIA Triad Simulations")
    print("[1] Confidentiality (Encrypt/Decrypt)")
    print("[2] Integrity (HMAC tamper check)")
    print("[3] Availability (rate-limit + retries + redundancy)")
    print("[4] Run all")
    choice = input("Choose an option (1-4): ").strip() or "4"

    if choice in {"1", "4"}:
        msg = input("Enter plaintext (or leave empty for random): ").strip()
        if not msg:
            msg = random_message()
        confidentiality_demo(msg)

    if choice in {"2", "4"}:
        msg = input("Enter message for integrity test (or leave empty for random): ").strip()
        if not msg:
            msg = random_message()
        integrity_demo(msg)

    if choice in {"3", "4"}:
        try:
            ticks = int(input("Ticks [50]: ") or "50")
            legit = int(input("Legit RPS [20]: ") or "20")
            attack = int(input("Attack RPS (starts mid-sim) [40]: ") or "40")
            servers = int(input("Servers [2]: ") or "2")
            cap = int(input("Per-server capacity per tick [20]: ") or "20")
            rl_rate = int(input("Rate-limit per tick [30]: ") or "30")
            rl_burst = int(input("Rate-limit burst [60]: ") or "60")
            retries = int(input("Retry attempts [2]: ") or "2")
        except ValueError:
            print("Invalid input, using defaults.")
            ticks, legit, attack, servers, cap, rl_rate, rl_burst, retries = 50, 20, 40, 2, 20, 30, 60, 2

        availability_demo(
            total_ticks=ticks,
            legit_rps=legit,
            attack_rps=attack,
            servers=servers,
            per_server_capacity=cap,
            rate_limit_per_tick=rl_rate,
            rate_limit_burst=rl_burst,
            retry_attempts=retries,
        )


if __name__ == "__main__":
    main()