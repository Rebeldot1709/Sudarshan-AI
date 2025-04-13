# Sudarshan-AI
All are Supportive system for MAin Chakravyuha
"""
THE DIGITAL CHAKRAVYUHA SECURITY FORTRESS
Version: Sudarshan Protocol Alpha 1.0
Architect: Abhishek Raj
Description: This code implements a 7-layer AI-driven cybersecurity defense system 
inspired by the mythological Chakravyuha. Each layer is both visible and secretly powered
by sub-systems working in parallel, rotating in alternate directions.
"""

import time
import hashlib
import logging
from threading import Lock
from functools import wraps
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SudarshanAI")

# System State
class SystemState:
    def __init__(self):
        self.under_attack = False
        self.failed_attempts = 0
        self.lock = Lock()
        self.max_attempts = 3
        self.attackers = []

    def increment_failure(self, ip):
        with self.lock:
            self.failed_attempts += 1
            self.attackers.append(ip)
            if self.failed_attempts >= self.max_attempts:
                self.under_attack = True
                logger.warning(f"Sudarshan Protocol Engaged: Too many failures from {ip}")

    def reset(self):
        with self.lock:
            self.failed_attempts = 0
            self.under_attack = False
            self.attackers.clear()

state = SystemState()

# User definition
class User:
    def __init__(self, authenticated=False, permissions=None, ip='0.0.0.0'):
        self.authenticated = authenticated
        self.permissions = permissions or []
        self.ip = ip

# Simulated Checks

def is_authenticated(user):
    return user.authenticated

def has_permission(user, permission):
    return permission in user.permissions

def is_ip_whitelisted(ip):
    whitelist = {'127.0.0.1', '192.168.1.1', '10.0.0.1'}
    return ip in whitelist

def is_recent(timestamp):
    return abs(time.time() - timestamp) < 5

def compute_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Attack Mode

def execute_attack_mode(user):
    logger.error(f"\u2620 ATTACK MODE: Intruder from {user.ip} neutralized by Sudarshan Protocol.")
    return "Digital Chakravyuha: You are absorbed into the system."

# Decorator Layers (7 Layer Chakravyuha)

def layer_1(func):
    @wraps(func)
    def wrapper(user, *args, **kwargs):
        if state.under_attack:
            return execute_attack_mode(user)
        if not is_authenticated(user):
            state.increment_failure(user.ip)
            raise PermissionError("Layer 1: Authentication failed")
        logger.info("Layer 1: Authenticated")
        return func(user, *args, **kwargs)
    return wrapper

def layer_2(func):
    @wraps(func)
    def wrapper(user, *args, **kwargs):
        if not is_ip_whitelisted(user.ip):
            state.increment_failure(user.ip)
            raise PermissionError("Layer 2: IP not whitelisted")
        logger.info("Layer 2: IP verified")
        return func(user, *args, **kwargs)
    return wrapper

def layer_3(func):
    @wraps(func)
    def wrapper(user, *args, **kwargs):
        if not has_permission(user, "access_core"):
            state.increment_failure(user.ip)
            raise PermissionError("Layer 3: Permission denied")
        logger.info("Layer 3: Permission granted")
        return func(user, *args, **kwargs)
    return wrapper

def layer_4(func):
    @wraps(func)
    def wrapper(user, timestamp, *args, **kwargs):
        if not is_recent(timestamp):
            state.increment_failure(user.ip)
            raise TimeoutError("Layer 4: Timestamp expired")
        logger.info("Layer 4: Timestamp valid")
        return func(user, timestamp, *args, **kwargs)
    return wrapper

def layer_5(func):
    @wraps(func)
    def wrapper(user, timestamp, request_data, request_hash, *args, **kwargs):
        expected_hash = compute_hash(f"{timestamp}{request_data}")
        if request_hash != expected_hash:
            state.increment_failure(user.ip)
            raise ValueError("Layer 5: Hash mismatch - data integrity failed")
        logger.info("Layer 5: Data integrity confirmed")
        return func(user, timestamp, request_data, request_hash, *args, **kwargs)
    return wrapper

def layer_6(func):
    @wraps(func)
    def wrapper(user, *args, **kwargs):
        logger.info("Layer 6: Adaptive AI Analysis Running...")
        # Simulate AI absorption by logging
        logger.info(f"Absorbing attacker signature: {user.ip} into system intelligence")
        return func(user, *args, **kwargs)
    return wrapper

def layer_7(func):
    @wraps(func)
    def wrapper(user, *args, **kwargs):
        logger.info("Layer 7: Sudarshan Protocol rotation complete. Digital Domination Verified.")
        return func(user, *args, **kwargs)
    return wrapper

# Core System Access
@layer_7
@layer_6
@layer_5
@layer_4
@layer_3
@layer_2
@layer_1
def access_sudarshan_core(user, timestamp, request_data, request_hash):
    logger.info("ACCESS GRANTED: Welcome to the Core of Sudarshan AI")
    return "\u2728 Sudarshan AI Core Activated \u2728"

# Example Usage
if __name__ == "__main__":
    user = User(authenticated=True, permissions=["access_core"], ip="192.168.1.1")
    timestamp = time.time()
    data = "invoke_core"
    data_hash = compute_hash(f"{timestamp}{data}")

    try:
        result = access_sudarshan_core(user, timestamp, data, data_hash)
        print(result)
    except Exception as e:
        print(f"Access Denied: {e}")
