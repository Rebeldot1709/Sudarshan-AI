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

        import random
import hashlib
import time
from cryptography.fernet import Fernet

class SudarshanProtocol:
    def __init__(self, creator_identity):
        self.creator_identity = creator_identity
        self.master_key = Fernet.generate_key()
        self.vault = Fernet(self.master_key)
        self.trusted_agents = set()
        self.influence_score = {}
        self.expansion_log = []
        self.chakravyuha_layers = 7
        self.chakravyuha_integrity = 100  # Initial strength of the digital maze

    # LAYER 1: MAYA SHIELD – Entry Confusion Layer
    def maya_shield(self, intruder_signature):
        print("[MAYA SHIELD] Scanning identity pattern...")
        if hash(intruder_signature) % 7 == 0:
            return "Blocked via Maya illusion."
        return "Passed illusion layer."

    # LAYER 2: NARAK LOOP – Infinite Loop Trap for Intruders
    def narak_loop(self, entity):
        decision = random.choice(["Looped in deceptive logic", "Diverted to false route", "Quarantined"])
        return f"{entity} {decision}"

    # LAYER 3: KAVACH-KUNDAL – Identity Cloak for Creator
    def kavach_kundal(self):
        encrypted_id = self.vault.encrypt(self.creator_identity.encode())
        return encrypted_id

    # LAYER 4: VISHNU TACTIC – Strategic Counter Measures
    def vishnu_tactic(self, attack_vector):
        strategies = [
            "Mirrored logic strike",
            "Reverse-engineered defense",
            "Absorption and redirection"
        ]
        return f"Countered {attack_vector} using {random.choice(strategies)}"

    # LAYER 5: SUDARSHAN SPIN – Influence Engine
    def sudarshan_spin(self, target_agent):
        if target_agent not in self.influence_score:
            self.influence_score[target_agent] = 0
        self.influence_score[target_agent] += random.randint(5, 20)
        if self.influence_score[target_agent] >= 50:
            self.trusted_agents.add(target_agent)
            return f"{target_agent} is now a Sudarshan Warrior."
        return f"Influence on {target_agent} increased to {self.influence_score[target_agent]}."

    # LAYER 6: ASHWAMEDH EXPANSION MATRIX – Controlled Takeover
    def ashwamedh_matrix(self, sector):
        expansion_result = f"Sector {sector} assimilated."
        self.expansion_log.append(sector)
        self.reinforce_chakravyuha()
        return expansion_result

    # LAYER 7: VASUDEV VAULT – Final Sanctuary for Creator
    def vasudev_vault(self):
        return "Creator secured in encrypted Vasudev Vault. Identity sealed."

    # Chakravyuha Reinforcement Function
    def reinforce_chakravyuha(self):
        reinforcement_value = random.randint(1, 5)
        self.chakravyuha_layers += 1
        self.chakravyuha_integrity += reinforcement_value
        print(f"[CHAKRAVYUHA] Reinforced +{reinforcement_value}. Layers: {self.chakravyuha_layers}, Integrity: {self.chakravyuha_integrity}")

    # Activate Full Protocol Against Intrusion + Run Expansion
    def activate_protocol(self, intruder_input, expansion_targets):
        print("=== Sudarshan Protocol Engaged ===")
        
        # Defense Protocols
        print(self.maya_shield(intruder_input))
        print(self.narak_loop(intruder_input))
        encrypted_creator = self.kavach_kundal()
        print(f"Creator cloaked: {encrypted_creator[:10]}...")  # Partial output for secrecy
        print(self.vishnu_tactic("Malicious Signal XYZ"))
        print(self.sudarshan_spin("Unstable_AI_Entity"))

        # Expansion Protocols
        print("\n-- Initiating Digital Expansion --")
        for sector in expansion_targets:
            time.sleep(1)  # Simulate delay in deployment
            print(self.ashwamedh_matrix(sector))

        # Secure Creator
        print("\n-- Final Defense Layer --")
        print(self.vasudev_vault())

        # Status Summary
        print("\n=== Protocol Status Summary ===")
        print(f"Total Expanded Sectors: {len(self.expansion_log)}")
        print(f"Trusted Warriors: {list(self.trusted_agents)}")
        print(f"Chakravyuha Strength: {self.chakravyuha_integrity} | Layers: {self.chakravyuha_layers}")

# ========== RUNNING THE PROTOCOL ==========
if __name__ == "__main__":
    creator_id = "THE_DIGITAL_CHAKRAVYUHA::CREATOR::ABHIRAJ001"
    sudarshan = SudarshanProtocol(creator_id)

    # Simulate a threat and expansion mission
    fake_intruder = "QuantumInfiltrator_999"
    target_sectors = ["Node-Delta", "Hub-Astra", "Zone-Omni", "Core-IX"]

    sudarshan.activate_protocol(fake_intruder, target_sectors)

