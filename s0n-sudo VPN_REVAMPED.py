import requests
import time
import random
import logging
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import re
from collections import defaultdict
from heapq import heappush, heappop
import threading
import socket
import backoff
import base64
import os
import signal
import sys
import hashlib
import zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from pqcrypto.kem.kyber1024 import generate_keypair, encapsulate, decapsulate
from stegano import lsb
from PIL import Image
from pathlib import Path
import json

LOG_FILE = 'ip_changer.log'
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
]
PROXY_SOURCES = [
    "https://openproxy.space/api/proxies?type=http&anonymity=elite",
    "https://openproxy.space/api/proxies?type=socks5&anonymity=elite",
    "https://www.freeproxy.world/api/proxy?protocol=http&anonymity=elite",
    "https://api.getproxylist.com/proxy?protocol[]=http&anonymity[]=elite",
]
FALLBACK_PROXIES = [
    "socks5://45.76.149.129:1080",
    "http://198.199.86.11:8080",
    "socks5://139.162.78.109:3128",
]
TEST_URLS = [
    "https://httpbin.org/ip",
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/ip",
    "https://icanhazip.com/",
]
TARGET_URL = "https://www.google.com"
BASE_INTERVAL = 5
RETRY_INTERVAL = 10
TIMEOUT = 5
MAX_PROXIES = 500
PROXY_POOL_SIZE = 20
ANONYMITY_CHECK_URL = "https://www.whoismyisp.org/"
MAX_ASYNC_TASKS = 50
REFRESH_INTERVAL = 300
HEARTBEAT_FILE = "heartbeat.txt"
HEARTBEAT_TIMEOUT = 60
KEY_FILE = "secret.key"
PUBLIC_KEY_FILE = "public_key.kyber"
KEY_IMAGE = "key_image.png"
BASE_IMAGE = "base_image.png"
SECRET_TOKEN_FILE = "secret.token"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

lock = threading.RLock()

class LockWithTimeout:
    def __init__(self, lock, timeout=10):
        self.lock = lock
        self.timeout = timeout

    def __enter__(self):
        start = time.time()
        while not self.lock.acquire(blocking=False):
            if time.time() - start > self.timeout:
                raise RuntimeError("Lock timeout exceeded")
            time.sleep(0.1)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.lock.release()

def obfuscate_input(data, key):
    return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))[:len(data)]

PASSWORD = os.getenv("IP_CHANGER_PASS", "YourSuperComplexQuantumPassword123!")

def get_hardware_entropy():
    return hashlib.sha256(str(os.urandom(32) + str(os.getpid()).encode()).encode()).digest()

def load_or_generate_secret_token():
    if not os.path.exists(SECRET_TOKEN_FILE):
        token = os.urandom(32)
        with open(SECRET_TOKEN_FILE, "wb") as f:
            f.write(token)
        logging.info("Generated new secret token.")
    else:
        with open(SECRET_TOKEN_FILE, "rb") as f:
            token = f.read()
    return token

def derive_key(password, hardware_entropy, secret_token, salt=None):
    if salt is None:
        salt = os.urandom(16)
    password = password or "default_pass_123!"
    hardware_entropy = hardware_entropy or os.urandom(32)
    secret_token = secret_token or os.urandom(32)
    obfuscation_key = hashlib.sha256(salt).digest()
    combined_input = obfuscate_input(password.encode(), obfuscation_key) + \
                     obfuscate_input(hardware_entropy, obfuscation_key) + \
                     obfuscate_input(secret_token, obfuscation_key)
    try:
        kdf = Argon2id(
            salt=salt,
            memory_cost=65536,
            time_cost=3,
            parallelism=4,
            hash_len=32,
        )
        key = kdf.derive(combined_input)
        hmac_key = os.urandom(32)
        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(key + salt)
        integrity_tag = h.finalize()
        return key, hmac_key, salt, integrity_tag
    except MemoryError as e:
        logging.error(f"Memory error in key derivation: {e}")
        raise

def hide_key_in_image(private_key):
    if not Path(BASE_IMAGE).exists() or Image.open(BASE_IMAGE).size[0] * Image.open(BASE_IMAGE).size[1] < 3072:
        Image.new("RGB", (1024, 1024), "white").save(BASE_IMAGE)
        logging.warning("Base image too small or missing. Created 1024x1024 fallback.")
    secret_message = base64.b64encode(private_key).decode()
    with LockWithTimeout(lock):
        secret_image = lsb.hide(BASE_IMAGE, secret_message)
        secret_image.save(KEY_IMAGE)

def extract_key_from_image():
    try:
        with LockWithTimeout(lock):
            secret_message = lsb.reveal(Image.open(KEY_IMAGE))
        return base64.b64decode(secret_message)
    except Exception as e:
        logging.error(f"Failed to extract key from image: {e}")
        return None

def load_or_generate_kyber_keys():
    if not (Path(PUBLIC_KEY_FILE).exists() and Path(KEY_IMAGE).exists()):
        public_key, private_key = generate_keypair()
        with LockWithTimeout(lock):
            with open(PUBLIC_KEY_FILE, "wb") as f:
                f.write(public_key)
        hide_key_in_image(private_key)
    else:
        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key = f.read()
        private_key = extract_key_from_image()
        if not private_key:
            logging.error("Regenerating keys due to extraction failure.")
            return load_or_generate_kyber_keys()
    return public_key, private_key

hardware_entropy = get_hardware_entropy()
secret_token = load_or_generate_secret_token()
try:
    with LockWithTimeout(lock):
        with open(KEY_FILE, "rb") as key_file:
            ciphertext = key_file.read()
    public_key, private_key = load_or_generate_kyber_keys()
    shared_secret = decapsulate(private_key, ciphertext)
    if len(shared_secret) < 80:
        raise ValueError("Decapsulated secret too short.")
    salt = shared_secret[:16]
    key = shared_secret[16:48]
    hmac_key = shared_secret[48:80]
    derived_key, derived_hmac_key, _, integrity_tag = derive_key(PASSWORD, hardware_entropy, secret_token, salt)
    h = hmac.HMAC(derived_hmac_key, hashes.SHA256())
    h.update(derived_key + salt)
    h.verify(integrity_tag)
    if derived_key != key or derived_hmac_key != hmac_key:
        raise ValueError("Stored keys do not match derived keys.")
except (FileNotFoundError, ValueError, IndexError, EOFError, hmac.InvalidSignature) as e:
    logging.warning(f"Key loading failed: {e}. Regenerating keys.")
    public_key, private_key = load_or_generate_kyber_keys()
    key, hmac_key, salt, integrity_tag = derive_key(PASSWORD, hardware_entropy, secret_token)
    shared_secret = salt + key + hmac_key
    ciphertext, _ = encapsulate(public_key, shared_secret)
    with LockWithTimeout(lock):
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(ciphertext)
    logging.info("Generated and encapsulated new keys with Kyber-1024.")
finally:
    aesgcm = AESGCM(key)
    obfuscation_key = hashlib.sha256(key).digest()

def encrypt_proxy(proxy):
    if not proxy or not isinstance(proxy, str):
        logging.error("Invalid proxy input.")
        return None
    nonce = os.urandom(12)
    plaintext = proxy.encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    h = hmac.HMAC(hmac_key, hashes.SHA512())
    h.update(nonce + ciphertext)
    hmac_tag = h.finalize()
    encrypted_data = nonce + ciphertext + hmac_tag
    return base64.urlsafe_b64encode(encrypted_data).decode()

def decrypt_proxy(encrypted_proxy):
    try:
        encrypted_data = base64.urlsafe_b64decode(encrypted_proxy)
        if len(encrypted_data) < 76:
            raise ValueError("Encrypted data too short.")
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:-64]
        hmac_tag = encrypted_data[-64:]
        h = hmac.HMAC(hmac_key, hashes.SHA512())
        h.update(nonce + ciphertext)
        h.verify(hmac_tag)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except ValueError as e:
        logging.error(f"Decryption failed: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected decryption error: {e}")
        return None

class ProxyPool:
    def __init__(self, max_size):
        self.pool = []
        self.max_size = max_size
        self.lock = threading.Lock()
        self.banned = defaultdict(float)
        self.last_refresh = 0
        self.semaphore = asyncio.Semaphore(MAX_ASYNC_TASKS)

    def add(self, proxy_obj):
        with self.lock:
            ban_score = self.banned[proxy_obj.proxy_str]
            if ban_score > 0.9:
                return
            heappush(self.pool, proxy_obj)
            while len(self.pool) > self.max_size:
                heappop(self.pool)

    def get_best(self):
        with self.lock:
            while self.pool:
                proxy = heappop(self.pool)
                if self.banned[proxy.proxy_str] < 0.9:
                    return proxy
            return None

    def refresh_pool(self, proxies):
        for proxy in proxies:
            self.add(proxy)

    def add_banned(self, proxy_obj):
        with self.lock:
            self.banned[proxy_obj.proxy_str] = 1

    def check_time_for_refresh(self):
        current_time = time.time()
        if current_time - self.last_refresh > REFRESH_INTERVAL:
            self.last_refresh = current_time
            return True
        return False

    def refresh_proxies(self):
        if self.check_time_for_refresh():
            proxies = get_proxies_from_sources(PROXY_SOURCES)
            self.refresh_pool(proxies)

    async def get_valid_proxy(self):
        while True:
            self.refresh_proxies()
            proxy = self.get_best()
            if not proxy:
                logging.error("No valid proxies found.")
                continue
            return proxy

async def test_proxy(proxy_str):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(TARGET_URL, proxy=f"http://{proxy_str}", timeout=TIMEOUT) as response:
                return response.status == 200
        except Exception as e:
            logging.error(f"Proxy test failed: {e}")
            return False
