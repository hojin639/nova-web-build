"""E2E 암호화 — X25519 ECDH + HKDF-SHA256 + AES-256-GCM."""
from __future__ import annotations
import base64, hashlib, hmac, os
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    salt = b'nova-session-v1'
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b'', b'', 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t; i += 1
    return out[:length]

def generate_keypair() -> Tuple[bytes, bytes]:
    sk = X25519PrivateKey.generate()
    priv = sk.private_bytes(encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    pub = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return priv, pub

def derive_session_key(my_priv: bytes, peer_pub: bytes, license_key: str) -> bytes:
    sk = X25519PrivateKey.from_private_bytes(my_priv)
    pk = X25519PublicKey.from_public_bytes(peer_pub)
    return _hkdf_sha256(sk.exchange(pk), info=license_key.encode(), length=32)

def encrypt(session_key: bytes, plaintext: bytes, nonce: bytes = None) -> Tuple[bytes, bytes]:
    if nonce is None: nonce = os.urandom(12)
    return nonce, AESGCM(session_key).encrypt(nonce, plaintext, None)

def decrypt(session_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(session_key).decrypt(nonce, ciphertext, None)

def b64e(data: bytes) -> str: return base64.b64encode(data).decode('ascii')
def b64d(s: str) -> bytes: return base64.b64decode(s)
