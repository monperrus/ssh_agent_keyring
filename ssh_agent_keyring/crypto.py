from __future__ import annotations

import hashlib
import hmac
import json
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


KEY_BYTES = 32
NONCE_BYTES = 12


def random_bytes(size: int) -> bytes:
    return secrets.token_bytes(size)


def build_unlock_challenge(store_id: bytes, public_key: str) -> bytes:
    key_hash = hashlib.sha256(public_key.encode("utf-8")).digest()
    return b"ssh-agent-keyring-unlock\0v1\0" + store_id + b"\0" + key_hash


def derive_kek(signature: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        info=b"ssh-agent-keyring/kek/v1",
    ).derive(signature)


def derive_subkey(dek: bytes, label: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=None,
        info=b"ssh-agent-keyring/" + label + b"/v1",
    ).derive(dek)


def wrap_dek(kek: bytes, dek: bytes, challenge: bytes, nonce: bytes) -> bytes:
    return ChaCha20Poly1305(kek).encrypt(nonce, dek, challenge)


def unwrap_dek(kek: bytes, wrapped_dek: bytes, challenge: bytes, nonce: bytes) -> bytes:
    return ChaCha20Poly1305(kek).decrypt(nonce, wrapped_dek, challenge)


def record_id(index_key: bytes, service: str, username: str) -> str:
    record_name = (service + "\0" + username).encode("utf-8")
    return hmac.new(index_key, record_name, hashlib.sha256).hexdigest()


def encrypt_record(value_key: bytes, record_name: str, service: str, username: str, password: str) -> tuple[bytes, bytes]:
    plaintext = json.dumps(
        {"service": service, "username": username, "password": password},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    nonce = random_bytes(NONCE_BYTES)
    ciphertext = ChaCha20Poly1305(value_key).encrypt(nonce, plaintext, record_name.encode("utf-8"))
    return nonce, ciphertext


def decrypt_record(value_key: bytes, record_name: str, nonce: bytes, ciphertext: bytes) -> dict[str, str]:
    plaintext = ChaCha20Poly1305(value_key).decrypt(nonce, ciphertext, record_name.encode("utf-8"))
    return json.loads(plaintext.decode("utf-8"))
