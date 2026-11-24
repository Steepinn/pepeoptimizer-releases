"""Encrypted activation requests and signed public license attestations."""
from __future__ import annotations

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REQUEST_MARKER = "PEPE_ACTIVATION_V1\n"
REPLY_MARKER = "PEPE_ACTIVATION_REPLY_V1\n"
_LABEL = b"PepeOptimazer activation v1"


def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def encrypt_request(payload: dict, public_pem: str) -> tuple[str, bytes]:
    secret, iv = os.urandom(32), os.urandom(12)
    public = serialization.load_pem_public_key(public_pem.encode())
    wrapped = public.encrypt(secret, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                algorithm=hashes.SHA256(), label=_LABEL))
    envelope = {"key": b64(wrapped), "iv": b64(iv),
                "data": b64(AESGCM(secret).encrypt(iv, canonical(payload), _LABEL))}
    return REQUEST_MARKER + canonical(envelope).decode(), secret


def decrypt_request(body: str, private_pem: str) -> tuple[dict, bytes]:
    if len(body) > 8192 or not body.startswith(REQUEST_MARKER):
        raise ValueError("Invalid activation envelope")
    envelope = json.loads(body[len(REQUEST_MARKER):])
    private = serialization.load_pem_private_key(private_pem.encode(), password=None)
    secret = private.decrypt(unb64(envelope["key"]), padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=_LABEL))
    payload = json.loads(AESGCM(secret).decrypt(unb64(envelope["iv"]), unb64(envelope["data"]), _LABEL))
    if not isinstance(payload, dict):
        raise ValueError("Invalid activation payload")
    return payload, secret


def encrypt_reply(payload: dict, secret: bytes) -> str:
    iv = os.urandom(12)
    return REPLY_MARKER + canonical({"iv": b64(iv), "data": b64(
        AESGCM(secret).encrypt(iv, canonical(payload), _LABEL))}).decode()


def decrypt_reply(body: str, secret: bytes) -> dict:
    if len(body) > 16384 or not body.startswith(REPLY_MARKER):
        raise ValueError("Invalid activation reply")
    envelope = json.loads(body[len(REPLY_MARKER):])
    return json.loads(AESGCM(secret).decrypt(unb64(envelope["iv"]), unb64(envelope["data"]), _LABEL))


def binding(key_hash: str, hwid: str) -> str:
    return hashlib.sha256(f"pepe-license-binding-v1:{key_hash}:{hwid}".encode()).hexdigest()


def sign_status(record: dict, private_pem: str) -> dict:
    private = serialization.load_pem_private_key(private_pem.encode(), password=None)
    signature = private.sign(b"pepe-license-status-v1:" + canonical(record), padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH), hashes.SHA256())
    return {"record": record, "signature": b64(signature)}


def verify_status(envelope: dict, public_pem: str) -> dict:
    record = envelope["record"]
    public = serialization.load_pem_public_key(public_pem.encode())
    public.verify(unb64(envelope["signature"]), b"pepe-license-status-v1:" + canonical(record),
                  padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
                  hashes.SHA256())
    return record
