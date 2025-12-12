# rsa_sign.py
from __future__ import annotations

import base64
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def digest_bits_to_bytes(digest_bits: str) -> bytes:
    """
    digest_bits is '00'/'0101'/'10101010' for 2/4/8 bits.
    We sign exactly these bits as a 1-byte message.
    """
    if not all(ch in "01" for ch in digest_bits):
        raise ValueError("digest_bits має містити лише '0' та '1'")
    if len(digest_bits) not in (2, 4, 8):
        raise ValueError("Довжина digest_bits має бути 2, 4 або 8")

    value = int(digest_bits, 2)
    return value.to_bytes(1, "big")


def generate_rsa_keypair(
    private_pem_path: str,
    public_pem_path: str,
    key_size: int = 2048,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    Path(private_pem_path).write_bytes(priv_bytes)
    Path(public_pem_path).write_bytes(pub_bytes)


def load_private_key(private_pem_path: str):
    data = Path(private_pem_path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def load_public_key(public_pem_path: str):
    data = Path(public_pem_path).read_bytes()
    return serialization.load_pem_public_key(data)


def sign_digest_bits(digest_bits: str, private_key) -> bytes:
    """
    RSA-PSS signature over SHA-256(digest_byte).
    """
    msg = digest_bits_to_bytes(digest_bits)

    signature = private_key.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_digest_bits(digest_bits: str, signature: bytes, public_key) -> bool:
    msg = digest_bits_to_bytes(digest_bits)
    try:
        public_key.verify(
            signature,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def signature_to_b64(signature: bytes) -> str:
    return base64.b64encode(signature).decode("ascii")


def signature_from_b64(signature_b64: str) -> bytes:
    return base64.b64decode(signature_b64.encode("ascii"))
