import base64
import os
import sys
import zipfile
from pathlib import Path

import pytest

from hash import secure_hash
from collision import make_collision
from rsa_sign import (
    generate_rsa_keypair,
    load_private_key,
    load_public_key,
    sign_digest_bits,
    verify_digest_bits,
    digest_bits_to_bytes,
    signature_to_b64,
    signature_from_b64,
)
import main as main_cli


# Helpers: minimal DOCX/PNG

def create_minimal_docx(path: Path) -> None:
    """
    Minimal .docx as ZIP with core.xml + minimal required parts.
    Not guaranteed to open in Word, but structurally valid ZIP and enough for our modifier/sanity.
    """
    content_types = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
</Types>"""

    core_xml = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties
 xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:dcterms="http://purl.org/dc/terms/"
 xmlns:dcmitype="http://purl.org/dc/dcmitype/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:description>Lab3</dc:description>
</cp:coreProperties>
"""

    document_xml = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>Hello</w:t></w:r></w:p>
  </w:body>
</w:document>
"""

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("docProps/core.xml", core_xml)
        zf.writestr("word/document.xml", document_xml)


def create_minimal_png(path: Path) -> None:
    """
    1x1 PNG (valid) from base64.
    """
    b64 = (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+lmXkAAAAASUVORK5CYII="
    )
    path.write_bytes(base64.b64decode(b64))


# secure_hash tests (hash.py)

@pytest.mark.parametrize("bits", [2, 4, 8])
def test_secure_hash_format_and_determinism(bits):
    data = b"hello world"
    h1 = secure_hash(data, bit_length=bits)
    h2 = secure_hash(data, bit_length=bits)

    assert isinstance(h1, str)
    assert len(h1) == bits
    assert set(h1).issubset({"0", "1"})
    assert h1 == h2


def test_secure_hash_accepts_file_path_and_string_literal(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("Привіт", encoding="utf-8")

    # path as str -> reads file bytes
    h_file = secure_hash(str(p), bit_length=8)
    h_file_expected = secure_hash(p.read_bytes(), bit_length=8)
    assert h_file == h_file_expected

    # string literal (not a path) -> hashes UTF-8 bytes
    h_text = secure_hash("Привіт", bit_length=8)
    h_text_expected = secure_hash("Привіт".encode("utf-8"), bit_length=8)
    assert h_text == h_text_expected


def test_secure_hash_invalid_bit_length_raises():
    with pytest.raises(ValueError):
        secure_hash(b"x", bit_length=3)


def test_secure_hash_invalid_type_raises():
    with pytest.raises(TypeError):
        secure_hash(123, bit_length=8)  # type: ignore


def test_secure_hash_reacts_to_changes_statistically():
    """
    Не вимагаємо 100% зміни (бо 2/4/8 біт легко колізійні),
    але перевіряємо, що при змінах вхідних даних хеш дає >1 значення (для 8 біт).
    """
    base = bytearray(b"A" * 256)
    base_hash = secure_hash(bytes(base), bit_length=8)

    values = {base_hash}
    for i in range(40):
        mod = base[:]
        mod[i] ^= 0x01  # flip one bit
        values.add(secure_hash(bytes(mod), bit_length=8))

    assert len(values) >= 2


# collision tests (collision.py)

def test_make_collision_text_creates_different_file_same_hash(tmp_path):
    inp = tmp_path / "source.py"
    inp.write_text("print('hello')\n", encoding="utf-8")

    out = tmp_path / "source_collision.py"
    res = make_collision(str(inp), bit_length=2, output_path=str(out), max_attempts=2000)

    assert Path(res.output_path).exists()
    assert Path(res.output_path).suffix == ".py"
    assert res.bit_length == 2
    assert res.attempts >= 1

    original_bytes = inp.read_bytes()
    new_bytes = Path(res.output_path).read_bytes()
    assert new_bytes != original_bytes
    assert secure_hash(original_bytes, bit_length=2) == res.target_hash
    assert secure_hash(new_bytes, bit_length=2) == res.target_hash


def test_make_collision_docx_creates_valid_zip_same_hash(tmp_path):
    inp = tmp_path / "word.docx"
    create_minimal_docx(inp)

    out = tmp_path / "word_collision.docx"
    res = make_collision(str(inp), bit_length=2, output_path=str(out), max_attempts=3000)

    assert Path(res.output_path).exists()
    assert Path(res.output_path).suffix == ".docx"

    original_bytes = inp.read_bytes()
    new_bytes = Path(res.output_path).read_bytes()
    assert new_bytes != original_bytes

    # same 2-bit digest
    assert secure_hash(original_bytes, bit_length=2) == res.target_hash
    assert secure_hash(new_bytes, bit_length=2) == res.target_hash

    # docx should still be a valid zip
    with zipfile.ZipFile(Path(res.output_path), "r") as zf:
        assert zf.testzip() is None
        # core.xml should exist and be readable
        assert "docProps/core.xml" in zf.namelist()
        _ = zf.read("docProps/core.xml")


def test_make_collision_png_keeps_png_signature_and_adds_text_chunk(tmp_path):
    inp = tmp_path / "image.png"
    create_minimal_png(inp)

    out = tmp_path / "image_collision.png"
    res = make_collision(str(inp), bit_length=2, output_path=str(out), max_attempts=2000)

    original_bytes = inp.read_bytes()
    new_bytes = Path(res.output_path).read_bytes()

    assert new_bytes != original_bytes
    assert new_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    assert b"IEND" in new_bytes

    # our strategy inserts a tEXt chunk
    assert b"tEXt" in new_bytes

    assert secure_hash(original_bytes, bit_length=2) == res.target_hash
    assert secure_hash(new_bytes, bit_length=2) == res.target_hash


# RSA signature tests (rsa_sign.py)

@pytest.mark.parametrize("bits_str, expected", [
    ("00", b"\x00"),
    ("11", b"\x03"),
    ("0101", b"\x05"),
    ("11110000", b"\xF0"),
])
def test_digest_bits_to_bytes(bits_str, expected):
    assert digest_bits_to_bytes(bits_str) == expected


def test_rsa_sign_verify_roundtrip(tmp_path):
    priv_path = tmp_path / "private.pem"
    pub_path = tmp_path / "public.pem"
    generate_rsa_keypair(str(priv_path), str(pub_path), key_size=2048)

    priv = load_private_key(str(priv_path))
    pub = load_public_key(str(pub_path))

    digest = "11"  # 2-bit digest example
    sig = sign_digest_bits(digest, priv)

    assert isinstance(sig, (bytes, bytearray))
    assert verify_digest_bits(digest, sig, pub) is True
    assert verify_digest_bits("10", sig, pub) is False  # different digest must fail


def test_signature_base64_roundtrip(tmp_path):
    priv_path = tmp_path / "private.pem"
    pub_path = tmp_path / "public.pem"
    generate_rsa_keypair(str(priv_path), str(pub_path))
    priv = load_private_key(str(priv_path))
    pub = load_public_key(str(pub_path))

    digest = "0101"
    sig = sign_digest_bits(digest, priv)
    b64 = signature_to_b64(sig)
    sig2 = signature_from_b64(b64)

    assert sig2 == sig
    assert verify_digest_bits(digest, sig2, pub) is True


# CLI tests (main.py) via main.main() with patched argv

def test_cli_sign_text_and_verify_text(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    # genkeys
    monkeypatch.setattr(sys, "argv", ["main.py", "genkeys", "--priv", "private.pem", "--pub", "public.pem"])
    rc = main_cli.main()
    assert rc == 0

    # sign-text -> write sig file
    monkeypatch.setattr(sys, "argv", ["main.py", "sign-text", "Привіт", "--bits", "4", "--priv", "private.pem", "--out", "sig.b64"])
    rc = main_cli.main()
    assert rc == 0
    assert (tmp_path / "sig.b64").exists()

    # verify-text (same text) -> OK
    monkeypatch.setattr(sys, "argv", ["main.py", "verify-text", "Привіт", "--bits", "4", "--pub", "public.pem", "--sigfile", "sig.b64"])
    rc = main_cli.main()
    assert rc == 0

    # verify-text (changed text) -> FAILED (rc=2)
    monkeypatch.setattr(sys, "argv", ["main.py", "verify-text", "Привіт!", "--bits", "4", "--pub", "public.pem", "--sigfile", "sig.b64"])
    rc = main_cli.main()
    assert rc == 2