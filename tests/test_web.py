from pathlib import Path
from fastapi.testclient import TestClient

from web.app import app
from core.hash import secure_hash


client = TestClient(app)


def create_text_file(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "sample.txt"
    p.write_text(content, encoding="utf-8")
    return p


def test_hash_page_loads():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "<html" in resp.text.lower()
    assert "digest" in resp.text.lower()


def test_hash_text_file_2_bits(tmp_path):
    file_path = create_text_file(tmp_path, "hello")

    with open(file_path, "rb") as f:
        resp = client.post(
            "/hash",
            files={"file": ("sample.txt", f, "text/plain")},
            data={"bits": "2", "mode": "hash"},
        )

    assert resp.status_code == 200
    expected = secure_hash(b"hello", bit_length=2)
    assert expected in resp.text


def test_hash_text_file_8_bits(tmp_path):
    file_path = create_text_file(tmp_path, "hello world")

    with open(file_path, "rb") as f:
        resp = client.post(
            "/hash",
            files={"file": ("sample.txt", f, "text/plain")},
            data={"bits": "8", "mode": "hash"},
        )

    assert resp.status_code == 200
    expected = secure_hash(b"hello world", bit_length=8)
    assert expected in resp.text


def test_verify_ok(tmp_path):
    content = b"verify me"
    digest = secure_hash(content, bit_length=4)

    p = tmp_path / "v.txt"
    p.write_bytes(content)

    with open(p, "rb") as f:
        resp = client.post(
            "/hash",
            files={"file": ("v.txt", f, "text/plain")},
            data={
                "bits": "4",
                "mode": "verify",
                "expected_digest": digest,
            },
        )

    assert resp.status_code == 200
    assert "OK" in resp.text


def test_verify_failed(tmp_path):
    content = b"verify me"
    wrong_digest = "0000"

    p = tmp_path / "v.txt"
    p.write_bytes(content)

    with open(p, "rb") as f:
        resp = client.post(
            "/hash",
            files={"file": ("v.txt", f, "text/plain")},
            data={
                "bits": "4",
                "mode": "verify",
                "expected_digest": wrong_digest,
            },
        )

    assert resp.status_code == 200
    assert "FAILED" in resp.text


def test_verify_invalid_format(tmp_path):
    content = b"data"

    p = tmp_path / "x.txt"
    p.write_bytes(content)

    with open(p, "rb") as f:
        resp = client.post(
            "/hash",
            files={"file": ("x.txt", f, "text/plain")},
            data={
                "bits": "4",
                "mode": "verify",
                "expected_digest": "abcd",
            },
        )

    assert resp.status_code == 200
    assert "format" in resp.text.lower() or "invalid" in resp.text.lower()


def test_missing_file_rejected():
    resp = client.post(
        "/hash",
        data={"bits": "2", "mode": "hash"},
    )
    assert resp.status_code in (400, 422)
