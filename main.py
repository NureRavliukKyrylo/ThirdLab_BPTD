# main.py
from __future__ import annotations

import argparse
from pathlib import Path

from hash import secure_hash
from rsa_sign import (
    generate_rsa_keypair,
    load_private_key,
    load_public_key,
    sign_digest_bits,
    verify_digest_bits,
    signature_to_b64,
    signature_from_b64,
)


def compute_digest_for_file(file_path: str, bits: int) -> str:
    data = Path(file_path).read_bytes()
    return secure_hash(data, bit_length=bits)


def compute_digest_for_text(text: str, bits: int) -> str:
    # secure_hash сам вміє приймати "стрічку", але ми робимо явно
    data = text.encode("utf-8")
    return secure_hash(data, bit_length=bits)


def cmd_genkeys(args) -> int:
    generate_rsa_keypair(args.priv, args.pub, key_size=args.size)
    print(f"OK: generated keys\n  private: {args.priv}\n  public : {args.pub}")
    return 0


def cmd_sign(args) -> int:
    digest_bits = compute_digest_for_file(args.file, args.bits)
    priv = load_private_key(args.priv)
    sig = sign_digest_bits(digest_bits, priv)
    sig_b64 = signature_to_b64(sig)

    if args.out:
        Path(args.out).write_text(sig_b64, encoding="utf-8")
        print(f"Digest ({args.bits}b): {digest_bits}")
        print(f"Signature (base64) saved to: {args.out}")
    else:
        print(f"Digest ({args.bits}b): {digest_bits}")
        print(f"Signature (base64): {sig_b64}")

    return 0


def cmd_verify(args) -> int:
    digest_bits = compute_digest_for_file(args.file, args.bits)
    pub = load_public_key(args.pub)

    if args.sigfile:
        sig_b64 = Path(args.sigfile).read_text(encoding="utf-8").strip()
    else:
        sig_b64 = args.sig.strip()

    sig = signature_from_b64(sig_b64)
    ok = verify_digest_bits(digest_bits, sig, pub)

    print(f"Digest ({args.bits}b): {digest_bits}")
    print("Verify:", "OK" if ok else "FAILED")
    return 0 if ok else 2


def cmd_sign_text(args) -> int:
    digest_bits = compute_digest_for_text(args.text, args.bits)
    priv = load_private_key(args.priv)
    sig = sign_digest_bits(digest_bits, priv)
    sig_b64 = signature_to_b64(sig)

    if args.out:
        Path(args.out).write_text(sig_b64, encoding="utf-8")
        print(f"Digest ({args.bits}b): {digest_bits}")
        print(f"Signature (base64) saved to: {args.out}")
    else:
        print(f"Digest ({args.bits}b): {digest_bits}")
        print(f"Signature (base64): {sig_b64}")

    return 0


def cmd_verify_text(args) -> int:
    digest_bits = compute_digest_for_text(args.text, args.bits)
    pub = load_public_key(args.pub)

    if args.sigfile:
        sig_b64 = Path(args.sigfile).read_text(encoding="utf-8").strip()
    else:
        sig_b64 = args.sig.strip()

    sig = signature_from_b64(sig_b64)
    ok = verify_digest_bits(digest_bits, sig, pub)

    print(f"Digest ({args.bits}b): {digest_bits}")
    print("Verify:", "OK" if ok else "FAILED")
    return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Lab3: RSA signature over custom digest bits (2/4/8).")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("genkeys", help="Generate RSA keypair (PEM).")
    g.add_argument("--priv", default="private.pem", help="Private key PEM path")
    g.add_argument("--pub", default="public.pem", help="Public key PEM path")
    g.add_argument("--size", type=int, default=2048, help="RSA key size (default 2048)")
    g.set_defaults(func=cmd_genkeys)

    s = sub.add_parser("sign", help="Sign digest of a file.")
    s.add_argument("file", help="Input file path")
    s.add_argument("--bits", type=int, choices=[2, 4, 8], default=2, help="Digest bit length")
    s.add_argument("--priv", default="private.pem", help="Private key PEM path")
    s.add_argument("--out", default=None, help="Save signature (base64) to file")
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="Verify signature for digest of a file.")
    v.add_argument("file", help="Input file path")
    v.add_argument("--bits", type=int, choices=[2, 4, 8], default=2, help="Digest bit length")
    v.add_argument("--pub", default="public.pem", help="Public key PEM path")
    sig_group = v.add_mutually_exclusive_group(required=True)
    sig_group.add_argument("--sig", help="Signature in base64 (inline)")
    sig_group.add_argument("--sigfile", help="Path to signature .b64 file")
    v.set_defaults(func=cmd_verify)

    st = sub.add_parser("sign-text", help="Sign digest of a UTF-8 text string.")
    st.add_argument("text", help="Text to hash+sign (UTF-8)")
    st.add_argument("--bits", type=int, choices=[2, 4, 8], default=2, help="Digest bit length")
    st.add_argument("--priv", default="private.pem", help="Private key PEM path")
    st.add_argument("--out", default=None, help="Save signature (base64) to file")
    st.set_defaults(func=cmd_sign_text)

    vt = sub.add_parser("verify-text", help="Verify signature for digest of a UTF-8 text string.")
    vt.add_argument("text", help="Text to hash+verify (UTF-8)")
    vt.add_argument("--bits", type=int, choices=[2, 4, 8], default=2, help="Digest bit length")
    vt.add_argument("--pub", default="public.pem", help="Public key PEM path")
    sig_group2 = vt.add_mutually_exclusive_group(required=True)
    sig_group2.add_argument("--sig", help="Signature in base64 (inline)")
    sig_group2.add_argument("--sigfile", help="Path to signature .b64 file")
    vt.set_defaults(func=cmd_verify_text)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
