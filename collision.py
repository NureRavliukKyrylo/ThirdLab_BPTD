# collision.py
from __future__ import annotations

import os
import io
import zlib
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Dict, Callable

from hash import secure_hash


# Public API

@dataclass
class CollisionResult:
    input_path: str
    output_path: str
    bit_length: int
    target_hash: str
    attempts: int
    strategy: str
    note: str


def make_collision(
    input_path: str,
    bit_length: int = 2,
    output_path: Optional[str] = None,
    max_attempts: int = 5000,
) -> CollisionResult:
    """
    Create a new file of the same type as input that:
      - has DIFFERENT bytes than the original
      - has the SAME hash (secure_hash) for the chosen bit_length (2/4/8)

    Supports:
      - code/text files (e.g. .py, .txt, .js, .java, .cs, ...)
      - .docx
      - .png

    Returns CollisionResult with details for the report.
    """
    if bit_length not in (2, 4, 8):
        raise ValueError("bit_length має бути 2, 4 або 8")

    in_path = Path(input_path)
    if not in_path.exists() or not in_path.is_file():
        raise FileNotFoundError(f"Файл не знайдено: {input_path}")

    original_bytes = in_path.read_bytes()
    target = secure_hash(original_bytes, bit_length=bit_length)

    file_type = _detect_type(in_path)
    modifier, strategy_name = _get_modifier(file_type)

    # choose output path
    out_path = Path(output_path) if output_path else _default_output_path(in_path, bit_length)

    # search loop: attempt -> modify -> hash -> compare
    for attempt in range(1, max_attempts + 1):
        candidate_bytes, note = modifier(original_bytes, attempt)

        if candidate_bytes == original_bytes:
            continue  # must be different content

        h = secure_hash(candidate_bytes, bit_length=bit_length)
        if h == target:
            # ensure output directory exists
            out_path.parent.mkdir(parents=True, exist_ok=True)
            # avoid overwriting if exists
            final_path = _avoid_overwrite(out_path)
            final_path.write_bytes(candidate_bytes)

            # quick sanity checks that format isn't broken
            _sanity_check(final_path, file_type)

            return CollisionResult(
                input_path=str(in_path),
                output_path=str(final_path),
                bit_length=bit_length,
                target_hash=target,
                attempts=attempt,
                strategy=strategy_name,
                note=note,
            )

    raise RuntimeError(
        f"Не вдалося знайти колізію за {max_attempts} спроб. "
        f"Спробуй збільшити max_attempts або обрати bit_length=2."
    )


# Type detection

def _detect_type(path: Path) -> str:
    ext = path.suffix.lower()
    if ext == ".docx":
        return "docx"
    if ext == ".png":
        return "png"
    # treat everything else as text/code (for this lab scope)
    return "text"


def _get_modifier(file_type: str) -> Tuple[Callable[[bytes, int], Tuple[bytes, str]], str]:
    if file_type == "text":
        return _modify_text, "Text/Code: append trailing whitespace"
    if file_type == "docx":
        return _modify_docx_core_props, "DOCX: change docProps/core.xml metadata"
    if file_type == "png":
        return _modify_png_add_text_chunk, "PNG: add tEXt chunk before IEND"
    raise ValueError(f"Unsupported file type: {file_type}")


# Output path helpers

def _default_output_path(in_path: Path, bit_length: int) -> Path:
    return in_path.with_name(f"{in_path.stem}_collision_{bit_length}b{in_path.suffix}")


def _avoid_overwrite(path: Path) -> Path:
    if not path.exists():
        return path
    base = path.with_suffix("")
    ext = path.suffix
    for i in range(1, 10_000):
        candidate = Path(f"{base}_{i}{ext}")
        if not candidate.exists():
            return candidate
    raise RuntimeError("Не вдалося підібрати унікальну назву вихідного файла.")


# Sanity checks (lightweight)

def _sanity_check(path: Path, file_type: str) -> None:
    try:
        if file_type == "docx":
            # DOCX should be a valid zip
            with zipfile.ZipFile(io.BytesIO(path.read_bytes()), "r") as zf:
                zf.testzip()  # returns first bad file name or None
        elif file_type == "png":
            data = path.read_bytes()
            if not data.startswith(b"\x89PNG\r\n\x1a\n"):
                raise ValueError("PNG signature invalid")
            # ensure IEND exists
            if b"IEND" not in data:
                raise ValueError("PNG missing IEND")
        else:
            # text: nothing to validate
            pass
    except Exception as e:
        raise RuntimeError(f"Згенерований файл має некоректний формат: {e}") from e


# Modification strategies

def _modify_text(original: bytes, attempt: int) -> Tuple[bytes, str]:
    """
    Make a minimal "invisible" change for code/text:
    append whitespace to EOF in a reversible/harmless way.
    """
    # Ensure we don't break encoding assumptions: we operate on raw bytes.
    # Variation: add newline + spaces, or just spaces.
    tail = b""
    if original.endswith(b"\n"):
        tail = (b" " * (attempt % 7 + 1)) + b"\n"
        note = f"Appended {attempt % 7 + 1} trailing spaces + newline at EOF"
    else:
        tail = b"\n" + (b" " * (attempt % 7 + 1)) + b"\n"
        note = f"Appended newline + {attempt % 7 + 1} trailing spaces + newline at EOF"
    return original + tail, note


def _modify_docx_core_props(original: bytes, attempt: int) -> Tuple[bytes, str]:
    """
    DOCX is a ZIP. We modify metadata (core.xml) AND add/update an extra invisible part
    (docProps/custom.xml) to increase variability and make collision search robust.
    """
    with zipfile.ZipFile(io.BytesIO(original), "r") as zf:
        entries = {name: zf.read(name) for name in zf.namelist()}
        infos = {zi.filename: zi for zi in zf.infolist()}

    core_name = "docProps/core.xml"
    core_xml = entries.get(core_name)
    if core_xml is None:
        core_xml = _new_core_xml()

    # update core.xml (small metadata change)
    new_core_xml = _update_core_xml_description(core_xml, attempt)
    entries[core_name] = new_core_xml

    # add/update invisible custom part to force more hash variability
    custom_name = "docProps/custom.xml"
    # nonce changes every attempt; keep it tiny and "invisible"
    custom_payload = f"<custom><nonce>{attempt}</nonce></custom>".encode("utf-8")
    entries[custom_name] = custom_payload

    out_buf = io.BytesIO()
    with zipfile.ZipFile(out_buf, "w", compression=zipfile.ZIP_DEFLATED) as out_zip:
        for name, data in entries.items():
            zi = infos.get(name)
            if zi is None:
                out_zip.writestr(name, data)
            else:
                new_zi = zipfile.ZipInfo(filename=zi.filename, date_time=zi.date_time)
                new_zi.compress_type = zipfile.ZIP_DEFLATED
                new_zi.external_attr = zi.external_attr
                out_zip.writestr(new_zi, data)

    note = f"Updated {core_name} and wrote {custom_name} nonce={attempt}"
    return out_buf.getvalue(), note


def _new_core_xml() -> bytes:
    # Minimal core properties (namespaces included)
    return b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties
 xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:dcterms="http://purl.org/dc/terms/"
 xmlns:dcmitype="http://purl.org/dc/dcmitype/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:description></dc:description>
</cp:coreProperties>
"""


def _update_core_xml_description(core_xml: bytes, attempt: int) -> bytes:
    """
    Append a tiny non-visible token into dc:description.
    We keep changes minimal: add one space + attempt mod marker.
    """
    import xml.etree.ElementTree as ET

    # Register namespaces (helps keep tags readable)
    ns = {
        "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
        "dc": "http://purl.org/dc/elements/1.1/",
        "dcterms": "http://purl.org/dc/terms/",
        "dcmitype": "http://purl.org/dc/dcmitype/",
        "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    }
    for prefix, uri in ns.items():
        ET.register_namespace(prefix, uri)

    root = ET.fromstring(core_xml)

    # Find dc:description, create if missing
    desc = root.find(f"{{{ns['dc']}}}description")
    if desc is None:
        desc = ET.SubElement(root, f"{{{ns['dc']}}}description")
        desc.text = ""

    base = desc.text or ""
    # Minimal change: trailing space + small marker (keeps it non-obvious)
    marker = f" {attempt % 10}"
    desc.text = base + marker

    # Serialize back
    updated = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return updated


def _modify_png_add_text_chunk(original: bytes, attempt: int) -> Tuple[bytes, str]:
    """
    Insert a valid PNG tEXt chunk before IEND.
    This doesn't change pixels, only adds metadata.
    """
    sig = b"\x89PNG\r\n\x1a\n"
    if not original.startswith(sig):
        # not a png, but type detection should prevent this
        return original, "Not a PNG signature (no change)"

    # Iterate chunks and find IEND offset
    pos = 8
    iend_pos = None
    while pos + 12 <= len(original):
        length = int.from_bytes(original[pos:pos+4], "big")
        ctype = original[pos+4:pos+8]
        data_start = pos + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if crc_end > len(original):
            break
        if ctype == b"IEND":
            iend_pos = pos
            break
        pos = crc_end

    if iend_pos is None:
        return original, "PNG without IEND found (no change)"

    # Build tEXt chunk
    keyword = b"Comment"
    # minimal variation: spaces + digit (invisible in image)
    text_value = (b" " * (attempt % 7 + 1)) + str(attempt % 10).encode("ascii")
    chunk_data = keyword + b"\x00" + text_value
    chunk_type = b"tEXt"
    chunk_len = len(chunk_data).to_bytes(4, "big")
    crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
    chunk_crc = crc.to_bytes(4, "big")
    chunk = chunk_len + chunk_type + chunk_data + chunk_crc

    # Insert before IEND
    new_bytes = original[:iend_pos] + chunk + original[iend_pos:]

    note = f"Inserted PNG tEXt chunk before IEND (attempt={attempt})"
    return new_bytes, note



def _cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Automatic hash collision generator for secure_hash (2/4/8 bits)."
    )
    parser.add_argument("input", help="Path to input file (.docx/.png or any text/code file)")
    parser.add_argument("--bits", type=int, default=2, choices=[2, 4, 8], help="Digest length in bits")
    parser.add_argument("--out", default=None, help="Optional output path")
    parser.add_argument("--max", type=int, default=5000, help="Max attempts")

    args = parser.parse_args()

    res = make_collision(args.input, bit_length=args.bits, output_path=args.out, max_attempts=args.max)

    print("=== Collision found ===")
    print("Input:", res.input_path)
    print("Output:", res.output_path)
    print("Bits:", res.bit_length)
    print("Hash:", res.target_hash)
    print("Attempts:", res.attempts)
    print("Strategy:", res.strategy)
    print("Note:", res.note)


if __name__ == "__main__":
    _cli()
