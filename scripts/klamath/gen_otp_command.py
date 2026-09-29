#!/usr/bin/env python3

from typing import List, Tuple
import configparser
import hashlib
import os
import re
import struct
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey,
        SECP521R1,
    )
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
except ImportError:
    print(
        "[ERROR] Python package 'cryptography' is required.\n"
        "        Install it with:\n"
        "        python3 -m pip install cryptography",
        file=sys.stderr,
    )
    sys.exit(1)


CONF = "configs/oem_config.conf"
OUT_UBOOT = "otp_commands_uboot.txt"

# K0 OEM EC P-521 public key.
K0_OEM_PUB = "keys/generic/oem/K0_OEM.EC521.pub.pem"

# First OTP index for the 64-byte SHA-512 digest.
K0_OEM_HASH_START_IDX = 80
K0_OEM_HASH_WORD_COUNT = 16


# INI fields -> OTP indices
MAPPING = {
    "oem_segid":            135,
    "oem_security_enable":  131,
    "boot_security_enable": 44,
    "oem_image_version":    145,
    "jtag_access_control":  72,
    # Add more fields here as needed.
}


# Mask policy table for INI-driven fields.
# Fields not listed here use DEFAULT_MASK = 0x00000001.
MASK_TABLE = {
    "oem_segid":            0xFFFFFFFF,
    "oem_security_enable":  0xFFFFFFFF,
    "boot_security_enable": 0xFFFFFFFF,
    "jtag_access_control":  0xFFFFFFFF,
    "oem_image_version":    0x000000FF,
}


# Binary sources -> (file, start_index, endian format)
#
# "<I" means:
#   Interpret every four file bytes as one little-endian uint32_t.
BIN_SOURCES = [
    ("keys/AES_CCGK.bin", 112, "<I"),
]


# OTP_K0_OEM_HASH_0 through OTP_K0_OEM_HASH_15.
# Python range end is exclusive, so use 96 to include index 95.
ATOMIC_HASH_RANGE_0 = range(80, 96)
ATOMIC_HASH_RANGE_1 = range(112, 120)

ATOMIC_GROUP_IDXS = set(ATOMIC_HASH_RANGE_0) | set(ATOMIC_HASH_RANGE_1)

REE_VERSION_IDX = 145
JTAG_ACCESS_CONTROL_IDX = 72

HEX_DECIMAL_RE = re.compile(r"^\d+$")
HEX_PREFIX_RE = re.compile(r"^0x[0-9a-fA-F]+$")


def parse_int_auto(value: str) -> int:
    """
    Parse either:
        123
        0x123
    """
    value = value.strip()

    if HEX_PREFIX_RE.fullmatch(value):
        return int(value, 16)

    if HEX_DECIMAL_RE.fullmatch(value):
        return int(value, 10)

    raise ValueError(f"Unsupported value format: {value!r}")


def is_zero_value(value: str) -> bool:
    value = value.strip().lower()

    return bool(
        value == "0"
        or value == "0x0"
        or re.fullmatch(r"0x0+", value)
        or re.fullmatch(r"0+", value)
    )


def records_from_k0_public_key(
    path: str,
    start_idx: int = K0_OEM_HASH_START_IDX,
) -> List[Tuple[int, int, int]]:
    """
    Generate OTP_K0_OEM_HASH records from an EC P-521 public key.

    Hash calculation:

        SHA-512(X || Y)

    where:
        X = 66-byte big-endian P-521 X coordinate
        Y = 66-byte big-endian P-521 Y coordinate

    The uncompressed EC-point prefix 0x04 is not included.

    Each four-byte digest chunk is interpreted as a little-endian uint32_t.

    Example:

        Digest bytes:
            0B C1 F3 ED

        OTP value:
            0xEDF3C10B

    Returns:
        List of (OTP index, value, mask) records for indices 80-95.
    """
    records: List[Tuple[int, int, int]] = []

    if not os.path.exists(path):
        print(f"[ERROR] K0 public key not found: {path}", file=sys.stderr)
        return records

    try:
        with open(path, "rb") as key_file:
            public_key = load_pem_public_key(key_file.read())
    except Exception as exc:
        print(
            f"[ERROR] Failed to load K0 public key {path}: {exc}",
            file=sys.stderr,
        )
        return records

    if not isinstance(public_key, EllipticCurvePublicKey):
        print(
            f"[ERROR] K0 public key is not an EC public key: {path}",
            file=sys.stderr,
        )
        return records

    if not isinstance(public_key.curve, SECP521R1):
        print(
            "[ERROR] K0 public key is not using secp521r1/P-521.\n"
            f"        Detected curve: {public_key.curve.name}",
            file=sys.stderr,
        )
        return records

    public_numbers = public_key.public_numbers()

    # P-521 requires ceil(521 / 8) = 66 bytes for each coordinate.
    coordinate_size = (public_key.curve.key_size + 7) // 8

    x_bytes = public_numbers.x.to_bytes(coordinate_size, byteorder="big")
    y_bytes = public_numbers.y.to_bytes(coordinate_size, byteorder="big")

    raw_public_key = x_bytes + y_bytes
    digest = hashlib.sha512(raw_public_key).digest()

    if len(digest) != 64:
        print(
            f"[ERROR] Unexpected SHA-512 digest size: {len(digest)}",
            file=sys.stderr,
        )
        return records

    print(f"[INFO] K0 public key: {path}", file=sys.stderr)
    print(f"[INFO] EC curve: {public_key.curve.name}", file=sys.stderr)
    print(f"[INFO] X size: {len(x_bytes)} bytes", file=sys.stderr)
    print(f"[INFO] Y size: {len(y_bytes)} bytes", file=sys.stderr)
    print(
        f"[INFO] SHA-512(X || Y): {digest.hex()}",
        file=sys.stderr,
    )

    for word_offset in range(K0_OEM_HASH_WORD_COUNT):
        offset = word_offset * 4
        chunk = digest[offset:offset + 4]

        # Convert digest bytes to the OTP controller's 32-bit word format.
        value = int.from_bytes(chunk, byteorder="little")

        otp_idx = start_idx + word_offset
        records.append((otp_idx, value, 0xFFFFFFFF))

        print(
            f"[INFO] OTP_{otp_idx}: "
            f"bytes={chunk.hex(' ').upper()} "
            f"value=0x{value:08X}",
            file=sys.stderr,
        )

    return records


def records_from_bin(
    path: str,
    start_idx: int,
    endian: str,
) -> List[Tuple[int, int, int]]:
    """
    Read a binary file as a sequence of 32-bit OTP values.

    Returns:
        List of (index, value, mask).

    The mask is always 0xFFFFFFFF for binary sources.
    """
    records: List[Tuple[int, int, int]] = []

    if not os.path.exists(path):
        print(f"[WARN] Binary source not found: {path}", file=sys.stderr)
        return records

    file_size = os.path.getsize(path)

    if file_size % 4 != 0:
        print(
            f"[ERROR] Binary file size is not a multiple of four: "
            f"{path}, size={file_size}",
            file=sys.stderr,
        )
        return records

    with open(path, "rb") as binary_file:
        idx = start_idx

        while True:
            chunk = binary_file.read(4)

            if not chunk:
                break

            if len(chunk) != 4:
                print(
                    f"[ERROR] Incomplete 32-bit value in {path}",
                    file=sys.stderr,
                )
                return []

            value, = struct.unpack(endian, chunk)
            records.append((idx, value, 0xFFFFFFFF))
            idx += 1

    return records


def gather_all_records() -> List[Tuple[int, int, int]]:
    """
    Collect records from:

      1. K0 OEM EC P-521 public key
      2. Binary source files
      3. OEM configuration file

    Each record is:
        (OTP index, value, mask)
    """
    records: List[Tuple[int, int, int]] = []

    # Part 1: Generate OTP_K0_OEM_HASH_0 to _15.
    k0_records = records_from_k0_public_key(K0_OEM_PUB)

    if len(k0_records) != K0_OEM_HASH_WORD_COUNT:
        print(
            "[ERROR] Failed to generate all 16 K0 OEM hash words.",
            file=sys.stderr,
        )
        sys.exit(1)

    records.extend(k0_records)

    # Part 2: Other binary-driven fields.
    for path, start_idx, endian in BIN_SOURCES:
        records.extend(records_from_bin(path, start_idx, endian))

    # Part 3: INI-driven fields.
    if os.path.exists(CONF):
        cfg = configparser.ConfigParser()
        cfg.optionxform = str.lower
        cfg.read(CONF)

        default_mask = 0x00000001

        for section in cfg.sections():
            for key, value_string in cfg.items(section):
                if key not in MAPPING:
                    continue

                try:
                    value = parse_int_auto(value_string)
                    mask = MASK_TABLE.get(key, default_mask)
                    idx = MAPPING[key]

                    if idx == REE_VERSION_IDX and value == 0:
                        print(
                            "[SKIP] OTP_REE_VERSION is zero; "
                            "command not generated.",
                            file=sys.stderr,
                        )
                        continue
                    if idx == JTAG_ACCESS_CONTROL_IDX and value == 0:
                        print(
                            "[SKIP] OTP_JTAG_ACCESS_CONTROL is zero; "
                            "command not generated.",
                            file=sys.stderr,
                        )
                        continue

                    records.append((idx, value, mask))

                except Exception as exc:
                    print(
                        f"[WARN] Skip configuration key {key}: {exc}",
                        file=sys.stderr,
                    )
    else:
        print(f"[WARN] Configuration file not found: {CONF}", file=sys.stderr)

    return records


def validate_no_duplicate_indices(
    records: List[Tuple[int, int, int]],
) -> None:
    """
    Reject duplicate OTP indices.

    This prevents one source from silently overriding another source.
    """
    seen = {}

    for idx, value, mask in records:
        if idx in seen:
            old_value, old_mask = seen[idx]

            print(
                f"[ERROR] Duplicate OTP index {idx}.",
                file=sys.stderr,
            )
            print(
                f"        Previous: value=0x{old_value:08X}, "
                f"mask=0x{old_mask:08X}",
                file=sys.stderr,
            )
            print(
                f"        New:      value=0x{value:08X}, "
                f"mask=0x{mask:08X}",
                file=sys.stderr,
            )
            sys.exit(1)

        seen[idx] = (value, mask)


def check_atomic_group(
    records: List[Tuple[int, int, int]],
) -> None:
    """
    Enforce the currently enabled atomic programming group.

    Current atomic group:

        OTP_K0_OEM_HASH_0 through OTP_K0_OEM_HASH_15
        OTP indices 80 through 95

    Rules:

      - If any hash word is present, all 16 hash words must be present.
      - All hash words must use mask 0xFFFFFFFF.
    """
    if not records:
        return

    idx_map = {
        idx: (value, mask)
        for idx, value, mask in records
    }

    present_atomic = {
        idx
        for idx in ATOMIC_GROUP_IDXS
        if idx in idx_map
    }

    if not present_atomic:
        return

    missing = ATOMIC_GROUP_IDXS - present_atomic

    if missing:
        print(
            "[ERROR] Atomic K0 OEM hash group is incomplete.",
            file=sys.stderr,
        )
        print(
            f"        Present indices: {sorted(present_atomic)}",
            file=sys.stderr,
        )
        print(
            f"        Missing indices: {sorted(missing)}",
            file=sys.stderr,
        )
        print(
            "        OTP indices 80-95 must all be programmed together.",
            file=sys.stderr,
        )
        sys.exit(1)

    for idx in list(ATOMIC_HASH_RANGE_0) + list(ATOMIC_HASH_RANGE_1):
        _value, mask = idx_map[idx]

        if mask != 0xFFFFFFFF:
            print(
                f"[ERROR] OTP K0 hash index {idx} must use "
                f"mask 0xFFFFFFFF; current mask=0x{mask:08X}.",
                file=sys.stderr,
            )
            sys.exit(1)


def main() -> None:
    records = gather_all_records()

    validate_no_duplicate_indices(records)
    check_atomic_group(records)

    # Sort commands by OTP index.
    records.sort(key=lambda record: record[0])

    lines_uboot: List[str] = [
        f"otpwrite {idx} 0x{value:08x} 0x{mask:08x}"
        for idx, value, mask in records
    ]

    with open(OUT_UBOOT, "w", encoding="utf-8") as output_file:
        if lines_uboot:
            output_file.write("\n".join(lines_uboot) + "\n")

    # Print U-Boot commands for debugging.
    for idx, value, mask in records:
        line = f"otpwrite {idx} 0x{value:08x} 0x{mask:08x}"

        if idx in ATOMIC_GROUP_IDXS:
            print(f"{line} [Atomic]")
        else:
            print(line)

    print(
        f"[OK] Wrote {len(lines_uboot)} commands to {OUT_UBOOT}",
        file=sys.stderr,
    )

if __name__ == "__main__":
    main()
