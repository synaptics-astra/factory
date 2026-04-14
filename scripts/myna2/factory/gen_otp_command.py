#!/usr/bin/env python3
from typing import List, Tuple
import os, sys, struct, configparser, re

CONF = "configs/oem_config.conf"
OUT_UBOOT = "otp_commands_uboot.txt"
OUT_LINUX = "otp_commands_linux.txt"

# INI fields → OTP indices
MAPPING = {
    "ree_segid":                 112,
    "ree_security_enable":       113,
    "boot_security_enable":      114,
    "mp_provision_done":         115,
    "scs_area_size_sel":         116,
    "ree_jtag_protection_policy":117,
    "ree_version":               118,
    "rkek_id_0":                 119,
    "rkek_id_1":                 120,
    "emmc_boot_disable":         200,
    "spi_boot_disable":          201,
    "oem_audio_customer_id":     203,
    "production_chip_flag":      204,
    "usb_boot_disable":          205,
    "boot_version":              206,
    # add more fields here as needed
}

# Mask policy table. Only for INI-driven fields. Only list non-0x1 masks here.
MASK_TABLE = {
    "ree_segid":                 0xFFFFFFFF,
    "scs_area_size_sel":         0x00000003,
    "ree_jtag_protection_policy":0x00000003,
    "oem_audio_customer_id":     0xFFFFFFFF,
    "production_chip_flag":      0x00000007,
    "ree_version":               0x000000FF,
    "rkek_id_0":                 0xFFFFFFFF,
    "rkek_id_1":                 0xFFFFFFFF,
    "boot_version":              0x000000FF,
    # add more keys here as needed
}

# ===== binary sources → (file, start_index, endian_format) =====
BIN_SOURCES = [
    ("keys/K0_REE_hash.bin", 100, "<I"),  # otp idx start: 100 (OTP_K0_OEM_HASH_0)
    ("keys/AESK0.bin",       108, "<I"),  # otp idx start: 108 (OTP_AESK0_0)
]

# Atomic group indices (must be programmed as a session if any are present)
ATOMIC_HASH_RANGE  = range(100, 108)      # OTP_K0_OEM_HASH_0 ~ _7
ATOMIC_AESK0_RANGE = range(108, 112)      # OTP_AESK0_0 ~ _3
ATOMIC_EXTRA_IDXS  = [112, 113]           # REE_SEGID, REE_SECURITY_ENABLE
ATOMIC_GROUP_IDXS  = set(ATOMIC_HASH_RANGE) | set(ATOMIC_AESK0_RANGE) | set(ATOMIC_EXTRA_IDXS)

MP_PROVISION_DONE_IDX = 115
REE_VERSION_IDX = 118
BOOT_VERSION_IDX = 206

HEX_DECIMAL_RE = re.compile(r"^\d+$")
HEX_PREFIX_RE  = re.compile(r"^0x[0-9a-fA-F]+$")


def parse_int_auto(s: str) -> int:
    s = s.strip()
    if HEX_PREFIX_RE.fullmatch(s):
        return int(s, 16)
    if HEX_DECIMAL_RE.fullmatch(s):
        return int(s, 10)
    raise ValueError(f"Unsupported value format: {s!r}")


def is_zero_value(s: str) -> bool:
    s = s.strip().lower()
    return s == "0" or s == "0x0" or re.fullmatch(r"0x0+", s) or re.fullmatch(r"0+", s)


def records_from_bin(path: str, start_idx: int, endian: str) -> List[Tuple[int, int, int]]:
    """
    Return list of (index, value, mask) tuples read from binary.
    Mask is always 0xffffffff for BIN_SOURCES.
    """
    recs: List[Tuple[int, int, int]] = []
    if not os.path.exists(path):
        print(f"[WARN] {path} not found", file=sys.stderr)
        return recs
    with open(path, "rb") as f:
        idx = start_idx
        while True:
            chunk = f.read(4)
            if len(chunk) < 4:
                break
            (val,) = struct.unpack(endian, chunk)
            recs.append((idx, val, 0xFFFFFFFF))
            idx += 1
    return recs


def gather_all_records() -> List[Tuple[int, int, int]]:
    """
    Collect records from BIN_SOURCES and CONF.
    Each record is (index, value, mask).
    """
    records: List[Tuple[int, int, int]] = []

    # --- Part 1: Binary-driven fields (HASH, AESK0, etc.) ---
    for path, start, endian in BIN_SOURCES:
        records.extend(records_from_bin(path, start, endian))

    # --- Part 2: INI-driven fields ---
    if os.path.exists(CONF):
        cfg = configparser.ConfigParser()
        cfg.optionxform = str.lower  # make keys case-insensitive
        cfg.read(CONF)

        DEFAULT_MASK = 0x00000001  # fallback if key not listed in MASK_TABLE

        for sect in cfg.sections():
            for key, val in cfg.items(sect):
                if key in MAPPING:
                    try:
                        value_int = parse_int_auto(val)
                        mask = MASK_TABLE.get(key, DEFAULT_MASK)
                        idx  = MAPPING[key]

                        # Special rule: If MP_PROVISION_DONE == 0, skip command
                        if idx == MP_PROVISION_DONE_IDX and value_int == 0:
                            print("[SKIP] OTP_MP_PROVISION_DONE value is 0, command not generated",
                                  file=sys.stderr)
                            continue
                        # Special rule: If REE_VERSION_IDX == 0, skip command
                        if idx == REE_VERSION_IDX and value_int == 0:
                            print("[SKIP] OTP_REE_VERSION value is 0, command not generated",
                                  file=sys.stderr)
                            continue
                        # Special rule: If BOOT_VERSION == 0, skip command
                        if idx == BOOT_VERSION_IDX and value_int == 0:
                            print("[SKIP] OTP_BOOT_VERSION value is 0, command not generated",
                                  file=sys.stderr)
                            continue
                        records.append((idx, value_int, mask))
                    except Exception as e:
                        print(f"[WARN] Skip key {key}: {e}", file=sys.stderr)
    else:
        print(f"[WARN] {CONF} not found", file=sys.stderr)

    return records

def check_atomic_group(records: List[Tuple[int, int, int]]) -> None:
    """
    Enforce atomic programming rules for security-critical fields:

        - OTP_K0_OEM_HASH_0 ~ _7 (100–107)
        - OTP_AESK0_0       ~ _3 (108–111)
        - OTP_REE_SEGID         (112)
        - OTP_REE_SECURITY_ENABLE (113)

    Rules:
      - If ANY of these indices are present, ALL must be present.
      - If HASH / AESK0 are present, REE_SECURITY_ENABLE must set bit0=1
        and the mask must program bit0 (mask & 0x1 != 0).
    """
    if not records:
        return

    # Map index → (value, mask)
    idx_map = {idx: (val, mask) for (idx, val, mask) in records}

    present_atomic = {idx for idx in ATOMIC_GROUP_IDXS if idx in idx_map}

    # If no atomic indices are present, nothing to enforce.
    if not present_atomic:
        return

    missing = ATOMIC_GROUP_IDXS - present_atomic
    if missing:
        print("[ERROR] Atomic security OTP group is incomplete.", file=sys.stderr)
        print(f"        Present atomic indices: {sorted(present_atomic)}", file=sys.stderr)
        print(f"        Missing atomic indices: {sorted(missing)}", file=sys.stderr)
        print("        All of the following must be programmed together:", file=sys.stderr)
        print("          - HASH (100–107)", file=sys.stderr)
        print("          - AESK0 (108–111)", file=sys.stderr)
        print("          - REE_SEGID (112)", file=sys.stderr)
        print("          - REE_SECURITY_ENABLE (113)", file=sys.stderr)
        sys.exit(1)

    # If HASH / AESK0 present, enforce REE_SECURITY_ENABLE conditions.
    hash_present  = any(idx in idx_map for idx in ATOMIC_HASH_RANGE)
    aesk_present  = any(idx in idx_map for idx in ATOMIC_AESK0_RANGE)

    if hash_present or aesk_present:
        if 113 not in idx_map:
            print("[ERROR] REE_SECURITY_ENABLE (index 113) is missing while HASH/AESK0 are present.", file=sys.stderr)
            sys.exit(1)

        val_ree, mask_ree = idx_map[113]

        # Mask must program bit 0
        if (mask_ree & 0x1) == 0:
            print("[ERROR] REE_SECURITY_ENABLE mask does not cover bit0 (must program bit0 when HASH/AESK0 are present).", file=sys.stderr)
            print(f"        Current mask for index 113: 0x{mask_ree:08x}", file=sys.stderr)
            sys.exit(1)

        # Value must set bit 0 to 1
        if (val_ree & 0x1) != 0x1:
            print("[ERROR] REE_SECURITY_ENABLE (index 113) must set bit0=1 when HASH/AESK0 are programmed.", file=sys.stderr)
            print(f"        Current value for index 113: 0x{val_ree:08x}", file=sys.stderr)
            sys.exit(1)


def main():
    records = gather_all_records()

    # Enforce atomic fields rule before generating any command files
    check_atomic_group(records)

    # Build commands in U-Boot
    lines_uboot: List[str] = [
        f"otpwrite {idx} 0x{val:08x} 0x{mask:08x}"
        for (idx, val, mask) in records
    ]

    # Build commands for Linux utility (factory_util)
    lines_linux: List[str] = [
        f"factory_util 6 otpwrite {idx} 0x{val:08x} 0x{mask:08x}"
        for (idx, val, mask) in records
    ]

    # Write files
    with open(OUT_UBOOT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines_uboot) + ("\n" if lines_uboot else ""))
    with open(OUT_LINUX, "w", encoding="utf-8") as f:
        f.write("\n".join(lines_linux) + ("\n" if lines_linux else ""))

    # Echo commands in U-Boot format to stdout for debugging
    for (idx, val, mask) in records:
        ln = f"otpwrite {idx} 0x{val:08x} 0x{mask:08x}"

        if idx in ATOMIC_GROUP_IDXS:
            print(f"{ln} [Atomic]")
        else:
            print(ln)

    print(f"[OK] Wrote {len(lines_uboot)} lines to {OUT_UBOOT}", file=sys.stderr)
    print(f"[OK] Wrote {len(lines_linux)} lines to {OUT_LINUX}", file=sys.stderr)


if __name__ == "__main__":
    main()
