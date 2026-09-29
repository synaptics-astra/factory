"""Read-only GenX V3 header checks performed before any signing starts."""

import struct
from pathlib import Path


IMAGE_IV_OFFSET = 0x0C
IMAGE_IV_SIZE = 16
IMAGE_PREPEND_INFO_SIZE = 64
PREBOOT_KEY_STORES_SIZE = 28672
PREBOOT_SPK_SIZE = 131072
TZK_CONTAINER_SIZE = 12
TZK_SUB_IMAGE_HEADER_SIZE = 12


def reject_nonzero_iv(path, image_name, header_offset=0):
    path = Path(path)
    iv_offset = header_offset + IMAGE_IV_OFFSET
    with path.open("rb") as source:
        source.seek(iv_offset)
        iv = source.read(IMAGE_IV_SIZE)
    if len(iv) != IMAGE_IV_SIZE:
        raise ValueError(
            f"{image_name} header is truncated at IV offset "
            f"{hex(iv_offset)}: {path}"
        )
    if any(iv):
        raise ValueError(
            f"{image_name} is already encrypted (non-zero IV {iv.hex()} at "
            f"{hex(iv_offset)}); refusing to sign it again: {path}"
        )


def reject_tzk_nonzero_ivs(path):
    path = Path(path)
    input_size = path.stat().st_size
    offset = TZK_CONTAINER_SIZE
    with path.open("rb") as source:
        container = source.read(TZK_CONTAINER_SIZE)
        if len(container) != TZK_CONTAINER_SIZE:
            raise ValueError(f"TZK container header is truncated: {path}")
        _, _, declared_size = struct.unpack("<III", container)
        if declared_size > input_size:
            raise ValueError(
                f"TZK declared size {declared_size} exceeds file size "
                f"{input_size}: {path}"
            )

        for image_name in ("ATF", "TZ_KERNEL", "TEE_BOOT_PARAMETER"):
            source.seek(offset)
            header = source.read(TZK_SUB_IMAGE_HEADER_SIZE)
            if len(header) != TZK_SUB_IMAGE_HEADER_SIZE:
                raise ValueError(f"TZK {image_name} header is truncated: {path}")
            _, _, total_length = struct.unpack("<III", header)
            if (
                total_length < TZK_SUB_IMAGE_HEADER_SIZE
                or offset + total_length > input_size
            ):
                raise ValueError(
                    f"Invalid TZK {image_name} length {total_length} at "
                    f"{hex(offset)}: {path}"
                )
            reject_nonzero_iv(path, f"tzk/{image_name}", offset)
            offset += total_length


def preflight_image(handler_name, path):
    """Dispatch the non-mutating IV check for one manifest handler."""
    if handler_name == "keystore":
        return
    if handler_name == "preboot":
        reject_nonzero_iv(
            path,
            "preboot/m52bl",
            PREBOOT_KEY_STORES_SIZE + PREBOOT_SPK_SIZE,
        )
    elif handler_name in {"bootloader", "m52bl", "sysmgr"}:
        reject_nonzero_iv(path, handler_name)
    elif handler_name == "tzk":
        reject_tzk_nonzero_ivs(path)
    elif handler_name in {"linux", "fastlogo"}:
        reject_nonzero_iv(path, handler_name, IMAGE_PREPEND_INFO_SIZE)
    else:
        raise ValueError(f"No IV preflight implementation for {handler_name}")
