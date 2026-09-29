#!/usr/bin/env python3

"""Transactional key lifecycle manager for the standalone factory flow."""

import argparse
import configparser
import fcntl
import hashlib
import json
import os
import secrets
import shutil
import stat
import struct
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.primitives.cmac import CMAC
except ImportError as error:
    raise SystemExit(
        "Error: the Python 'cryptography' package is required for secure "
        "in-process AES-CMAC and ECDSA key generation"
    ) from error

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from tool.config import load_factory_config
else:
    from .tool.config import load_factory_config


PROJECT_ROOT = Path(__file__).resolve().parent
KEYS_LINK = PROJECT_ROOT / "keys"
KEYSETS_DIR = PROJECT_ROOT / "keysets"
KDF_CONFIG_PATH = PROJECT_ROOT / "configs" / "key_derivation.conf"
GENX_TOOL = PROJECT_ROOT / "tool" / "genx_img_v3"
LOCK_PATH = PROJECT_ROOT / ".keyset.lock"

AES_ROOT = Path("AES_CCGK.bin")
OEM_DIR = Path("generic/oem")
STORE_DIR = Path("store")
K0_PRIVATE = OEM_DIR / "K0_OEM.EC521.priv.pem"
K0_PUBLIC = OEM_DIR / "K0_OEM.EC521.pub.pem"
K1_PRIVATE = OEM_DIR / "K1_C.EC521.priv.pem"
K1_PUBLIC = OEM_DIR / "K1_C.EC521.pub.pem"
K0_STORE = STORE_DIR / "K0_OEM_store_4k.bin"
K1_STORE = STORE_DIR / "K1_C_store_4k.bin"
KEYSET_SCHEMA_VERSION = 1

ACTION_PLANS = {
    "all": frozenset({"aes-root", "derived", "k0", "k1", "k0-store", "k1-store"}),
    "rebuild-encryption-Image-keys": frozenset({"derived"}),
    "rebuild-key-stores": frozenset({"k0-store", "k1-store"}),
    "rotate-CCGK": frozenset({"aes-root", "derived"}),
    "rotate-k0-oem": frozenset({"k0", "k0-store", "k1-store"}),
    "rotate-k1_c_ECC_pair": frozenset({"k1", "k1-store"}),
}


@dataclass(frozen=True)
class KdfImage:
    name: str
    image_type: int


@dataclass(frozen=True)
class KdfConfig:
    context: bytes
    image_production_flag: int
    desired_bits: int
    images: tuple


def _parse_int(value, name, minimum=0, maximum=0xFFFFFFFF):
    try:
        parsed = int(value, 0)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be a valid integer") from error
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def load_kdf_config(factory_config, path=KDF_CONFIG_PATH):
    parser = configparser.ConfigParser()
    if not Path(path).is_file():
        raise FileNotFoundError(f"KDF configuration file not found: {path}")
    with Path(path).open(encoding="utf-8") as source:
        parser.read_file(source)

    if not parser.has_section("KDF") or not parser.has_section("Images"):
        raise ValueError(f"{path} must contain [KDF] and [Images] sections")

    context_text = parser.get("KDF", "context", fallback="")
    if not context_text or not context_text.isascii():
        raise ValueError("KDF context must be non-empty ASCII")
    desired_bits = _parse_int(
        parser.get("KDF", "desired_bits", fallback=""),
        "desired_bits",
        1,
        4096,
    )
    if desired_bits != 256:
        raise ValueError("Only 256-bit derived image keys are supported")

    images = []
    names = set()
    types = set()
    for name, image_type_text in parser.items("Images"):
        normalized_name = name.upper()
        image_type = _parse_int(image_type_text, f"image type for {normalized_name}")
        if normalized_name in names or image_type in types:
            raise ValueError("KDF image names and types must be unique")
        names.add(normalized_name)
        types.add(image_type)
        images.append(KdfImage(normalized_name, image_type))
    if not images:
        raise ValueError("At least one KDF image must be configured")

    return KdfConfig(
        context=context_text.encode("ascii"),
        image_production_flag=factory_config.image_production_flag,
        desired_bits=desired_bits,
        images=tuple(images),
    )


def version_bitmask(version):
    if not 0 <= version <= 32:
        raise ValueError("OEM version must be between 0 and 32")
    return (1 << version) - 1


def derive_image_key(master_key, image, kdf, seg_id, image_version):
    if len(master_key) != 32:
        raise ValueError("AES_CCGK.bin must contain exactly 32 bytes")
    label = struct.pack(
        "<IIII",
        image.image_type,
        image_version,
        kdf.image_production_flag,
        seg_id,
    )
    output = bytearray()
    iterations = (kdf.desired_bits + 127) // 128
    for counter in range(1, iterations + 1):
        payload = (
            struct.pack(">I", counter)
            + label
            + b"\x00"
            + kdf.context
            + struct.pack(">I", kdf.desired_bits)
        )
        cmac = CMAC(algorithms.AES(master_key))
        cmac.update(payload)
        output.extend(cmac.finalize())
    return bytes(output[: kdf.desired_bits // 8]), label


def _write_private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    os.chmod(path, 0o600)


def _write_public(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    os.chmod(path, 0o644)


def generate_aes_root(keyset):
    _write_private(keyset / AES_ROOT, secrets.token_bytes(32))


def generate_ec_key_pair(keyset, private_path, public_path):
    private_key = ec.generate_private_key(ec.SECP521R1())
    private_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_data = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_private(keyset / private_path, private_data)
    _write_public(keyset / public_path, public_data)


def generate_derived_keys(keyset, factory_config, kdf):
    master_key = (keyset / AES_ROOT).read_bytes()
    for image in kdf.images:
        derived_key, label = derive_image_key(
            master_key,
            image,
            kdf,
            factory_config.oem.oem_segid,
            factory_config.oem.oem_version,
        )
        output = keyset / OEM_DIR / f"CCGK_{image.name}.bin"
        _write_private(output, derived_key)
        print(
            f"Derived Key: CCGK_{image.name}.bin"
            f" | Hex: {derived_key.hex()}"
        )
        print(f"Context Str: {kdf.context.decode('ascii')}")
        print(f"Label Hex  : {label.hex()}")


def _run_genx(arguments):
    if not GENX_TOOL.is_file() or not os.access(GENX_TOOL, os.X_OK):
        raise FileNotFoundError(f"Executable GenX V3 tool not found: {GENX_TOOL}")
    try:
        result = subprocess.run(
            [str(GENX_TOOL), *map(str, arguments)],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "").strip()
        raise RuntimeError(
            f"genx_img_v3 failed with exit code {error.returncode}: {detail}"
        ) from error
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")


def _finalize_store(generated, destination):
    size = generated.stat().st_size
    if size > 4096:
        raise ValueError(f"Generated store is {size} bytes; maximum is 4096")
    with generated.open("ab") as store:
        store.write(b"\x00" * (4096 - size))
    if generated.stat().st_size != 4096:
        raise ValueError(f"Failed to finalize 4096-byte store: {generated}")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(generated, 0o600)
    os.replace(generated, destination)


def generate_k0_store(keyset):
    generated = keyset / STORE_DIR / ".K0_OEM.generated"
    generated.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _run_genx(("-t", "K0_OEM", "-i", keyset / K0_PUBLIC, "-o", generated))
    _finalize_store(generated, keyset / K0_STORE)


def generate_k1_store(keyset, factory_config):
    generated = keyset / STORE_DIR / ".K1_C.generated"
    generated.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _run_genx((
        "-t", "K1_C",
        "-f",  str(factory_config.image_production_flag),
        "-n", keyset / K0_PRIVATE,
        "-s", hex(factory_config.oem.oem_segid),
        "-r", str(version_bitmask(factory_config.oem.oem_version)),
        "-i", keyset / K1_PUBLIC,
        "-o", generated,
    ))
    _finalize_store(generated, keyset / K1_STORE)


def _public_bytes_from_private(path):
    private_key = serialization.load_pem_private_key(
        path.read_bytes(),
        password=None,
    )
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError(f"Not an EC private key: {path}")
    if private_key.curve.name != "secp521r1":
        raise ValueError(f"Private key does not use secp521r1: {path}")
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def validate_keyset(keyset, kdf):
    required_secrets = [AES_ROOT, K0_PRIVATE, K1_PRIVATE, K0_STORE, K1_STORE]
    required_secrets.extend(
        OEM_DIR / f"CCGK_{image.name}.bin" for image in kdf.images
    )
    required_public = [K0_PUBLIC, K1_PUBLIC]

    missing = [
        str(path) for path in (*required_secrets, *required_public)
        if not (keyset / path).is_file()
    ]
    if missing:
        raise FileNotFoundError(f"Incomplete keyset; missing: {', '.join(missing)}")

    for path in [AES_ROOT, *required_secrets[5:]]:
        if (keyset / path).stat().st_size != 32:
            raise ValueError(f"AES key must contain exactly 32 bytes: {path}")
    for path in (K0_STORE, K1_STORE):
        if (keyset / path).stat().st_size != 4096:
            raise ValueError(f"Key store must contain exactly 4096 bytes: {path}")

    if _public_bytes_from_private(keyset / K0_PRIVATE) != (keyset / K0_PUBLIC).read_bytes():
        raise ValueError("K0 OEM private/public key pair does not match")
    if _public_bytes_from_private(keyset / K1_PRIVATE) != (keyset / K1_PUBLIC).read_bytes():
        raise ValueError("K1_C private/public key pair does not match")

    for path in required_secrets:
        mode = stat.S_IMODE((keyset / path).stat().st_mode)
        if mode & 0o077:
            raise PermissionError(f"Secret grants group/other access: {path} ({mode:03o})")


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def write_manifest(keyset, keyset_id, action, factory_config, kdf):
    manifest = {
        "schema_version": KEYSET_SCHEMA_VERSION,
        "keyset_id": keyset_id,
        "action": action,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "chip_name": factory_config.oem.chip_name,
        "chip_rev": factory_config.oem.chip_rev,
        "oem_segid": hex(factory_config.oem.oem_segid),
        "oem_version": factory_config.oem.oem_version,
        "Image_production_flag": factory_config.image_production_flag,
        "kdf_context": kdf.context.decode("ascii"),
        "kdf_images": {
            image.name: hex(image.image_type) for image in kdf.images
        },
        "public_key_sha256": {
            "K0_OEM": _sha256(keyset / K0_PUBLIC),
            "K1_C": _sha256(keyset / K1_PUBLIC),
        },
        "config_sha256": {
            "oem_config.conf": _sha256(
                PROJECT_ROOT / "configs" / "oem_config.conf"
            ),
            "key_derivation.conf": _sha256(KDF_CONFIG_PATH),
        },
        "genx_img_v3_sha256": _sha256(GENX_TOOL),
    }
    destination = keyset / "keyset_manifest.json"
    destination.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(destination, 0o644)


def _resolve_current_keyset():
    if not KEYS_LINK.is_symlink():
        raise RuntimeError(
            f"{KEYS_LINK} must be a relative symlink managed by this tool"
        )
    resolved = KEYS_LINK.resolve(strict=True)
    keysets_root = KEYSETS_DIR.resolve(strict=True)
    if resolved.parent != keysets_root:
        raise RuntimeError(f"Current keys symlink escapes {KEYSETS_DIR}: {resolved}")
    return resolved


def _prepare_keys_destination(action):
    """Normalize the keys path before staging or publishing a keyset."""
    if KEYS_LINK.is_symlink():
        return
    if not KEYS_LINK.exists():
        if action != "all":
            raise RuntimeError(
                f"No current keyset exists at {KEYS_LINK}; run without a "
                "command to generate a complete keyset first"
            )
        return
    if not KEYS_LINK.is_dir():
        raise RuntimeError(
            f"{KEYS_LINK} must be a managed symlink, an empty directory, "
            "or absent"
        )
    if action != "all":
        raise RuntimeError(
            f"{KEYS_LINK} is not a managed keyset symlink; run without a "
            "command to generate a complete keyset first"
        )
    if any(KEYS_LINK.iterdir()):
        raise RuntimeError(
            f"Refusing to replace non-empty unmanaged keys directory: {KEYS_LINK}"
        )
    KEYS_LINK.rmdir()


@contextmanager
def lifecycle_lock():
    LOCK_PATH.touch(mode=0o600, exist_ok=True)
    os.chmod(LOCK_PATH, 0o600)
    with LOCK_PATH.open("r+") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("Another key lifecycle operation is already running") from error
        yield


def _create_staging(action):
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    keyset_id = f"{now}-{action}-{secrets.token_hex(4)}"
    staging = KEYSETS_DIR / f".{keyset_id}.staging"
    staging.mkdir(parents=True, mode=0o700)
    if action != "all":
        shutil.copytree(
            _resolve_current_keyset(),
            staging,
            dirs_exist_ok=True,
            copy_function=shutil.copy2,
        )
    return keyset_id, staging


def _publish(staging, keyset_id):
    final_keyset = KEYSETS_DIR / keyset_id
    os.replace(staging, final_keyset)
    temp_link = PROJECT_ROOT / f".keys.{keyset_id}.tmp"
    try:
        os.symlink(Path("keysets") / keyset_id, temp_link)
        os.replace(temp_link, KEYS_LINK)
    except Exception:
        if final_keyset.exists():
            shutil.rmtree(final_keyset)
        raise
    finally:
        if temp_link.is_symlink():
            temp_link.unlink()
    return final_keyset


def execute_action(action):
    plan = ACTION_PLANS[action]
    factory_config = load_factory_config(PROJECT_ROOT)
    kdf = load_kdf_config(factory_config)
    KEYSETS_DIR.mkdir(mode=0o700, exist_ok=True)

    with lifecycle_lock():
        _prepare_keys_destination(action)
        keyset_id, staging = _create_staging(action)
        try:
            if "aes-root" in plan:
                generate_aes_root(staging)
            if "k0" in plan:
                generate_ec_key_pair(staging, K0_PRIVATE, K0_PUBLIC)
            if "k1" in plan:
                generate_ec_key_pair(staging, K1_PRIVATE, K1_PUBLIC)
            if "derived" in plan:
                generate_derived_keys(staging, factory_config, kdf)
            if "k0-store" in plan:
                generate_k0_store(staging)
            if "k1-store" in plan:
                generate_k1_store(staging, factory_config)

            validate_keyset(staging, kdf)
            write_manifest(
                staging,
                keyset_id,
                action,
                factory_config,
                kdf,
            )
            published = _publish(staging, keyset_id)
        except Exception:
            if staging.exists():
                shutil.rmtree(staging)
            raise

    print(f"Published complete keyset: {published}")
    print(f"Current keys: {KEYS_LINK} -> {os.readlink(KEYS_LINK)}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="gen_all_keys_stores.py",
        description=(
            "Generate or rotate factory keys as a complete transactional keyset.\n"
            "A new keyset is validated before the active 'keys' symlink is switched."
        ),
        epilog=(
            "Commands:\n"
            "  (no command)\n"
            "      Regenerate CCGK, all encryption image keys, K0/K1 ECC key\n"
            "      pairs, and both key stores.\n"
            "\n"
            "  rebuild-encryption-Image-keys\n"
            "      Keep the current CCGK and rebuild all encryption image keys.\n"
            "\n"
            "  rebuild-key-stores\n"
            "      Keep the current K0 OEM and K1_C ECC key pairs and rebuild\n"
            "      both the K0 OEM and K1_C key stores.\n"
            "\n"
            "  rotate-CCGK\n"
            "      Generate a new CCGK and rebuild all encryption image keys.\n"
            "\n"
            "  rotate-k0-oem\n"
            "      Generate a new K0 OEM ECC key pair and rebuild the K0/K1\n"
            "      key stores. The current K1_C ECC key pair is retained.\n"
            "\n"
            "  rotate-k1_c_ECC_pair\n"
            "      Generate a new K1_C ECC key pair and rebuild the K1_C key\n"
            "      store. The current K0 OEM ECC key pair is retained.\n"
            "\n"
            "Examples:\n"
            "  python3 gen_all_keys_stores.py\n"
            "  python3 gen_all_keys_stores.py rebuild-encryption-Image-keys\n"
            "  python3 gen_all_keys_stores.py rebuild-key-stores\n"
            "  python3 gen_all_keys_stores.py rotate-CCGK\n"
            "  python3 gen_all_keys_stores.py rotate-k0-oem\n"
            "  python3 gen_all_keys_stores.py rotate-k1_c_ECC_pair\n"
            "\n"
            "Note: derived AES key values are printed to the console; protect\n"
            "manufacturing logs that capture this output."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=tuple(action for action in ACTION_PLANS if action != "all"),
        metavar="COMMAND",
        help="key lifecycle operation; omit COMMAND to regenerate everything",
    )
    return parser


def parse_args(argv=None):
    return build_parser().parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    action = args.command or "all"
    try:
        execute_action(action)
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
