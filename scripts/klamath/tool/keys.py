"""Key selection, validation, and private workspace lifecycle."""

import fcntl
import json
import os
import shutil
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path


IMAGE_KEY_MAP = {
    "m52bl": ("BL",),
    "SM": ("SM",),
    "UBOOT": ("UBOOT",),
    "OPTEE": ("OPTEE", "TEEBP"),
    "ATF": ("ATF",),
    "Fastlogo": ("FAST_LOGO",),
    "Linux": ("LINUX",),
}

FIXED_KEY_PATHS = (
    "generic/oem/K0_OEM.EC521.priv.pem",
    "generic/oem/K1_C.EC521.priv.pem",
    "store/K1_C_store_4k.bin",
    "store/K0_OEM_store_4k.bin",
)
KEYSET_MANIFEST_FILENAME = "keyset_manifest.json"


@contextmanager
def keyset_read_lock(project_root):
    """Keep the current keyset stable while a production image is generated."""
    lock_path = Path(project_root) / ".keyset.lock"
    lock_path.touch(mode=0o600, exist_ok=True)
    os.chmod(lock_path, 0o600)
    with lock_path.open("r+") as lock_file:
        try:
            fcntl.flock(
                lock_file.fileno(),
                fcntl.LOCK_SH | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise RuntimeError(
                "A key lifecycle operation is running; retry production image "
                "generation after it completes"
            ) from error
        yield


def required_key_paths(policy):
    paths = list(FIXED_KEY_PATHS)
    for image_name in sorted(policy):
        paths.extend(
            f"generic/oem/CCGK_{key_name}.bin"
            for key_name in IMAGE_KEY_MAP[image_name]
        )
    return tuple(dict.fromkeys(paths))


def validate_required_keys(keys_dir, relative_paths):
    keys_dir = Path(keys_dir)
    missing = [path for path in relative_paths if not (keys_dir / path).is_file()]
    if missing:
        raise FileNotFoundError(f"Required key files not found: {', '.join(missing)}")

    insecure = []
    for relative_path in relative_paths:
        if not (
            relative_path.endswith(".priv.pem") or "/CCGK_" in relative_path
        ):
            continue
        mode = stat.S_IMODE((keys_dir / relative_path).stat().st_mode)
        if mode & 0o077:
            insecure.append(f"{relative_path} ({mode:03o})")
    if insecure:
        raise PermissionError(
            "Secret key permissions must not grant group/other access: "
            + ", ".join(insecure)
        )


def validate_keyset_config(keys_dir, config):
    """Require the active keyset's generation settings to match this run."""
    manifest_path = Path(keys_dir) / KEYSET_MANIFEST_FILENAME
    if not manifest_path.is_file():
        raise FileNotFoundError(
            "Current keyset is missing keyset_manifest.json; run "
            "gen_all_keys_stores.py before generating a production image"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Current keyset manifest is not valid JSON: {manifest_path}"
        ) from error
    if not isinstance(manifest, dict):
        raise ValueError(f"Current keyset manifest is not an object: {manifest_path}")

    expected_values = {
        "chip_name": config.oem.chip_name,
        "chip_rev": config.oem.chip_rev,
        "oem_segid": hex(config.oem.oem_segid),
        "oem_version": config.oem.oem_version,
        "Image_production_flag": config.image_production_flag,
    }
    mismatches = [
        f"{name} (keyset={manifest.get(name)!r}, config={expected!r})"
        for name, expected in expected_values.items()
        if manifest.get(name) != expected
    ]
    if mismatches:
        raise ValueError(
            "Active keyset configuration does not match configs/oem_config.conf; "
            "regenerate the keyset before generating a production image: "
            + ", ".join(mismatches)
        )


@contextmanager
def temporary_key_workspace(keys_dir, relative_paths):
    """Copy only selected keys to a mode-0700 directory and always remove it."""
    with tempfile.TemporaryDirectory(prefix="factory_keys_") as workspace:
        workspace_path = Path(workspace)
        os.chmod(workspace_path, 0o700)
        for relative_path in relative_paths:
            source = Path(keys_dir) / relative_path
            destination = workspace_path / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(source, destination)
            secret = (
                relative_path.endswith(".priv.pem") or "/CCGK_" in relative_path
            )
            os.chmod(destination, 0o600 if secret else 0o644)
        yield workspace_path
