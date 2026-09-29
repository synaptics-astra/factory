"""Create non-secret audit records for published production image runs."""

import hashlib
import json
import os
import re
import secrets
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path


INFO_FILENAME = "signed_image_info.txt"
MANIFEST_FILENAME = "production_manifest.json"
RECORD_SCHEMA_VERSION = 1
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_TOOL_PATHS = (
    "gen_production_image.py",
    "tool/config.py",
    "tool/crc_calc.py",
    "tool/handlers.py",
    "tool/image_header.py",
    "tool/in_extras.py",
    "tool/keys.py",
    "tool/manifests.py",
    "tool/production_records.py",
    "tool/workflow.py",
    "tool/gen_x_image_pack.py",
    "tool/gen_x_secure_image.py",
    "tool/genx_img_v3",
)
_CONFIG_PATHS = (
    "configs/oem_config.conf",
    "configs/encrypto_image.conf",
)


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_output_name(name):
    name = _SAFE_NAME.sub("-", name.strip()).strip("._-")
    if not name:
        name = "signed-image"
    return name[:80]


def _new_record_identity(profile, output_name, records_root):
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    base = f"{timestamp}-{profile}-{_safe_output_name(output_name)}"
    record_id = base
    while True:
        if (records_root / record_id).exists():
            record_id = f"{base}-{secrets.token_hex(4)}"
            continue
        reservation = records_root / f".reserve-{record_id}"
        try:
            reservation.mkdir(mode=0o700)
        except FileExistsError:
            record_id = f"{base}-{secrets.token_hex(4)}"
            continue
        return record_id, now.isoformat(), reservation


def _load_keyset_reference(keys_root):
    manifest_path = Path(keys_root) / "keyset_manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(
            "Current keyset is missing keyset_manifest.json; publish keys with "
            "gen_all_keys_stores.py before generating a production image"
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    keyset_id = manifest.get("keyset_id")
    if not isinstance(keyset_id, str) or not keyset_id:
        raise ValueError("Current keyset_manifest.json has no valid keyset_id")
    return {
        "keyset_id": keyset_id,
        "keyset_manifest_sha256": _sha256(manifest_path),
        "public_key_sha256": manifest.get("public_key_sha256", {}),
    }


def _relative_file_hashes(root):
    root = Path(root)
    return {
        path.relative_to(root).as_posix(): _sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _tree_digest(file_hashes):
    digest = hashlib.sha256()
    for relative_path, file_digest in sorted(file_hashes.items()):
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _image_records(flow_manifest, input_hashes, staging_dir, config):
    records = []
    for spec in flow_manifest.images:
        output_path = Path(staging_dir) / spec.filename
        if spec.filename not in input_hashes:
            continue
        selected_policy = sorted(
            name for name in spec.policy_names if config.encrypts(name)
        )
        records.append(
            {
                "filename": spec.filename,
                "handler": spec.handler,
                "input_sha256": input_hashes[spec.filename],
                "output_sha256": _sha256(output_path),
                "signed": spec.handler != "keystore",
                "encryption_requested": bool(selected_policy),
                "encryption_policy_names": selected_policy,
                "input_iv_preflight": (
                    "not_applicable" if spec.handler == "keystore" else "zero"
                ),
            }
        )
    return records


def capture_manifest_input_hashes(flow_manifest, staging_dir):
    """Hash the exact source copies that will enter the signing workflow."""
    staging_dir = Path(staging_dir)
    return {
        spec.filename: _sha256(staging_dir / spec.filename)
        for spec in flow_manifest.images
        if (staging_dir / spec.filename).is_file()
    }


def capture_production_context(config):
    """Capture all non-image audit inputs before the first signing operation."""
    return {
        "keyset": _load_keyset_reference(config.project_root / "keys"),
        "oem": {
            "chip_name": config.oem.chip_name,
            "chip_rev": config.oem.chip_rev,
            "oem_segid": hex(config.oem.oem_segid),
            "oem_version": config.oem.oem_version,
            "Image_production_flag": config.image_production_flag,
        },
        "encryption_policy": sorted(config.encryption_policy),
        "config_sha256": {
            path: _sha256(config.project_root / path)
            for path in _CONFIG_PATHS
        },
        "tool_sha256": {
            path: _sha256(config.project_root / path)
            for path in _TOOL_PATHS
        },
    }


def prepare_production_record(
    profile,
    output_name,
    input_hashes,
    staging_dir,
    config,
    flow_manifest,
    production_context,
):
    """Add the output pointer and stage a restricted external JSON record."""
    records_root = config.project_root / "production_records"
    records_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(records_root, 0o700)

    record_id, created_at, reservation = _new_record_identity(
        profile, output_name, records_root
    )
    record_stage = Path(
        tempfile.mkdtemp(prefix=".record-", dir=records_root)
    )
    os.chmod(record_stage, 0o700)

    try:
        pointer = (
            f"schema_version={RECORD_SCHEMA_VERSION}\n"
            f"production_record_id={record_id}\n"
            f"profile={profile}\n"
            f"created_at_utc={created_at}\n"
        )
        info_path = Path(staging_dir) / INFO_FILENAME
        info_path.write_text(pointer, encoding="utf-8")
        os.chmod(info_path, 0o644)

        output_files = _relative_file_hashes(staging_dir)
        manifest = {
            "schema_version": RECORD_SCHEMA_VERSION,
            "production_record_id": record_id,
            "created_at_utc": created_at,
            "status": "success",
            "profile": profile,
            "output": {
                "directory_name": output_name,
                "tree_sha256": _tree_digest(output_files),
                "files_sha256": output_files,
            },
            **production_context,
            "images": _image_records(
                flow_manifest, input_hashes, staging_dir, config
            ),
        }
        manifest_path = record_stage / MANIFEST_FILENAME
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(manifest_path, 0o600)
        return record_id, record_stage, reservation
    except Exception:
        shutil.rmtree(record_stage, ignore_errors=True)
        reservation.rmdir()
        raise


def publish_production_record(record_id, record_stage, reservation):
    """Atomically publish a prepared record and release its ID reservation."""
    destination = record_stage.parent / record_id
    if destination.exists():
        raise FileExistsError(f"Production record already exists: {destination}")
    os.replace(record_stage, destination)
    try:
        reservation.rmdir()
    except Exception:
        os.replace(destination, record_stage)
        raise
    return destination


def discard_prepared_record(record_stage, reservation):
    """Remove record staging after a failed image transaction."""
    if Path(record_stage).exists():
        shutil.rmtree(record_stage)
    if Path(reservation).exists():
        Path(reservation).rmdir()
