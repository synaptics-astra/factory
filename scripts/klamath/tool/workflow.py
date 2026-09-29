"""Shared transactional workflow used by eMMC and USB entry points."""

import gzip
import logging
import os
import shutil
import tempfile
from pathlib import Path

from .handlers import process_image
from .image_header import preflight_image
from .keys import (
    keyset_read_lock,
    required_key_paths,
    temporary_key_workspace,
    validate_keyset_config,
    validate_required_keys,
)
from .manifests import get_manifest
from .production_records import (
    capture_manifest_input_hashes,
    capture_production_context,
    discard_prepared_record,
    prepare_production_record,
    publish_production_record,
)


LOGGER = logging.getLogger(__name__)
COPY_BUFFER_SIZE = 65536


def _gunzip(source, destination):
    with gzip.open(source, "rb") as compressed, destination.open("wb") as clear:
        shutil.copyfileobj(compressed, clear, COPY_BUFFER_SIZE)


def _gzip(source, destination):
    with source.open("rb") as clear, gzip.open(destination, "wb") as compressed:
        shutil.copyfileobj(clear, compressed, COPY_BUFFER_SIZE)


def _validate_paths(source, destination):
    if not source.is_dir():
        raise FileNotFoundError(f"Input image directory not found: {source}")
    if destination.exists():
        raise FileExistsError(f"Destination directory already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)


def _validate_manifest_inputs(manifest, source, config):
    missing = [
        spec.filename
        for spec in manifest.images
        if spec.is_required(config) and not (source / spec.filename).is_file()
    ]
    if missing:
        raise FileNotFoundError(
            f"Required {manifest.name} images not found: {', '.join(missing)}"
        )


def _prepare_inputs(manifest, staging_dir, work_dir):
    """Expand inputs and return paths without modifying the staging tree."""
    prepared = {}
    for spec in manifest.images:
        source = staging_dir / spec.filename
        if not source.is_file():
            LOGGER.info("Optional image is absent; skipping %s", spec.filename)
            continue
        if spec.compressed:
            clear_path = work_dir / spec.filename.removesuffix(".gz")
            _gunzip(source, clear_path)
            prepared[spec.filename] = clear_path
        else:
            prepared[spec.filename] = source
    return prepared


def _preflight_all(manifest, prepared):
    """Check every input IV before allowing the first signing operation."""
    for spec in manifest.images:
        input_path = prepared.get(spec.filename)
        if input_path is not None:
            preflight_image(spec.handler, input_path)


def _process_all(manifest, staging_dir, work_dir, prepared, keys_dir, config):
    for index, spec in enumerate(manifest.images):
        input_path = prepared.get(spec.filename)
        if input_path is None:
            continue

        raw_output = work_dir / f"output_{index}_{Path(input_path).name}"
        LOGGER.info("Processing %s with %s handler", spec.filename, spec.handler)
        process_image(
            spec.handler,
            input_path,
            raw_output,
            keys_dir,
            config,
        )
        if not raw_output.is_file() or raw_output.stat().st_size == 0:
            raise ValueError(f"Generated image is empty: {spec.filename}")

        destination = staging_dir / spec.filename
        if spec.compressed:
            compressed_output = work_dir / f"output_{index}_{spec.filename}"
            _gzip(raw_output, compressed_output)
            os.replace(compressed_output, destination)
        else:
            os.replace(raw_output, destination)


def run_factory_flow(profile, source_dir, output_dir, config):
    """Run one profile and publish its output directory only after full success."""
    manifest = get_manifest(profile)
    source = Path(source_dir).resolve()
    destination = Path(output_dir).resolve()
    _validate_paths(source, destination)
    _validate_manifest_inputs(manifest, source, config)

    with keyset_read_lock(config.project_root):
        key_paths = required_key_paths(config.encryption_policy)
        keys_root = config.project_root / "keys"
        validate_keyset_config(keys_root, config)
        validate_required_keys(keys_root, key_paths)
        production_context = capture_production_context(config)

        with tempfile.TemporaryDirectory(
            prefix=f".codex_v1_{profile}_",
            dir=destination.parent,
        ) as transaction_root_text:
            transaction_root = Path(transaction_root_text)
            staging_dir = transaction_root / "image"
            work_dir = transaction_root / "work"
            work_dir.mkdir(mode=0o700)
            shutil.copytree(source, staging_dir)
            input_hashes = capture_manifest_input_hashes(
                manifest, staging_dir
            )

            prepared = _prepare_inputs(manifest, staging_dir, work_dir)
            _preflight_all(manifest, prepared)

            with temporary_key_workspace(keys_root, key_paths) as keys_dir:
                _process_all(
                    manifest,
                    staging_dir,
                    work_dir,
                    prepared,
                    keys_dir,
                    config,
                )

            record_id, record_stage, reservation = prepare_production_record(
                profile,
                destination.name,
                input_hashes,
                staging_dir,
                config,
                manifest,
                production_context,
            )
            record_destination = None
            try:
                record_destination = publish_production_record(
                    record_id, record_stage, reservation
                )
                try:
                    os.replace(staging_dir, destination)
                except Exception:
                    # Restore the newly-created record to staging so the outer
                    # transaction cleanup does not leave an orphan audit record.
                    os.replace(record_destination, record_stage)
                    raise
            except Exception:
                discard_prepared_record(record_stage, reservation)
                raise

            LOGGER.info("Published production record: %s", record_destination)

    return destination
