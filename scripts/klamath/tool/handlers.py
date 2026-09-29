"""Image-specific adapters and workflow dispatch."""

from .gen_x_image_pack import (
    patch_KeyStore,
    patch_preboot,
    resign_SM,
    resign_bootloader,
    resign_fastlogo,
    resign_linux,
    resign_m52bl,
    resign_tzk,
)


def _keystore(input_path, output_path, keys_dir, config):
    del config
    patch_KeyStore(str(input_path), str(output_path), str(keys_dir))


def _preboot(input_path, output_path, keys_dir, config):
    patch_preboot(
        str(input_path),
        str(output_path),
        str(keys_dir),
        encrypt_m52bl=config.encrypts("m52bl"),
    )


def _bootloader(input_path, output_path, keys_dir, config):
    resign_bootloader(
        str(input_path),
        str(output_path),
        str(keys_dir),
        encrypt=config.encrypts("UBOOT"),
    )


def _m52bl(input_path, output_path, keys_dir, config):
    resign_m52bl(
        str(input_path),
        str(output_path),
        str(keys_dir),
        encrypt=config.encrypts("m52bl"),
    )


def _sysmgr(input_path, output_path, keys_dir, config):
    resign_SM(
        str(input_path),
        str(output_path),
        str(keys_dir),
        encrypt=config.encrypts("SM"),
    )


def _tzk(input_path, output_path, keys_dir, config):
    resign_tzk(
        str(input_path),
        str(output_path),
        str(keys_dir),
        encrypt_atf=config.encrypts("ATF"),
        encrypt_optee=config.encrypts("OPTEE"),
    )


def _linux(input_path, output_path, keys_dir, config):
    resign_linux(
        str(input_path),
        str(output_path),
        str(keys_dir),
        encrypt=config.encrypts("Linux"),
    )


def _fastlogo(input_path, output_path, keys_dir, config):
    resign_fastlogo(
        str(input_path),
        str(output_path),
        str(keys_dir),
        encrypt=config.encrypts("Fastlogo"),
    )


HANDLERS = {
    "keystore": _keystore,
    "preboot": _preboot,
    "bootloader": _bootloader,
    "m52bl": _m52bl,
    "sysmgr": _sysmgr,
    "tzk": _tzk,
    "linux": _linux,
    "fastlogo": _fastlogo,
}


def process_image(handler_name, input_path, output_path, keys_dir, config):
    try:
        handler = HANDLERS[handler_name]
    except KeyError as error:
        raise ValueError(f"Unknown image handler: {handler_name}") from error
    handler(input_path, output_path, keys_dir, config)
