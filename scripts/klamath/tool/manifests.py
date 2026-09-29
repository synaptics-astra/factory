"""Data-driven image lists for each factory delivery profile."""

from dataclasses import dataclass
from typing import Tuple

from .config import FactoryConfig


@dataclass(frozen=True)
class ImageSpec:
    filename: str
    handler: str
    policy_names: Tuple[str, ...] = ()
    always_required: bool = False
    compressed: bool = False

    def is_required(self, config: FactoryConfig):
        return self.always_required or any(
            config.encrypts(name) for name in self.policy_names
        )


@dataclass(frozen=True)
class FlowManifest:
    name: str
    default_output: str
    images: Tuple[ImageSpec, ...]


EMMC = FlowManifest(
    name="emmc",
    default_output="./eMMCimg_Production_codex_v1",
    images=(
        ImageSpec("preboot.subimg.gz", "preboot", ("m52bl",), True, True),
        ImageSpec("bl.subimg.gz", "bootloader", ("UBOOT",), compressed=True),
        ImageSpec("sysmgr.subimg.gz", "sysmgr", ("SM",), compressed=True),
        ImageSpec("tzk.subimg.gz", "tzk", ("ATF", "OPTEE"), compressed=True),
        ImageSpec("boot.subimg.gz", "linux", ("Linux",), compressed=True),
        ImageSpec(
            "fastlogo.subimg.gz",
            "fastlogo",
            ("Fastlogo",),
            compressed=True,
        ),
    ),
)

USB = FlowManifest(
    name="usb",
    default_output="./resign_images_codex_v1",
    images=(
        ImageSpec("key.bin", "keystore", always_required=True),
        ImageSpec("bl.subimg", "bootloader", ("UBOOT",)),
        ImageSpec("m52bl.bin", "m52bl", ("m52bl",)),
        ImageSpec("sysmgr.subimg", "sysmgr", ("SM",)),
        ImageSpec("tzk.subimg", "tzk", ("ATF", "OPTEE")),
    ),
)

MANIFESTS = {"emmc": EMMC, "usb": USB}


def get_manifest(profile):
    try:
        return MANIFESTS[profile]
    except KeyError as error:
        supported = ", ".join(sorted(MANIFESTS))
        raise ValueError(
            f"Unsupported factory profile {profile!r}; choose {supported}"
        ) from error
