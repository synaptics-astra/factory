"""Single, strict loader for user-defined factory configuration."""

import ast
import configparser
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet


@dataclass(frozen=True)
class OemConfig:
    chip_name: str
    chip_rev: str
    oem_segid: int
    oem_version: int
    image_production_flag: int


@dataclass(frozen=True)
class FactoryConfig:
    project_root: Path
    oem: OemConfig
    encryption_policy: FrozenSet[str]

    def encrypts(self, image_name):
        return image_name in self.encryption_policy


    @property
    def image_production_flag(self):
        """Image/key production state selected explicitly by the operator."""
        return self.oem.image_production_flag


SUPPORTED_ENCRYPTED_IMAGES = frozenset(
    {"m52bl", "SM", "UBOOT", "OPTEE", "ATF", "Fastlogo", "Linux"}
)
LOGGER = logging.getLogger(__name__)


def _required_value(parser, section, option, source):
    if not parser.has_section(section):
        raise ValueError(f"Missing [{section}] section in {source}")
    value = parser.get(section, option, fallback="").strip()
    if not value:
        raise ValueError(f"Missing {section}.{option} in {source}")
    return value


def _load_oem_config(path):
    if not path.is_file():
        raise FileNotFoundError(f"OEM configuration file not found: {path}")

    parser = configparser.ConfigParser()
    with path.open(encoding="utf-8") as source:
        parser.read_file(source)

    chip_name = _required_value(parser, "Chip Info", "chip_name", path)
    chip_rev = _required_value(parser, "Chip Info", "chip_rev", path)
    segid_text = _required_value(parser, "Segmentation ID", "oem_segid", path)
    version_text = _required_value(parser, "Version", "oem_version", path)
    image_production_flag_text = _required_value(
        parser, "Image Production Flag", "Image_production_flag", path
    )
    try:
        oem_segid = int(segid_text, 0)
    except ValueError as error:
        raise ValueError("oem_segid must be a valid integer") from error
    if not 0 <= oem_segid <= 0xFFFFFFFF:
        raise ValueError("oem_segid must be between 0 and 0xFFFFFFFF")

    try:
        oem_version = int(version_text, 0)
    except ValueError as error:
        raise ValueError("oem_version must be an integer from 0 to 32") from error
    if not 0 <= oem_version <= 32:
        raise ValueError("oem_version must be an integer from 0 to 32")

    try:
        image_production_flag = int(image_production_flag_text, 0)
    except ValueError as error:
        raise ValueError("Image_production_flag must be either 0 or 1") from error
    if image_production_flag not in (0, 1):
        raise ValueError("Image_production_flag must be either 0 or 1")

    return OemConfig(
        chip_name,
        chip_rev,
        oem_segid,
        oem_version,
        image_production_flag,
    )


def _load_encryption_policy(path):
    if not path.is_file():
        raise FileNotFoundError(f"Encryption configuration file not found: {path}")

    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    assignments = [
        node for node in module.body
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "encrypto_image_list"
        )
    ]
    if len(assignments) != 1:
        raise ValueError(
            f"{path} must define encrypto_image_list exactly once"
        )
    try:
        policy = ast.literal_eval(assignments[0].value)
    except (ValueError, TypeError) as error:
        raise ValueError("encrypto_image_list must be a literal list") from error

    if not isinstance(policy, list) or not policy:
        raise ValueError("encrypto_image_list must be a non-empty list")
    if not all(isinstance(item, str) for item in policy):
        raise ValueError("Every encrypto_image_list entry must be a string")
    if len(policy) != len(set(policy)):
        raise ValueError("encrypto_image_list contains duplicate entries")
    unknown = sorted(set(policy) - SUPPORTED_ENCRYPTED_IMAGES)
    if unknown:
        raise ValueError(f"Unsupported encrypted image names: {', '.join(unknown)}")
    return frozenset(policy)


def load_factory_config(project_root=None):
    """Load all user configuration once and return an immutable value object."""
    root = (
        Path(project_root).resolve()
        if project_root is not None
        else Path(__file__).resolve().parent.parent
    )
    config_dir = root / "configs"
    return FactoryConfig(
        project_root=root,
        oem=_load_oem_config(config_dir / "oem_config.conf"),
        encryption_policy=_load_encryption_policy(
            config_dir / "encrypto_image.conf"
        ),
    )


class ParseConfig:
    """Compatibility facade used by the local GenX image implementation."""

    def __init__(self):
        self._config = load_factory_config()

    def get_chip_info(self, info_name):
        values = {
            "chip_name": self._config.oem.chip_name,
            "chip_rev": self._config.oem.chip_rev,
        }
        return values[info_name]

    def get_oem_seg_id(self, seg_id_name):
        if seg_id_name != "oem_segid":
            raise KeyError(seg_id_name)
        return hex(self._config.oem.oem_segid)

    def get_oem_version(self, ver_name):
        if ver_name != "oem_version":
            raise KeyError(ver_name)
        return str(self._config.oem.oem_version)

    def get_image_production_flag(self):
        return self._config.image_production_flag

    def print_chip_info(self):
        LOGGER.info("Chip Attributes Information:")
        LOGGER.info("chip_name: %s", self._config.oem.chip_name)
        LOGGER.info("chip_rev: %s", self._config.oem.chip_rev)

    def print_oem_config_segid(self):
        LOGGER.info("OEM Seg_id:")
        LOGGER.info("oem_segid: %s", hex(self._config.oem.oem_segid))

    def print_oem_config_version(self):
        LOGGER.info("OEM Version:")
        LOGGER.info("oem_version: %s", self._config.oem.oem_version)
