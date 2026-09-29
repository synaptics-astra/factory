#!/usr/bin/env python3

"""Unified eMMC production and USB image entry point."""

import argparse
import logging
import sys
import traceback
from pathlib import Path


if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from tool.config import load_factory_config
    from tool.manifests import get_manifest
    from tool.workflow import run_factory_flow
else:
    from .tool.config import load_factory_config
    from .tool.manifests import get_manifest
    from .tool.workflow import run_factory_flow


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Astra modular eMMC/USB production image generator."
    )
    parser.add_argument(
        "image_type",
        choices=("emmc", "usb"),
        help="select the eMMC production or USB resigning flow",
    )
    parser.add_argument("source", help="source image directory")
    parser.add_argument(
        "-o",
        "--output",
        help="output directory; it must not already exist",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable debug logging",
    )
    args = parser.parse_args(argv)
    manifest = get_manifest(args.image_type)
    output = args.output or manifest.default_output

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s : %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        project_root = Path(__file__).resolve().parent
        config = load_factory_config(project_root)
        result = run_factory_flow(
            args.image_type,
            args.source,
            output,
            config,
        )
        logging.getLogger(__name__).info("Published output: %s", result)
        return 0
    except Exception as error:
        logging.getLogger(__name__).error("Factory flow failed: %s", error)
        if args.verbose:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
