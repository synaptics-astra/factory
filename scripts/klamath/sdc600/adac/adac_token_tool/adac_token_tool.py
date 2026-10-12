#!/usr/bin/env python3
"""
Interactive ADAC debug token helper.

The tool builds a 16-byte ADAC permission table for SL261x or SR2xx, then can
optionally call the ADAC signing tool and append the ADAC store binary to build
the final debug token.
"""

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Sequence


PERMISSION_SIZE = 16


class Permission(NamedTuple):
    name: str
    value: bytes
    description: str
    otp_note: str


SL261X_PERMISSIONS: Sequence[Permission] = (
    Permission("M52_NS", bytes.fromhex("01 ac"), "Enable M52 NS DP", "M52 NS DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("M52_Sec", bytes.fromhex("02 ac"), "Enable M52 Secure DP", "M52 Secure DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("A55_NS", bytes.fromhex("03 ac"), "Enable A55 NS DP", "A55 NS DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("A55_Sec", bytes.fromhex("04 ac"), "Enable A55 Secure DP", "A55 Secure DP OTP JTAG_Acc_Ctrl must be 2'b01"),
)


SR2XX_PERMISSIONS: Sequence[Permission] = (
    Permission("M85_Sec", bytes.fromhex("a0"), "Enable M85 Secure DP", "M85 Secure DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("M85_NS", bytes.fromhex("a1"), "Enable M85 NS DP", "M85 NS DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("M52_Sec", bytes.fromhex("a2"), "Enable M52 Secure DP", "M52 Secure DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("M52_NS", bytes.fromhex("a3"), "Enable M52 NS DP", "M52 NS DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("hifi1_Sec", bytes.fromhex("a4"), "Enable HiFi1 Secure DP", "HiFi1 Secure DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("hifi1_NS", bytes.fromhex("a5"), "Enable HiFi1 NS DP", "HiFi1 NS DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("hifi5_Sec", bytes.fromhex("a6"), "Enable HiFi5 Secure DP", "HiFi5 Secure DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("hifi5_NS", bytes.fromhex("a7"), "Enable HiFi5 NS DP", "HiFi5 NS DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("etr_Sec", bytes.fromhex("a8"), "Enable ETR Secure DP", "ETR Secure DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("etr_NS", bytes.fromhex("a9"), "Enable ETR NS DP", "ETR NS DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("cti_Sec", bytes.fromhex("aa"), "Enable CTI Secure DP", "CTI Secure DP OTP JTAG_Acc_Ctrl must be 2'b01"),
    Permission("cti_NS", bytes.fromhex("ab"), "Enable CTI NS DP", "CTI NS DP OTP JTAG_Acc_Ctrl must be 2'b01"),
)


PLATFORMS: Dict[str, Sequence[Permission]] = {
    "SL261x": SL261X_PERMISSIONS,
    "SR2xx": SR2XX_PERMISSIONS,
}


def format_hex(data: bytes) -> str:
    return " ".join("{:02x}".format(byte) for byte in data)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate ADAC permission table and optional debug token."
    )
    parser.add_argument("--platform", choices=PLATFORMS.keys(), help="Target platform.")
    parser.add_argument(
        "--permissions",
        nargs="+",
        help="Permission names to enable, for example: M52_NS M85_Sec. Use 'all' to enable all listed ports.",
    )
    parser.add_argument("--permission-out", default="tmp/adac_permission.bin", help="Output permission binary path.")
    parser.add_argument("--challenge", default="adac_challenge.bin", help="Input ADAC challenge binary.")
    parser.add_argument("--adac", default="bin/adac", help="ADAC executable path.")
    parser.add_argument("--key", default="keys/K1_C_ADAC.EC521.priv.pem", help="ADAC private key path.")
    parser.add_argument("--store", default="tmp/out_K1_C_ADAC_store.bin", help="ADAC store binary path.")
    parser.add_argument("--signature-out", default="tmp/adac_signature.out", help="Output signature path.")
    parser.add_argument("--token-out", default="out/cmd3_k1c_debug_token.bin", help="Output debug token path.")
    parser.add_argument("--build-token", action="store_true", help="Run adac and build final debug token.")
    parser.add_argument("--permission-only", action="store_true", help="Only generate the permission binary.")
    parser.add_argument("--genx-img", default="bin/genx_img", help="genx_img executable path.")
    parser.add_argument("--store-img-type", default="K1_C_ADAC", help="genx_img -t value for the ADAC store binary.")
    parser.add_argument("--store-production-flag", help="genx_img -f value for the ADAC store binary.")
    parser.add_argument("--store-signing-key", default="keys/K0_OEM.priv.pem", help="genx_img -n signing key for the ADAC store binary.")
    parser.add_argument("--store-seg-id", help="genx_img -s segment ID for the ADAC store binary.")
    parser.add_argument("--store-version", help="genx_img -r version for the ADAC store binary.")
    parser.add_argument("--store-key-payload", default="keys/K1_C_ADAC.EC521.pub.pem", help="genx_img -i key payload for the ADAC store binary.")
    parser.add_argument("--yes", action="store_true", help="Do not ask for confirmation in non-interactive mode.")
    return parser.parse_args()


def choose_from_menu(title: str, choices: Sequence[str]) -> str:
    print(f"\n{title}")
    for index, choice in enumerate(choices, start=1):
        print(f"  {index}. {choice}")

    while True:
        raw = input("Select number: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1]
        print("Invalid selection, please try again.")


def print_permission_menu(platform: str, permissions: Sequence[Permission]) -> None:
    print(f"\nAvailable permissions for {platform}:")
    print("  idx  value     permission   requested DP enablement")
    print("  ---  --------  -----------  -----------------------")
    for index, permission in enumerate(permissions, start=1):
        value = format_hex(permission.value).upper()
        print(f"  {index:>2}.  {value:<8}  {permission.name:<11}  {permission.description}")
        print(f"       OTP requirement: {permission.otp_note}")


def print_permission_select_menu(
    platform: str,
    permissions: Sequence[Permission],
    selected: Sequence[Permission],
) -> None:
    print(f"\nSelect permissions for {platform}:")
    print("  mark idx  value     permission   requested DP enablement")
    print("  ---- ---  --------  -----------  -----------------------")
    for index, permission in enumerate(permissions, start=1):
        value = format_hex(permission.value).upper()
        mark = "[x]" if permission in selected else "[ ]"
        print(f"  {mark} {index:>2}.  {value:<8}  {permission.name:<11}  {permission.description}")
        print(f"          OTP requirement: {permission.otp_note}")


def choose_permissions(platform: str, permissions: Sequence[Permission]) -> List[Permission]:
    selected: List[Permission] = []
    name_map = {permission.name.lower(): permission for permission in permissions}

    while True:
        print_permission_select_menu(platform, permissions, selected)
        print("\nCommands:")
        print("  - Type one or more numbers/names to select or unselect them. Example: 1 3 M85_NS")
        print("  - Type all to select all permissions")
        print("  - Type clear to clear the current selection")
        print("  - Type done to continue")

        raw = input("Selection: ").strip()
        command = raw.lower()

        if command in ("done", "d"):
            if selected:
                return selected
            print("Please select at least one permission before continuing.")
            continue

        if command == "all":
            selected = list(permissions)
            continue

        if command in ("clear", "c"):
            selected = []
            continue

        valid = True
        for item in raw.replace(",", " ").split():
            if item.isdigit() and 1 <= int(item) <= len(permissions):
                permission = permissions[int(item) - 1]
            else:
                permission = name_map.get(item.lower())
            if permission is None:
                print(f"Unknown permission: {item}")
                valid = False
                break
            if permission not in selected:
                selected.append(permission)
            else:
                selected.remove(permission)

        if not valid:
            print("Please select valid permission numbers or names.")


def validate_permission_names(platform: str, names: Iterable[str]) -> List[Permission]:
    permissions = PLATFORMS[platform]
    if len(names) == 1 and next(iter(names)).lower() == "all":
        return list(permissions)

    name_map = {permission.name.lower(): permission for permission in permissions}
    selected: List[Permission] = []
    for name in names:
        permission = name_map.get(name.lower())
        if permission is None:
            valid_names = ", ".join(permission.name for permission in permissions)
            raise SystemExit(f"Unknown permission '{name}' for {platform}. Valid names: {valid_names}")
        if permission not in selected:
            selected.append(permission)
    return selected


def build_permission_table(platform: str, selected: Sequence[Permission]) -> bytes:
    table = bytearray(PERMISSION_SIZE)
    permissions = PLATFORMS[platform]

    for permission in selected:
        index = permissions.index(permission)
        offset = index * len(permission.value)
        end = offset + len(permission.value)
        if end > PERMISSION_SIZE:
            raise ValueError(f"Permission {permission.name} does not fit into 16-byte table")
        table[offset:end] = permission.value

    return bytes(table)


def require_file(path: Path, description: str) -> None:
    if not path.is_file():
        raise SystemExit(f"Missing {description}: {path}")


def require_executable(path: Path) -> None:
    require_file(path, "ADAC executable")
    if not path.stat().st_mode & 0o111:
        raise SystemExit(f"ADAC executable is not executable, please run: chmod +x {path}")


def ask_build_token(args: argparse.Namespace) -> bool:
    if args.build_token:
        return True

    if args.permission_only or args.yes or not sys.stdin.isatty():
        return False

    print("\nADAC token input paths:")
    print(f"  challenge : {args.challenge}")
    print(f"  adac      : {args.adac}")
    print(f"  key       : {args.key}")
    print(f"  store out : {args.store}")
    answer = input("\nBuild debug token now? [y/N]: ").strip().lower()
    return answer in ("y", "yes")


def ask_text(prompt: str, current_value: str = None) -> str:
    suffix = f" [{current_value}]" if current_value else ""
    while True:
        value = input(f"{prompt}{suffix}: ").strip()
        if value:
            return value
        if current_value:
            return current_value
        print("This value is required.")


def get_store_param(args: argparse.Namespace, arg_name: str, prompt: str) -> str:
    value = getattr(args, arg_name)
    if value:
        return value
    if args.yes or not sys.stdin.isatty():
        option = "--" + arg_name.replace("_", "-")
        raise SystemExit(f"Missing {option}; it is required to generate {args.store}")
    value = ask_text(prompt)
    setattr(args, arg_name, value)
    return value


def build_store_if_needed(args: argparse.Namespace) -> None:
    store = Path(args.store)
    genx_img = Path(args.genx_img)
    require_executable(genx_img)

    img_type = get_store_param(args, "store_img_type", "Store image type, genx_img -t")
    production_flag = get_store_param(args, "store_production_flag", "Production flag, genx_img -f")
    signing_key = Path(get_store_param(args, "store_signing_key", "Store signing key, genx_img -n"))
    seg_id = get_store_param(args, "store_seg_id", "Segment ID, genx_img -s")
    version = get_store_param(args, "store_version", "Version, genx_img -r")
    key_payload = Path(get_store_param(args, "store_key_payload", "Key payload, genx_img -i"))

    require_file(signing_key, "store signing key")
    require_file(key_payload, "store key payload")
    store.parent.mkdir(parents=True, exist_ok=True)

    genx_cmd = [
        str(genx_img),
        "-t",
        img_type,
        "-f",
        production_flag,
        "-n",
        str(signing_key),
        "-s",
        seg_id,
        "-r",
        version,
        "-i",
        str(key_payload),
        "-o",
        str(store),
    ]

    print("\nGenerating ADAC store binary:")
    print("  " + " ".join(genx_cmd))
    subprocess.run(genx_cmd, check=True)
    require_file(store, "generated ADAC store binary")
    print(f"Generated ADAC store binary: {store}")


def run_adac(args: argparse.Namespace, permission_out: Path) -> None:
    challenge = Path(args.challenge)
    adac = Path(args.adac)
    key = Path(args.key)
    store = Path(args.store)
    signature_out = Path(args.signature_out)
    token_out = Path(args.token_out)

    require_file(challenge, "ADAC challenge file")
    if "/" in str(adac):
        require_executable(adac)
    require_file(key, "ADAC private key")
    build_store_if_needed(args)
    require_file(store, "ADAC store binary")
    signature_out.parent.mkdir(parents=True, exist_ok=True)
    token_out.parent.mkdir(parents=True, exist_ok=True)

    adac_cmd = [
        str(adac),
        "-C",
        str(challenge),
        "-P",
        str(permission_out),
        "-K",
        str(key),
        "-O",
        str(signature_out),
    ]

    print("\nRunning ADAC command:")
    print("  " + " ".join(adac_cmd))
    subprocess.run(adac_cmd, check=True)

    with signature_out.open("rb") as sig_file, store.open("rb") as store_file, token_out.open("wb") as token_file:
        token_file.write(sig_file.read())
        token_file.write(store_file.read())

    print(f"Generated debug token: {token_out}")


def confirm_selected(platform: str, selected: Sequence[Permission], assume_yes: bool) -> None:
    print(f"\nPlatform: {platform}")
    print("Selected permissions:")
    for permission in selected:
        print(f"  - {permission.name}: {permission.description}")
        print(f"    {permission.otp_note}")

    if assume_yes:
        return

    answer = input("\nContinue and generate permission table? [y/N]: ").strip().lower()
    if answer not in ("y", "yes"):
        raise SystemExit("Canceled.")


def main() -> int:
    args = parse_args()

    if args.platform:
        platform = args.platform
    else:
        platform = choose_from_menu("Select platform:", list(PLATFORMS.keys()))

    permissions = PLATFORMS[platform]
    if args.permissions:
        selected = validate_permission_names(platform, args.permissions)
    else:
        selected = choose_permissions(platform, permissions)

    confirm_selected(platform, selected, args.yes)

    permission_table = build_permission_table(platform, selected)
    permission_out = Path(args.permission_out)
    permission_out.parent.mkdir(parents=True, exist_ok=True)
    permission_out.write_bytes(permission_table)
    print(f"\nGenerated permission binary: {permission_out}")

    if ask_build_token(args):
        run_adac(args, permission_out)
    else:
        print("\nToken build skipped. Re-run with --build-token if you want to build it later.")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode)
