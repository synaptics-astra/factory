#!/usr/bin/python
# coding=UTF-8
#==============================================================================================
#
# Copyright 2026 Synaptics Incorporated. All rights reserved.
#
# This file contains information that is proprietary to Synaptics Incorporated ("Synaptics").
# The holder of this file shall treat all information contained herein as confidential,
# shall use the information only for its intended purpose, and shall not duplicate, disclose,
# or disseminate any of this information in any manner unless Synaptics has otherwise provided
# express, written permission.
#==============================================================================================

###############################################################################################
#  File: gen_x_image_pack.py
#  Auth: Darren Huang
#  Note: Python 3 tool to generate production images (Strictly Optimized for Klamath Architecture)
###############################################################################################

import os
import tempfile
import shutil
import subprocess
import logging
import sys
import struct

from .config import ParseConfig
# ==========================================
# Core Security Tools Definitions
# ==========================================
GENX_TOOL = 'gen_x_secure_image.py'
EXTRA_TOOL = 'in_extras.py'

# ==========================================
# System Common and I/O Buffer Configuration
# ==========================================
IO_BUFFER_SIZE = 65536         # Unified 64KB chunk size for binary file I/O operations

# ==========================================
# Klamath Hardware Layout Constants
# ==========================================
IMAGE_PREPEND_INFO_SIZE = 64
HEADER_SIZE = 0x274                 # 628 Bytes boundary header for modern layout
IMAGE_IV_OFFSET_IN_HEADER = 0x0C    # AES IV field inside a GenX V3 image header
IMAGE_IV_SIZE = 16                  # GenX V3 stores a 128-bit AES IV
EXTRAS_OFFSET_IN_HEADER = 0x64      # Offset position for extras structure inside header
EXTRAS_SIZE = 16                    # Fixed structure size for 4-Dwords parameter block (no include Linux type)

# ==========================================
# Image Type Signatures & Formats (Lower-case Normalized)
# ==========================================
OPTEE_CONTAINER_TYPE = hex(0x00020014).lower()
ATF_IMAGE_TYPE = hex(0x00020013).lower()
OPTEE_IMAGE_TYPE = hex(0x00020015).lower()
BOOT_PARAMETER_IMAGE_TYPE = hex(0x00020016).lower()
SM_FIRMWARE_IMAGE_TYPE = hex(0x00000012).lower()
LINUX_IMAGE_TYPE = hex(0x020018).lower()
FASTLOGO_IMAGE_TYPE = hex(0x02001B).lower()
# Layout Field Offsets
TZK_CONTAINER_SIZE = 12
TZK_SUB_IMAGE_DEST_ADDR_FIELD_OFFSET = 0x68 # Relative offset to dest_addr field inside description block
TZK_SUB_IMAGE_BODY_FIELD_OFFSET = 0x26C # Relative offset to ATF/OPTEE/Boot parameter field inside description block
TZK_SUB_IMAGE_EXTRA_SIZE = 12
LINUX_IMAGE_LENGTH_FIELD_OFFSET = 8
FASTLOGO_IMAGE_LENGTH_FIELD_OFFSET = 8
LINUX_HEADER_OFFSET = 616
FASTLOGO_HEADER_OFFSET = 616
logger = logging.getLogger(__name__)

def slice_file(input_file, output_file, skip=None, count=None):
    """
    Cuts a part of a file and stores it in a new file
    """
    skip = 0 if skip is None else int(skip)
    count = None if count is None else int(count)
    if skip < 0 or (count is not None and count < 0):
        raise ValueError("slice offsets and lengths must not be negative")

    remaining = count
    with open(input_file, 'rb') as source, open(output_file, 'wb') as destination:
        source.seek(skip)
        while remaining is None or remaining > 0:
            read_size = IO_BUFFER_SIZE if remaining is None else min(IO_BUFFER_SIZE, remaining)
            block = source.read(read_size)
            if not block:
                break
            destination.write(block)
            if remaining is not None:
                remaining -= len(block)

    if remaining not in (None, 0):
        raise ValueError(
            f"Cannot read requested {count} bytes at offset {skip} from {input_file}"
        )

def version_bitmask_conv(version_num):
    """
    Version bitmask converter
    """
    try:
        version = int(str(version_num), 0)
    except ValueError as error:
        raise ValueError(f"Invalid OEM version: {version_num}") from error
    if not 0 <= version <= 32:
        raise ValueError("OEM version must be between 0 and 32")
    value = (1 << version) - 1

    logger.debug("Version Bitmask result = 0x%02x" % value)
    return value

def _get_tool_path(my_dir, tool_name):
    """
    Internal helper method to locate security tools in project directories
    """
    possible_paths = [
        os.path.join(my_dir, 'tools', tool_name),
        os.path.join(my_dir, tool_name),
        os.path.join('/usr/bin', tool_name)
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return os.path.join(my_dir, 'tools', tool_name)


def _atomic_assemble(output_file, components):
    """Assemble components beside the destination and atomically publish them."""
    output_path = os.path.abspath(output_file)
    output_dir = os.path.dirname(output_path)
    os.makedirs(output_dir, exist_ok=True)
    descriptor, temp_output = tempfile.mkstemp(prefix=".factory_image.", dir=output_dir)
    try:
        with os.fdopen(descriptor, 'wb') as destination:
            for component in components:
                if isinstance(component, bytes):
                    destination.write(component)
                else:
                    with open(component, 'rb') as source:
                        shutil.copyfileobj(source, destination, IO_BUFFER_SIZE)
            destination.flush()
            os.fsync(destination.fileno())
        os.chmod(temp_output, 0o644)
        os.replace(temp_output, output_path)
    finally:
        if os.path.exists(temp_output):
            os.unlink(temp_output)


def _atomic_copy(source_file, output_file):
    _atomic_assemble(output_file, (source_file,))


def _reject_encrypted_image(input_file, image_name, header_offset=0):
    """
    Refuse to sign an image whose GenX V3 header already contains an IV.

    A clear image has an all-zero 16-byte IV. A non-zero IV means that the
    payload has already been encrypted and must not be encrypted again.
    """
    iv_offset = header_offset + IMAGE_IV_OFFSET_IN_HEADER

    with open(input_file, 'rb') as image_file:
        image_file.seek(iv_offset)
        iv = image_file.read(IMAGE_IV_SIZE)

    if len(iv) != IMAGE_IV_SIZE:
        raise ValueError(
            f"ERROR: {image_name} image header is truncated; cannot read "
            f"the {IMAGE_IV_SIZE}-byte IV at offset {hex(iv_offset)}: {input_file}"
        )

    if any(iv):
        raise ValueError(
            f"ERROR: {image_name} image is already encrypted "
            f"(non-zero IV {iv.hex()} at offset {hex(iv_offset)}); "
            f"refusing to sign/encrypt it again: {input_file}"
        )

    logger.debug(
        "%s image encryption guard passed: zero IV at offset %s",
        image_name,
        hex(iv_offset)
    )


def _require_encrypted_image(input_file, image_name, header_offset=0):
    """Verify that a requested encryption operation produced a non-zero IV."""
    iv_offset = header_offset + IMAGE_IV_OFFSET_IN_HEADER
    with open(input_file, 'rb') as image_file:
        image_file.seek(iv_offset)
        iv = image_file.read(IMAGE_IV_SIZE)
    if len(iv) != IMAGE_IV_SIZE:
        raise ValueError(
            f"ERROR: {image_name} output header is truncated at IV offset "
            f"{hex(iv_offset)}: {input_file}"
        )
    if not any(iv):
        raise ValueError(
            f"ERROR: {image_name} encryption was required but output IV is zero: "
            f"{input_file}"
        )

def patch_KeyStore(input_file, output_file, keys_dir):
    """
    Applies precise physical layout, parses mandatory SoC attributes and production flags
    straight from the centralized configuration object, and invokes GenX V3 tools stream.
    """

    if not os.path.exists(input_file):
        raise Exception(f'Cannot find {input_file} file')

    STORE_SIZE = 4096                  # 4KB per key store partition

    try:
        temp_dir = tempfile.mkdtemp()
        my_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        
        # --- Phase 1: Disassemble key stores, SPK, and old bl_en ---
        orig_syna = os.path.join(temp_dir, 'orig_syna.bin')
        orig_oem = os.path.join(temp_dir, 'orig_oem.bin')
        orig_3rd = os.path.join(temp_dir, 'orig_3rd.bin')
        orig_k1_a = os.path.join(temp_dir, 'orig_k1_a.bin')
        orig_k1_b = os.path.join(temp_dir, 'orig_k1_b.bin')
        orig_k1_c = os.path.join(temp_dir, 'orig_k1_c.bin')
        orig_k1_d = os.path.join(temp_dir, 'orig_k1_d.bin')

        slice_file(input_file, orig_syna, skip=0, count=STORE_SIZE)
        slice_file(input_file, orig_oem, skip=STORE_SIZE, count=STORE_SIZE)
        slice_file(input_file, orig_3rd, skip=STORE_SIZE * 2, count=STORE_SIZE)
        slice_file(input_file, orig_k1_a, skip=STORE_SIZE * 3, count=STORE_SIZE)
        slice_file(input_file, orig_k1_b, skip=STORE_SIZE * 4, count=STORE_SIZE)
        slice_file(input_file, orig_k1_c, skip=STORE_SIZE * 5, count=STORE_SIZE)
        slice_file(input_file, orig_k1_d, skip=STORE_SIZE * 6, count=STORE_SIZE)

        # --- Phase 5: Key replacement path verification ---
        final_syna = orig_syna
        final_k1_a = orig_k1_a
        final_k1_b = orig_k1_b

        final_oem = os.path.join(keys_dir, 'store/K0_OEM_store_4k.bin')
        final_k1_c = os.path.join(keys_dir, 'store/K1_C_store_4k.bin')
        
        if not os.path.exists(final_oem):
            raise Exception(f"CRITICAL ERROR: Mandatory key missing in keys_dir: {final_oem}")
        if not os.path.exists(final_k1_c):
            raise Exception(f"CRITICAL ERROR: Mandatory key missing in keys_dir: {final_k1_c}")

        path_3rd_new = os.path.join(keys_dir, 'store/K0_3RD_store_4k.bin')
        final_3rd = path_3rd_new if os.path.exists(path_3rd_new) else orig_3rd

        path_k1_d_new = os.path.join(keys_dir, 'store/K1_D_store_4k.bin')
        final_k1_d = path_k1_d_new if os.path.exists(path_k1_d_new) else orig_k1_d

        # --- Phase 6: Reassemble the full structured production preboot image ---
        final_order_list = [
            final_syna, final_oem, final_3rd, final_k1_a, final_k1_b, final_k1_c, final_k1_d
        ]

        _atomic_assemble(output_file, final_order_list)
                    
        logger.info(f"Successfully Patch KeyStore to {output_file}")
    finally:
        if os.path.exists(temp_dir):
           shutil.rmtree(temp_dir)

def resign_m52bl(input_file, output_file, keys_dir, encrypt=True):
    """
    Independently unpacks, patches extras, and resigns the m52bl bootloader image.
    """
    if not os.path.exists(input_file):
        raise Exception(f'Cannot find {input_file} file')

    _reject_encrypted_image(input_file, 'm52bl')

    config = ParseConfig()
    config.print_chip_info()
    config.print_oem_config_segid()
    config.print_oem_config_version()

    chip_name = config.get_chip_info('chip_name')
    chip_rev = config.get_chip_info('chip_rev')
    oem_segid = config.get_oem_seg_id('oem_segid')
    oem_version = config.get_oem_version('oem_version')
    image_production_flag = config.get_image_production_flag()

    logger.info(f"Process m52 bootloader image for {chip_name} {chip_rev} using V3 secure tools")
    
    try:
        temp_dir = tempfile.mkdtemp()
        my_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))

        # --- Phase 3: Extract f_BL and f_BL_EXTRA ---
        logger.info(f"Extracting apbl_output and apbl_extras using {hex(HEADER_SIZE)} layout boundaries...")
        old_bl_header = os.path.join(temp_dir, 'old_bl_header.bin')
        f_BL = os.path.join(temp_dir, 'apbl_output.bin')
        f_BL_EXTRA = os.path.join(temp_dir, 'apbl_extras.bin')
        generated_output = os.path.join(temp_dir, 'm52bl_en.bin')

        slice_file(input_file, old_bl_header, skip=0, count=HEADER_SIZE)
        slice_file(input_file, f_BL, skip=HEADER_SIZE)
        slice_file(old_bl_header, f_BL_EXTRA, skip=EXTRAS_OFFSET_IN_HEADER, count=EXTRAS_SIZE)

        # --- Phase 3.5: Patch Flags and Re-generate f_BL_EXTRA ---
        logger.info("Phase 3.5: Parsing and modifying f_BL_EXTRA fields for GENX_V3...")
        with open(f_BL_EXTRA, 'rb') as ex_f:
            ex_data = ex_f.read(EXTRAS_SIZE)
            if len(ex_data) != EXTRAS_SIZE:
                raise Exception(f"CRITICAL ERROR: Extracted f_BL_EXTRA size is {len(ex_data)} Bytes, expected 16 Bytes.")
            orig_prod_flag, rfu, dest_addr, bl_entry = struct.unpack('<4I', ex_data)

        new_prod_flag = image_production_flag
        logger.info(
            "Patching Extras: Production Flag %s -> %s",
            hex(orig_prod_flag),
            hex(image_production_flag),
        )

        h_prod = hex(new_prod_flag)
        h_rfu = hex(rfu)
        h_dest = hex(dest_addr)
        h_entry = hex(bl_entry)

        in_extras_tool_path = _get_tool_path(my_dir, EXTRA_TOOL)

        cmd_in_extras = [
            sys.executable, in_extras_tool_path,
            'BL', f_BL_EXTRA,
            h_prod, h_rfu, h_dest, h_entry
        ]
        logger.info(f"Running in_extras tool: {' '.join(cmd_in_extras)}")
        subprocess.check_call(cmd_in_extras)

        # --- Phase 4: Execute gen_x_secure_image (Aligned with GenX V3 Engine) ---
        logger.info("Phase 4: Running updated gen_x_secure_image with V3 command line mapping...")
        tool_full_path = _get_tool_path(my_dir, GENX_TOOL)

        if not os.path.exists(tool_full_path):
            raise Exception("ERROR: Secure image signing tool not found")

        cmd2run = [
            sys.executable, tool_full_path,
            '--chip-name', chip_name,
            '--chip-rev', chip_rev,
            '--img_type', 'BL',
            '--key_type', 'oem',
            '--seg_id', str(oem_segid),
            '--version', hex(version_bitmask_conv(oem_version)),
            '--extras', f_BL_EXTRA,
            '--length', '0',
            '--in_payload', f_BL,
            '--out_store', generated_output,
            '--workdir-security-tools', my_dir,
            '--workdir-security-keys', keys_dir,
            '--tool-version', 'genx_v3'
        ]
        if not encrypt:
            cmd2run.append('--allow-unencrypted')

        logger.info(f"Executing Modern GenX V3 Command: {' '.join(cmd2run)}")
        subprocess.check_call(cmd2run)

        if not os.path.exists(generated_output) or os.path.getsize(generated_output) == 0:
            raise Exception("CRITICAL ERROR: Failed to re-sign and generate new bl_en.bin via gen_x_secure_image.")
        if encrypt:
            _require_encrypted_image(generated_output, 'm52bl')
        _atomic_copy(generated_output, output_file)
        logger.info(f"Successfully generated production m52 bootloader image to {output_file}")    
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def patch_preboot(input_file, output_file, keys_dir, encrypt_m52bl=True):
    """
    Applies precise physical layout, delegates KeyStore patching to patch_preboot(),
    delegates Bootloader resigning to resign_m52bl(), and reassembles the final production preboot image.
    """
    logger.info(f"Processing preboot image container: {input_file} -> {output_file}")

    if not os.path.exists(input_file):
        raise Exception(f'Cannot find {input_file} file')

    KEY_STORES_TOTAL_SIZE = 28672      # 4KB * 7 = 28KB total key area
    SPK_SIZE = 131072                  # Fixed 128KB SPK certificate area

    try:
        temp_dir = tempfile.mkdtemp()
        
        # Define temporary file paths
        orig_keystores = os.path.join(temp_dir, 'orig_keystores.bin')
        new_keystores = os.path.join(temp_dir, 'new_keystores.bin')
        orig_spk = os.path.join(temp_dir, 'orig_spk.bin')
        old_bl_en = os.path.join(temp_dir, 'old_bl_en.bin')
        new_bl_en = os.path.join(temp_dir, 'new_bl_en.bin')

        # --- Phase 1: Disassemble original preboot image segments ---
        # 1. Extract the 28KB original key store segment
        slice_file(input_file, orig_keystores, skip=0, count=KEY_STORES_TOTAL_SIZE)
        # 2. Extract the 128KB original SPK certificate segment
        slice_file(input_file, orig_spk, skip=KEY_STORES_TOTAL_SIZE, count=SPK_SIZE)
        # 3. Extract the remaining original bootloader segment (bl_en)
        slice_file(input_file, old_bl_en, skip=KEY_STORES_TOTAL_SIZE + SPK_SIZE)

        # --- Phase 2: Invoke independent processing functions ---
        # Process KeyStore replacement
        patch_KeyStore(orig_keystores, new_keystores, keys_dir)

        # Process Bootloader resigning
        resign_m52bl(old_bl_en, new_bl_en, keys_dir, encrypt=encrypt_m52bl)

        # --- Phase 3: Reassemble back to the complete Preboot Image in order ---
        final_order_list = [
            new_keystores,  # New patched 28KB KeyStores
            orig_spk,       # Untouched 128KB SPK
            new_bl_en       # Newly resigned Bootloader
        ]

        _atomic_assemble(output_file, final_order_list)

        logger.info(f"Successfully generated precision-patched production preboot image to {output_file}")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def resign_bootloader(input_file, output_file, keys_dir, encrypt=True):
    """
    Refactored container for Klamath architecture.
    Invokes the modern GenX V3 engine to encrypt/sign U-Boot.
    """
    logger.info("Encrypt and Sign Klamath OEM U-Boot container via GenX V3 stream")

    if not os.path.exists(input_file):
        raise Exception(f'Cannot find {input_file} file')

    _reject_encrypted_image(input_file, 'bootloader')

    config = ParseConfig()
    config.print_chip_info()
    config.print_oem_config_segid()
    config.print_oem_config_version()

    chip_name = config.get_chip_info('chip_name')
    chip_rev = config.get_chip_info('chip_rev')
    oem_segid = config.get_oem_seg_id('oem_segid')
    oem_version = config.get_oem_version('oem_version')
    image_production_flag = config.get_image_production_flag()
    try:
        temp_dir = tempfile.mkdtemp()
        logger.debug("Created temporary directory: %s", temp_dir)
        my_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        
        uboot_body = os.path.join(temp_dir, 'uboot_raw.bin')
        uboot_header_old = os.path.join(temp_dir, 'uboot_header_old.bin')
        uboot_header_EXTRA = os.path.join(temp_dir, 'in_boot_loader_extras.bin')
        new_bl_en = os.path.join(temp_dir, 'uboot_en.bin')

        # --- Phase 1: Extract Pure Raw U-Boot Payload ---
        actual_input_size = os.path.getsize(input_file)
        if actual_input_size < HEADER_SIZE:
            raise Exception(f"CRITICAL ERROR: Input container size ({actual_input_size}) smaller than header ({HEADER_SIZE})")

        slice_file(input_file, uboot_header_old, skip=0, count=HEADER_SIZE)
        slice_file(input_file, uboot_body, skip=HEADER_SIZE)
        slice_file(uboot_header_old, uboot_header_EXTRA, skip=EXTRAS_OFFSET_IN_HEADER, count=EXTRAS_SIZE)

        # --- Phase 2: Patch Flags and Re-generate uboot_header_EXTRA ---
        logger.info("Phase 2: Parsing and modifying uboot_header_EXTRA fields for GENX_V3...")
        with open(uboot_header_EXTRA, 'rb') as ex_f:
            ex_data = ex_f.read(EXTRAS_SIZE)
            if len(ex_data) != EXTRAS_SIZE:
                raise Exception(f"CRITICAL ERROR: Extracted uboot_header_EXTRA size is {len(ex_data)} Bytes, expected 16 Bytes.")
            orig_prod_flag, rfu, dest_addr, bl_entry = struct.unpack('<4I', ex_data)

        logger.info(
            "Patching Extras: Production Flag %s -> %s",
            hex(orig_prod_flag),
            hex(image_production_flag),
        )

        h_prod = hex(image_production_flag)
        h_rfu = hex(rfu)
        h_dest = hex(dest_addr)
        h_entry = hex(bl_entry)

        in_extras_tool_path = _get_tool_path(my_dir, EXTRA_TOOL)

        cmd_in_extras = [
            sys.executable, in_extras_tool_path,
            'BOOT_LOADER_GENX_V3', uboot_header_EXTRA,
            h_prod, h_rfu, h_dest, h_entry
        ]
        logger.info(f"Running in_extras tool: {' '.join(cmd_in_extras)}")
        subprocess.check_call(cmd_in_extras)

        # --- Phase 3: Execute GenX V3 Engine Processing Stream ---
        tool_full_path = _get_tool_path(my_dir, GENX_TOOL)
        if not os.path.exists(tool_full_path):
            raise Exception("ERROR: Secure image signing tool not found")

        cmd2run = [
            sys.executable, tool_full_path,
            '--chip-name', chip_name,
            '--chip-rev', chip_rev,
            '--img_type', 'UBOOT',
            '--key_type', 'oem',
            '--seg_id', str(oem_segid),
            '--version', hex(version_bitmask_conv(oem_version)),
            '--extras', uboot_header_EXTRA,
            '--length', '0',
            '--in_payload', uboot_body,
            '--out_store', new_bl_en,
            '--workdir-security-tools', my_dir,
            '--workdir-security-keys', keys_dir,
            '--tool-version', 'genx_v3'
        ]
        if not encrypt:
            cmd2run.append('--allow-unencrypted')

        logger.info(f"Executing Modern GenX V3 Image Processing Command: {' '.join(cmd2run)}")
        subprocess.check_call(cmd2run)

        # --- Phase 4: Finalize Artifact Deployment ---
        if not os.path.exists(new_bl_en) or os.path.getsize(new_bl_en) == 0:
            raise Exception("CRITICAL ERROR: Secured output target block generation failed.")
        if encrypt:
            _require_encrypted_image(new_bl_en, 'bootloader')

        _atomic_copy(new_bl_en, output_file)
        logger.info(f"Successfully generated signed production Klamath bootloader to: {output_file}")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def resign_SM(input_file, output_file, keys_dir, encrypt=True):
    """
    Applies strict layout disassembly for Klamath System Manager (SM) firmware.
    """
    logger.info("Encrypt and Sign System Manager (SM) firmware container")

    if not os.path.exists(input_file):
        raise Exception(f'Cannot find {input_file} file')

    _reject_encrypted_image(input_file, 'sysmgr (SM)')

    config = ParseConfig()
    config.print_chip_info()
    config.print_oem_config_segid()
    config.print_oem_config_version()

    chip_name = config.get_chip_info('chip_name')
    chip_rev = config.get_chip_info('chip_rev')
    oem_segid = config.get_oem_seg_id('oem_segid')
    oem_version = config.get_oem_version('oem_version')
    image_production_flag = config.get_image_production_flag()
    try:
        temp_dir = tempfile.mkdtemp()
        my_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        
        old_sm_header = os.path.join(temp_dir, 'old_sm_header.bin')
        f_SM_Body = os.path.join(temp_dir, 'sm_payload_raw.bin')
        f_SM_EXTRA = os.path.join(temp_dir, 'sm_extras.bin')
        new_SM_en = os.path.join(temp_dir, 'sm_en.bin')

        # --- Phase 1: Slice Header and Extract Raw SM Payload Data Stream ---
        actual_input_size = os.path.getsize(input_file)
        if actual_input_size < HEADER_SIZE:
            raise Exception(f"CRITICAL ERROR: Input SM binary size ({actual_input_size}) smaller than container boundary.")

        logger.info("Slicing container boundaries to split SM layout attributes...")
        slice_file(input_file, old_sm_header, skip=0, count=HEADER_SIZE)
        slice_file(input_file, f_SM_Body, skip=HEADER_SIZE)
        slice_file(old_sm_header, f_SM_EXTRA, skip=EXTRAS_OFFSET_IN_HEADER, count=EXTRAS_SIZE)

        # --- Phase 1.5: Validate SM Firmware Image Type Signature ---
        with open(input_file, 'rb') as sm_file:
            # SM image has NO prepend info size shell. The type ID is located right at Offset 0.
            sm_file.seek(0)
            sm_image_type = struct.unpack('<I', sm_file.read(4))[0]
            
            logger.info(f"SM Image Type Validation -> Detected: {hex(sm_image_type)}, Expected: {SM_FIRMWARE_IMAGE_TYPE}")
            if hex(sm_image_type).lower() != SM_FIRMWARE_IMAGE_TYPE:
                raise Exception(f"CRITICAL ERROR: System Manager image type verification failed for {input_file}")

        # --- Phase 2: Unpack, Modify Security Flag, and Re-pack SM Extras Block ---
        with open(f_SM_EXTRA, 'rb') as ex_f:
            ex_data = ex_f.read(EXTRAS_SIZE)
            if len(ex_data) != EXTRAS_SIZE:
                raise Exception("CRITICAL ERROR: Failed to parse structural SM extras chunk.")
            orig_prod_flag, rfu, dest_addr, bl_entry = struct.unpack('<4I', ex_data)


        logger.info(
            "Patching SM Extras: Production Flag %s -> %s",
            hex(orig_prod_flag),
            hex(image_production_flag),
        )

        h_prod = hex(image_production_flag)
        h_rfu = hex(rfu)
        h_dest = hex(dest_addr)
        h_entry = hex(bl_entry)

        in_extras_tool_path = _get_tool_path(my_dir, EXTRA_TOOL)

        cmd_in_extras = [
            sys.executable, in_extras_tool_path,
            'SM_GENX_V3', f_SM_EXTRA,
            h_prod, h_rfu, h_dest, h_entry
        ]
        logger.info(f"Assembling structural SM extras parameter block: {' '.join(cmd_in_extras)}")
        subprocess.check_call(cmd_in_extras)

        # --- Phase 3: Verify Secure Tooling Engine and Invoke Sign Sequence ---
        tool_full_path = _get_tool_path(my_dir, GENX_TOOL)
        if not os.path.exists(tool_full_path):
            raise Exception("ERROR: Secure image signing tool not found")

        cmd2run = [
            sys.executable, tool_full_path,
            '--chip-name', chip_name,
            '--chip-rev', chip_rev,
            '--img_type', 'SM',
            '--key_type', 'oem',
            '--seg_id', str(oem_segid),
            '--version', hex(version_bitmask_conv(oem_version)),
            '--extras', f_SM_EXTRA,
            '--length', '0',
            '--in_payload', f_SM_Body,
            '--out_store', new_SM_en,
            '--workdir-security-tools', my_dir,
            '--workdir-security-keys', keys_dir,
            '--tool-version', 'genx_v3'
        ]
        if not encrypt:
            cmd2run.append('--allow-unencrypted')

        logger.info(f"Executing Modern GenX V3 Core SM Cryptography routine: {' '.join(cmd2run)}")
        subprocess.check_call(cmd2run)

        # --- Phase 4: Finalize Artifact Deployment and Verification ---
        if not os.path.exists(new_SM_en) or os.path.getsize(new_SM_en) == 0:
            raise Exception("CRITICAL ERROR: System Manager signed output payload missing or corrupted data.")
        if encrypt:
            _require_encrypted_image(new_SM_en, 'sysmgr (SM)')

        _atomic_copy(new_SM_en, output_file)
        logger.info(f"Successfully generated signed production Klamath SM firmware to: {output_file}")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def sign_tzk_img(clr_img, enc_img, img_type, dest_addr, keys_dir, encrypt=True):
    """
    For 'TZ_KERNEL', 'ATF', and 'TZK_BOOT_PARAMETER', raise production flag and signed and encrypt
    """
    config = ParseConfig()
    chip_name = config.get_chip_info('chip_name')
    chip_rev = config.get_chip_info('chip_rev')
    oem_segid = config.get_oem_seg_id('oem_segid')
    oem_version = config.get_oem_version('oem_version')
    image_production_flag = config.get_image_production_flag()

    try:
        temp_dir = tempfile.mkdtemp()
        my_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        
        input_file_name = os.path.basename(clr_img)
        f_tzk_EXTRA = os.path.join(temp_dir, 'tzk_extras_' + os.path.splitext(input_file_name)[0] + '.bin')

        in_extras_tool_path = _get_tool_path(my_dir, EXTRA_TOOL)

        h_prod = hex(image_production_flag)
        h_dest = hex(dest_addr)

        cmd_in_extras = [
            sys.executable, in_extras_tool_path,
            img_type, f_tzk_EXTRA,
            h_prod, h_dest
        ]
        logger.info(f"Assembling aligned Klamath TZK component extras: {' '.join(cmd_in_extras)}")
        subprocess.check_call(cmd_in_extras)

        tool_full_path = _get_tool_path(my_dir, GENX_TOOL)
        if not os.path.exists(tool_full_path):
            raise Exception("ERROR: Secure image signing tool not found")

        file_size = os.path.getsize(clr_img)
        logger.debug("Size of '%s': %d bytes", clr_img, file_size)
        cmd2run = [
            sys.executable, tool_full_path,
            '--chip-name', chip_name,
            '--chip-rev', chip_rev,
            '--img_type', img_type,
            '--key_type', 'oem',
            '--seg_id', str(oem_segid),
            '--version', hex(version_bitmask_conv(oem_version)),
            '--extras', f_tzk_EXTRA,
            '--length', '0',
            '--in_payload', clr_img,
            '--out_store', enc_img,
            '--workdir-security-tools', my_dir,
            '--workdir-security-keys', keys_dir,
            '--tool-version', 'genx_v3'
        ]
        if not encrypt:
            cmd2run.append('--allow-unencrypted')
        logger.info(f"Invoking Modern GenX V3 Core TZK execution loop: {' '.join(cmd2run)}")
        subprocess.check_call(cmd2run)
        if encrypt:
            _require_encrypted_image(enc_img, f'tzk/{img_type}')
        file_size = os.path.getsize(enc_img)
        logger.debug("Size of '%s': %d bytes", enc_img, file_size)
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def resign_tzk(input_file, output_file, keys_dir, encrypt_atf=True, encrypt_optee=True):
    """
    Refactored for Klamath architecture layout specification.
    """
    logger.info("Encrypt and Sign Klamath TZK secure bundle image stack")

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Cannot find {input_file} file")

    temp_dir = tempfile.mkdtemp()
    
    try:
        with open(input_file, 'rb') as tzk_file:
            OPTEE_container_file = os.path.join(temp_dir, 'tzk_container.bin')
            slice_file(input_file, OPTEE_container_file, skip=0, count=TZK_CONTAINER_SIZE)

            # --- Phase 1: Verify Container Header ---
            container_bytes = tzk_file.read(TZK_CONTAINER_SIZE)
            if len(container_bytes) != TZK_CONTAINER_SIZE:
                raise ValueError("ERROR: Corrupted OPTEE_CONTAINER header stream block")

            c_type, c_ver, total_tzk_chain_length = struct.unpack('<III', container_bytes)

            if hex(c_type).lower() != OPTEE_CONTAINER_TYPE:
                raise ValueError("ERROR: OPTEE CONTAINER TYPE is not correct!")

            logger.info(f"OPTEE_CONTAINER -> Total Secure Chain Payload Size: {total_tzk_chain_length} Bytes")

            current_offset = TZK_CONTAINER_SIZE
            final_pack_order = [OPTEE_container_file]

            # --- Phase 2: Validate Sub-Images (ATF, TZ_KERNEL, BOOT_PARAMETER) ---
            # Define attributes for each segment (Name, Expected Type, File Prefix)
            segments = [
                ('ATF', ATF_IMAGE_TYPE, 'atf'),
                ('TZ_KERNEL', OPTEE_IMAGE_TYPE, 'tzk'),
                ('TEE_BOOT_PARAMETER', BOOT_PARAMETER_IMAGE_TYPE, 'bootp')
            ]
            segment_layouts = []
            input_size = os.path.getsize(input_file)

            for seg_name, expected_type, prefix in segments:
                tzk_file.seek(current_offset)
                sub_hdr_bytes = tzk_file.read(TZK_SUB_IMAGE_EXTRA_SIZE)
                if len(sub_hdr_bytes) != TZK_SUB_IMAGE_EXTRA_SIZE:
                    raise ValueError(f"ERROR: Truncated {seg_name} image header in {input_file}")

                img_type, ver, total_len = struct.unpack('<III', sub_hdr_bytes)

                if total_len < TZK_SUB_IMAGE_BODY_FIELD_OFFSET or current_offset + total_len > input_size:
                    raise ValueError(
                        f"ERROR: Invalid {seg_name} image length {total_len} at offset "
                        f"{hex(current_offset)} in {input_file}"
                    )

                tzk_file.seek(current_offset + TZK_SUB_IMAGE_DEST_ADDR_FIELD_OFFSET)
                dest_addr_bytes = tzk_file.read(4)
                if len(dest_addr_bytes) != 4:
                    raise ValueError(f"ERROR: Truncated {seg_name} destination address in {input_file}")
                dest_addr = struct.unpack('<I', dest_addr_bytes)[0]

                if hex(img_type).lower() != expected_type:
                    raise ValueError(f"ERROR: {seg_name} TYPE/OFFSET is not correct! Expected {expected_type}.")

                _reject_encrypted_image(input_file, f'tzk/{seg_name}', current_offset)

                logger.info(f"Unpacking {seg_name} Component -> Total Section Length Stride: {total_len} Bytes")
                segment_layouts.append((seg_name, prefix, current_offset, total_len, dest_addr))
                current_offset += total_len

            # All IVs are checked before signing any part of the TZK bundle.
            for seg_name, prefix, current_offset, total_len, dest_addr in segment_layouts:
                raw_file = os.path.join(temp_dir, f'{prefix}_raw.bin')
                body_file = os.path.join(temp_dir, f'{prefix}_body_raw.bin')
                enc_file = os.path.join(temp_dir, f'{prefix}.enc')
                
                slice_file(input_file, raw_file, skip=current_offset, count=total_len)
                slice_file(raw_file, body_file, skip=TZK_SUB_IMAGE_BODY_FIELD_OFFSET)
                
                encrypt_segment = encrypt_atf if seg_name == 'ATF' else encrypt_optee
                sign_tzk_img(
                    body_file,
                    enc_file,
                    seg_name,
                    dest_addr,
                    keys_dir,
                    encrypt=encrypt_segment,
                )
                
                # Replace print statements with logger for consistent logging output
                logger.debug(f"[INFO] Size of '{raw_file}': {os.path.getsize(raw_file)} bytes")
                logger.debug(f"[INFO] Size of '{enc_file}': {os.path.getsize(enc_file)} bytes")
                
                final_pack_order.append(enc_file)

        # --- Phase 3: Stitching Signed Blocks into Final Klamath Package ---
        logger.info("Phase 3: Stitching newly encrypted sub-components into unified secure stack...")
        
        _atomic_assemble(output_file, final_pack_order)

        logger.info(f"Successfully deployed precision aligned Klamath secure OS stack bundle to: {output_file}")

    finally:
        # Ensure the temporary directory is properly cleaned up on exit or error to prevent disk space leaks
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def resign_linux(input_file, output_file, keys_dir, encrypt=True):
    """
    Sign and encrypt Linux Kernel with OEM keys
    """
    logger.info("Encrypt and Sign Linux")

    if not os.path.exists(input_file):
        raise Exception(f'Cannot find {input_file} file')

    _reject_encrypted_image(input_file, 'linux', IMAGE_PREPEND_INFO_SIZE)

    try:
        temp_dir = tempfile.mkdtemp()
        input_file_name = os.path.basename(input_file)
        image_prepend_info_file = os.path.join(temp_dir, 'prepend_info.bin')
        body_file = os.path.join(temp_dir, 'linux_body.bin')
        in_extras_file = os.path.join(temp_dir, 'in_extras_' + os.path.splitext(input_file_name)[0] + '.bin')
        enc_linux = os.path.join(temp_dir, 'enc_linux.bin')

        with open(input_file, 'rb') as linux_file:
            slice_file(input_file, image_prepend_info_file, count=IMAGE_PREPEND_INFO_SIZE)

            # Get Linux payload size
            linux_file.seek(LINUX_IMAGE_LENGTH_FIELD_OFFSET)
            linux_size = struct.unpack('<I', linux_file.read(4))[0]

            # Verify Linux image type signatures
            linux_file.seek(IMAGE_PREPEND_INFO_SIZE)
            linux_image_type = struct.unpack('<I', linux_file.read(4))[0]
            if hex(linux_image_type).lower() != LINUX_IMAGE_TYPE:
                raise Exception(f'Linux: {input_file} image type verification failed')

        slice_file(input_file, body_file, skip=IMAGE_PREPEND_INFO_SIZE + LINUX_HEADER_OFFSET, count=linux_size - LINUX_HEADER_OFFSET)

        # Configure deployment parameters via parser object
        config = ParseConfig()
        config.print_oem_config_segid()
        config.print_oem_config_version()
        oem_segid = config.get_oem_seg_id('oem_segid')
        oem_version = config.get_oem_version('oem_version')
        image_production_flag = config.get_image_production_flag()
        chip_name = config.get_chip_info('chip_name')
        chip_rev = config.get_chip_info('chip_rev')

        my_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        
        extra_tool_full_path = _get_tool_path(my_dir, EXTRA_TOOL)
        genx_tool_full_path = _get_tool_path(my_dir, GENX_TOOL)
        logger.info("run extra")
        cmd2run_extra = [ 
            sys.executable, extra_tool_full_path,
            'LINUX_KERNEL',
            in_extras_file,
            hex(image_production_flag)
        ]
        subprocess.check_call(cmd2run_extra)
        logger.info("run genx_img_v3")
        cmd2run_genx = [ 
            sys.executable, genx_tool_full_path,
            '--chip-name', chip_name,
            '--chip-rev', chip_rev,            
            '--img_type', 'LINUX_KERNEL',
            '--key_type', 'oem',
            '--seg_id', str(oem_segid),
            '--version', hex(version_bitmask_conv(oem_version)),
            '--extras', in_extras_file,
            '--length', '0',
            '--in_payload', body_file,
            '--out_store', enc_linux,
            '--workdir-security-tools', my_dir,
            '--workdir-security-keys', keys_dir,
            '--tool-version', 'genx_v3'
        ]
        if not encrypt:
            cmd2run_genx.append('--allow-unencrypted')
        subprocess.check_call(cmd2run_genx)
        if encrypt:
            _require_encrypted_image(enc_linux, 'linux')

        # Strict size matching validation block
        if os.path.getsize(enc_linux) != linux_size:
            raise Exception(f'Linux: {input_file} size mismatch during processing')

        # Reassemble components into unified Linux deployment package
        _atomic_assemble(output_file, (image_prepend_info_file, enc_linux))
        logger.info(f"Successfully generated signed production Linux to: {output_file}")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def resign_fastlogo(input_file, output_file, keys_dir, encrypt=True):
    """
    Sign and encrypt fastlogo with OEM keys
    """
    logger.info("Encrypt and Sign fastlogo")

    if not os.path.exists(input_file):
        raise Exception(f'Cannot find {input_file} file')

    _reject_encrypted_image(input_file, 'fastlogo', IMAGE_PREPEND_INFO_SIZE)

    try:
        temp_dir = tempfile.mkdtemp()
        input_file_name = os.path.basename(input_file)
        image_prepend_info_file = os.path.join(temp_dir, 'prepend_info.bin')
        body_file = os.path.join(temp_dir, 'fastlogo_body.bin')
        in_extras_file = os.path.join(temp_dir, 'in_extras_' + os.path.splitext(input_file_name)[0] + '.bin')
        enc_fastlogo = os.path.join(temp_dir, 'enc_fastlogo.bin')

        with open(input_file, 'rb') as fastlogo_file:
            slice_file(input_file, image_prepend_info_file, count=IMAGE_PREPEND_INFO_SIZE)

            # Get fastlogo payload size
            fastlogo_file.seek(FASTLOGO_IMAGE_LENGTH_FIELD_OFFSET)
            fastlogo_size = struct.unpack('<I', fastlogo_file.read(4))[0]

            # Verify fastlogo image type signatures
            fastlogo_file.seek(IMAGE_PREPEND_INFO_SIZE)
            fastlogo_image_type = struct.unpack('<I', fastlogo_file.read(4))[0]
            if hex(fastlogo_image_type).lower() != FASTLOGO_IMAGE_TYPE:
                raise Exception(f'fastlogo: {input_file} image type verification failed')

        slice_file(input_file, body_file, skip=IMAGE_PREPEND_INFO_SIZE + FASTLOGO_HEADER_OFFSET, count=fastlogo_size - FASTLOGO_HEADER_OFFSET)

        # Configure deployment parameters via parser object
        config = ParseConfig()
        config.print_oem_config_segid()
        config.print_oem_config_version()
        oem_segid = config.get_oem_seg_id('oem_segid')
        oem_version = config.get_oem_version('oem_version')
        image_production_flag = config.get_image_production_flag()
        chip_name = config.get_chip_info('chip_name')
        chip_rev = config.get_chip_info('chip_rev')

        my_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        
        extra_tool_full_path = _get_tool_path(my_dir, EXTRA_TOOL)
        genx_tool_full_path = _get_tool_path(my_dir, GENX_TOOL)
        logger.info("run extra")
        cmd2run_extra = [ 
            sys.executable, extra_tool_full_path,
            'FASTLOGO',
            in_extras_file,
            hex(image_production_flag)
        ]
        subprocess.check_call(cmd2run_extra)
        logger.info("run genx_img_v3")
        cmd2run_genx = [ 
            sys.executable, genx_tool_full_path,
            '--chip-name', chip_name,
            '--chip-rev', chip_rev,            
            '--img_type', 'FASTLOGO',
            '--key_type', 'oem',
            '--seg_id', str(oem_segid),
            '--version', hex(version_bitmask_conv(oem_version)),
            '--extras', in_extras_file,
            '--length', '0',
            '--in_payload', body_file,
            '--out_store', enc_fastlogo,
            '--workdir-security-tools', my_dir,
            '--workdir-security-keys', keys_dir,
            '--tool-version', 'genx_v3'
        ]
        if not encrypt:
            cmd2run_genx.append('--allow-unencrypted')
        subprocess.check_call(cmd2run_genx)
        if encrypt:
            _require_encrypted_image(enc_fastlogo, 'fastlogo')

        # Strict size matching validation block
        if os.path.getsize(enc_fastlogo) != fastlogo_size:
            raise Exception(f'fastlogo: {input_file} size mismatch during processing')

        # Reassemble components into unified Linux deployment package
        _atomic_assemble(output_file, (image_prepend_info_file, enc_fastlogo))
        logger.info(f"Successfully generated signed production Klamath Fast Logo firmware to: {output_file}")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
