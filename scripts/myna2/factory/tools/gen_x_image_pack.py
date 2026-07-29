#!/usr/bin/env python3
# coding=UTF-8
#==============================================================================================
#
# Copyright 2021 Synaptics Incorporated. All rights reserved.
#
# This file contains information that is proprietary to Synaptics Incorporated ("Synaptics").
# The holder of this file shall treat all information contained herein as confidential,
# shall use the information only for its intended purpose, and shall not duplicate, disclose,
# or disseminate any of this information in any manner unless Synaptics has otherwise provided
# express, written permission.
#==============================================================================================

###############################################################################################
#  File: gen_x_image_pack.py
#  Auth: Victor Ku
#  Note: Tool to generate production images
###############################################################################################

import os
import tempfile
import shutil
import subprocess
import logging
import sys
import re
import struct

from configs.parse_config import *

GENX_TOOL = 'gen_x_secure_image'
EXTRA_TOOL = 'in_extras.py'

BLOCK_SIZE = 1024 * 1024
K0_REE_STORE_OFFSET = 32488
K0_REE_STORE_SIZE = 316
K1_REE_STORE_OFFSET = 133268
K1_REE_STORE_SIZE = 2176
SCS_DATA_PARAM_AREA_OFFSET = 135444
SCS_DATA_PARAM_AREA_SIZE = 33568
FPK_OFFSET = 4
FPK_SIZE = 16
BOOT_FlASH_ENCRYPTION_ENABLE_OFFSET = 56
REE_FlASH_ENCRYPTION_ENABLE_OFFSET = 60

BOOTLOADER_HEADER_OFFSET = 336
TZK_HEADER_OFFSET = 340
FASTLOGO_HEADER_OFFSET = 336
LINUX_HEADER_OFFSET = 336
ATF_IMAGE_TYPE = hex(0x00000017)
TZK_IMAGE_TYPE = hex(0x00000016)
TZK_PARAMETER_IMAGE_TYPE = hex(0x00000018)
TZK_OEM_SETTING_IMAGE_TYPE = hex(0x00000022)
SM_FIRMWARE_IMAGE_TYPE = hex(0x00000034)
TZK_OEM_SETTING_DEST_ADDR_OFFSET = 80
IMAGE_PREPEND_INFO_SIZE = 64
TZK_CONTAINER_SIZE = 12
TZ_IMAGE_LENGTH_FIELD_OFFSET = 8
TZ_DEST_ADDRESS_FIELD_OFFSET = 80
BL_IMAGE_LENGTH_FIELD_OFFSET = 8
FASTLOGO_IMAGE_LENGTH_FIELD_OFFSET = 8
LINUX_IMAGE_LENGTH_FIELD_OFFSET = 8
IMAGE_INFO_MAGIC_OFFEST = 4
IMAGE_INFO_MAGIC = hex(0x482a4d49)

IMAGE_TYPE_FIRMWARE = hex(0x6d726966)
IMAGE_FIRMWARE_TYPE_SM = hex(0x57464d53)

BL_IMAGE_TYPE = hex(0x20)
LINUX_IMAGE_TYPE = hex(0x21)
FASTLOGO_IMAGE_TYPE = hex(0x27)

logger = logging.getLogger(__name__)

def check_call(*args, **kwargs):
    """
    Utility method to call an external program and raise an exception if its exit value is not 0
    """

    logger.debug("calling subprocess: %s", ' '.join(args[0]))

    # we want to capture stdout and stderr with communicate later
    kwargs['stderr'] = subprocess.PIPE
    kwargs['stdout'] = subprocess.PIPE

    p = subprocess.Popen(*args, **kwargs)

    normal, err = p.communicate()

    if p.returncode != 0:
        logger.error("%s, %s", normal, err)
        raise Exception('Error while executing command %s (return code = %d)' % (' '.join(args[0]), p.returncode))

    logger.debug("%s, %s", normal, err)

def slice_file(input_file, output_file, skip=None, count=None):
    """
    Cuts a part of a file and stores it in a new file
    """

    cmd = ['dd', 'if=' + input_file, 'of=' + output_file, 'bs=1']

    if skip :
        cmd.append('skip=' + str(skip))

    if count :
        cmd.append('count=' + str(count))

    check_call(cmd)

def version_bitmask_conv(version_num):
    """
    Version bitmask converter
    """
    value = 0x0
    if ( int(version_num) > 32 ):
        raise Exception("REE Version number can't greater then 32")
    else:
        for i in range(int(version_num)):
            value = value + (0x1 << i)

    logger.debug("Version Bitmask result = 0x%02x" % value)
    return value

def patch_usb_bkl(input_file, output_file, keys_dir):
    """
    Process USB BKL image
    """
    logger.info("Process USB BKL image")

    if not os.path.exists(input_file):
        raise Exception('Cannot find %s file', input_file)

    try:
        temp_dir = tempfile.mkdtemp()
        p1_file = os.path.join(temp_dir, 'image_p1.bin')
        p2_file = os.path.join(temp_dir, 'image_p2.bin')
        K0_ree_file = os.path.join(temp_dir, 'image_k0_ree.bin')
        K1_ree_a_file = os.path.join(temp_dir, 'image_k1_ree_a.bin')
        K1_ree_b_file = os.path.join(temp_dir, 'image_k1_ree_b.bin')
        K1_ree_c_file = os.path.join(temp_dir, 'image_k1_ree_c.bin')

        slice_file(input_file, p1_file, count=2264)
        slice_file(input_file, p2_file, skip=2264, count=100464)

        shutil.copy(keys_dir + '/K0_REE_store.bin', K0_ree_file)
        shutil.copy(keys_dir + '/K1_REE_A_store.bin', K1_ree_a_file)
        shutil.copy(keys_dir + '/K1_REE_B_store.bin', K1_ree_b_file)
        shutil.copy(keys_dir + '/K1_REE_C_store.bin', K1_ree_c_file)

        # reassemble the parts
        with open(output_file, 'wb') as out:
            with open(p1_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(K0_ree_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(p2_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(K1_ree_a_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(K1_ree_b_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(K1_ree_c_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)

    finally:
        shutil.rmtree(temp_dir)

def patch_preboot(input_file, output_file, keys_dir):
    """
    Process pre-bootloader image
    """
    logger.info("Process pre-bootloader image")

    if not os.path.exists(input_file):
        raise Exception('Cannot find %s file', input_file)

    try:
        temp_dir = tempfile.mkdtemp()
        p1_file = os.path.join(temp_dir, 'preboot_p1.bin')
        p2_file = os.path.join(temp_dir, 'preboot_p2.bin')
        p3_file = os.path.join(temp_dir, 'preboot_p3.bin')
        K0_ree_file = os.path.join(temp_dir, 'preboot_k0_ree.bin')
        K1_ree_a_file = os.path.join(temp_dir, 'preboot_k1_ree_a.bin')
        K1_ree_b_file = os.path.join(temp_dir, 'preboot_k1_ree_b.bin')
        K1_ree_c_file = os.path.join(temp_dir, 'preboot_k1_ree_c.bin')
        K1_ree_d_file = os.path.join(temp_dir, 'preboot_k1_ree_d.bin')
        scs_data_param_file = os.path.join(temp_dir, 'preboot_scs_data_p.bin')

        slice_file(input_file, p1_file, count=K0_REE_STORE_OFFSET)
        slice_file(input_file, p2_file, skip=K0_REE_STORE_OFFSET + K0_REE_STORE_SIZE, count=K1_REE_STORE_OFFSET - (K0_REE_STORE_OFFSET + K0_REE_STORE_SIZE))
        slice_file(input_file, scs_data_param_file, skip=SCS_DATA_PARAM_AREA_OFFSET, count=SCS_DATA_PARAM_AREA_SIZE)
        slice_file(input_file, p3_file, skip=SCS_DATA_PARAM_AREA_OFFSET + SCS_DATA_PARAM_AREA_SIZE)

        shutil.copy(keys_dir + '/K0_REE_store.bin', K0_ree_file)
        shutil.copy(keys_dir + '/K1_REE_A_store.bin', K1_ree_a_file)
        shutil.copy(keys_dir + '/K1_REE_B_store.bin', K1_ree_b_file)
        shutil.copy(keys_dir + '/K1_REE_C_store.bin', K1_ree_c_file)
        shutil.copy(keys_dir + '/K1_REE_D_store.bin', K1_ree_d_file)

        # reassemble the parts
        with open(output_file, 'wb') as out:
            with open(p1_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(K0_ree_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(p2_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(K1_ree_a_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(K1_ree_b_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(K1_ree_c_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(K1_ree_d_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(scs_data_param_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(p3_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)

    finally:
        shutil.rmtree(temp_dir)

def resign_bootloader(input_file, output_file, keys_dir):
    """
    Encrypt OEM BL with OEM keys
    """
    logger.info("Encrypt and Sign OEM BL")

    if not os.path.exists(input_file):
        raise Exception('Cannot find %s file', input_file)

    try:
        temp_dir = tempfile.mkdtemp()
        input_file_name = os.path.basename(input_file)
        image_prepend_info_file = os.path.join(temp_dir, 'prepend_info.bin')
        body_file = os.path.join(temp_dir, 'bootloader_body.bin')
        preload_ta_file = os.path.join(temp_dir, 'preload_ta.bin')
        in_extras_file = os.path.join(temp_dir, 'in_extras_' + os.path.splitext(input_file_name)[0])
        enc_bl = os.path.join(temp_dir, 'enc_bl.bin')
        bl_w_head = os.path.join(temp_dir, 'bl_w_h.bin')

        bl_file = open(input_file, 'rb')

        slice_file(input_file, image_prepend_info_file, count=IMAGE_PREPEND_INFO_SIZE)

        # get BL  size
        current_offset = BL_IMAGE_LENGTH_FIELD_OFFSET
        bl_file.seek(current_offset)
        bl_size = struct.unpack('<I', bl_file.read(4))[0]

        # check BL image type
        current_offset = IMAGE_PREPEND_INFO_SIZE
        bl_file.seek(current_offset)
        bl_image_type = struct.unpack('<I', bl_file.read(4))[0]
        if hex(bl_image_type) != BL_IMAGE_TYPE:
            raise Exception('bl: %s image type failed', input_file)

        slice_file(input_file, body_file, skip=IMAGE_PREPEND_INFO_SIZE + BOOTLOADER_HEADER_OFFSET, count=bl_size - BOOTLOADER_HEADER_OFFSET)

        #calculate append size
        bl_append = 0
        if (bl_size + IMAGE_PREPEND_INFO_SIZE) % 512 != 0:
            bl_append = 512 - ((bl_size + IMAGE_PREPEND_INFO_SIZE) % 512)

        # encrypt bl
        config = parse_config()
        config.print_oem_config_segid()
        config.print_oem_config_version()
        ree_segid=config.get_oem_seg_id('ree_segid')
        ree_version=config.get_oem_version('ree_version')

        my_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        tool_full_path = os.path.join(my_dir, EXTRA_TOOL)
        cmd2run = [ tool_full_path,
                    'BOOT_LOADER',
                    in_extras_file,
                    '0x00000001' ]

        check_call(cmd2run,)

        tool_full_path = os.path.join(my_dir, GENX_TOOL)
        cmd2run = [ tool_full_path,
                    '--img_type', 'BOOT_LOADER',
                    '--seg_id', ree_segid,
                    '--seg_id_mask', '0xffffffff',
                    '--version', hex(version_bitmask_conv(ree_version)),
                    '--version_mask', '0xffffffff',
                    '--extras', in_extras_file,
                    '--length', '0',
                    '--in_payload', body_file,
                    '--out_store', enc_bl,
                    '--workdir-security-tools', my_dir,
                    '--workdir-security-keys', keys_dir ]

        check_call(cmd2run,)

        # check enc bl size org bl size are matched
        if os.path.getsize(enc_bl) != bl_size:
           raise Exception('bl: %s size missmatch', input_file)

        # apend preload tas to 512B aligned address
        with open(bl_w_head, 'wb') as out:
            with open(image_prepend_info_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(enc_bl, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
      

        with open(bl_w_head, 'rb+') as f:
            text_len = len(f.read())
            f.truncate(IMAGE_PREPEND_INFO_SIZE + bl_size + bl_append)
            f.close()

        # assemble bl subimg
        with open(output_file, 'wb') as out:
            with open(bl_w_head, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)

    finally:
        shutil.rmtree(temp_dir)

def resign_fastlogo(input_file, output_file, keys_dir):
    """
    Sign Fastlogo with OEM keys
    """
    logger.info("Sign Fastlogo")

    if not os.path.exists(input_file):
        raise Exception('Cannot find %s file', input_file)

    try:
        temp_dir = tempfile.mkdtemp()
        input_file_name = os.path.basename(input_file)
        image_prepend_info_file = os.path.join(temp_dir, 'prepend_info.bin')
        body_file = os.path.join(temp_dir, 'fastlogo_body.bin')
        in_extras_file = os.path.join(temp_dir, 'in_extras_' + os.path.splitext(input_file_name)[0])
        enc_fastlogo = os.path.join(temp_dir, 'enc_fastlogo.bin')

        fastlogo_file = open(input_file, 'rb')

        slice_file(input_file, image_prepend_info_file, count=IMAGE_PREPEND_INFO_SIZE)

        # get fastlogo size
        current_offset = FASTLOGO_IMAGE_LENGTH_FIELD_OFFSET
        fastlogo_file.seek(current_offset)
        fastlogo_size = struct.unpack('<I', fastlogo_file.read(4))[0]

        # check fastlogo image type
        current_offset = IMAGE_PREPEND_INFO_SIZE
        fastlogo_file.seek(current_offset)
        fastlogo_image_type = struct.unpack('<I', fastlogo_file.read(4))[0]
        if hex(fastlogo_image_type) != FASTLOGO_IMAGE_TYPE:
            raise Exception('fastlogo: %s image type failed', input_file)

        slice_file(input_file, body_file, skip=IMAGE_PREPEND_INFO_SIZE + FASTLOGO_HEADER_OFFSET, count=fastlogo_size - FASTLOGO_HEADER_OFFSET)

        # sign fastlogo
        config = parse_config()
        config.print_oem_config_segid()
        config.print_oem_config_version()
        ree_segid=config.get_oem_seg_id('ree_segid')
        ree_version=config.get_oem_version('ree_version')

        my_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        tool_full_path = os.path.join(my_dir, EXTRA_TOOL)
        cmd2run = [ tool_full_path,
                    'FASTLOGO',
                    in_extras_file,
                    '0x00000001' ]

        check_call(cmd2run,)

        tool_full_path = os.path.join(my_dir, GENX_TOOL)
        cmd2run = [ tool_full_path,
                    '--img_type', 'FASTLOGO',
                    '--seg_id', ree_segid,
                    '--seg_id_mask', '0xffffffff',
                    '--version', hex(version_bitmask_conv(ree_version)),
                    '--version_mask', '0xffffffff',
                    '--extras', in_extras_file,
                    '--length', '0',
                    '--in_payload', body_file,
                    '--out_store', enc_fastlogo,
                    '--workdir-security-tools', my_dir,
                    '--workdir-security-keys', keys_dir ]

        check_call(cmd2run,)

        # check fastlogo size and org fastlogo size are matched
        if os.path.getsize(enc_fastlogo) != fastlogo_size:
           raise Exception('fastlogo: %s size missmatch', input_file)

        # assemble fastlogo subimg
        with open(output_file, 'wb') as out:
            with open(image_prepend_info_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(enc_fastlogo, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)

    finally:
        shutil.rmtree(temp_dir)

def sign_tzk_img(clr_img, enc_img, img_type, dest_addr, keys_dir):

    try:

        # sign TZK image
        temp_dir = tempfile.mkdtemp()
        input_file_name = os.path.basename(clr_img)
        in_extras_file = os.path.join(temp_dir, 'in_extras_' + os.path.splitext(input_file_name)[0])

        config = parse_config()
        config.print_oem_config_segid()
        config.print_oem_config_version()
        ree_segid=config.get_oem_seg_id('ree_segid')
        ree_version=config.get_oem_version('ree_version')

        my_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        tool_full_path = os.path.join(my_dir, EXTRA_TOOL)
        cmd2run = [ tool_full_path,
                    img_type,
                    in_extras_file,
                    '0x00000001',
                    str(hex(dest_addr)) ]

        check_call(cmd2run,)

        tool_full_path = os.path.join(my_dir, GENX_TOOL)
        cmd2run = [ tool_full_path,
                    '--img_type', img_type,
                    '--seg_id', ree_segid,
                    '--seg_id_mask', '0xffffffff',
                    '--version', hex(version_bitmask_conv(ree_version)),
                    '--version_mask', '0xffffffff',
                    '--extras', in_extras_file,
                    '--length', '0',
                    '--in_payload', clr_img,
                    '--out_store', enc_img,
                    '--workdir-security-tools', my_dir,
                    '--workdir-security-keys', keys_dir ]

        check_call(cmd2run,)

    finally:
        shutil.rmtree(temp_dir)

def resign_tzk(input_file, output_file, keys_dir):
    """
    Encrypt TZK with OEM keys
    """
    logger.info("Encrypt and Sign TZK")

    if not os.path.exists(input_file):
        raise Exception('Cannot find %s file', input_file)

    temp_dir = tempfile.mkdtemp()
    tzk_file = open(input_file, 'rb')

    image_prepend_info_file = os.path.join(temp_dir, 'tzk_prepend_info.bin')
    slice_file(input_file, image_prepend_info_file, count=IMAGE_PREPEND_INFO_SIZE)

    tzk_container_file = os.path.join(temp_dir, 'tzk_container.bin')
    slice_file(input_file, tzk_container_file, skip=IMAGE_PREPEND_INFO_SIZE, count=TZK_CONTAINER_SIZE)

    current_offset = IMAGE_PREPEND_INFO_SIZE + TZK_CONTAINER_SIZE
    tzk_file.seek(current_offset)
    atf_img_type = struct.unpack('<I', tzk_file.read(4))[0]
    tzk_file.seek(current_offset + TZ_IMAGE_LENGTH_FIELD_OFFSET)
    atf_size = struct.unpack('<I', tzk_file.read(4))[0]
    tzk_file.seek(current_offset + TZ_DEST_ADDRESS_FIELD_OFFSET)
    atf_dest_addr = struct.unpack('<I', tzk_file.read(4))[0]
    if hex(atf_img_type) == ATF_IMAGE_TYPE:
        input_file_name = os.path.basename(input_file)
        atf_body_file = os.path.join(temp_dir, 'atf_body.bin')
        enc_atf_file = os.path.join(temp_dir, 'atf.enc')
        slice_file(input_file, atf_body_file,
                   skip=current_offset + TZK_HEADER_OFFSET,
                   count=atf_size - TZK_HEADER_OFFSET)
        sign_tzk_img(atf_body_file, enc_atf_file, 'ATF', atf_dest_addr, keys_dir)
    else:
        raise Exception('ATF offset is not correct!')

    current_offset = current_offset + atf_size
    tzk_file.seek(current_offset)
    tzk_img_type = struct.unpack('<I', tzk_file.read(4))[0]
    tzk_file.seek(current_offset + TZ_IMAGE_LENGTH_FIELD_OFFSET)
    tzk_size = struct.unpack('<I', tzk_file.read(4))[0]
    tzk_file.seek(current_offset + TZ_DEST_ADDRESS_FIELD_OFFSET)
    tzk_dest_addr = struct.unpack('<I', tzk_file.read(4))[0]
    if hex(tzk_img_type) == TZK_IMAGE_TYPE:
        input_file_name = os.path.basename(input_file)
        tzk_body_file = os.path.join(temp_dir, 'tzk_body.bin')
        enc_tzk_file = os.path.join(temp_dir, 'tzk.enc')
        slice_file(input_file, tzk_body_file,
                   skip=current_offset + TZK_HEADER_OFFSET,
                   count=tzk_size - TZK_HEADER_OFFSET)
        sign_tzk_img(tzk_body_file, enc_tzk_file, 'TZ_KERNEL', tzk_dest_addr, keys_dir)
    else:
        raise Exception('TZK offset is not correct!')

    current_offset = current_offset + tzk_size
    tzk_file.seek(current_offset)
    bootp_img_type = struct.unpack('<I', tzk_file.read(4))[0]
    tzk_file.seek(current_offset + TZ_IMAGE_LENGTH_FIELD_OFFSET)
    bootp_size = struct.unpack('<I', tzk_file.read(4))[0]
    tzk_file.seek(current_offset + TZ_DEST_ADDRESS_FIELD_OFFSET)
    bootp_dest_addr = struct.unpack('<I', tzk_file.read(4))[0]
    if hex(bootp_img_type) == TZK_PARAMETER_IMAGE_TYPE:
        input_file_name = os.path.basename(input_file)
        bootp_body_file = os.path.join(temp_dir, 'bootp_body.bin')
        enc_bootp_file = os.path.join(temp_dir, 'bootp.enc')
        slice_file(input_file, bootp_body_file,
                   skip=current_offset + TZK_HEADER_OFFSET,
                   count=bootp_size - TZK_HEADER_OFFSET)
        sign_tzk_img(bootp_body_file, enc_bootp_file, 'TZK_BOOT_PARAMETER', bootp_dest_addr, keys_dir)
    else:
        raise Exception('Boot Parameter offset is not correct!')

    current_offset = current_offset + bootp_size
    tzk_file.seek(current_offset)
    oem_img_type = struct.unpack('<I', tzk_file.read(4))[0]
    tzk_file.seek(current_offset + TZ_IMAGE_LENGTH_FIELD_OFFSET)
    oem_size = struct.unpack('<I', tzk_file.read(4))[0]
    if hex(oem_img_type) == TZK_OEM_SETTING_IMAGE_TYPE:
        input_file_name = os.path.basename(input_file)
        oem_setting_file = os.path.join(temp_dir, 'oem_setting_body.bin')
        slice_file(input_file, oem_setting_file, skip=current_offset, count=oem_size)
    else:
        raise Exception('TZK OEM setting offset is not correct!')

    try:
        # reassemble the parts
        with open(output_file, 'wb') as out:
            with open(image_prepend_info_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(tzk_container_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(enc_atf_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(enc_tzk_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(enc_bootp_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(oem_setting_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)

    finally:
        shutil.rmtree(temp_dir)
        tzk_file.close()

def resign_firmware(input_file, output_file, keys_dir, sm_only):
    """
    Encrypt SM firmware with OEM keys
    """
    logger.info("Encrypt and Sign SM firmware")

    if not os.path.exists(input_file):
        raise Exception('Cannot find %s file', input_file)

    firmware_file = open(input_file, 'rb')
    current_offset = IMAGE_PREPEND_INFO_SIZE
    firmware_file.seek(current_offset)
    image_magic = struct.unpack('<I', firmware_file.read(4))[0]
    if IMAGE_INFO_MAGIC != hex(image_magic):
        raise Exception('%s firmware file format error', input_file)
    else:
        current_offset = current_offset + 16 # seek to image type
        firmware_file.seek(current_offset)
        image_type = struct.unpack('<I', firmware_file.read(4))[0]
        if IMAGE_TYPE_FIRMWARE != hex(image_type):
            raise Exception('%s not firmware image', input_file)
        else:
            current_offset = current_offset + 44 # check firmware count
            firmware_file.seek(current_offset)
            fw_count = struct.unpack('<I', firmware_file.read(4))[0]
            current_offset = current_offset + 4  # seek to firmware info
            firmware_file.seek(current_offset)
            found_sm = 0
            while found_sm != 1:
                data = firmware_file.read(4)
                if len(data) < 4:
                    print("Warning: reached end of {input_file} before finding firmware")
                    shutil.copyfile(input_file, output_file)
                    return None
                firmware_type = struct.unpack('<I', data)[0]
                if IMAGE_FIRMWARE_TYPE_SM != hex(firmware_type):
                    current_offset = current_offset + 32 # seek to next firmware
                    firmware_file.seek(current_offset)
                    if current_offset > (fw_count - 1) * 32 + 128:
                        raise Exception('No SM firmware found in %s', input_file)
                else:
                    found_sm = 1
                    logger.info("SM firmware found")
                    sm_offset = struct.unpack('<I', firmware_file.read(4))[0] + IMAGE_PREPEND_INFO_SIZE
                    sm_size = struct.unpack('<I', firmware_file.read(4))[0]
                    firmware_file.seek(sm_offset)
                    sm_image_type = struct.unpack('<I', firmware_file.read(4))[0]
                    if SM_FIRMWARE_IMAGE_TYPE != hex(sm_image_type):
                        raise Exception('SM firmware image type error in %s', input_file)
    try:
        temp_dir = tempfile.mkdtemp()
        input_file_name = os.path.basename(input_file)
        in_extras_file = os.path.join(temp_dir, 'in_extras_' + os.path.splitext(input_file_name)[0])

        firmware_p1 = os.path.join(temp_dir, 'firmware_p1.bin')
        firmware_p2 = os.path.join(temp_dir, 'firmware_p2.bin')

        sm_firmware_file = os.path.join(temp_dir, 'sm_firmware.bin')
        enc_sm_firmware_file = os.path.join(temp_dir, 'enc_sm_firmware.bin')

        slice_file(input_file, firmware_p1, count=str(sm_offset))
        slice_file(input_file, sm_firmware_file, skip=str(sm_offset + 336), count=str(sm_size - 336))
        slice_file(input_file, firmware_p2, skip=str(sm_offset + sm_size))

        config = parse_config()
        config.print_oem_config_segid()
        config.print_oem_config_version()
        ree_segid=config.get_oem_seg_id('ree_segid')
        ree_version=config.get_oem_version('ree_version')

        my_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        tool_full_path = os.path.join(my_dir, EXTRA_TOOL)
        cmd2run = [ tool_full_path,
                    'SM_FW',
                    in_extras_file,
                    '0x00000001' ]

        check_call(cmd2run,)

        tool_full_path = os.path.join(my_dir, GENX_TOOL)
        cmd2run = [ tool_full_path,
                    '--img_type', 'SM_FW',
                    '--seg_id', ree_segid,
                    '--seg_id_mask', '0xffffffff',
                    '--version', hex(version_bitmask_conv(ree_version)),
                    '--version_mask', '0xffffffff',
                    '--extras', in_extras_file,
                    '--length', '0',
                    '--in_payload', sm_firmware_file,
                    '--out_store', enc_sm_firmware_file,
                    '--workdir-security-tools', my_dir,
                    '--workdir-security-keys', keys_dir ]

        check_call(cmd2run,)

        # assemble the firmware subimg
        if sm_only is True:
           with open(output_file, 'wb') as out:
               with open(enc_sm_firmware_file, 'rb') as inp:
                   shutil.copyfileobj(inp, out, BLOCK_SIZE)
        else:
           with open(output_file, 'wb') as out:
               with open(firmware_p1, 'rb') as inp:
                   shutil.copyfileobj(inp, out, BLOCK_SIZE)
               with open(enc_sm_firmware_file, 'rb') as inp:
                   shutil.copyfileobj(inp, out, BLOCK_SIZE)
               with open(firmware_p2, 'rb') as inp:
                   shutil.copyfileobj(inp, out, BLOCK_SIZE)

    finally:
        shutil.rmtree(temp_dir)

def resign_linux(input_file, output_file, keys_dir):
    """
    Sign and encrypt Linux Kernel with OEM keys
    """
    logger.info("Encrypt and Sign Linux")

    if not os.path.exists(input_file):
        raise Exception('Cannot find %s file', input_file)

    try:
        temp_dir = tempfile.mkdtemp()
        input_file_name = os.path.basename(input_file)
        image_prepend_info_file = os.path.join(temp_dir, 'prepend_info.bin')
        body_file = os.path.join(temp_dir, 'linux_body.bin')
        in_extras_file = os.path.join(temp_dir, 'in_extras_' + os.path.splitext(input_file_name)[0])
        enc_linux = os.path.join(temp_dir, 'enc_linux.bin')

        linux_file = open(input_file, 'rb')

        slice_file(input_file, image_prepend_info_file, count=IMAGE_PREPEND_INFO_SIZE)

        # get Linux size
        current_offset = LINUX_IMAGE_LENGTH_FIELD_OFFSET
        linux_file.seek(current_offset)
        linux_size = struct.unpack('<I', linux_file.read(4))[0]

        # check Linux image type
        current_offset = IMAGE_PREPEND_INFO_SIZE
        linux_file.seek(current_offset)
        linux_image_type = struct.unpack('<I', linux_file.read(4))[0]
        if hex(linux_image_type) != LINUX_IMAGE_TYPE:
            raise Exception('Linux: %s image type failed', input_file)

        slice_file(input_file, body_file, skip=IMAGE_PREPEND_INFO_SIZE + LINUX_HEADER_OFFSET, count=linux_size - LINUX_HEADER_OFFSET)

        # encrypt and sign Linux
        config = parse_config()
        config.print_oem_config_segid()
        config.print_oem_config_version()
        ree_segid=config.get_oem_seg_id('ree_segid')
        ree_version=config.get_oem_version('ree_version')

        my_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        tool_full_path = os.path.join(my_dir, EXTRA_TOOL)
        cmd2run = [ tool_full_path,
                    'LINUX_KERNEL',
                    in_extras_file,
                    '0x00000001' ]

        check_call(cmd2run,)

        tool_full_path = os.path.join(my_dir, GENX_TOOL)
        cmd2run = [ tool_full_path,
                    '--img_type', 'LINUX_KERNEL',
                    '--seg_id', ree_segid,
                    '--seg_id_mask', '0xffffffff',
                    '--version', hex(version_bitmask_conv(ree_version)),
                    '--version_mask', '0xffffffff',
                    '--extras', in_extras_file,
                    '--length', '0',
                    '--in_payload', body_file,
                    '--out_store', enc_linux,
                    '--workdir-security-tools', my_dir,
                    '--workdir-security-keys', keys_dir ]

        check_call(cmd2run,)

        # check Linux size and org Linux size are matched
        if os.path.getsize(enc_linux) != linux_size:
           raise Exception('Linux: %s size missmatch', input_file)

        # assemble Linux subimg
        with open(output_file, 'wb') as out:
            with open(image_prepend_info_file, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)
            with open(enc_linux, 'rb') as inp:
                shutil.copyfileobj(inp, out, BLOCK_SIZE)

    finally:
        shutil.rmtree(temp_dir)
