#!/usr/bin/env python
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
#  File: resign_usb_boot_image.py
#  Auth: Victor Ku
#  Note: Tool to resign USB boot image to boot-up devices on production board
###############################################################################################

from argparse import ArgumentParser
import os
import traceback
import tempfile
import shutil
import subprocess
import logging
import sys
import re
import struct
import hashlib

from tools.gen_x_image_pack import *
from configs.parse_config import *

sys.path.append('.')
KEYS_FOLDER = 'keys'

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
        print normal, err
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

def gzip_file(input_file):
    """
    gzip input file
    """
    logger.debug("gzip file: %s", input_file)
    cmd = ['gzip', '-f', input_file]
    check_call(cmd)

def gunzip_file(input_file):
    """
    gunzip input file
    """
    logger.debug("gunzip file: %s", input_file)
    cmd = ['gzip', '-d', input_file]
    check_call(cmd)

def copy_from_src_image(src_image, dst_image):
    """
    Copy all files to dest directory
    """

    logger.info("input folder: %s", src_image)
    logger.info("output folder: %s", dst_image)

    shutil.copytree(src_image, dst_image)

def resign_image(dst_image, keys_dir):
    # create a temporary working directory
    temp_dir = tempfile.mkdtemp()
    input_image = os.path.abspath(dst_image)

    org_images = [ 'gen3_bkl.bin.usb',
                   'gen3_uboot.bin.usb',
                   'gen3_tzk.bin.usb',
                 ]

    try:
	# copy image files to temp folder
	for image in org_images:
	      shutil.copy(os.path.join(input_image, image), temp_dir)

        for i in range(len(org_images)):
            if "gen3_bkl.bin.usb" in org_images[i]:
	        patch_usb_bkl(os.path.join(temp_dir, org_images[i]), os.path.join(dst_image, org_images[i]), keys_dir)
            elif "gen3_uboot.bin.usb" in org_images[i]:
                resign_bootloader(os.path.join(temp_dir, org_images[i]), os.path.join(dst_image, org_images[i]), keys_dir)
                slice_file(os.path.join(dst_image, org_images[i]), os.path.join(dst_image, org_images[i] + ".header"), count=512)
            elif "gen3_tzk.bin.usb" in org_images[i]:
                resign_tzk(os.path.join(temp_dir, org_images[i]), os.path.join(dst_image, org_images[i]), keys_dir)
                slice_file(os.path.join(dst_image, org_images[i]), os.path.join(dst_image, org_images[i] + ".header"), count=512)
            else:
                logger.info("No image type: %s", org_images[i])

    finally:
        shutil.rmtree(temp_dir)

def overwrite_file(input_file, output_file, seek=None):
    """
    Overwrites the beginning of a file with the content of another file
    """

    if os.path.getsize(input_file) > os.path.getsize(output_file):
        raise Exception("Input file is bigger than output file")

    cmd = ['dd', 'if=' + input_file, 'of=' + output_file, 'conv=notrunc', 'bs=1']

    if seek :
        cmd.append('seek=' + str(seek))

    check_call(cmd,)

def resign_usb_boot_image(src_image, dst_image, keys_dir):
    """
    Resign USB boot images
    """
    if not os.path.isdir(src_image):
        raise Exception('Cannot find input USB boot image directory')

    if os.path.exists(dst_image):
        raise Exception('Destination directory already exists')

    done = False

    try :
        copy_from_src_image(src_image, dst_image)

        resign_image(dst_image, keys_dir)

        done = True

    finally:

        # remove partially created output in case of exceptions
        if not done:
            shutil.rmtree(dst_image)

def tool_md5():
    factory_md5_hash = hashlib.md5()
    pack_md5_hash = hashlib.md5()
    config_md5_hash = hashlib.md5()

    factory_file = open(__file__, "rb")
    factory_content = factory_file.read()
    factory_md5_hash.update(factory_content)
    factory_digest = factory_md5_hash.hexdigest()

    pack_file = open("tools/gen_x_image_pack.py", "rb")
    pack_content = pack_file.read()
    pack_md5_hash.update(pack_content)
    pack_digest = pack_md5_hash.hexdigest()

    config_file = open("configs/parse_config.py", "rb")
    config_content = config_file.read()
    config_md5_hash.update(config_content)
    config_digest = config_md5_hash.hexdigest()

    return factory_digest[:5] + pack_digest[:5] + config_digest[:5]

def main():

    with open('./version') as f:
        ver = f.readline()
    version = "Version:\n" + "".join(ver) + tool_md5()

    parser = ArgumentParser(description='Astra USB Boot Image Resigning helper.', epilog=str(version))

    parser.add_argument('src_usb_boot_image_dir', help='USB boot image to be used as model')
    parser.add_argument('-o', dest='output', default='./resign_images', help='directory where the resigned images should be written')
    parser.add_argument('--v', action='store_true', help='More verbose output')

    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.v else logging.INFO,
                        format='%(asctime)s - %(levelname)s : %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    cur_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
    keys_dir = os.path.join(cur_dir, KEYS_FOLDER)

    key_files = ["AESK0_BOOT_LOADER.bin", "AESK0_ATF.bin", "AESK0_TZ_KERNEL.bin", "AESK0_TZK_BOOT_PARAMETER.bin", "AESK0_SM_FW.bin", "K1_REE_A.rsa.priv.pem", "K1_REE_B.rsa.priv.pem", "K1_REE_C.rsa.priv.pem"];
    key_exist = [f for f in key_files if os.path.isfile( keys_dir + "/" + f )];
    key_non_exist = list(set(key_exist) ^ set(key_files))
    if key_non_exist:
       logger.error("%s key file not found!", key_non_exist)
       sys.exit(1)

    try:
        resign_usb_boot_image(args.src_usb_boot_image_dir, args.output, keys_dir)

    except Exception as ex:
        logger.error("Error: %s", ex)

        logger.error("Details:\n")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
