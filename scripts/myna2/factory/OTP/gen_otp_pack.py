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
#  File: gen_otp_pack.py
#  Auth: Victor Ku
#  Note: Tool to generate OTP packages
###############################################################################################

import subprocess
import struct
import logging
import sys
import os
import binascii
import configparser

from configs.kms_error import *

keys_folder= './keys'

logger = logging.getLogger(__name__)
sys.path.append('.')

config_cust = configparser.ConfigParser()
config_cust.read('configs/cust_config.conf')

def get_config(work_dir):
    if not os.path.exists('configs/oem_config.conf'):
         logger.error('oem_config.conf not found!! Copy it from PRODUCTION_X')
         sys.exit(1)

    config_oem = configparser.ConfigParser()
    config_oem.read('configs/oem_config.conf')
    ree_segid = config_oem.get('Segmentation ID', 'REE_SegID')

    return ree_segid

def exec_cmd(args):
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (stdout, stderr) = p.communicate()
    #logger.debug(stderr.decode())
    assert p.returncode == 0

def get_OTP_layout(workdir):
    """
    OTP fields to be written
    REE_Security_Enable
    K0_REE
    REE_SEGID
    AESK0
    jtag
    MP_Provision_Done
    """
    otp_pack_file = workdir + '/' + 'otp_pack' + '.bin'

    logger.info("Get MP OTP layout")

    try:
           ## generate MP OTP layout
           ree_segid = get_config(workdir)

           ## Check AESK0 and K0_REE_hash exist
           if not os.path.exists(keys_folder + '/AESK0.bin'):
              raise Exception('Cannot find AESK0')
           if not os.path.exists(keys_folder + '/K0_REE_hash.bin'):
              raise Exception('Cannot find K0_REE_HASH')

           ## get AESK0 value
           AESK0hex = open(keys_folder + '/AESK0.bin').read()
           AESK0hexbyte = binascii.hexlify(AESK0hex).decode('utf-8')

           ## selesct SCS_Total_Area_Size
           scs_size_dict = { '394240'  : 0,  #385K
                             '656384'  : 1,  #641K
                             '918528'  : 2,  #897K
                             '1672192' : 3 } #1633K

           scs_sel =  scs_size_dict.get('394240')
           if scs_sel is None:
              raise Exception("SCS_Total_Area_Size error!")

           gen_otp_layout_cmd = os.getcwd() + '/tools/gen_genx_otp_layout_v1'
           gen_otp_layout_cmd += ' -a ' + '0x' + AESK0hexbyte     # 16 bytes AESK0 key
           gen_otp_layout_cmd += ' -g ' + ree_segid          # 4 bytes REE Segmentation id
           gen_otp_layout_cmd += ' -n ' + '1'                # flag to enable REE security
           gen_otp_layout_cmd += ' -q ' + str(scs_sel)       # flag to select SCS size
           gen_otp_layout_cmd += ' -j ' + keys_folder + '/K0_REE_hash.bin'   # K0 REE hash file
           gen_otp_layout_cmd += ' -l ' + '1'                # flag to set jtag protection level
           gen_otp_layout_cmd += ' -r ' + '1'                # flag to enable MP provision done
           gen_otp_layout_cmd += ' -s ' + os.getcwd() + '/tools/device_prov_pub.pem'
           gen_otp_layout_cmd += ' -o ' + otp_pack_file

           logger.info("Gen MP OTP command: %s", str(gen_otp_layout_cmd))
           exec_cmd(gen_otp_layout_cmd)

           filesize = os.path.getsize(otp_pack_file)
           logger.debug("MP otp_pack filesize = %s", str(filesize))

           os.remove("raw_layout.bin")

    except Exception as e:
         logger.error("Error while generating MP OTP pack (%s)", str(e))
         sys.exit(1)

    return KMS_SUCCEED, otp_pack_file
