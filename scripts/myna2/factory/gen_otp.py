#!/usr/bin/python
# coding=UTF-8
#==============================================================================================
#
# Copyright 2023 Synaptics Incorporated. All rights reserved.
#
# This file contains information that is proprietary to Synaptics Incorporated ("Synaptics").
# The holder of this file shall treat all information contained herein as confidential,
# shall use the information only for its intended purpose, and shall not duplicate, disclose,
# or disseminate any of this information in any manner unless Synaptics has otherwise provided
# express, written permission.
#==============================================================================================

###############################################################################################
#  File: gen_otp.py
#  Auth: Victor Ku
#  Note: Tool to generate OTP layout only
###############################################################################################

import sys
import time
import datetime
import os
import ConfigParser
import shutil
import sys
import logging
import argparse
import hashlib

sys.path.append('.')
from OTP.gen_otp_pack import *

workingdir = '/tmp/gen_otp_tmp'
logger = logging.getLogger(__name__)

config = ConfigParser.ConfigParser()
config.read('configs/cust_config.conf')

def tool_md5():
    gen_otp_md5_hash = hashlib.md5()
    otp_md5_hash = hashlib.md5()

    gen_otp_file = open("gen_otp.py", "rb")
    gen_otp_content = gen_otp_file.read()
    gen_otp_md5_hash.update(gen_otp_content)
    gen_otp_digest = gen_otp_md5_hash.hexdigest()

    otp_file = open("OTP/gen_otp_pack.py", "rb")
    otp_content = otp_file.read()
    otp_md5_hash.update(otp_content)
    otp_digest = otp_md5_hash.hexdigest()

    return gen_otp_digest[:5] + otp_digest[:5]

def main():
    with open('./version') as f:
        ver = f.readline()
    version = "Version:\n" + ver + tool_md5()

    parser = argparse.ArgumentParser(description='Synaptics OTP layout generator helper.', epilog=str(version))
    parser.add_argument('--out', default='./otp_layout',
                        help='Output name of OTP layout')
    parser.add_argument('--v', action='store_true',
                        help='More verbose output')
    parser.add_argument('--logfile',
                        help='Output log to file')

    args = parser.parse_args()

    if args.logfile is not None:
        logging.basicConfig(level=logging.DEBUG if args.v else logging.INFO, filename=args.logfile, filemode='w',
                            format='%(asctime)s - %(levelname)s : %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    else:
        logging.basicConfig(level=logging.DEBUG if args.v else logging.INFO,
                            format='%(asctime)s - %(levelname)s : %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    logger.info("Output Name = %s", args.out)
    if os.path.exists(args.out + '.bin'):
        logger.error("Error: output file exist")
        exit()

    start = datetime.datetime.now()
    localtime  = time.localtime()
    timeString = time.strftime("%Y%W", localtime) + '_'

    if not os.path.exists(workingdir):
        os.mkdir(workingdir, 0755)
    else:
        shutil.rmtree(workingdir)
        os.mkdir(workingdir, 0755)

    lres, otp_pack = get_OTP_layout(workingdir)
    if lres != KMS_SUCCEED:
        logger.error("Error: Failed to create OTP layout. error(%s)", str(lres))
        exit(1)
 
    res = os.system('cp ' + otp_pack + ' ' + args.out  + '.bin')
    if res != 0:
        logger.error("Fail to copy OTP layout!")
        exit(1)

    stop = datetime.datetime.now()
    elapsed = stop - start
    logger.info("time elapsed = %s", str(elapsed))
    logger.info("The OTP layout are produced")

if __name__ == '__main__':
    sys.exit(main())
