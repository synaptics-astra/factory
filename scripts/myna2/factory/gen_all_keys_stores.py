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
#  File: gen_all_keys_stores.py
#  Auth: Victor Ku
#  Note: Tool to generate secure keys and store for factory flow.
###############################################################################################

import os
import sys
import shutil
import argparse
import subprocess

sys.path.append('.')
gen_keys_path = 'gen_keys'
kdf_tool_path = gen_keys_path + '/kdf'
ree_store_tool_path = gen_keys_path + '/ree_store'
keys_folder = 'keys'

pushstack = list()

def pushdir(dirname):
     global pushstack
     pushstack.append(os.getcwd())
     os.chdir(dirname)

def popdir():
     global pushstack
     os.chdir(pushstack.pop())

def exec_cmd(args):
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (stdout, stderr) = p.communicate()
    print(stderr.decode())
    assert p.returncode == 0

def main():
    parser = argparse.ArgumentParser(description='Synaptics secure keys generator helper.', epilog="Output keys are in \"keys\" folder")
    parser.add_argument('--AESK0_rootk', action='store_true',
                        help='Generate AESK0 root key only')
    parser.add_argument('--REE_rootk', action='store_true',
                        help='Generate K0_ree and K1_ree root keys only')
    parser.add_argument('--AESK0_kdf', action='store_true',
                        help='Derive AESK0 encryption keys')
    parser.add_argument('--REE_keystore', action='store_true',
                        help='Generate K0 and K1 keystore')
    parser.add_argument('--UPDATE_K1_keystore', action='store_true',
                        help='Update K1 keystore for version dumping')

    args = parser.parse_args()

    if args.AESK0_rootk is True:
       print("Generate AESK0 root key only")
       pushdir(gen_keys_path)
       exec_cmd( './gen_AESK0_rootk.sh ' )
       popdir()

    elif args.REE_rootk is True:
       print("Generate K0_ree and K1_ree root keys only")
       pushdir(gen_keys_path)
       exec_cmd( './gen_REE_rootk.sh ' )
       popdir()

    elif args.AESK0_kdf is True:
       print("Derive AESK0 encryption keys")
       if os.path.isfile(keys_folder + '/AESK0.bin'):
          pushdir(kdf_tool_path)
          exec_cmd( './AESK0_kdf.sh ' )
          popdir()
       else:
          print("AESK0.bin file not found!")
          exit(1)

    elif args.REE_keystore is True:
       print("Generate K0 and K1 keystore")
       ree_files = ["AESK0_K0_REE.bin", "K0_REE.rsa.priv.pem", "K0_REE.rsa.pub.pem", "K1_REE_A.rsa.priv.pem", "K1_REE_A.rsa.pub.pem", "K1_REE_B.rsa.priv.pem", "K1_REE_B.rsa.pub.pem", "K1_REE_C.rsa.priv.pem", "K1_REE_C.rsa.pub.pem", "K1_REE_D.rsa.priv.pem", "K1_REE_D.rsa.pub.pem"];
       ree_exist = [f for f in ree_files if os.path.isfile( keys_folder + "/" + f )];
       ree_non_exist = list(set(ree_exist) ^ set(ree_files))
       if not ree_non_exist:
          pushdir(ree_store_tool_path)
          exec_cmd( './rsa_store.sh ' )
          popdir()
       else:
          print("%s file not found!" % ree_non_exist)
          exit(1)

    elif args.UPDATE_K1_keystore is True:
       print("Update K1 keystore")
       ree_files = ["AESK0_K0_REE.bin", "K0_REE.rsa.priv.pem", "K0_REE.rsa.pub.pem", "K1_REE_A.rsa.priv.pem", "K1_REE_A.rsa.pub.pem", "K1_REE_B.rsa.priv.pem", "K1_REE_B.rsa.pub.pem", "K1_REE_C.rsa.priv.pem", "K1_REE_C.rsa.pub.pem", "K1_REE_D.rsa.priv.pem", "K1_REE_D.rsa.pub.pem"];
       ree_exist = [f for f in ree_files if os.path.isfile( keys_folder + "/" + f )];
       ree_non_exist = list(set(ree_exist) ^ set(ree_files))
       if not ree_non_exist:
          pushdir(ree_store_tool_path)
          exec_cmd( './rsa_store.sh K1_only' )
          popdir()
       else:
          print("%s file not found!" % ree_non_exist)
          exit(1)

    else:
        """ generate rootk """
        pushdir(gen_keys_path)
        exec_cmd( './gen_rootk.sh ' )
        popdir()

        """ derive AESK0 """
        pushdir(kdf_tool_path)
        exec_cmd( './AESK0_kdf.sh ' )
        popdir()

        """ generate ree keystore """
        pushdir(ree_store_tool_path)
        exec_cmd( './rsa_store.sh ' )
        popdir()

    print("Output keys are in \"keys\" folder")

if __name__ == "__main__":
    main()
