#!/bin/bash
#==============================================================================================
#
# Copyright © 2011-2017 Synaptics Incorporated. All rights reserved.
#
# This file contains information that is proprietary to Synaptics Incorporated ("Synaptics").
# The holder of this file shall treat all information contained herein as confidential,
# shall use the information only for its intended purpose, and shall not duplicate, disclose,
# or disseminate any of this information in any manner unless Synaptics has otherwise provided
# express, written permission.
#
# $Source: gen_rootk.sh
#==============================================================================================

###############################################################################################
#  Goal:  This script is used to generate AESK0 and REE keys
#  Date:  2020/10/28
###############################################################################################
KeyDIR=../keys

if [ ! -d $KeyDIR ]; then
  echo "create keys folder"
  mkdir $KeyDIR
else
  rm -fr $KeyDIR
  mkdir $KeyDIR
fi

echo "Generate AESK0.bin ......"
dd if=/dev/urandom of=$KeyDIR/AESK0.bin bs=1 count=16

echo "Generate K0_REE.rsa ......"
openssl genrsa -out $KeyDIR/K0_REE.rsa.priv.pem -f4 2048
openssl rsa -in $KeyDIR/K0_REE.rsa.priv.pem -pubout > $KeyDIR/K0_REE.rsa.pub.pem

echo "Generate K1_REE_A.rsa ......"
openssl genrsa -out $KeyDIR/K1_REE_A.rsa.priv.pem -f4 2048
openssl rsa -in $KeyDIR/K1_REE_A.rsa.priv.pem -pubout > $KeyDIR/K1_REE_A.rsa.pub.pem

echo "Generate K1_REE_B.rsa.priv.pem  ......"
openssl genrsa -out $KeyDIR/K1_REE_B.rsa.priv.pem -f4 2048
openssl rsa -in $KeyDIR/K1_REE_B.rsa.priv.pem -pubout > $KeyDIR/K1_REE_B.rsa.pub.pem

echo "Generate K1_REE_C.rsa ......"
openssl genrsa -out $KeyDIR/K1_REE_C.rsa.priv.pem -f4 2048
openssl rsa -in $KeyDIR/K1_REE_C.rsa.priv.pem -pubout > $KeyDIR/K1_REE_C.rsa.pub.pem

echo "Generate K1_REE_D.rsa.priv.pem  ......"
openssl genrsa -out $KeyDIR/K1_REE_D.rsa.priv.pem -f4 2048
openssl rsa -in $KeyDIR/K1_REE_D.rsa.priv.pem -pubout > $KeyDIR/K1_REE_D.rsa.pub.pem
