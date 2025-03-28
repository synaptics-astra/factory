#!/bin/bash

TOOLS_DIR=$(dirname $0)/../../tools
GENX_IMG=$TOOLS_DIR/genx_img
keys_dir=../../keys
config=../../configs/oem_config.conf

function version_bitmask_con()
{
version_num=$1; shift

value=0

if [ $version_num -gt 32 ]; then
   exit 1
else
   for ((i=0;i<=$(($version_num-1));i++))
   do
     value=$(($value+$((1 << i))))
   done
fi
echo "$value"
}

function root_rsa()
{
in_img_type=$1; shift
in_aes_key=$1; shift
in_modulus=$1; shift
out_store=$1; shift
out_header_hash=$1; shift

$GENX_IMG -t $in_img_type  -k $in_aes_key  -i $in_modulus  -o $out_store  -p $out_header_hash
}

function level1_rsa()
{
in_img_type=$1; shift
in_production_flag=$1; shift
in_signing_key=$1; shift
in_seg_id=$1; shift
in_seg_id_mask=$1; shift
in_version=$1; shift
in_version_mask=$1; shift
in_rsa_key_payload=$1; shift
out_store=$1; shift

con_version=$( version_bitmask_con $in_version )
echo "con_version = $con_version"

echo "$GENX_IMG -t $in_img_type -f $in_production_flag -n $in_signing_key -s $in_seg_id  -S $in_seg_id_mask  -r $con_version  -R $in_version_mask -i $in_rsa_key_payload -o $out_store"

$GENX_IMG -t $in_img_type -f $in_production_flag -n $in_signing_key -s $in_seg_id  -S $in_seg_id_mask  -r $con_version  -R $in_version_mask -i $in_rsa_key_payload -o $out_store
}

function gen_k0_ree()
{
  in_img_type="K0_REE"
  in_aes_key=$keys_dir/AESK0_K0_REE.bin
  in_modulus=$keys_dir/K0_REE.rsa.pub.pem
  out_K0_REE_store=$keys_dir/K0_REE_store.bin
  out_header_hash=$keys_dir/K0_REE_hash.bin

  echo "Generating $in_img_type"
  root_rsa $in_img_type $in_aes_key  $in_modulus  $out_K0_REE_store  $out_header_hash
}

function gen_k1_ree_A()
{
  in_img_type="K1_REE_A"
  in_production_flag=1
  in_signing_key=$keys_dir/K0_REE.rsa.priv.pem
  in_seg_id=$ree_segid
  in_seg_id_mask=0xffffffff
  in_version=$ree_version
  in_version_mask=0xffffffff
  in_rsa_key_payload=$keys_dir/K1_REE_A.rsa.pub.pem
  out_K1_REE_A_store=$keys_dir/K1_REE_A_store.bin

  echo "Generating $in_img_type"
  level1_rsa $in_img_type $in_production_flag $in_signing_key $in_seg_id $in_seg_id_mask $in_version $in_version_mask $in_rsa_key_payload $out_K1_REE_A_store
}
# ----------------------------------------------------------------------------------------
function gen_k1_ree_B()
{
  in_img_type="K1_REE_B"
  in_production_flag=1
  in_signing_key=$keys_dir/K0_REE.rsa.priv.pem
  in_seg_id=$ree_segid
  in_seg_id_mask=0xffffffff
  in_version=$ree_version
  in_version_mask=0xffffffff
  in_rsa_key_payload=$keys_dir/K1_REE_B.rsa.pub.pem
  out_K1_REE_B_store=$keys_dir/K1_REE_B_store.bin

  echo "Generating $in_img_type"
  level1_rsa $in_img_type $in_production_flag $in_signing_key $in_seg_id $in_seg_id_mask $in_version $in_version_mask $in_rsa_key_payload $out_K1_REE_B_store
}
# ----------------------------------------------------------------------------------------
function gen_k1_ree_C()
{
  in_img_type="K1_REE_C"
  in_production_flag=1
  in_signing_key=$keys_dir/K0_REE.rsa.priv.pem
  in_seg_id=$ree_segid
  in_seg_id_mask=0xffffffff
  in_version=$ree_version
  in_version_mask=0xffffffff
  in_rsa_key_payload=$keys_dir/K1_REE_C.rsa.pub.pem
  out_K1_REE_C_store=$keys_dir/K1_REE_C_store.bin

  echo "Generating $in_img_type"
  level1_rsa $in_img_type $in_production_flag $in_signing_key $in_seg_id $in_seg_id_mask $in_version $in_version_mask $in_rsa_key_payload $out_K1_REE_C_store
}
# ----------------------------------------------------------------------------------------
function gen_k1_ree_D()
{
  in_img_type="K1_REE_D"
  in_production_flag=1
  in_signing_key=$keys_dir/K0_REE.rsa.priv.pem
  in_seg_id=$ree_segid
  in_seg_id_mask=0xffffffff
  in_version=$ree_version
  in_version_mask=0xffffffff
  in_rsa_key_payload=$keys_dir/K1_REE_D.rsa.pub.pem
  out_K1_REE_D_store=$keys_dir/K1_REE_D_store.bin

  echo "Generating $in_img_type"
  level1_rsa $in_img_type $in_production_flag $in_signing_key $in_seg_id $in_seg_id_mask $in_version $in_version_mask $in_rsa_key_payload $out_K1_REE_D_store
}

function main()
{
  [ -f $config ]

  echo $1

  ree_segid=`grep -nrw "ree_segid" $config | sed 's/^.*0x/0x/'`
  #ree_segid_mask=`grep -nrw "ree_segid_mask" $config | sed 's/^.*0x/0x/'`
  ree_version=`grep -nrw "ree_version" $config | sed 's/^.*=//'`
  #ree_version_mask=`grep -nrw "ree_version_mask" $config | sed 's/^.*0x/0x/'`
  echo "REE SegID: $ree_segid"
  #echo "REE SegID Mask: $ree_segid_mask"
  echo "REE Version: $ree_version"
  #echo "REE Version Mask: $ree_version_mask"

  if [ "$1" = "K1_only" ]; then
     gen_k1_ree_A
     gen_k1_ree_B
     gen_k1_ree_C
     gen_k1_ree_D
  else
     gen_k0_ree
     gen_k1_ree_A
     gen_k1_ree_B
     gen_k1_ree_C
     gen_k1_ree_D
  fi
}

main $@
