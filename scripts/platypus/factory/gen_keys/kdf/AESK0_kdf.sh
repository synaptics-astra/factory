#!/bin/bash
source $PWD/config

function write_l_endian32() {
  echo `printf "%08x"  $1` | grep -o .. | tac | echo "$(tr -d '\n')" | xxd -r -p
}

function write_l_endian16() {
  echo `printf "%04x"  $1` | grep -o .. | tac | echo "$(tr -d '\n')" | xxd -r -p
}

function write_byte() {
  echo `printf "%02x"  $1` | xxd -r -p
}

function calc_hmac_sha256() {
  key_in=$1
  image_name=$2
  image_type=$3
  f_out=$4

  f_value="$PWD/value.bin"
  if [ -f $f_value ]; then
    rm $f_value
  fi
  write_l_endian16 $LEVEL > $f_value
  write_byte 0x09 >> $f_value
  write_l_endian32 $image_type >> $f_value
  if [ $image_name = "K0_REE"  ]; then
    write_l_endian32 $HEADER_VERSION_K0_REE >> $f_value
    echo 1 $HEADER_VERSION_K0_REE
  else
    write_l_endian32 $HEADER_VERSION >> $f_value
    echo 2 $HEADER_VERSION
  fi
  write_byte $PROD_IMAGE_FLAG >> $f_value
  write_byte 0x00 >> $f_value
  write_l_endian32 $CONTEXT0_3 >> $f_value
  write_l_endian32 $CONTEXT4_7 >> $f_value
  write_l_endian16 $DESIRED_NUM >> $f_value
  if [ "$PRINT_INFO" -eq "1" ]; then
    printf "%16s | %08x | " $image_name $image_type
    xxd -ps $f_value
  fi

  openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key_in" -binary -out $f_out $f_value
  truncate -s 16 $f_out

  if [ -f $f_value ]; then
    rm $f_value
  fi
}

if [ ! -f $F_AESK0 ]; then
  echo "Error! can't find $F_AESK0"
  exit 1
fi

if [ ! -d $DIR_OUT ]; then
  echo "Error! $DIR_OUT not exist!"
  exit 1
fi

if [ "$PRINT_INFO" -eq "1" ]; then
  str_aesk0=`xxd -p -l 16 $F_AESK0`
  echo "*****************************************************************************"
  echo "AESK0: $str_aesk0"
  echo "*****************************************************************************"
  echo "KDF values:"
fi

for ((i=0; i<${#Imgs[@]}; i++)); do
  str_image_type="IMAGE_TYPE_"${Imgs[$i]}
  calc_hmac_sha256 $str_aesk0 ${Imgs[$i]} ${!str_image_type} $DIR_OUT/AESK0_${Imgs[$i]}.bin
done

echo "*****************************************************************************"
echo "Generate AESK0 KDF keys in $DIR_OUT"
echo "*****************************************************************************"
exit 0

