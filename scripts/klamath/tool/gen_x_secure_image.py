#!/usr/bin/env python3

""" %prog [options]
"""

""" Check version """
import sys
sys.dont_write_bytecode = True

if sys.hexversion < 0x03040000:
  raise Exception("ERROR: Python 3.4 or newer is required")

""" Import modules """
import os
import argparse
import shutil
import subprocess

from pathlib import Path
#
# Functions
#

def exec_cmd(args):
  print("+ execute command: ", str(args))
  try:
    result = subprocess.run(
      args,
      check=True,
      capture_output=True,
      text=True,
      env=dict(os.environ),
    )
  except subprocess.CalledProcessError as error:
    if error.stdout:
      print(error.stdout, end="")
    if error.stderr:
      print(error.stderr, file=sys.stderr, end="")
    raise RuntimeError(
      f"Secure image tool failed with exit code {error.returncode}: {' '.join(args)}"
    ) from error

  if result.stdout:
    print(result.stdout, end="")
  if result.stderr:
    print(result.stderr, file=sys.stderr, end="")

#
# Classes
#

class GenXSecureImage:
  def __init__(self):
    self.opts = argparse.Namespace()
    self.opts.basedir_security = os.path.realpath(
      os.path.join(os.path.dirname(__file__), "..")
    )

  def parse_args(self):
    """ parse command line arguments """
    parser = argparse.ArgumentParser(description="Generate GenX Secure Image")

    parser.add_argument('--chip-name', nargs=1, required=True)
    parser.add_argument('--chip-rev', nargs=1, required=True)
    parser.add_argument('--img_type', nargs=1, required=True)
    parser.add_argument('--key_type', nargs=1, required=True)
    parser.add_argument('--seg_id', nargs=1, default=["0x00000000"])
    parser.add_argument('--seg_id_mask', nargs=1, default=["0xFFFFFFFF"])
    parser.add_argument('--version', nargs=1, default=["0x00000000"])
    parser.add_argument('--version_mask', nargs=1, default=["0xFFFFFFFF"])
    parser.add_argument('--extras', nargs=1)
    parser.add_argument('--length', nargs=1, required=True)
    parser.add_argument('--in_payload', nargs=1, required=True)
    parser.add_argument('--out_store', nargs=1, required=True)
    parser.add_argument('--workdir-security-tools', nargs=1)
    parser.add_argument('--workdir-security-keys', nargs=1)
    parser.add_argument('--tool-version', nargs=1, required=True)
    parser.add_argument(
      '--allow-unencrypted',
      action='store_true',
      help='Explicitly permit signing without AES encryption',
    )

    self.opts = parser.parse_args(args=sys.argv[1:], namespace=self.opts)


    if self.opts.img_type[0] != "DDR_FW0" and self.opts.img_type[0] != "DDR_FW1":
      if self.opts.extras is None:
        parser.error("--extras is required for this image type")

    self.setup_workdir()

  def setup_workdir(self):
    """ print(self.opts) """

    if self.opts.workdir_security_tools is None:
      self.opts.workdir_security_tools = self.opts.basedir_security + "/tool"
    else:
      self.opts.workdir_security_tools = self.opts.workdir_security_tools[0]

    if self.opts.workdir_security_keys is None:
      self.opts.workdir_security_keys = self.opts.basedir_security + "/keys/"
      self.opts.workdir_security_keys = self.opts.workdir_security_keys + self.opts.chip_name[0]
      self.opts.workdir_security_keys += "/" + self.opts.chip_rev[0] + "/generic"
      self.opts.workdir_security_keys += "/" + self.opts.key_type[0]
    else:
      self.opts.workdir_security_keys = self.opts.workdir_security_keys[0] + "/generic"
      self.opts.workdir_security_keys += "/" + self.opts.key_type[0]

    """ print(self.opts) """

  def sign_image(self):
    if self.opts.tool_version[0] != "genx_v3":
      self.sign_image_x()
    else:
      self.sign_image_x3()

  def sign_image_x(self):
    """ assign AES and RSA """
    aes_list = {'MINILOADER':'MDK_MINI_LOADER.bin',
                'SYS_INIT': 'MDK_SYS_INIT.bin',
                'TZK_BOOT_PARAMETER': 'MDK_TZK_BOOT_PARAMETER.bin',
                'TA': 'TA_K1_AES_Key_TA.bin',
                'TSP_FW': 'MDK_TSP_FW.bin',
                'DSP_FW': 'MDK_DSP_FW.bin',
                'GPU_FW': 'MDK_GPU_FW.bin',
                'DDR_FW0': 'MDK_DDR_FW0.bin',
                'DDR_FW1': 'MDK_DDR_FW1.bin'}

    rsa_list = {'MINILOADER': 'K1_BOOT_B.rsa.priv.pem',
                'UBOOT': 'K1_BOOT_B.rsa.priv.pem',
                'SYS_INIT': 'K1_BOOT_B.rsa.priv.pem',
                'SCS_DATA_PARAM': 'K1_BOOT_B.rsa.priv.pem',
                'TZK_BOOT_PARAMETER': 'K1_TEE_B.rsa.priv.pem',
                'TZK_BOOT_PARAMETER_OPEN': 'K1_OEM_A.rsa.priv.pem',
                'TZ_KERNEL': 'K1_OEM_A.rsa.priv.pem',
                'ATF': 'K1_OEM_A.rsa.priv.pem',
                'TA': 'TA_K1_RSA.priv.pem',
                'TZK_OEM_SETTINGS': 'K1_OEM_A.rsa.priv.pem',
                'FASTBOOT': 'K1_OEM_A.rsa.priv.pem',
                'FASTLOGO': 'K1_OEM_A.rsa.priv.pem',
                'BOOT_LOADER': 'K1_OEM_A.rsa.priv.pem',
                'AVB_KEYS': 'K1_OEM_C.rsa.priv.pem',
                'LINUX_KERNEL': 'K1_OEM_C.rsa.priv.pem',
                'SM_FW': 'K1_OEM_B.rsa.priv.pem',
                'TSP_FW': 'K1_TEE_D.rsa.priv.pem',
                'DSP_FW': 'K1_TEE_C.rsa.priv.pem',
                'GPU_FW': 'K1_TEE_C.rsa.priv.pem'}

    # Determine encryption capability based on physical file existence
    use_encryption = False
    if aes_list.get(self.opts.img_type[0]) is not None:
      aes_key = self.opts.workdir_security_keys + "/" + aes_list.get(self.opts.img_type[0])
      if os.path.isfile(aes_key):
        use_encryption = True
        print(f">>> [AES ENCRYPT] Image Type: {self.opts.img_type[0]} -> Using Key: {aes_key}")
      else:
        if self.opts.allow_unencrypted:
          print(
            f">>> [EXPLICIT NO ENCRYPT] Image Type: {self.opts.img_type[0]} "
            f"has no staged AES key."
          )
        else:
          raise FileNotFoundError(
            f"Required AES key for {self.opts.img_type[0]} not found: {aes_key}"
          )
    else:
      print(f">>> [NO ENCRYPT] Image Type: {self.opts.img_type[0]} has no AES key target defined.")

    if self.opts.img_type[0] != "DDR_FW0" and self.opts.img_type[0] != "DDR_FW1":
      signing_key_name = rsa_list.get(self.opts.img_type[0])
      if signing_key_name is None:
        raise ValueError(f"Unsupported image type: {self.opts.img_type[0]}")
      signing_key = self.opts.workdir_security_keys + "/" + signing_key_name
      if not os.path.isfile(signing_key):
        raise FileNotFoundError(f"Required signing key not found: {signing_key}")

    """ Command and arguments """
    exec_bin = Path(self.opts.workdir_security_tools) / 'genx_img'
    exec_bin = exec_bin.as_posix()

    if not os.access(exec_bin, os.X_OK):
        exec_bin = Path(self.opts.workdir_security_tools).parent / 'lib' / 'sec_tools' / 'bin' / 'genx_img'
        exec_bin = exec_bin.as_posix()
        if not os.access(exec_bin, os.X_OK):
            exec_bin = shutil.which('genx_img')
    if not exec_bin:
      raise Exception("can't find genx_img")

    cmd2run = [ exec_bin ]

    # Dynamic payload configuration flags based on key verification results
    if use_encryption:
      cmd2run.extend(["-k", aes_key])
    else:
      cmd2run.extend(["--noenc"])

    if self.opts.img_type[0] == "TZK_BOOT_PARAMETER_OPEN":
      self.opts.img_type[0] = "TZK_BOOT_PARAMETER"

    cmd2run.extend(["-t", self.opts.img_type[0]])

    if self.opts.img_type[0] != "DDR_FW0" and self.opts.img_type[0] != "DDR_FW1":
      cmd2run.extend(["-n", signing_key])
      cmd2run.extend(["-s", self.opts.seg_id[0]])
      cmd2run.extend(["-S", self.opts.seg_id_mask[0]])
      cmd2run.extend(["-r", self.opts.version[0]])
      cmd2run.extend(["-R", self.opts.version_mask[0]])
      cmd2run.extend(["-x", self.opts.extras[0]])

    #cmd2run.extend(["-l", self.opts.length[0]])
    cmd2run.extend(["-i", self.opts.in_payload[0]])
    cmd2run.extend(["-o", self.opts.out_store[0]])

    exec_cmd(cmd2run)

  def sign_image_x3(self):
    """ assign AES and ecc """
    type_map_list = {
                     'BOOT_LOADER': 'UBOOT',
                     'TZ_KERNEL': 'OPTEE',
                     'TZK_BOOT_PARAMETER_OPEN': 'TEE_BOOT_PARAMETER',
                     'LINUX_KERNEL': 'LINUX'}
    aes_list = {
                'BL': 'CCGK_BL.bin',
                'FASTLOGO': 'CCGK_FAST_LOGO.bin',
                'ATF': 'CCGK_ATF.bin',
                'SM': 'CCGK_SM.bin',
                'GPU': 'CCGK_GPU.bin',
                'NPU': 'CCGK_NPU.bin',
                'OPTEE': 'CCGK_OPTEE.bin',
                'TEE_BOOT_PARAMETER': 'CCGK_TEEBP.bin',
                'UBOOT': 'CCGK_UBOOT.bin',
                'LINUX': 'CCGK_LINUX.bin'
                }
    ecc_list = {
                'BL': 'K1_C.EC521.priv.pem',
                'SM': 'K1_C.EC521.priv.pem',
                'GPU': 'K1_C.EC521.priv.pem',
                'ATF': 'K1_C.EC521.priv.pem',
                'FASTLOGO': 'K1_C.EC521.priv.pem',
                'OPTEE': 'K1_C.EC521.priv.pem',
                'TEE_BOOT_PARAMETER': 'K1_C.EC521.priv.pem',
                'UBOOT': 'K1_C.EC521.priv.pem',
                'AVB_KEYS':'K1_C.EC521.priv.pem',
                'LINUX': 'K1_C.EC521.priv.pem'}

    if type_map_list.get(self.opts.img_type[0]) is not None:
      self.opts.img_type[0] = type_map_list.get(self.opts.img_type[0])

    # Check key existence dynamically to choose between AES cipher layout or --noenc mode
    use_encryption = False
    if aes_list.get(self.opts.img_type[0]) is not None:
      aes_key = self.opts.workdir_security_keys + "/" + aes_list.get(self.opts.img_type[0])
      if os.path.isfile(aes_key):
        use_encryption = True
        print(f">>> [AES ENCRYPT] Image Type: {self.opts.img_type[0]} -> Using Key: {aes_key}")
      else:
        if self.opts.allow_unencrypted:
          print(
            f">>> [EXPLICIT NO ENCRYPT] Image Type: {self.opts.img_type[0]} "
            f"has no staged AES key."
          )
        else:
          raise FileNotFoundError(
            f"Required AES key for {self.opts.img_type[0]} not found: {aes_key}"
          )
    else:
      print(f">>> [NO ENCRYPT] Image Type: {self.opts.img_type[0]} has NO AES key defined.")

    if self.opts.img_type[0] != "DDR_FW0" and self.opts.img_type[0] != "DDR_FW1":
      signing_key_name = ecc_list.get(self.opts.img_type[0])
      if signing_key_name is None:
        raise ValueError(f"Unsupported GenX V3 image type: {self.opts.img_type[0]}")
      signing_key = self.opts.workdir_security_keys + "/" + signing_key_name
      if not os.path.isfile(signing_key):
        raise FileNotFoundError(f"Required signing key not found: {signing_key}")

    """ Command and arguments """
    exec_bin = Path(self.opts.workdir_security_tools) / 'genx_img_v3'
    exec_bin = exec_bin.as_posix()

    if not os.access(exec_bin, os.X_OK):
        exec_bin = Path(self.opts.workdir_security_tools).parent / 'lib' / 'sec_tools' / 'bin' / 'genx_img_v3'
        exec_bin = exec_bin.as_posix()
        if not os.access(exec_bin, os.X_OK):
            exec_bin = shutil.which('genx_img_v3')
    if not exec_bin:
      raise Exception("can't find genx_img_v3")

    cmd2run = [ exec_bin ]

    # Dynamically inject encryption parameters or bypass depending on layout parameters validation status
    if use_encryption:
      cmd2run.extend(["-k", aes_key])
    else:
      cmd2run.extend(["--noenc"])

    cmd2run.extend(["-t", self.opts.img_type[0]])

    if self.opts.img_type[0] != "DDR_FW0" and self.opts.img_type[0] != "DDR_FW1":
      cmd2run.extend(["-n", signing_key])
      cmd2run.extend(["-s", self.opts.seg_id[0]])
      cmd2run.extend(["-r", self.opts.version[0]])
      cmd2run.extend(["-x", self.opts.extras[0]])

    #cmd2run.extend(["-l", self.opts.length[0]])
    cmd2run.extend(["-i", self.opts.in_payload[0]])
    cmd2run.extend(["-o", self.opts.out_store[0]])

    exec_cmd(cmd2run)

#
# Main
#

def main():
  genXSecImg = GenXSecureImage()
  genXSecImg.parse_args()

  """
  print("\n")
  print(genXSecImg.opts)
  """

  genXSecImg.sign_image()

if __name__ == "__main__":
  exitcode = main()
  sys.exit(exitcode)
