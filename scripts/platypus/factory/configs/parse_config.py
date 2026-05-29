#!/usr/bin/env python3

import os
import shutil
import logging
import sys
import configparser

logger = logging.getLogger(__name__)
syna_config_path = 'configs/syna_config.conf'
oem_config_path = 'configs/oem_config.conf'

class parse_config:

    def __init__(self):
        logger.debug("Parsing config files...")

        if not os.path.exists(oem_config_path):
           raise Exception('Cannot find OEM configuration file %s' % oem_config_path)

        oem_config = configparser.ConfigParser()
        oem_config.read(oem_config_path)

        self.oem_segid = oem_config.items("Segmentation ID")
        self.oem_version = oem_config.items("Version")

        self.oem_segid_dict = { self.oem_segid[i][0] : self.oem_segid[i][1] for i in range(0, len(self.oem_segid) ) }
        self.oem_ver_dict = { self.oem_version[i][0] : self.oem_version[i][1] for i in range(0, len(self.oem_version) ) }

    def get_oem_seg_id(self, seg_id_name):
        return self.oem_segid_dict[seg_id_name]

    def get_oem_version(self, ver_name):
        return self.oem_ver_dict[ver_name]

    def print_oem_config_segid(self):
        logger.info("OEM Seg_id:")
        for i in range(0, len(self.oem_segid)):
            logger.info("%s: %s", self.oem_segid[i][0], self.oem_segid[i][1])

    def print_oem_config_version(self):
        logger.info("OEM Version:")
        for i in range(0, len(self.oem_version)):
            logger.info("%s: %s", self.oem_version[i][0], self.oem_version[i][1])
