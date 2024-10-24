#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import sys

sys.path.append('adcheck/libs')

import logging

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
