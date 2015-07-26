# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

import logging

from oppy.netstatus.microconsensusmanager import MicroconsensusManager
from oppy.netstatus.microdescriptormanager import MicrodescriptorManager


class NetStatus(object):
    '''Download consensus and server descriptor documents.'''

    def __init__(self):
        logging.debug("Created NetStatus.")
        self._mcm = MicroconsensusManager()
        self._mdm = MicrodescriptorManager(self._mcm)

    def getMicrodescriptorsForCircuit(self):
        return self._mdm.getMicrodescriptorsForCircuit()

    def getMicroconsensus(self):
        return self._mcm.getMicroconsensus()
