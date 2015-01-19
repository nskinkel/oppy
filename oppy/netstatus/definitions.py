# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

from oppy import base_dir

CONSENSUS_CACHE_FILE = base_dir + '/../data/cached-consensus'

CONSENSUS_URL = '/tor/status-vote/current/consensus.z'
STEM_CONSENSUS_TYPE = 'network-status-consensus-3 1.0'
DESCRIPTORS_URL = '/tor/server/all.z'
STEM_DESCRIPTORS_TYPE = 'server-descriptor 1.0'
