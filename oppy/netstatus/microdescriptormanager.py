# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

import re
import logging
import random
import zlib

from base64 import b64encode
from hashlib import sha256

from twisted.internet import defer
from twisted.web.client import getPage

from stem.descriptor import microdescriptor

from oppy import data_dir
import oppy.netstatus.microconsensusmanager as microconsensusmanager


MICRO_DESC_PATH = '/tor/micro/d/'
CIRCUIT_BUILD_THRESHOLD = 0.8
REQUEST_MAX = 92
REGEX = re.compile('^onion-key$', re.MULTILINE)
REQUEST_DELIM = '-'
MICRO_DESC_CACHE_FILE = data_dir + 'cached-microdescs.new'
TIMEOUT = 20


# Major TODO's:
#   - docs
#   - better logging
#   - do we reset whether or not we can we have enough descs to build a
#     circuit after getting a new consensus?
#   - write cached descriptors file
#   - discard descriptors not found in consensus
#   - set download timeout


class MicrodescriptorManager(object):

    def __init__(self, microconsensus_manager, autostart=True):
        logging.debug('MicrodescriptorManager created.')
        self._microconsensus_manager = microconsensus_manager
        self._pending_requests_for_circuit = []
        self._enough_for_circuit = False
        self._total_descriptors = 0
        self._microdescriptors = None

        if autostart is True:
            self.start()

    def start(self):
        self._microdescriptors = _getMicrodescriptorsFromCacheFile()
        self._downloadMicrodescriptors(initial=True)

    def getMicrodescriptorsForCircuit(self):
        d = defer.Deferred()
        if self._microdescriptors and self._enough_for_circuit:
            d.callback(self._microdescriptors)
        else:
            self._pending_requests_for_circuit.append(d)

        return d

    def _servePendingRequestsForCircuit(self):
        for request in self._pending_requests_for_circuit:
            request.callback(self._microdescriptors)
        self._pending_requests_for_circuit = []

    @defer.inlineCallbacks
    def _downloadMicrodescriptors(self, initial=False):
        consensus = yield self._microconsensus_manager.getMicroconsensus()
        v2dirs = microconsensusmanager.getV2DirsFromConsensus(consensus)
        self._total_descriptors = len(consensus.routers)
        self._discardUnlistedMicrodescriptors(consensus)
        needed_digests = _getNeededDescriptorDigests(
            consensus, self._microdescriptors)
        # if we already have >= 80% of descriptors, we can build circuits
        # immediately
        self._checkIfReadyToBuildCircuit()
        # only request <= REQUEST_MAX descriptors from each dircache
        blocks = [needed_digests[i:i+REQUEST_MAX]
                  for i in xrange(0, len(needed_digests), REQUEST_MAX)]

        if len(blocks) > 0:
            task_list = [self._downloadMicrodescriptorBlock(b, v2dirs)
                         for b in blocks]
            d = defer.gatherResults(task_list)
            d.addCallback(self._writeMicrodescriptorCacheFile)

        if initial is True:
            self._microconsensus_manager.addMicroconsensusDownloadCallback(
                self._downloadMicrodescriptors)

    @defer.inlineCallbacks
    def _downloadMicrodescriptorBlock(self, block, v2dirs):
        descs = set()
        for d in block:
            try:
                tmp = b64encode(d.decode('hex')).rstrip('=')
                descs.add(tmp)
            except TypeError:
                msg = "Malformed descriptor {}. Discarding.".format(d)
                logging.debug(msg)

        dircaches = list(v2dirs)

        for _ in xrange(len(dircaches)):
            dircache = random.choice(dircaches)
            url = _makeDescDownloadURL(dircache, descs)
            try:
                result = yield getPage(url, timeout=TIMEOUT)
                # descs set to leftover descriptors that weren't received
                descs = self._processMicrodescriptorBlockResult(result, descs)
                if len(descs) == 0:
                    break
            except Exception:
                # if a download fails, try again at a different dircache
                dircaches.remove(dircache)

        if len(descs) != 0:
            msg = ("Tried all V2Dir caches and failed to download the "
                   "descriptors with digests: {}".format(' '.join(descs)))
            logging.debug(msg)

        defer.returnValue(None)

    def _processMicrodescriptorBlockResult(self, result, requested):
        try:
            micro_descs = _decompressAndSplitResult(result)
        except ValueError:
            return requested

        processed = {}

        for m in micro_descs:
            hashed = b64encode(sha256(m).digest()).rstrip('=')
            # discard any descriptors we didn't request
            if hashed not in requested:
                continue
            try:
                desc = microdescriptor.Microdescriptor(m)
            except Exception:
            # discard unparseable descriptors (shouldn't happen)
                continue

            processed[desc.digest] = desc
            requested.remove(hashed)

        self._saveProcessedMicrodescriptors(processed)
        # return any requested descriptors that weren't received/processed
        return requested

    def _saveProcessedMicrodescriptors(self, processed_descriptors):
        if self._microdescriptors is None:
            self._microdescriptors = processed_descriptors
        else:
            self._microdescriptors.update(processed_descriptors)

        if self._enough_for_circuit is False:
            self._checkIfReadyToBuildCircuit()

    def _checkIfReadyToBuildCircuit(self):
        if not self._microdescriptors or self._enough_for_circuit:
            return

        ml = float(len(self._microdescriptors))
        cl = float(self._total_descriptors)

        if (ml / cl) >= CIRCUIT_BUILD_THRESHOLD:
            self._enough_for_circuit = True
            self._servePendingRequestsForCircuit()

    def _writeMicrodescriptorCacheFile(self, _):
        try:
            with open(MICRO_DESC_CACHE_FILE, 'w') as f:
                for desc in self._microdescriptors.values():
                    f.write(str(desc))
            logging.debug("Wrote microdescriptor cache file.")
        except Exception as e:
            msg = ("Failed to write microdescriptor cache file. Reason: {}."
                   .format(e))
            logging.debug(msg)

    def _discardUnlistedMicrodescriptors(self, consensus):
        if self._microdescriptors is None:
            return

        digests = set([r.digest for r in consensus.routers.values()])
        old_digests = set(self._microdescriptors.keys())
        unlisted = old_digests - digests
        for d in unlisted:
            del self._microdescriptors[d]


# TODO: see if there's a way to parse_file() with stem
def _getMicrodescriptorsFromCacheFile(fname=MICRO_DESC_CACHE_FILE):
    try:
        with open(fname, 'r') as f:
            data = f.read()
    except Exception as e:
        msg = ("Failed to read microdescriptor cache file. Reason: {}."
               .format(e))
        logging.debug(msg)
        return None

    micro_descs = {}
    cached_descs = ['onion-key' + m for m in REGEX.split(data)]
    for m in cached_descs:
        try:
            desc = microdescriptor.Microdescriptor(m)
        # discard any malformed descriptors
        except Exception as e:
            continue

        micro_descs[desc.digest] = desc

    msg = ("Read {} cached microdescriptors.".format(len(micro_descs)))
    logging.debug(msg)
    return micro_descs if len(micro_descs) > 0 else None


def _decompressAndSplitResult(result):
    try:
        result = zlib.decompress(result)
        micro_descs = ['onion-key' + m for m in REGEX.split(result)]
        micro_descs.pop(0)
    except Exception as e:
        raise ValueError(str(e))

    return micro_descs

def _makeDescDownloadURL(v2dir, digest_list):
    request = REQUEST_DELIM.join([digest for digest in digest_list])
    host = 'http://' + v2dir.address + ':' + str(v2dir.dir_port)
    path = MICRO_DESC_PATH + request + '.z'
    return str(host+path)


def _getNeededDescriptorDigests(consensus, descriptors):
    total_digests = set([r.digest for r in consensus.routers.values()])
    if descriptors is None:
        return list(total_digests)
    return list(total_digests - set([r.digest for r in descriptors.values()]))
