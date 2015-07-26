# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

import logging
import random
import time
import zlib

from twisted.internet import defer
from twisted.web.client import getPage

from stem import Flag
from stem.descriptor.networkstatus import NetworkStatusDocumentV3
from stem.descriptor.remote import get_authorities

from oppy import data_dir


MICRO_CONSENSUS_PATH = '/tor/status-vote/current/consensus-microdesc.z'
MICRO_CONSENSUS_CACHE_FILE = data_dir + 'cached-microdesc-consensus'
SLEEP = 30


# Major TODO's:
#   - check consensus signatures are valid before accepting
#   - better logging
#   - docs
#   - add download timeout
#   - check if cached consensus is still valid and don't download if it is

class ConsensusDownloadFailed(Exception):
    pass


class MicroconsensusManager(object):

    def __init__(self, autostart=True):
        logging.debug("MicroconsensusManager created.")
        self._consensus = None
        self._pending_consensus_requests = []
        self._consensus_download_callbacks = set()

        if autostart is True:
            self.start()

    def start(self, initial=True):
        self._scheduledConsensusUpdate(initial)

    # TODO: add to callback list or something to be nicer
    def getMicroconsensus(self):
        d = defer.Deferred()
        if self._consensus:
            d.callback(self._consensus)
        else:
            self._pending_consensus_requests.append(d)

        return d

    def addMicroconsensusDownloadCallback(self, callback):
        self._consensus_download_callbacks.add(callback)

    def removeMicroconsensusDownloadCallback(self, callback):
        try:
            self._consensus_download_callbacks.remove(callback)
        except KeyError:
            msg = ("MicroconsensusManager got request to remove callback "
                   "{} but has no reference to this function."
                   .format(callback))
            logging.debug(msg)

    def _servePendingRequests(self):
        for request in self._pending_consensus_requests:
            request.callback(self._consensus)
        self._pending_consensus_requests = []

    def _serveConsensusDownloadCallbacks(self):
        for callback in self._consensus_download_callbacks:
            callback()

    @defer.inlineCallbacks
    def _scheduledConsensusUpdate(self, initial=False):
        logging.debug("MicroconsensusManager running scheduled consensus "
                      "update.")
        if initial is True or self._consensus is None:
            v2dirs = _readV2DirsFromCacheFile() or get_authorities().values()
        else:
            v2dirs = getV2DirsFromConsensus(self._consensus)

        try:
            self._consensus = yield self._downloadMicroconsensus(v2dirs)
        except ConsensusDownloadFailed as e:
            logging.debug(e)
            from twisted.internet import reactor
            reactor.callLater(SLEEP, self._scheduledConsensusUpdate, initial)
            return

        self._scheduleNextConsensusDownload()
        self._servePendingRequests()
        self._serveConsensusDownloadCallbacks()

    @defer.inlineCallbacks
    def _downloadMicroconsensus(self, v2dirs):
        random.shuffle(v2dirs)
        for dc in v2dirs:
            try:
                host = "http://" + str(dc.address) + ":" + str(dc.dir_port)
                raw = yield getPage(str(host+MICRO_CONSENSUS_PATH))
                # TODO: validate signatures
                consensus = _processRawMicroconsensus(raw)
                defer.returnValue(consensus)
            except Exception as e:
                msg = "Error downloading consensus: {}. Retrying.".format(e)
                logging.debug(msg)

        raise ConsensusDownloadFailed("Failed to download fresh consensus.")

    def _scheduleNextConsensusDownload(self):
        from twisted.internet import reactor

        va = time.mktime(self._consensus.valid_after.utctimetuple())
        fu = time.mktime(self._consensus.fresh_until.utctimetuple())
        vu = time.mktime(self._consensus.valid_until.utctimetuple())
        i1 = (fu - va) * (3.0/4.0)
        i2 = (vu - (fu +i1)) * (7.0/8.0)

        seconds = random.randrange(int(i1), int(i2))

        reactor.callLater(seconds, self._scheduledConsensusUpdate)


def getV2DirsFromConsensus(consensus):
    return [r for r in consensus.routers.values() if Flag.V2DIR in r.flags]


def _readV2DirsFromCacheFile():
    try:
        with open(MICRO_CONSENSUS_CACHE_FILE, 'rb') as f:
            data = f.read()
        consensus = NetworkStatusDocumentV3(data)
        return getV2DirsFromConsensus(consensus)
    except Exception as e:
        msg = ("Failed to read cached-consensus-microdesc. Reason: {}."
               .format(e))
        logging.debug(msg)
        return None


def _writeConsensusCacheFile(consensus):
    try:
        with open(MICRO_CONSENSUS_CACHE_FILE, 'wb') as f:
            f.write(str(consensus))
    except Exception as e:
        msg = ("Failed to write cached-consensus-microdesc. Reason: {}."
               .format(e))
        logging.debug(msg)


def _processRawMicroconsensus(raw):
    raw = zlib.decompress(raw)
    consensus = NetworkStatusDocumentV3(raw)
    _writeConsensusCacheFile(consensus)
    return consensus
