# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

'''
.. topic:: Details

    NetStatus handles downloading network status documents and serving requests
    for server descriptors (needed for building paths and circuits). When
    instantiated, NetStatus immediately tries to download the most
    recent copies of the network consensus and the set of current server
    descriptors. NetStatus also takes care of automatically updating local
    copies of network status documents.

    NetStatus:

        - Uses V2Dir directory caches when possible, only falling back to
          directory authorities if we don't know about any caches.
        - Tries to use a cached copy of the consensus from the filesystem
          to initially figure out the V2Dir caches.
        - Writes a copy of the consensus to the filesystem for later use.
        - Uses stem to represent the consensus, consensus entries, and
          server descriptors.
        - Does the actual document parsing in separate worker threads.
        - Schedules the next document download
        - Handles incoming requests for server descriptors by returning
          a deferred that fires when NetStatus has a good set of server
          descriptors

'''
import io
import logging
import random
import zlib

from twisted.internet import defer, threads
from twisted.web.client import getPage

from stem import Flag
from stem.descriptor import parse_file
from stem.descriptor import DocumentHandler
from stem.descriptor.networkstatus import NetworkStatusDocumentV3
from stem.descriptor.remote import get_authorities

from oppy.netstatus import definitions as DEF


# how long we'll wait before downloading fresh network status documents
# NOTE: this is wrong according to tor-spec. We should actually be checking
#       the times on the consensus and choosing a random time within some
#       window.
DEFAULT_DOWNLOAD_INTERVAL = 3600


class NetStatus(object):
    '''Download consensus and server descriptor documents.'''

    def __init__(self):
        '''Immediately start downloading network status documents.

        Upon instantiation, NetStatus will immediately begin trying to
        download new network status documents. Incoming requests for
        descriptors (usually caused by requests to get a Path) will be
        added to a callback chain and called back when we have a good set of
        router descriptors.
        '''
        logging.debug("Starting NetStatus.")
        # self._initial tracks whether we're on the "initial" download of the
        # network docs. if so, the path request callback is fired when we
        # have descriptors available.
        self._initial = True
        # chain of requests for descriptors that will get called back when we
        # get the first set of network docs. after that, this is no longer used
        self._descriptor_request_stack = defer.Deferred()
        # endpoints is a list of V2Dir directory caches we can choose from to
        # try getting network docs. upon instantiation, we check if there is
        # a "cached-consensus" file to pull them from, otherwise endpoints is
        # initialized to the set of directory authorities
        self._endpoints = self._getInitialEndpoints()
        self._consensus = None
        self._descriptors = None
        self._getDocuments()

    def getDescriptors(self):
        '''Return a deferred which will callback with a dict mapping
        fingerprint->RelayDescriptor when we get a set of good descriptors.

        Called back immediately if we already have server descriptors.

        :returns: **twisted.internet.defer.Deferred** that fires with a dict
            that maps fingerprints->RelayDescriptors
        '''
        d = defer.Deferred()
        # if we have descriptors, immediately callback
        if self._descriptors is not None:
            d.callback(self._descriptors)
        # if we don't have descriptors yet, add this request to the
        # descriptor request chain and callback when we get docs downloaded
        else:
            def serveDescriptor(result):
                d.callback(result)
                return result
            self._descriptor_request_stack.addCallback(serveDescriptor)

        return d

    @defer.inlineCallbacks
    def _getDocuments(self):
        '''Download and parse network status documents.

        Asynchronously download and parse a fresh consensus and set of server
        descriptors. The parsing is done using stem in a separate thread.

        If this is the first time we've attempted to download documents,
        callback the descriptor request chain to start satisfying pending
        requests for server descriptors as soon as we have a good set of
        descriptors.
        '''
        logging.debug("Starting document downloader.")
        self._consensus = yield self._downloadConsensus()
        logging.info("Got fresh consensus.")
        self._descriptors = yield self._downloadDescriptors()
        logging.info("Got fresh server descriptors.")
        # if this is the first set of documents we've downloaded, start the
        # descriptor_request_stack callback chain to satisfy requests for
        if self._initial is True:
            self._descriptor_request_stack.callback(self._descriptors)
            self._initial = False
        # schedule the next download time
        self._scheduleDownload()

    @defer.inlineCallbacks
    def _downloadConsensus(self):
        '''Download, parse, and cache the current consensus.

        Try random V2Dir directory caches if we know about any already,
        falling back to directory authorities if have to. Actual consensus
        parsing is done in a separate thread.

        .. note: If this download fails for any reason (timeout, 503, zlib
            error, etc.), it will be immediately retried with another random
            V2Dir choice.

        :returns: **twisted.internet.defer.Deferred** that fires with a
            NetworkStatusDocumentV3.
        '''
        try:
            logging.debug("Starting consensus download.")
            d = random.choice(self._endpoints)
            addr = "http://" + str(d.address) + ":" + str(d.dir_port)
            logging.debug("Starting consensus download from {}".format(addr))
            raw = yield getPage(str(addr + DEF.CONSENSUS_URL))
            consensus = yield threads.deferToThread(self._processConsensus,
                                                    raw)
            defer.returnValue(consensus)
        except Exception as e:
            logging.debug("Error downloading consensus: {}.".format(e))
            logging.debug("Retrying consensus download.")
            # immediately retry the download on error
            ret = yield self._downloadConsensus()
            defer.returnValue(ret)

    @defer.inlineCallbacks
    def _downloadDescriptors(self):
        '''Download and parse the full set of server descriptors.

        Choose a random V2Dir cache to attempt a download from. Parse using
        stem in a separate thread.

        .. note:: We currently just download *all* server descriptors at
            once. This is probably not the best way to get descriptors,
            and these requests should be split up over multiple V2Dir
            caches.

        :returns: **twisted.internet.defer.Deferred** that fires with a dict
            mapping fingerprints->RelayDescriptors.
        '''
        try:
            d = random.choice(self._endpoints)
            addr = "http://" + str(d.address) + ":" + str(d.dir_port)
            logging.debug("Downloading descriptors from {}".format(addr))
            raw = yield getPage(str(addr + DEF.DESCRIPTORS_URL))
            descriptors = yield threads.deferToThread(self._processDescriptors,
                                                      raw)
            defer.returnValue(descriptors)
        except Exception as e:
            logging.debug("Error downloading descriptors: {}.".format(e))
            logging.debug("Retrying descriptors download.")
            # immediately retry on failure
            ret = yield self._downloadDescriptors()
            defer.returnValue(ret)

    def _processConsensus(self, raw):
        '''Decompress consensus, parse, write to "cached-consensus" and
        choose a new set of endpoints to use for the next download.

        .. note: This is run in a separate worker thread using
            twisted.internet.threads.deferToThread() because consensus
            parsing can take a while.

        :param str raw: compressed consensus bytes
        :returns: stem.descriptors.networkstatus.NetworkStatusDocumentV3
        '''
        raw = zlib.decompress(raw)
        consensus = NetworkStatusDocumentV3(raw)
        self._cacheConsensus(consensus)
        logging.debug("Wrote cached-consensus.")
        self._endpoints = self._extractV2DirEndpoints(consensus)
        logging.debug("Found {} V2Dir endpoints.".format(len(self._endpoints)))
        return consensus

    def _processDescriptors(self, raw):
        '''Decompress and parse descriptors, then build a dict mapping
        fingerprint -> RelayDescriptor for all relays found in both the
        network consensus and the server descriptor set.

        We throw away and relays that are not found in the network consensus.

        We also add a new attribute 'flags' to each RelayDescriptor. 'flags'
        is an attribue of RouterStatusEntry's found in the consensus, and
        adding them here simplifies path selection. 'flags' is a set of
        unicode strings.

        .. note: This runs in a separate work thread using
            twisted.internet.threads.deferToThread() because parsing tends to
            take a while.

        :param str raw: compressed server descriptor bytes
        :returns: **dict** mapping fingerprint -> RelayDescriptor for every
            relay found in both the current network consensus and the set
            of server descriptors.
        '''
        raw = zlib.decompress(raw)
        gen = parse_file(
            io.BytesIO(raw),
            DEF.STEM_DESCRIPTORS_TYPE,
            validate=False,
            document_handler=DocumentHandler.DOCUMENT,
        )
        descriptors = {}
        # only use descriptors that are also found in the consensus, and
        # also add the 'flags' attribute, a set of unicode strings describing
        # the flags a given RelayDescriptor has
        for relay in gen:
            try:
                flags = set(self._consensus.routers[relay.fingerprint].flags)
                relay.flags = flags
                descriptors[relay.fingerprint] = relay
            # skip any relays not found in the consensus
            except KeyError:
                pass

        return descriptors

    def _cacheConsensus(self, consensus):
        '''Dump a copy of the consensus to the "cached-consensus" file.

        :param stem.descriptor.networkstatus.NetworkStatusDocumentV3 consensus:
            fresh consensus to cache on filesystem
        '''
        try:
            with open(DEF.CONSENSUS_CACHE_FILE, 'w') as f:
                f.write(str(consensus))
        except Exception as e:
            logging.debug("Failed to write 'cached-consensus': {}.".format(e))

    def _extractV2DirEndpoints(self, consensus):
        '''Find a new set of V2Dir directory caches to use from the current
        consensus.

        :param stem.descriptors.networkstatus.NetworkStatusDocumentV3 consensus:
            fresh consensus to grab V2Dir caches from
        :return: **list, stem.descriptor.router_status_entry.RouterStatusEntry**
            RouterStatusEntry's that have the 'V2Dir' flag
        '''
        endpoints = set()
        for relay in consensus.routers.values():
            if Flag.V2DIR in relay.flags:
                endpoints.add(relay)

        return list(endpoints)

    def _getInitialEndpoints(self):
        '''Get an initial set of servers to download the network status
        documents from.

        First try reading from the "cached-consensus" file. If this isn't
        successful for any reason fallback to using the directory
        authorities.

        This is only called on instantiation, and any future downloads will
        already have a fresh set of V2Dir endpoints.

        .. note: We just use the directory authorities defined in stem.

        :returns: **list** containing either RouterStatusEntry objects with
            the 'V2Dir' flag or DirectoryAuthorities
        '''
        endpoints = None
        try:
            with open(DEF.CONSENSUS_CACHE_FILE, 'rb') as f:
                data = f.read()
            old_consensus = NetworkStatusDocumentV3(data)
            endpoints = self._extractV2DirEndpoints(old_consensus)
            msg = "Found {} V2Dir endpoints in cached-consensus."
            logging.debug(msg.format(len(endpoints)))
        except (IOError, ValueError) as e:
            logging.debug("Error reading from cached-consensus: {}".format(e))
            logging.debug("Falling back to directory authorities.")

        return list(endpoints) if endpoints else get_authorities().values()

    def _scheduleDownload(self):
        '''Schedule the next network status document download.

        .. note: This is incorrect. We should actually be calculating the
            correct time according to the parameters defined in Tor's
            **dir-spec**, but for now we just schedule a download an hour in
            the future of the previous download.
        '''
        from twisted.internet import reactor
        # XXX this is a bug, we should be choosing according to parameters
        #     in the tor `dir-spec`
        seconds = DEFAULT_DOWNLOAD_INTERVAL
        reactor.callLater(seconds, self._getDocuments)
        msg = "Scheduled next consensus download in {} seconds."
        logging.debug(msg.format(seconds))
