# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

import logging

from twisted.internet import defer

from oppy.cell.definitions import MAX_RPAYLOAD_LEN
from oppy.circuit.circuit import MaximumStreamLoad


SENDME_THRESHOLD = 450
STREAM_WINDOW_INIT = 500
STREAM_WINDOW_SIZE = 50


class Stream(object):
    '''Represent a Tor Stream.'''

    def __init__(self, circuit_manager, request, socks):
        self.id = None
        self._read_queue = defer.DeferredQueue()
        self._write_queue = defer.DeferredQueue()
        self._read_deferred = None
        self._write_deferred = None
        self.request = request
        self.socks = socks
        self._deliver_window = STREAM_WINDOW_INIT
        self._package_window = STREAM_WINDOW_INIT
        self.circuit = None
        # set this flag if SOCKS closes our connection before the circuit
        # is done building
        self._closed = False
        self._circuit_request = circuit_manager.getOpenCircuit(self)
        self._circuit_request.addCallback(self._registerNewStream)

    def recv(self, data):
        self._read_queue.put(data)

    def send(self, data):
        chunks = _chunkRelayData(data)
        for chunk in chunks:
            self._write_queue.put(chunk)

    def incrementPackageWindow(self):
        self._package_window += STREAM_WINDOW_SIZE
        # if we were buffering, we're now free to send data again
        if self._write_deferred is None and self._package_window > 0:
            self._pollWriteQueue()

    def streamConnected(self):
        self._pollWriteQueue()

    def closeFromCircuit(self):
        logging.debug("Stream {} closing from circuit {}."
                      .format(self.id,
                              self.circuit.id if self.circuit else None))
        self._closed = True
        self.socks.closeFromStream()

    # TODO: fix docs
    def closeFromSOCKS(self):
        if self.circuit is not None:
            logging.debug("Stream {} closing on circuit {} from SOCKS."
                          .format(self.id, self.circuit.id))
            self.circuit.removeStream(self)
        else:
            logging.debug("Stream closed before circuit build task completes.")

        self._closed = True

    def _registerNewStream(self, circuit):
        # don't do anything if socks closed the connection before the
        # circuit was done building
        if self._closed is True:
            return

        try:
            circuit.addStreamAndSetStreamID(self)
        except MaximumStreamLoad:
            self._circuit_request = circuit_manager.getOpenCircuit(self)
            self._circuit_request.addCallback(self._registerNewStream)
            return

        self.circuit = circuit
        self._circuit_request = None
        self.circuit.beginStream(self)
        self._pollReadQueue()

    def _pollWriteQueue(self):
        self._write_deferred = self._write_queue.get()
        self._write_deferred.addCallback(self._writeData)

    def _pollReadQueue(self):
        self._read_deferred = self._read_queue.get()
        self._read_deferred.addCallback(self._recvData)

    def _writeData(self, data):
        self.circuit.send(data, self)
        self._decPackageWindow()

    def _recvData(self, data):
        self.socks.recv(data)
        self._decDeliverWindow()

    def _decDeliverWindow(self):
        # XXX we should be checking how many cells we have left to flush
        #     here before just blindly writing a RELAY_SENDME
        #     i.e. check len(_read_queue.pending)
        self._deliver_window -= 1
        if self._deliver_window <= SENDME_THRESHOLD:
            self.circuit.sendStreamSendMe(self)
            self._deliver_window += STREAM_WINDOW_SIZE
        self._pollReadQueue()

    def _decPackageWindow(self):
        self._package_window -= 1
        if self._package_window > 0:
            self._pollWriteQueue()
        else:
            self._write_deferred = None


def _chunkRelayData(data):
    LEN = MAX_RPAYLOAD_LEN
    return [data[i:i + LEN] for i in xrange(0, len(data), LEN)]
