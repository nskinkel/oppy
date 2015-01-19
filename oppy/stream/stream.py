# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

'''
.. topic:: Details

    Streams are the interface between local requests coming from
    OppySOCKSProtocol instances and circuits. Streams are responsible for:

        - Initiating a connection request (i.e. a RelayBeginCell) on behalf
          of a local application
        - Passing data from circuits to local applications and vice versa
        - Informing OppySOCKSProtocol instances (and thus, the client
          application) when a remote resource closes the stream
        - Informing the circuit when the local application closes the stream
        - Splitting up data to be written to the network into chunks that
          can fit into a RelayData cell
        - Doing some rudimentary flow-control

'''
import logging

from twisted.internet import defer

from oppy.cell.definitions import MAX_RPAYLOAD_LEN
from oppy.shared import circuit_manager


SENDME_THRESHOLD = 450
STREAM_WINDOW_INIT = 500
STREAM_WINDOW_SIZE = 50


class Stream(object):
    '''Represent a Tor Stream.'''

    def __init__(self, request, socks):
        '''
        :param oppy.util.exitrequest.ExitRequest request: connection request
            for this stream
        :param oppy.socks.socks.OppySOCKSProtocol socks: socks protocol
            instance this stream should relay data to and from
        '''
        self.stream_id = None
        self._read_queue = defer.DeferredQueue()
        self._write_queue = defer.DeferredQueue()
        self._read_deferred = None
        self._write_deferred = None
        self.request = request
        self.socks = socks
        self._deliver_window = STREAM_WINDOW_INIT
        self._package_window = STREAM_WINDOW_INIT
        self.circuit = None
        self._circuit_request = circuit_manager.requestOpenCircuit(self)
        self._circuit_request.addCallback(self._registerNewStream)

    def _registerNewStream(self, circuit):
        '''Register this stream with it's circuit, initiate a conenction
        request, and begin listening for data from the network.

        Called when this stream receives a suitable open circuit.

        :param oppy.circuit.circuit.Circuit circuit: open circuit suitable
            for use on this stream
        '''
        self.circuit = circuit
        self._circuit_request = None
        # notify circuit it has a new stream
        # NOTE: circuit sets this stream's stream_id
        self.circuit.registerStream(self)
        # tell the circuit to setup this stream (i.e. send a RELAY_BEGIN cell)
        self.circuit.initiateStream(self)
        # start listening for incoming cells from our circuit
        self._pollReadQueue()

    @staticmethod
    def _chunkRelayData(data):
        '''Split *data* into chunks that can fit inside a RelayData cell.

        :param str data: data to split
        :returns **list, str** list of pieces of data split into sizes that
            fit into a RelayData cell
        '''
        LEN = MAX_RPAYLOAD_LEN
        return [data[i:i + LEN] for i in xrange(0, len(data), LEN)]

    def recvData(self, data):
        '''Put data received from the network on this stream's read queue.

        Called when the circuit attached to this stream passes data to this
        stream.

        :param str data: data passed in from circuit to write to this stream's
            attached SOCKS protocol
        '''
        self._read_queue.put(data)

    def writeData(self, data):
        '''Split *data* into chunks that can fit in a RelayData cell, and put
        each chunk on this stream's write queue.

        Called when the local application attached to this stream sends data
        to the network.

        :param str data: data passed in from this stream's attached SOCKS
            protocol to write to this stream's circuit
        '''
        chunks = Stream._chunkRelayData(data)
        for chunk in chunks:
            self._write_queue.put(chunk)

    def _pollWriteQueue(self):
        '''Pull a chunk of data from this stream's write queue and, when the
        data is ready, write it to the attached circuit.
        '''
        self._write_deferred = self._write_queue.get()
        self._write_deferred.addCallback(self._writeData)

    def _pollReadQueue(self):
        '''Pull a chunk of data from this stream's read queue and, when the
        data is ready, write it to the attached SOCKS protocol instance.
        '''
        self._read_deferred = self._read_queue.get()
        self._read_deferred.addCallback(self._recvData)

    def _writeData(self, data):
        '''Write *data* to the circuit attached to this stream and decrement
        the packaging window.

        :param str data: data received from attached SOCKS protocol instance
            to be written to the attached circuit
        '''
        self.circuit.writeData(data, self.stream_id)
        self._decPackageWindow()

    def _recvData(self, data):
        '''Receive *data* from the attached circuit and hand off to the
        attached SOCKS protocol instance. Decrement this stream's deliver
        window.

        :param str data: data received from attached circuit, to be written
            to the attached SOCKS protocol instance
        '''
        self.socks.writeData(data)
        self._decDeliverWindow()

    def _decDeliverWindow(self):
        '''Decrement this stream's deliver window and initiate sending a
        sendme cell if the deliver window drops too low.

        If the deliver window is <= SENDME_THRESHOLD, tell the attached
        circuit to send a sendme cell on behalf of this stream.
        '''
        # XXX we should be checking how many cells we have left to flush
        #     here before just blindly writing a RELAY_SENDME
        self._deliver_window -= 1
        if self._deliver_window <= SENDME_THRESHOLD:
            self.circuit.sendStreamSendMe(self.stream_id)
            self._deliver_window += STREAM_WINDOW_SIZE
        self._pollReadQueue()

    def _decPackageWindow(self):
        '''Decrement this stream's package window and, if we still can,
        listen for more data from the attached SOCKS protocol instance.

        If the package window <= 0, we need to wait until we receive a
        sendme cell before writing anymore local data from this stream to
        the attached circuit.
        '''
        self._package_window -= 1
        if self._package_window > 0:
            self._pollWriteQueue()
        else:
            self._write_deferred = None

    def incrementPackageWindow(self):
        '''Increment this stream's package window and, if the package window
        is now above zero and this stream was in a buffering state, begin
        listening for local data again.

        Called by the attached circuit when it receives a sendme cell
        for this stream.
        '''
        self._package_window += STREAM_WINDOW_SIZE
        # if we were buffering, we're now free to send data again
        if self._write_deferred is None and self._package_window > 0:
            self._pollWriteQueue()

    def streamConnected(self):
        '''Begin listening for local data from the attached SOCKS protocol
        to write to this stream's circuit.

        Called when the attached circuit receives a RelayConnected cell for
        this stream's RelayBegin request.
        '''
        self._pollWriteQueue()

    def closeFromCircuit(self):
        '''Called when this stream is closed by the circuit.

        This can be caused by receiving a RelayEnd cell, the circuit being
        torn down, or the connection going down. We do not need to send a
        RelayEnd cell ourselves if the circuit closed this stream.

        Notify any associated SOCKS protocols and let circuit know this stream
        has closed.
        '''
        msg = "Stream {} closing from circuit {}"
        msg = msg.format(self.stream_id, self.circuit.circuit_id)
        logging.debug(msg)
        self.socks.closeFromStream()

    def closeFromSOCKS(self):
        '''Called when the attached SOCKS protocol object is done with this
        stream.

        Request that circuit send a RelayEnd cell on our behalf and notify
        circuit we're now closed.
        '''
        msg = "Stream {} on circuit {} closing from SOCKS."
        msg = msg.format(self.stream_id, self.circuit.circuit_id)
        logging.debug(msg)
        self.circuit.unregisterStream(self)
