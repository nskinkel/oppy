# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

import logging

from twisted.internet import defer

import oppy.crypto.util as crypto

from oppy.cell.definitions import MAX_RPAYLOAD_LEN, REASON_DONE
from oppy.cell.fixedlen import DestroyCell, EncryptedCell
from oppy.cell.relay import (
    RelayBeginCell,
    RelayDataCell,
    RelayEndCell,
    RelaySendMeCell,
)

from oppy.circuit.cellprocessor import CellProcessor
# TODO: put this shit back in circuit.py?
from oppy.circuit.definitions import (
    CIRCUIT_WINDOW_THRESHOLD_INIT,
    SENDME_THRESHOLD,
    WINDOW_SIZE,
    CState,
    CUsage,
    BACKWARD_CELL_TYPES,
    BACKWARD_RELAY_CELL_TYPES,
    MAX_STREAMS_V3,
)
from oppy.util.flowcontrolmanager import CircuitFlowControlManager
from oppy.util.tools import ctr


# how many seconds until marking this circuit closed
ROTATE_TIME = 600


class MaximumStreamLoad(Exception):
    pass


# TODO: add 'dirty since', 'built at', etc.
class CircuitState(object):

    slots = ('type', 'state', 'usage')

    def __init__(self, type):
        self.type = type
        self.state = CState.OPEN
        self.usage = CUsage.CLEAN


# TODO: stream isolation logic goes here?
class StreamHandler(object):
    
    slots = ()

    def __init__(self, max):
        self.max = max
        self.streams = {}
        self._ctr = ctr(max)
        self.count = 0

    def canAdd(self):
        return self.count < self.max

    def add(self, stream):
        self.streams[stream.id] = stream
        self.count += 1

    def remove(self, stream):
        del self.streams[stream.id]
        self.count -= 1

    def getNextID(self):
        if self.count == self.max:
            raise MaximumStreamLoad()

        for _ in xrange(self.max):
            id = next(self._ctr)
            if id not in self.streams:
                return id

    def closeAllStreams(self):
        for stream in self.streams.values():
            stream.closeFromCircuit()
        self.streams = {}


# Major TODO's:
#               - figure out policy for handling cells with unexpected origins
#               - catch/handle crypto exceptions explicitly
#               - catch/handle connection.send exceptions explicitly
#               - fix documentation
class Circuit(object):

    # TODO: do we really need write/read task anymore?
    # TODO: make a streamhandler?
    def __init__(self, circuit_manager, id, conn, circuit_type,
                 path, crypt_path, max_streams=MAX_STREAMS_V3):
        self._circuit_manager = circuit_manager
        self.id = id
        self._connection = conn
        self._path = path
        self._crypt_path = crypt_path
        self._read_queue = defer.DeferredQueue()
        self._write_queue = defer.DeferredQueue()
        # TODO: remove constant
        self.streamhandler = StreamHandler(30000)
        self._rotate_task = None
        self._cellprocessor = CellProcessor(self)
        self.state = CircuitState(circuit_type)
        self.flowcontrol = CircuitFlowControlManager(self)

        self._pollReadQueue()
        self._pollWriteQueue()

    def _setRotateTask(self):
        from twisted.internet import reactor
        self._rotate_task = reactor.callLater(ROTATE_TIME, self._markClosed)
        logging.debug("Circuit {} set to be rotated in {} seconds."
                      .format(self.id, ROTATE_TIME))

    def _markClosed(self):
        self.state.state = CState.CLOSED
        logging.debug("Marked circuit {} as CLOSED.".format(self.id))
        # teardown if we have no open streams, otherwise circuit will be
        # torn down when the last currently open stream closes
        if self.streamhandler.count == 0:
            self._sendDestroyCell()
            self._closeCircuit()

    def canHandleRequest(self, request):
        if self.state.state != CState.OPEN:
            return False

        if not self.streamhandler.canAdd():
            return False

        return self._path.exit.microdescriptor.exit_policy.can_exit_to(
            port=request.port)

    def send(self, data, stream):
        if len(data) > MAX_RPAYLOAD_LEN:
            msg = ("Data cannot be longer than {}. len(data) == {}."
                   .format(MAX_RPAYLOAD_LEN, len(data)))
            raise ValueError(msg)
        self._write_queue.put((data, stream.id))

    def recv(self, cell):
        self._read_queue.put(cell)

    def removeStream(self, stream):
        try:
            self.streamhandler.remove(stream)
            cell = RelayEndCell.make(self.id, stream.id)
            self._encryptAndSendCell(cell)
        except KeyError:
            msg = ("Circuit {} notified that stream {} was closed, but "
                   "the circuit has no reference to this stream."
                   .format(self.id, stream.id))
            logging.debug(msg)

        if self.state.state == CState.CLOSED and self.streamhandler.count == 0:
            self._sendDestroyCell()
            self._closeCircuit()

    def beginStream(self, stream):
        msg = ("Circuit {} sending a RelayBeginCell for stream {}."
               .format(self.id, stream.id))
        logging.debug(msg)
        cell = RelayBeginCell.make(self.id, stream.id,
                                   stream.request)
        self._encryptAndSendCell(cell)

    def addStreamAndSetStreamID(self, stream):
        id = self.streamhandler.getNextID()
        stream.id = id
        self.streamhandler.add(stream)
        logging.debug("Circuit {} added stream {}.".format(self.id, stream.id))
        if self.state.usage == CUsage.CLEAN:
            logging.debug("Circuit {} marked as DIRTY.".format(self.id))
            self.state.usage = CUsage.DIRTY
            self._setRotateTask()

    def sendStreamSendMe(self, stream):
        cell = RelaySendMeCell.make(self.id,
                                    stream_id=stream.id)
        self._encryptAndSendCell(cell)
        logging.debug("Circuit {} sent a RelaySendMeCell for stream {}."
                      .format(self.id, stream.id))

    def destroyCircuitFromManager(self):
        self._sendDestroyCell()
        self._closeAllStreams()
        self._connection.removeCircuit(self)
        self.state.state = CState.CLOSED
        logging.debug("Circuit {} destroyed by manager.".format(self.id))
        self._cancelRotateTask()

    def destroyCircuitFromConnection(self):
        logging.debug("Circuit {} destroyed by its connection.".format(self.id))
        self._closeCircuit()

    @defer.inlineCallbacks
    def _pollReadQueue(self):
        cell = yield self._read_queue.get()
        self._recvCell(cell)

    @defer.inlineCallbacks
    def _pollWriteQueue(self):
        data = yield self._write_queue.get()
        self._writeData(data)

    def _writeData(self, data_stream_id_tuple):
        data, stream_id = data_stream_id_tuple
        cell = RelayDataCell.make(self.id, stream_id, data)
        self._encryptAndSendCell(cell)
        self.flowcontrol.dataSent()
        # we may enter a BUFFERING state if our flow control
        # window has dropeed too low
        if self._canWrite():
            self._pollWriteQueue()

    def _recvCell(self, cell):
        if isinstance(cell, EncryptedCell):
            # TODO: should we tear down circuit if decryption fails?
            #       probably
            try:
                cell, origin = crypto.decryptCell(cell, self._crypt_path)
            except Exception as e:
                msg = ("Circuit {} failed to decrypt an incoming cell. Reason: {}"
                       ". Dropping cell.".format(self.id, e))
                logging.debug(msg)
                return

        self._cellprocessor.processCell(cell)
        self._pollReadQueue()

    def sendCircuitSendMe(self):
        cell = RelaySendMeCell.make(self.id)
        self._encryptAndSendCell(cell)
        logging.debug("Circuit {} sent a circuit-level RelaySendMeCell."
                      .format(self.id))

    def _canWrite(self):
        return self.state.state != CState.BUFFERING

    def setStateOpen(self):
        assert self.state.state == CState.BUFFERING
        logging.debug("Circuit {} transitioned from BUFFERING to OPEN.")
        self.state.state = CState.OPEN
        self._pollWriteQueue()

    def setStateBuffering(self):
        assert self.state.state == CState.OPEN
        logging.debug("Circuit {} transitioned from OPEN to BUFFERING.")
        self.state.state = CState.BUFFERING

    def _sendDestroyCell(self):
        cell = DestroyCell.make(self.id)
        self._connection.send(cell)

    def _closeAllStreams(self):
        self.streamhandler.closeAllStreams()

    def _encryptAndSendCell(self, cell):
        try:
            enc = crypto.encryptCell(cell, self._crypt_path)
        except Exception as e:
            logging.warning("Error: {}. Failed to encrypt a {} cell on circuit"
                            " {}. Tearing down the circuit."
                            .format(e, type(cell), self.id))
            self._sendDestroyCell()
            self._closeCircuit()
            return

        try:
            self._connection.send(enc)
        except Exception as e:
            logging.warning("Error: {}. Failed to send a cell on circuit {}."
                            " The circuit will be torn down."
                            .format(e, self.id))
            self.destroyCircuitFromConnection()

    def _closeCircuit(self):
        self._closeAllStreams()
        self._circuit_manager.circuitDestroyed(self)
        self._connection.removeCircuit(self)
        self.state.state = CState.CLOSED
        logging.debug("Circuit {} destroyed.".format(self.id))
        self._cancelRotateTask()

    def _cancelRotateTask(self):
        if self._rotate_task and not self._rotate_task.called:
            self._rotate_task.cancel()
            logging.debug("Circuit {} rotation canceled.".format(self.id))
