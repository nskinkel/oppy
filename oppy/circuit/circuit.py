# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

'''
.. topic:: Details

    Circuits are channels through the Tor network through which data is
    written and received.

    Circuits have a few jobs:

        - Get a valid path of relays through the Tor network (circuits
          received some path_constraints, but it's up to each circuit
          to build it's own path)
        - Build the path by extending the circuit one hop at a time
        - Derive shared key material for each node on the path
        - Encrypt outgoing cells and decrypt incoming cells
        - Process incoming control cells to manage circuit state
        - Initiate new stream connections
        - Process incoming data cells and pass data to associated streams
        - Do some flow-control management
        - Handle different ways of circuit tear-down depending on the
          current state and why a circuit is being torn down

'''
import logging

from twisted.internet import defer

import oppy.crypto.util as crypto

from oppy.cell.definitions import MAX_RPAYLOAD_LEN, REASON_DONE
from oppy.cell.fixedlen import DestroyCell
from oppy.cell.relay import (
    RelayBeginCell,
    RelayConnectedCell,
    RelayDataCell,
    RelayDropCell,
    RelayEndCell,
    RelayResolvedCell,
    RelaySendMeCell,
    RelayTruncatedCell,
)

# TODO: put common stuff in definitions
from oppy.circuit.definitions import (
    CIRCUIT_WINDOW_THRESHOLD_INIT,
    SENDME_THRESHOLD,
    WINDOW_SIZE,
    CState,
    CircuitType,
    BACKWARD_CELL_TYPES,
    BACKWARD_RELAY_CELL_TYPES,
    MAX_STREAMS_V3,
)
from oppy.util.tools import ctr, enum


# Major TODO's:
#               - figure out policy for handling cells with unexpected origins
#               - catch/handle crypto exceptions explicitly
#               - catch/handle connection.send exceptions explicitly
#               - fix documentation
class Circuit(object):

    def __init__(self, circuit_manager, circuit_id, conn, circuit_type,
                 path, crypt_path, max_streams=MAX_STREAMS_V3):
        '''
        :param int cid: id of this circuit
        :param oppy.path.path.PathConstraints path_constraints: the constraints
            that this circuit's path should satisfy
        '''
        self._circuit_manager = circuit_manager
        self.circuit_id = circuit_id
        self._connection = conn
        self.circuit_type = circuit_type
        self._path = path
        self._crypt_path = crypt_path
        # _read_queue handles incoming cells from the network
        self._read_queue = defer.DeferredQueue()
        self._read_task = None
        # _write_queue handles incoming data from local applications
        self._write_queue = defer.DeferredQueue()
        self._write_task = None
        self._streams = {}
        self._ctr = ctr(max_streams)
        self._max_streams = max_streams
        self._state = CState.OPEN
        # deliver window is incoming data cells
        self._deliver_window = CIRCUIT_WINDOW_THRESHOLD_INIT
        # package window is outgoing data cells
        self._package_window  = CIRCUIT_WINDOW_THRESHOLD_INIT

        self._pollReadQueue()
        self._pollWriteQueue()

    def canHandleRequest(self, request):
        '''Return **True** if this circuit can (probably/possibly) handle
        the *request*.

        If this circuit is pending we may not have a relay exit relay whose
        exit policy we can check, so make a guess and return True if the
        request is of the same type as this circuit. Always return True if
        this request is a host type request (this is probably wrong). If the
        circuit is open and we do have an exit policy to check, then return
        whether or not this circuit's exit relay's exit policy claims to
        support this request.

        :param oppy.util.exitrequest.ExitRequest request: the request to
            check if this circuit can handle
        :returns: **bool** **True** if this circuit thinks it can handle
            the request, False otherwise
        '''
        if self._state == CState.BUFFERING:
            return False

        if len(self._streams) == self._max_streams:
            return False

        if request.is_host:
            return self._path.exit.exit_policy.can_exit_to(port=request.port,
                                                           strict=False)
        else:
            return self._path.exit.exit_policy.can_exit_to(
                                       address=request.addr, port=request.port)


    def send(self, data, stream):
        '''Put a tuple of (data, stream_id) on this circuit's write_queue.
        
        Called by stream's when they want to write data to this circuit.

        .. warning:: writeData() requires that *data* can fit in a single
            relay cell. The caller should take care to split data into
            properly sized chunks.

        :param str data: data string to write to this circuit
        :param int stream_id: id of the stream writing this data
        '''
        if len(data) > MAX_RPAYLOAD_LEN:
            msg = ("Data cannot be longer than {}. len(data) == {}."
                   .format(MAX_RPAYLOAD_LEN, len(data)))
            raise ValueError(msg)
        self._write_queue.put((data, stream.stream_id))

    def recv(self, cell):
        '''Put the incoming cell on this circuit's read_queue to be processed.
        
        Called be a connection when it receives a cell addressed to this
        circuit.
        
        :param cell cell: incoming cell that was received from the network
        '''
        self._read_queue.put(cell)

    def removeStream(self, stream):
        '''Unregister *stream* from this circuit.

        Remove the stream from this circuit's stream map and send a
        RelayEndCell. If the number of streams on this circuit drops to
        zero, check with the circuit manager to see if this circuit should
        be destroyed. If so, tear down the circuit.

        :param oppy.stream.stream.Stream stream: stream to unregister
        '''
        try:
            del self._streams[stream.stream_id]
            cell = RelayEndCell.make(self.circuit_id, stream.stream_id)
            self._encryptAndSendCell(cell)
        except KeyError:
            msg = ("Circuit {} notified that stream {} was closed, but "
                   "the circuit has no reference to this stream."
                   .format(self.circuit_id, stream.stream_id))
            logging.debug(msg)
            return

        if len(self._streams) == 0:
            if self._circuit_manager.shouldDestroyCircuit(self) is True:
                self._sendDestroyCell()
                self._closeCircuit()
                msg = "Destroyed unused circuit {}.".format(self.circuit_id)
                logging.debug(msg)

    def beginStream(self, stream):
        '''Initiate a new stream by sending a RelayBeginCell.

        Create the begin cell, encrypt it, and immediately write it to this
        circuit's connection.

        :param oppy.stream.stream.Stream stream: stream on behalf of which
            we're sending a RelayBeginCell
        '''
        msg = ("Circuit {} sending a RelayBeginCell for stream {}."
               .format(self.circuit_id, stream.stream_id))
        logging.debug(msg)

        cell = RelayBeginCell.make(self.circuit_id, stream.stream_id,
                                   stream.request)
        self._encryptAndSendCell(cell)

    def addStreamAndSetStreamID(self, stream):
        '''Register the new *stream* on this circuit.

        Set the stream's stream_id and add it to this circuit's stream map.

        :param oppy.stream.stream.Stream stream: stream to add to this circuit
        '''
        # find the next available stream ID and assign it to the requesting
        # stream. fail if we can't assign an ID (should never happen).
        if len(self._streams) == self._max_streams:
            msg = ("Circuit {} tried to add a stream, but it's stream map was "
                   "full. This is a bug.".format(self.circuit_id))
            raise RuntimeError(msg) 

        assigned = False
        for _ in xrange(self._max_streams):
            _id = next(self._ctr)
            if _id not in self._streams:
                self._streams[_id] = stream
                stream.stream_id = _id
                assigned = True
                break

        if not assigned:
            msg = ("Circuit {} failed to assign a requesting stream an ID, "
                   "even though it's stream map only contains {} streams. "
                   "This is a bug."
                   .format(self.circuit_id, len(self._streams)))
            raise RuntimeError(msg)

        msg = ("Circuit {} added a new stream {}."
               .format(self.circuit_id, stream.stream_id))
        logging.debug(msg)

    def sendStreamSendMe(self, stream):
        '''Send a stream-level RelaySendMe cell with its stream_id equal to
        *stream_id*.

        Construct the send me cell, encrypt it, and immediately write it to
        this circuit's connection.

        :param int stream_id: stream_id to use in the RelaySendMeCell
        '''
        cell = RelaySendMeCell.make(self.circuit_id,
                                    stream_id=stream.stream_id)
        self._encryptAndSendCell(cell)

        msg = ("Circuit {} sent a RelaySendMeCell for stream {}."
               .format(self.circuit_id, stream.stream_id))

    def destroyCircuitFromManager(self):
        '''Called by the circuit manager when it decides to destroy this
        circuit.

        Send a destroy cell and notify this circuit's connection that this
        circuit is now closed.
        '''
        msg = "Circuit {} destroyed by circuit manager."
        logging.debug(msg.format(self.circuit_id))
        self._sendDestroyCell()
        self._closeCircuit(notify_manager=False)

    def destroyCircuitFromConnection(self):
        '''Called when a connection closes this circuit (usually because
        the connection went down).

        Primarily called when we lose the TLS connection to our connection
        object.  Do a 'hard' destroy and immediately close all associated
        streams.  Do not send a destroy cell.
        '''
        msg = "Circuit {} destroyed by its connection."
        logging.debug(msg.format(self.circuit_id))
        self._closeCircuit()

    def _pollReadQueue(self):
        '''Try pulling a cell from this circuit's read_queue and add a
        callback to handle the cell when it's available.
        '''
        self._read_task = self._read_queue.get()
        self._read_task.addCallback(self._recvCell)

    def _pollWriteQueue(self):
        '''Try pulling data from this circuit's write_queue and add a
        callback to process the data when it's available.
        '''
        self._write_task = self._write_queue.get()
        self._write_task.addCallback(self._writeData)

    def _writeData(self, data_stream_id_tuple):
        '''Write data to this circuit's connection.

        Do the following:

            1. Package this data (with appropriate stream_id) into a
               RelayDataCell.
            2. Encrypt this cell.
            3. Write this cell to this circuit's connection.
            4. Decrement this circuit's packaging window (if we can't
               package anymore data, enter state CState.BUFFERING, otherwise
               begin polling from _write_queue again).

        :param tuple, str, int data_stream_id_tuple: tuple of (data, stream_id)
            to package into a RelayData cell
        '''
        data, stream_id = data_stream_id_tuple
        cell = RelayDataCell.make(self.circuit_id, stream_id, data)
        self._encryptAndSendCell(cell)
        self._decPackageWindow()

    def _recvCell(self, cell):
        '''Called when this circuit receives a cell and it's state is
        CState.OPEN.

        If we received a non-backward cell or a DestroyCell, immediately
        tear-down the circuit. Otherwise process as usual.

        :param cell cell: the cell received from the network.
        '''
        if type(cell) not in BACKWARD_CELL_TYPES:
            msg = ("Circuit {} received a {} cell that violates the Tor "
                   "protocol. Destroying circuit."
                   .format(self.circuit_id, type(cell)))
            logging.warning(msg)
            self._sendDestroyCell()
            self._closeCircuit()
        elif isinstance(cell, DestroyCell):
            msg = ("Circuit {} received a DestroyCell. Tearing down circuit."
                   .format(self.circuit_id))
            logging.debug(msg)
            self._closeCircuit()
        else:
            self._recvRelayCell(cell)
            self._pollReadQueue()

    def _recvRelayCell(self, cell):
        '''Called when this circuit receives some sort of RelayCell from
        the network.

        Decrypt this cell and take action based on the cell type and this
        circuit's current state. Each valid backward cell type has a
        handler function that's called when that cell type is received.

        .. note:: oppy just drops any unrecognized cells.

        :param cell cell: cell received from the network
        '''
        try:
            cell, origin = crypto.decryptCell(cell, self._crypt_path)
        except Exception as e:
            logging.debug("Circuit {} failed to decrypt an incoming cell. "
                          "Reason: {}. Dropping cell."
                          .format(self.circuit_id, e))
            return

        if type(cell) not in BACKWARD_RELAY_CELL_TYPES:
            msg = ("Circuit {} received a non-backward {} relay cell. This "
                   "is a violation of the Tor protocol, and the circuit will "
                   "be destroyed.".format(self.circuit_id, type(cell)))
            logging.warning(msg)
            self._sendDestroyCell()
            self._closeCircuit()
        elif isinstance(cell, RelayDataCell):
            self._processRelayDataCell(cell, origin)
        elif isinstance(cell, RelayEndCell):
            self._processRelayEndCell(cell, origin)
        elif isinstance(cell, RelayConnectedCell):
            self._processRelayConnectedCell(cell, origin)
        elif isinstance(cell, RelaySendMeCell):
            self._processRelaySendMeCell(cell, origin)
        elif isinstance(cell, RelayTruncatedCell):
            self._processRelayTruncatedCell(cell, origin)
        elif isinstance(cell, RelayDropCell):
            self._processRelayDropCell(cell, origin)
        elif isinstance(cell, RelayResolvedCell):
            self._processRelayResolvedCell(cell, origin)
        else:
            msg = ("Circuit {} received an unexpected backward cell {} "
                   "from relay in position {}. Dropping cell."
                   .format(self.circuit_id, type(cell), origin))
            logging.debug(msg)

    def _processRelayDataCell(self, cell, origin):
        '''Called when this circuit receives an incoming RelayData cell.

        Take the following actions:

            1. Pass the relay payload in this cell to the stream with the
               stream_id contained in this RelayData cell. Drop the cell
               if we have no reference to the stream_id contained in the
               cell.
            2. Decrement this circuit's delivery window (which will
               automatically send a RelaySendMeCell if this circuit's
               deliver window is low enough).
        
        :param oppy.cell.relay.RelayDataCell cell: relay data cell recieved
            from the network
        :param int origin: which node on the circuit's path this cell
            came from
        '''
        sid = cell.rheader.stream_id

        try:
            self._streams[sid].recv(cell.rpayload)
            self._decDeliverWindow()
        except KeyError:
            msg  = ("Circuit {} received a RelayDataCell for nonexistent "
                    "stream {}. Dropping cell.".format(self.circuit_id, sid))
            logging.debug(msg)

    def _processRelayEndCell(self, cell, origin):
        '''Called when this circuit receives a RelayEndCell.

        Tear down the stream associated with the stream in the RelayEndCell
        if this circuit has a reference to it. Drop the cell if we have
        no reference to this stream.

        :param oppy.cell.relay.RelayEndCell cell: relay end cell recieved
            from the network
        :param int origin: which node on the circuit's path this cell
            came from
        '''
        sid = cell.rheader.stream_id

        try:
            self._streams[sid].closeFromCircuit()
            # TODO: handle REASON_EXITPOLICY
            if cell.reason != REASON_DONE:
                msg = ("Circuit {} received a RelayEndCell for stream {}, "
                       "and reason was not REASON_DONE. Reason: {}."
                       .format(self.circuit_id, sid, cell.reason))
                logging.debug(msg)
        except KeyError:
            msg  = ("Circuit {} received a RelayEndCell for nonexistent "
                    "stream {}. Dropping cell.".format(self.circuit_id, sid))
            logging.debug(msg)

    def _processRelayConnectedCell(self, cell, origin):
        '''Called when this circuit receives a RelayConnectedCell.

        Notify the stream associated with this cell's stream id that it's
        now connected. Drop the cell if we have no reference to this
        stream id.

        :param oppy.cell.relay.RelayConnectedCell cell: relay connected cell
            recieved from the network
        :param int origin: which node on the circuit's path this cell
            came from
        '''
        sid = cell.rheader.stream_id

        try:
            self._streams[sid].streamConnected()
        except KeyError:
            msg = ("Circuit {} received a RelayConnectedCell for nonexistent "
                   "stream {}. Dropping cell.".format(self.circuit_id, sid))
            logging.debug(msg)
            return

        logging.debug("Circuit {} received a RelayConnectedCell for "
                      "stream {}".format(self.circuit_id, sid))

    def _processRelaySendMeCell(self, cell, origin):
        '''Called when this circuit receives a RelaySendMeCell.

        If this is a circuit-level sendme cell (i.e. its stream id is zero)
        then increment this circuit's packaging window. If this circuit
        is currently in state CState.BUFFERING **and** receiving this
        sendme cell has incremented its packaging window > 0, then begin
        listening for incoming data again (i.e. self._pollWriteQueue).

        If this is a stream-level sendme cell, increment the corresponding
        stream's packaging window. Drop the cell if we have no reference
        to the stream associated with its stream id.

        Drop this cell if it's received while we're still building the
        circuit.

        :param oppy.cell.relay.RelaySendMeCell cell: relay sendme cell
            recieved from the network
        :param int origin: which node on the circuit's path this cell
            came from
        '''
        sid = cell.rheader.stream_id

        if sid == 0:
            self._incPackageWindow()
        else:
            try:
                self._streams[sid].incPackageWindow()
            except KeyError:
                msg = ("Circuit {} received a RelaySendMe cell on nonexistent"
                       " stream {}. Dropping cell."
                       .format(self.circuit_id, sid))
                logging.debug(msg)

    def _processRelayTruncatedCell(self, cell, origin):
        '''Called when this circuit receives a RelayTruncatedCell.

        oppy currently doesn't know how to rebuild or cannabalize circuits,
        so we just destroy the whole circuit if we get a truncated cell.

        :param oppy.cell.relay.RelayTruncatedCell cell: relay truncated cell
            recieved from the network
        :param int origin: which node on the circuit's path this cell
            came from
        '''
        msg = ("Circuit {} received a RelayTruncatedCell. oppy can't "
               "rebuild or cannabalize circuits yet, so the circuit will "
               "be destroyed.".format(self.circuit_id))
        logging.debug(msg)
        self._sendDestroyCell()
        self._closeCircuit()

    def _processRelayDropCell(self, cell, origin):
        '''Called when this circuit receives a RelayDrop cell.

        Just drop it :)

        :param oppy.cell.relay.RelayDropCell cell: relay drop cell
            recieved from the network
        :param int origin: which node on the circuit's path this cell
            came from
        '''
        msg = "Circuit {} received a RelayDropCell.".format(self.circuit_id)
        logging.debug(msg)

    def _processRelayResolvedCell(self, cell, origin):
        '''Called when this circuit receives a RelayResolvedCell.

        oppy doesn't know how to handle these right now, so we just drop
        them.

        :param oppy.cell.relay.RelayResolvedCell cell: relay resolved cell
            recieved from the network
        :param int origin: which node on the circuit's path this cell
            came from
        '''
        msg = ("Circuit {} received a RelayResolvedCell for stream {}."
               .format(self.circuit_id, cell.rheader.stream_id))
        logging.debug(msg)

    def _decDeliverWindow(self):
        '''Decrement this circuit's deliver window.
        
        Called when we deliver an incoming RelayDataCell's payload to
        a stream. If the delivery window is below the default threshold, send
        a RelaySendMeCell.
        '''
        self._deliver_window -= 1
        if self._deliver_window <= SENDME_THRESHOLD:
            cell = RelaySendMeCell.make(self.circuit_id)
            self._encryptAndSendCell(cell)
            self._deliver_window += WINDOW_SIZE

            msg = ("Circuit {}'s delivery window dropped to {}. The circuit "
                   "sent a circuit-level RelaySendMeCell and incremented "
                   "its delivery window to {}."
                   .format(self.circuit_id, self._deliver_window - WINDOW_SIZE,
                           self._deliver_window))
            logging.debug(msg)


    def _decPackageWindow(self):
        '''Decrement this circuit's package window.

        If the package window is above zero, listen for more incoming local
        data. Otherwise, enter a state CState.BUFFERING. In this buffering
        state, this circuit will not accept any new streams and will not
        write any data to its connection. It will leave it's buffering state
        and become open again when it receives enough RelaySendMeCell's to
        move its package window above zero again.
        '''
        self._package_window -= 1
        if self._package_window > 0:
            self._pollWriteQueue()
        else:
            self._state = CState.BUFFERING
            self._write_task = None
            msg = ("Circuit {}'s packaging window dropped to 0. The circuit "
                   "entered a buffering state.".format(self.circuit_id))
            logging.debug(msg)

    def _incPackageWindow(self):
        '''Increment this circuit's package window.

        Called when this circuit receives a RelaySendMeCell. If this circuit
        is currently in state CState.BUFFERING **and** receiving this
        sendme cell has moved this circuit's package window above zero,
        transition back to CState.OPEN and begin listening for incoming local
        data again.
        '''
        self._package_window += WINDOW_SIZE

        msg = ("Circuit {} received a circuit-level RelaySendMeCell. Its "
               "packaging window is now {}."
               .format(self.circuit_id, self._package_window))
        logging.debug(msg)

        if self._state == CState.BUFFERING and self._package_window > 0:
            self._state = CState.OPEN

            msg = ("Circuit {} has transitioned from buffering to open."
                   .format(self.circuit_id))
            logging.debug(msg)

            if self._write_task is None:
                self._pollWriteQueue()

    def _sendDestroyCell(self):
        '''Send a destroy cell.

        .. note:: reason NONE is always used when sending forward destroy
            cells to avoid leaking version information.
        '''
        cell = DestroyCell.make(self.circuit_id)
        self._connection.send(cell)

    def _closeAllStreams(self):
        for stream in self._streams.values():
            stream.closeFromCircuit()

    def _encryptAndSendCell(self, cell):
        try:
            enc = crypto.encryptCell(cell, self._crypt_path)
        except Exception as e:
            msg = ("Error: {}. Failed to encrypt a {} cell on circuit {}. "
                   "Refusing to send unencrypted cell. Dropping the cell."
                   .format(e, type(cell), self.circuit_id))
            logging.warning(msg)

        try:
            self._connection.send(enc)
        except Exception as e:
            msg = ("Error: {}. Failed to send an encrypted cell on circuit "
                   "{}.".format(e, self.circuit_id))
            logging.debug(msg)

    def _closeCircuit(self, notify_manager=True):
        '''Close this circuit.

        Close all associated streams, notify the circuit manager this
        circuit has closed, and notify this circuit's connection that this
        circuit has closed.
        '''
        self._closeAllStreams()
        if notify_manager is True:
            self._circuit_manager.circuitDestroyed(self)
        self._connection.removeCircuit(self)
