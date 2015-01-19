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

from oppy.cell.definitions import (
    MAX_RPAYLOAD_LEN,
    BACKWARD_CELLS,
    DESTROY_CMD,
    RELAY_DATA_CMD,
    RELAY_END_CMD,
    RELAY_CONNECTED_CMD,
    RELAY_SENDME_CMD,
    RELAY_TRUNCATED_CMD,
    RELAY_DROP_CMD,
    RELAY_RESOLVED_CMD,
    REASON_DONE,
)

from oppy.circuit.handshake.exceptions import (
    BadHandshakeState,
    HandshakeFailed,
    ReceivedDestroyCell,
    UnexpectedCell,
)

from oppy.cell.fixedlen import DestroyCell
from oppy.cell.relay import RelayBeginCell
from oppy.cell.relay import RelayDataCell
from oppy.cell.relay import RelayEndCell
from oppy.cell.relay import RelaySendMeCell

from oppy.circuit.handshake.ntorfsm import NTorFSM
from oppy.crypto.exceptions import KeyDerivationFailed, UnrecognizedCell
from oppy.path.path import PathSelector
from oppy.util.tools import dispatch, enum


CIRCUIT_WINDOW_THRESHOLD_INIT = 1000
SENDME_THRESHOLD = 900
WINDOW_SIZE = 100


CState = enum(
    PENDING=0,
    OPEN=1,
    BUFFERING=2,
)


CType = enum(
    IPv4=0,
    IPv6=1,
)


class Circuit(object):

    # dispatch table used to lookup handler functions for incoming cells
    # filled in with the `dispatch` decorator
    _response_table = {}
    
    def __init__(self, cid, path_constraints):
        '''
        :param int cid: id of this circuit
        :param oppy.path.path.PathConstraints path_constraints: the constraints
            that this circuit's path should satisfy
        '''
        self.circuit_id = cid
        self.path_constraints = path_constraints
        self.connection = None
        self._selector = PathSelector()
        # _read_queue handles incoming cells from the network
        self._read_queue = defer.DeferredQueue()
        self._read_deferred = None
        # _write_queue handles incoming data from local applications
        self._write_queue = defer.DeferredQueue()
        self._write_deferred = None
        self._stream_map = {}
        self._stream_ctr = 1
        self._crypt_path = []
        self._state = CState.PENDING
        # deliver window is incoming data cells
        self._deliver_window = CIRCUIT_WINDOW_THRESHOLD_INIT
        # package window is outgoing data cells
        self._package_window  = CIRCUIT_WINDOW_THRESHOLD_INIT

        if path_constraints.is_IPv6_exit is True:
            self.ctype = CType.IPv6
        else:
            self.ctype = CType.IPv4

        # get a path and a connection
        self._startBuilding()

    ##################################################################
    #################### CIRCUIT BUILD METHODS #######################
    ##################################################################

    @defer.inlineCallbacks
    def _startBuilding(self):
        '''Begin building this circuit.

        The following steps are taken to build a circuit:

            1. Choose a path that satisfies this circuit's path constraints.
            2. Get a TLS connection to the entry node on this circuit's
               chosen path.
            3. Notify this connection that it has a new circuit on it.
            4. Begin the circuit handshake (i.e. send a Create2 cell to the
               entry node).
            5. Start listening for incoming cells (i.e. _pollReadQueue())

        If any of these steps fail, the circuit will be destroyed.
        '''
        from oppy.shared import connection_pool

        try:
            self.path = yield self._selector.getPath(self.path_constraints)
        except IndexError as e:
            msg = "Circuit {} could not get a valid path. Destroying circuit."
            msg = msg.format(self.circuit_id)
            logging.debug(msg)
            self._closeCircuit()
            return

        msg = "Circuit {} using path: {}."
        logging.debug(msg.format(self.circuit_id, self.path))

        try:
            self.connection = yield connection_pool.getConnection(self.path.entry)
        except Exception as e:
            msg = "Circuit {}'s TLS connection failed: {}. Circuit destroyed."
            msg = msg.format(self.circuit_id, str(e))
            logging.debug(msg)
            self._closeCircuit()
            return

        msg = "Circuit {} got a connection to {}."
        logging.debug(msg.format(self.circuit_id, self.path.entry.address))

        # register ourselves with this circuit's connection
        self.connection.addNewCircuit(self)
        # start the handshaking process immediately
        self._initiateCircuitHandshake()
        # can now start listening for incoming cells
        self._pollReadQueue()

    def _initiateCircuitHandshake(self):
        '''Initiate the handshaking process for this circuit.

        Create a new handshake object (for now, always an NTorFSM) and
        write the initiating cell to the entry node (for now, always a
        Create2 cell).
        '''
        self._handshake = NTorFSM(self.circuit_id, self.path,
                                  self._crypt_path)
        cell = self._handshake.getInitiatingCell()
        self.connection.writeCell(cell)
        msg = "Circuit {} initiated NTor handshake with {}."
        logging.debug(msg.format(self.circuit_id, self.path.entry.address))

    def _openCircuit(self):
        '''_openCircuit() is called when this circuit has successfully
        completed a handshake and derived crypto keys with every relay
        on its path.

        Do three things as soon as this circuit finishes extending itself
        through its whole path:

            1. Set this circuit's state to CState.OPEN
            2. Notify the CircuitManager that this circuit is ready to
               be assinged streams.
            3. Start listening for incoming data from local applications
               (i.e. _pollWriteQueue()).

        '''
        from oppy.shared import circuit_manager

        self._handshake = None

        self._state = CState.OPEN
        # notify circuit manager we're open
        circuit_manager.circuitOpened(self)
        # notify each pending stream that we're now open
        # can now start listening for outgoing data
        self._pollWriteQueue()

    ##################################################################
    ###################### QUEUEING METHODS ##########################
    ##################################################################

    def _pollReadQueue(self):
        '''Try pulling a cell from this circuit's read_queue and add a
        callback to handle the cell when it's available.
        '''
        self._read_deferred = self._read_queue.get()
        self._read_deferred.addCallback(self._recvCell)

    def _pollWriteQueue(self):
        '''Try pulling data from this circuit's write_queue and add a
        callback to process the data when it's available.
        '''
        self._write_deferred = self._write_queue.get()
        self._write_deferred.addCallback(self._writeData)

    def writeData(self, data, stream_id):
        '''Put a tuple of (data, stream_id) on this circuit's write_queue.
        
        Called by stream's when they want to write data to this circuit.

        .. warning:: writeData() requires that *data* can fit in a single
            relay cell. The caller should take care to split data into
            properly sized chunks.

        :param str data: data string to write to this circuit
        :param int stream_id: id of the stream writing this data
        '''
        assert len(data) <= MAX_RPAYLOAD_LEN
        self._write_queue.put((data, stream_id))

    def recvCell(self, cell):
        '''Put the incoming cell on this circuit's read_queue to be processed.
        
        Called be a connection when it receives a cell addressed to this
        circuit.
        
        :param cell cell: incoming cell that was received from the network
        '''
        self._read_queue.put(cell)

    ##################################################################
    ################### CELL PROCESSING METHODS ######################
    ##################################################################

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
        assert len(data) <= MAX_RPAYLOAD_LEN
        cell = RelayDataCell.make(self.circuit_id, stream_id, data)
        enc = crypto.encryptCellToTarget(cell, self._crypt_path)
        self.writeCell(enc)
        self._decPackageWindow()

    def _recvCell(self, cell):
        '''Pass *cell* to the appropriate handler depending on this circuit's
        state and listen for more incoming cells.

        :param cell cell: the cell received from the network.
        '''
        if self._state == CState.PENDING:
            self._recvHandshakeCell(cell)
        else:
            self._recvCircuitCell(cell)
        self._pollReadQueue()

    def _recvHandshakeCell(self, cell):
        '''Called when this circuit is in state CState.PENDING and a cell
        is received from the network.

        Attempt to process this cell. If the handshake receives an invalid
        or malformed cell, destroy this circuit. If the handshake has
        a new cell to send, immediately write it to this circuit's
        connection. If the handshake is complete with every node on this
        circuit's path, open the circuit (e.g. call self._openCircuit()).

        :param cell cell: the cell received from the network.
        '''
        try:
            response = self._handshake.recvCell(cell)
        except ReceivedDestroyCell as e:
            logging.debug(str(e))
            self.destroyCircuitFromRelay(cell)
            return
        except (BadHandshakeState, HandshakeFailed, UnexpectedCell) as e:
            self.destroyCircuitProtocolViolation(cell)
            logging.debug(str(e))
            return
        except KeyDerivationFailed:
            msg = "NTor key derivation failed on circuit {}."
            logging.debug(msg.format(self.circuit_id))
            self.destroyCircuitProtocolViolation(cell)
            return

        if response is not None:
            self.connection.writeCell(response)
        if self._handshake.isDone():
            self._openCircuit()
            self._handshake = None

    def _recvCircuitCell(self, cell):
        '''Called when this circuit receives a cell and it's state is
        CState.OPEN.

        If we received a non-backward cell or a DestroyCell, immediately
        tear-down the circuit. Otherwise process as usual.

        :param cell cell: the cell received from the network.
        '''
        # receiving a non-backward cell violates the Tor Protocol.
        # immediately tear down the circuit
        if cell.header.cmd not in BACKWARD_CELLS:
            self.destroyCircuitProtocolViolation(cell)
        elif cell.header.cmd == DESTROY_CMD:
            self._processDestroy(cell)
        else:
            self._recvRelayCell(cell)

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
            cell, origin = crypto.decryptCellUntilRecognized(cell,
                                                             self._crypt_path)
        # drop unrecognized cells
        except UnrecognizedCell:
            msg = "Circuit {} received an unrecognized cell."
            logging.debug(msg.format(self.circuit_id))
            return

        cmd = cell.rheader.cmd
        handler = Circuit._response_table[cmd].__get__(self, type(self))
        handler(cell, origin)

    def writeCell(self, cell):
        '''Write a cell to this circuit's connection.

        :param cell cell: cell to write to this circuit's connection
        '''
        self.connection.writeCell(cell)

    def _processDestroy(self, cell):
        '''Called when this circuit receives a destroy cell from the
        network.

        Immediately tear-down this circuit and all associated streams.

        :param oppy.cell.fixedlen.DestroyCell cell: destroy cell that this
            circuit received.
        '''
        self.destroyCircuitFromRelay(cell)

    @dispatch(_response_table, RELAY_DATA_CMD)
    def _processRelayData(self, cell, origin):
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
            self._stream_map[sid].recvData(cell.rpayload)
            self._decDeliverWindow()
        except KeyError:
            msg  = 'Got a RELAY_DATA cell for non-existent stream {} '
            msg += 'on circuit {}. Dropping cell.'
            logging.debug(msg.format(sid, self.circuit_id))

    @dispatch(_response_table, RELAY_END_CMD)
    def _processRelayEnd(self, cell, origin):
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
            self._stream_map[sid].closeFromCircuit()
            if cell.reason != REASON_DONE:
                msg = "Received a RELAY_END cell on stream {}, and reason "
                msg += "was not REASON_DONE. Reason: {}."
                logging.debug(msg.format(sid, cell.reason))
        except KeyError:
            msg  = 'Circuit {} received a RELAY_END cell for '
            msg += 'non-existent stream {}. Dropping cell.'
            logging.debug(msg.format(self.circuit_id, sid))

    @dispatch(_response_table, RELAY_CONNECTED_CMD)
    def _processRelayConnected(self, cell, origin):
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
            self._stream_map[sid].streamConnected()
        except KeyError:
            msg  = 'Received a RELAY_CONNECTED cell for non-existent '
            msg += 'stream {} on circuit {}.'
            logging.debug(msg.format(sid, self.circuit_id))

    @dispatch(_response_table, RELAY_SENDME_CMD)
    def _processRelaySendMe(self, cell, origin):
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

        if self._state == CState.PENDING:
            msg  = "Received a RELAY_SENDME cell on circuit {} destined for "
            msg += "stream {}, but circuit's state was {}. Dropping cell."
            logging.debug(msg.format(self.circuit_id, sid, self._state))
            return

        if sid == 0:
            self._incPackageWindow()
        else:
            try:
                self._stream_map[sid].incrementPackageWindow()
            except KeyError:
                msg  = "Circuit {} received a RELAY_SENDME on "
                msg += "non-existent stream {}."
                logging.debug(msg.format(self.circuit_id, sid))

    @dispatch(_response_table, RELAY_TRUNCATED_CMD)
    def _processRelayTruncated(self, cell, origin):
        '''Called when this circuit receives a RelayTruncatedCell.

        oppy currently doesn't know how to rebuild or cannabalize circuits,
        so we just destroy the whole circuit if we get a truncated cell.

        :param oppy.cell.relay.RelayTruncatedCell cell: relay truncated cell
            recieved from the network
        :param int origin: which node on the circuit's path this cell
            came from
        '''
        msg = "Received a RELAY_TRUNCATED cell on circuit {}."
        msg += " We can't rebuild circuit paths yet, so circuit {}"
        msg += " and all associated streams will be destroyed."
        logging.debug(msg.format(self.circuit_id, self.circuit_id))
        self.destroyCircuitFromRelay(cell)

    @dispatch(_response_table, RELAY_DROP_CMD)
    def _processRelayDrop(self, cell, origin):
        '''Called when this circuit receives a RelayDrop cell.

        Just drop it :)

        :param oppy.cell.relay.RelayDropCell cell: relay drop cell
            recieved from the network
        :param int origin: which node on the circuit's path this cell
            came from
        '''
        msg  = 'Received a RELAY_DROP cell on circuit {} in state {}. '
        msg += 'Dropping cell.'
        logging.debug(msg.format(self.circuit_id, self._state))

    @dispatch(_response_table, RELAY_RESOLVED_CMD)
    def _processRelayResolved(self, cell, origin):
        '''Called when this circuit receives a RelayResolvedCell.

        oppy doesn't know how to handle these right now, so we just drop
        them.

        :param oppy.cell.relay.RelayResolvedCell cell: relay resolved cell
            recieved from the network
        :param int origin: which node on the circuit's path this cell
            came from
        '''
        msg  = "Circuit {} received a RELAY_RESOLVED cell destined for stream "
        msg += "{}, but we don't know how to handle these yet. Dropping cell."
        logging.debug(msg.format(self.circuit_id, cell.rheader.stream_id))

    ##################################################################
    ################### STREAM PROCESSING METHODS ####################
    ##################################################################

    # return True iff this circuit's exit node can handle the request
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

        .. note:: For host type requests, I'd like to just check the exit
            policy of the exit relay to see if it allows exits to the
            desired port. However, I can't seem to get stem's
            exit_policy.can_exit_to() function to work when it's passed only
            a port with no IP address. I'm not sure if this is a bug in
            stem or how I'm using it. Ideally, in the case of host type
            requests, we'd check if the exit relay's exit policy claims to
            support exits to the requested port. Currently stem's
            exit_policy.can_exit_to() always returns False when passed just
            a port as an argument (at least when it's loaded with real
            exit policies from server descriptors).

        :param oppy.util.exitrequest.ExitRequest request: the request to
            check if this circuit can handle
        :returns: **bool** **True** if this circuit thinks it can handle
            the request, False otherwise
        '''
        # don't accept any new requests if we're buffering
        if self._state == CState.BUFFERING:
            return False

        # workaround for stem's exit_policy.can_exit_to method always
        # returning false when passed just a port. ideally, we'd check if
        # exiting to the desired port is allowed and then make a more educated
        # guess about whether or not the exit will support this stream. for
        # now, if it's a host request we just assume we can support it.
        if request.is_host:
            # XXX stem (possible) bug workaround
            #return self.path.exit.exit_policy.can_exit_to(port=request.port)
            return True
        elif request.is_ipv6 and self.ctype == CType.IPv6:
            # just guess that we can support the request if we're pending
            # and it's of the type that this circuit is
            if self._state == CState.PENDING:
                return True
            return self.path.exit.exit_policy.can_exit_to(address=request.addr,
                                                          port=request.port)
        elif request.is_ipv4 and self.ctype == CType.IPv4:
        # just guess that we can support the request if we're pending
            if self._state == CState.PENDING:
                return True
            return self.path.exit.exit_policy.can_exit_to(address=request.addr,
                                                          port=request.port)
        else:
            return False

    def _closeAllStreams(self):
        '''Close all streams associated with this circuit.
        '''
        for stream in self._stream_map.values():
            stream.closeFromCircuit()

    def unregisterStream(self, stream):
        '''Unregister *stream* from this circuit.

        Remove the stream from this circuit's stream map and send a
        RelayEndCell. If the number of streams on this circuit drops to
        zero, check with the circuit manager to see if this circuit should
        be destroyed. If so, tear down the circuit.

        :param oppy.stream.stream.Stream stream: stream to unregister
        '''
        from oppy.shared import circuit_manager

        try:
            del self._stream_map[stream.stream_id]
            cell = RelayEndCell.make(self.circuit_id, stream.stream_id)
            enc = crypto.encryptCellToTarget(cell, self._crypt_path)
            self.writeCell(enc)
        except KeyError:
            msg = "Circuit {} notified that stream {} was closed, but "
            msg += "circuit has no reference to this stream."
            logging.debug(msg.format(self.circuit_id, stream.stream_id))

        if len(self._stream_map) == 0:
            if circuit_manager.shouldDestroyCircuit(self) is True:
                self._sendDestroyCell()
                self._closeCircuit()
                msg = "Destroyed unused circuit {0}.".format(self.circuit_id)
                logging.debug(msg)

    def initiateStream(self, stream):
        '''Initiate a new stream by sending a RelayBeginCell.

        Create the begin cell, encrypt it, and immediately write it to this
        circuit's connection.

        :param oppy.stream.stream.Stream stream: stream on behalf of which
            we're sending a RelayBeginCell
        '''
        cell = RelayBeginCell.make(self.circuit_id, stream.stream_id,
                                   stream.request)
        enc = crypto.encryptCellToTarget(cell, self._crypt_path)
        self.writeCell(enc)

    def registerStream(self, stream):
        '''Register the new *stream* on this circuit.

        Set the stream's stream_id and add it to this circuit's stream map.

        :param oppy.stream.stream.Stream stream: stream to add to this circuit
        '''
        self._stream_map[self._stream_ctr] = stream
        stream.stream_id = self._stream_ctr
        self._stream_ctr += 1

    def sendStreamSendMe(self, stream_id):
        '''Send a stream-level RelaySendMe cell with its stream_id equal to
        *stream_id*.

        Construct the send me cell, encrypt it, and immediately write it to
        this circuit's connection.

        :param int stream_id: stream_id to use in the RelaySendMeCell
        '''
        cell = RelaySendMeCell.make(self.circuit_id, stream_id=stream_id)
        enc = crypto.encryptCellToTarget(cell, self._crypt_path)
        self.writeCell(enc)

    ##################################################################
    #################### FLOW CONTROL METHODS ########################
    ##################################################################

    def _decDeliverWindow(self):
        '''Decrement this circuit's deliver window.
        
        Called when we deliver an incoming RelayDataCell's payload to
        a stream. If the delivery window is below the default threshold, send
        a RelaySendMeCell.
        '''
        self._deliver_window -= 1
        if self._deliver_window <= SENDME_THRESHOLD:
            cell = RelaySendMeCell.make(self.circuit_id)
            enc = crypto.encryptCellToTarget(cell, self._crypt_path)
            self.writeCell(enc)
            self._deliver_window += WINDOW_SIZE

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
            self._write_deferred = None

    def _incPackageWindow(self):
        '''Increment this circuit's package window.

        Called when this circuit receives a RelaySendMeCell. If this circuit
        is currently in state CState.BUFFERING **and** receiving this
        sendme cell has moved this circuit's package window above zero,
        transition back to CState.OPEN and begin listening for incoming local
        data again.
        '''
        self._package_window += WINDOW_SIZE
        # if we're buffering, we can start writing again
        if self._state == CState.BUFFERING and self._package_window > 0:
            self._state = CState.OPEN
            if self._write_deferred is None:
                self._pollWriteQueue()

    ##################################################################
    ################### CIRCUIT TEARDOWN METHODS #####################
    ##################################################################

    def destroyCircuitProtocolViolation(self, cell):
        '''Destroy a circuit because the Tor protocol was violated.

        Send a DestroyCell and close the circuit.

        :param cell cell: received cell that violated the Tor protocol.
        '''
        msg = "Circuit {0} received a {1} cell that violates the Tor "
        msg += "protocol. Destroying circuit."
        logging.warning(msg.format(self.circuit_id, cell.header.cmd))
        self._sendDestroyCell()
        self._closeCircuit()

    def destroyCircuitFromRelay(self, cell):
        '''Called when a DestroyCell is received from a relay on
        this circuit's path.

        Immediately close the circuit. We don't need to send a DestroyCell
        in this case.

        :param cell cell: either the DestroyCell or the RelayTruncatedCell
            that was received.
        '''
        msg = "{} cell received on circuit {}. Destroying circuit."
        logging.debug(msg.format(cell.header.cmd, self.circuit_id))
        self._closeCircuit()

    def destroyCircuitFromManager(self):
        '''Called by the circuit manager when it decides to destroy this
        circuit.

        Send a destroy cell and notify this circuit's connection that this
        circuit is now closed.
        '''
        msg = "Circuit {} destroyed by circuit manager."
        logging.debug(msg.format(self.circuit_id))
        self._sendDestroyCell()
        if self.connection is not None:
            self.connection.circuitDestroyed(self.circuit_id)

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

    def _sendDestroyCell(self):
        '''Send a destroy cell.

        .. note:: reason NONE is always used when sending forward destroy
            cells to avoid leaking version information.
        '''
        if self.connection is not None:
            cell = DestroyCell.make(self.circuit_id)
            self.connection.writeCell(cell)

    def _closeCircuit(self):
        '''Close this circuit.

        Close all associated streams, notify the circuit manager this
        circuit has closed, and notify this circuit's connection that this
        circuit has closed.
        '''
        from oppy.shared import circuit_manager

        self._closeAllStreams()
        circuit_manager.circuitDestroyed(self)
        if self.connection is not None:
            self.connection.circuitDestroyed(self.circuit_id)
