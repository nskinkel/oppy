# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

'''
.. topic:: Details

    Connection objects represent TLS connections to Tor entry nodes. Connection
    objects have a few important jobs:

        - Do the initial handshake to authenticate the entry node and negotiate
          a Link Protocl version (currently oppy only supports Link Protocol
          Version 3)
        - Extract cells from incoming data streams and pass them to the
          appropriate circuit (based on circuit ID)
        - Write cells from circuits to entry nodes
        - Notify all associated circuits when the connection goes down

'''
import logging

from twisted.internet.protocol import Protocol

from oppy.cell.cell import Cell
from oppy.cell.definitions import PADDING_CMD_IDS
from oppy.cell.exceptions import NotEnoughBytes

from oppy.connection.handshake.v3 import V3FSM
from oppy.connection.handshake.exceptions import (
    BadHandshakeState,
    HandshakeFailed,
    UnexpectedCell,
)
from oppy.util.tools import enum


ConnState = enum(
    PENDING=0,
    OPEN=1,
)


class Connection(Protocol):
    '''A TLS connection to an entry node.'''

    def __init__(self, connection_pool, relay):
        '''
        :param stem.descriptor.server_descriptor.RelayDescriptor relay:
            relay we should create a connection to
        '''
        logging.debug('Creating connection to {0}'.format(relay.address))
        # map all circuits using this connections
        self._connection_pool = connection_pool
        self._circuit_map = {}
        self._buffer = ''
        self._relay = relay
        self._handshake = None
        self._state = ConnState.PENDING
        self._cell_queue = []

    # TODO: fix docs
    def send(self, cell):
        '''Write a cell to this connections transport.

        If this connection is not yet open, append to the cell_queue to be
        written when the connection opens up.

        :param cell cell: cell to write
        '''
        if self._state == ConnState.OPEN:
            self.transport.write(cell.getBytes())
        else:
            self._cell_queue.append(cell)

    def dataReceived(self, data):
        '''We received data from the remote connection.

        Extract cells from the data stream and send them along to be
        processed.

        :param str data: data received from remote end
        '''
        self._buffer += data

        while Cell.enoughDataForCell(self._buffer):
            try:
                cell = Cell.parse(self._buffer, encrypted=True)
                self._deliverCell(cell)
                self._buffer = self._buffer[len(cell):]
            # this shouldn't happen and if it does, it's probably a bug
            except NotEnoughBytes as e:
                logging.debug(str(e))
                break
            # XXX remove len(unimplemented cell bytes) from buffer
            except NotImplementedError:
                logging.debug("Received a cell we can't handle yet.")
                logging.debug('buffer contents:\n')
                logging.debug([ord(i) for i in self._buffer])
                raise
            except (BadHandshakeState, HandshakeFailed, UnexpectedCell) as e:
                logging.warning(e)
                self.closeConnection()
                self._buffer = ''
                break

    def _deliverCell(self, cell):
        '''Deliver *cell* either to an appropriate circuit or, if the
        handshake is not complete, to the handshake fsm.

        :param cell cell: incoming cell to deliver
        '''
        # just drop any padding cells
        if cell.header.cmd in PADDING_CMD_IDS:
            return

        if self._state == ConnState.OPEN:
            self._recvCircuitCell(cell)
        else:
            self._recvHandshakeCell(cell)

    def _recvCircuitCell(self, cell):
        '''Process an incoming cell destined for a circuit.

        If we have a reference to the circuit with the ID indicated in the
        cell, hand off this cell to that circuit. If we have no reference
        to the circuit, drop the cell.

        :param cell cell: incoming cell
        '''
        try:
            self._circuit_map[cell.header.circ_id].recv(cell)
        # drop cells to circuits we don't know about
        except KeyError:
            msg = "Connection {} received a cell to nonexistent circuit:"
            msg += "{}."
            msg = msg.format(self._relay.address, cell.header.circ_id)
            logging.debug(msg)

    def _recvHandshakeCell(self, cell):
        '''Process an incoming cell as part of this connection's handshake.
        
        Immediately write any response from the handshake fsm to this
        connection's transport. If any errors occur in the handshake, tear
        down this connection.

        If the handshake is completed after receiving this cell, transition
        this connection's state to ConnState.OPEN and flush this connection's
        queued up cells.

        :param cell cell: incoming handshake cell
        '''
        try:
            response = self._handshake.recv(cell)
        except Exception as e:
            logging.debug(str(e))
            self.closeConnection()
            return

        # send a handshake response if required
        if response is not None:
            self.transport.write(response.getBytes())
        # empty our queue if we're finished with the handshake
        if self._handshake.isDone():
            self._state = ConnState.OPEN
            msg = 'Completed handshake on connection: {0}'
            msg = msg.format(self._relay.address)
            logging.debug(msg)
            self._emptyQueue()
            self._handshake = None

    def _emptyQueue(self):
        '''Write any cells in this connection's queue to this connection's
        transport and remove them from the queue.
        '''
        for cell in self._cell_queue:
            self.send(cell)
        self._cell_queue = None

    def connectionMade(self):
        '''Initial TLS connection made, immediately start the connection
        handshake.
        '''
        logging.debug('Connection made to {0}.'.format(self._relay.address))
        self._handshake = V3FSM(self.transport)
        cell = self._handshake.getInitiatingCell()
        self.transport.write(cell.getBytes())

    # TODO: update docs
    def addCircuit(self, circuit):
        '''Add new a new circuit to the circuit map for this connection.

        Raise a ValueError if *circuit.circuit_id* already exists in
        self._circuit_map - that means something went very wrong.

        :param oppy.circuit.circuit.Circuit circuit: circuit to add to this
            connection's circuit map
        '''
        self._circuit_map[circuit.circuit_id] = circuit

    def closeConnection(self):
        '''Close this connection and all associated circuits; notify the
        connection pool.
        '''
        logging.debug("Closing connection to {}.".format(self._relay.address))
        self._destroyAllCircuits()
        self._connection_pool.removeConnection(self._relay.fingerprint)
        self.transport.abortConnection()

    def connectionLost(self, reason):
        '''Connection to relay has been lost; close this connection and
        all associated circuits; notify connection pool.

        :param reason reason: reason this connection was lost
        '''
        msg = "Connection to {} lost: {}."
        logging.warning(msg.format(self._relay.address, reason))
        self._destroyAllCircuits()
        self._connection_pool.removeConnection(self._relay.fingerprint)

    def _destroyAllCircuits(self):
        '''Destroy all circuits associated with this connection.
        '''
        for circuit in self._circuit_map.values():
            circuit.destroyCircuitFromConnection()

    # TODO: fix docs
    def removeCircuit(self, circuit):
        '''The circuit with *circuit_id* has been destroyed.

        Remove this circuit from this connection's circuit map if we know
        about it. If there are no remaining circuit's using this connection,
        ask the connection pool if this connection should be closed and, if
        so, close this connection.

        :param int circuit_id: id of the circuit that was destroyed
        '''
        cid = circuit.circuit_id
        try:
            del self._circuit_map[cid]
        except KeyError:
            msg = "Connection to {} was notified that circuit {} was destroyed"
            msg += ", but connection has no reference to circuit {}."
            msg = msg.format(self._relay.address, cid, cid)
            logging.debug(msg)

        if len(self._circuit_map) == 0:
            fprint = self._relay.fingerprint
            if self._connection_pool.shouldDestroyConnection(fprint) is True:
                self._connection_pool.removeConnection(fprint)
                self.closeConnection()
