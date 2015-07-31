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


class Connection(Protocol):
    '''A TLS connection to an entry node.'''

    def __init__(self, connection_manager, connection_task):
        '''
        '''
        self._connection_manager = connection_manager
        self.micro_status_entry = connection_task.micro_status_entry
        self._circuit_dict = {}
        self._buffer = ''
        self._closed = False

    def send(self, cell):
        self.transport.write(cell.getBytes())

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
                self._recv(cell)
                self._buffer = self._buffer[len(cell):]
            except NotEnoughBytes as e:
                logging.debug(e)
                break
            # TODO: remove len(unimplemented cell bytes) from buffer
            except NotImplementedError:
                logging.debug("Received a cell we can't handle yet.")
                logging.debug('buffer contents:\n')
                logging.debug([ord(i) for i in self._buffer])
                raise

    def _recv(self, cell):
        # just drop padding cells
        if cell.header.cmd in PADDING_CMD_IDS:
            return

        try:
            self._circuit_dict[cell.header.circ_id].recv(cell)
        except KeyError:
            msg = ("Connection to {} received a {} cell for nonexistent "
                   "circuit {}. Dropping cell."
                   .format(self.micro_status_entry.fingerprint, type(cell),
                           cell.header.circ_id))
            logging.debug(msg)

    def addCircuit(self, circuit):
        '''Add new a new circuit to the circuit map for this connection.

        :param oppy.circuit.circuit.Circuit circuit: circuit to add to this
            connection's circuit map
        '''
        self._circuit_dict[circuit.id] = circuit

    def closeConnection(self):
        '''Close this connection and all associated circuits; notify the
        connection manager.
        '''
        msg = ("Closing connection to {}."
              .format(self.micro_status_entry.address))
        logging.debug(msg)
        self._closed = True
        self._destroyAllCircuits()
        self._connection_manager.removeConnection(self)
        self.transport.loseConnection()

    def connectionLost(self, reason):
        '''Connection to relay has been lost; close this connection and
        all associated circuits; notify connection pool.

        :param reason reason: reason this connection was lost
        '''
        if self._closed is True:
            return

        self._closed = True
        msg = ("Connection to {} lost. Reason: {}."
               .format(self.micro_status_entry.fingerprint, reason))
        logging.debug(msg)
        self._destroyAllCircuits()
        self._connection_manager.removeConnection(self)

    def _destroyAllCircuits(self):
        '''Destroy all circuits associated with this connection.
        '''
        for circuit in self._circuit_dict.values():
            circuit.destroyCircuitFromConnection()

    def removeCircuit(self, circuit):
        '''The circuit with *circuit_id* has been destroyed.

        Remove this circuit from this connection's circuit map if we know
        about it. If there are no remaining circuit's using this connection,
        ask the connection pool if this connection should be closed and, if
        so, close this connection.

        :param int circuit_id: id of the circuit that was destroyed
        '''
        try:
            del self._circuit_dict[circuit.id]
        except KeyError:
            msg = ("Connection to {} notified circuit {} was destroyed, but "
                   "the connection has no reference to that circuit."
                   .format(self.micro_status_entry.fingerprint,
                           circuit.id))
            logging.debug(msg)
            return

        if len(self._circuit_dict) == 0:
            if self._connection_manager.shouldDestroyConnection(self) is True:
                self.closeConnection()
