# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

'''
.. topic:: Details

    An NTorFSM steps through each state of a circuit handshake. At each step
    an NTorFSM expects to receive a certain kind of cell. Either this cell is
    received, processed, and a response cell is returned or an exception
    is raised (and the circuit is destroyed).

    NTorFSM's also derive key material and add RelayCrypto objects to the
    associated circuit's *crypt_path*.

'''
import logging

from oppy.cell.definitions import (
    CREATED2_CMD,
    DESTROY_CMD,
    RELAY_CMD,
    RELAY_EXTENDED2_CMD,
)
from oppy.cell.fixedlen import Create2Cell
from oppy.cell.relay import RelayExtend2Cell
from oppy.cell.util import LinkSpecifier
from oppy.circuit.handshake.exceptions import (
    BadHandshakeState,
    HandshakeFailed,
    ReceivedDestroyCell,
    UnexpectedCell,
)
from oppy.crypto.exceptions import UnrecognizedCell
from oppy.crypto.ntorhandshake import NTorHandshake
import oppy.crypto.util as crypto
from oppy.util.tools import dispatch, enum


State = enum(
    INIT=0,
    EXPECT_CREATED2=1,
    EXPECT_FIRST_EXTENDED2=2,
    EXPECT_SECOND_EXTENDED2=3,
    DONE=4,
)


class NTorFSM(object):
    '''Finite state machine to step through an ntor handshake with relays
    on a circuit's path.
    '''

    _response_map = {}

    def __init__(self, circuit_id, path, crypt_path):
        '''
        :param int circuit_id: id of the circuit for this ntor fsm
        :param oppy.path.path.Path path: path for this circuit
        :param list, oppy.crypto.relaycrypto.RelayCrypto crypt_path: a list
            (to be filled in by this ntor fsm) of RelayCrypto objects
        '''
        assert len(crypt_path) == 0
        msg = "Creating NTorFSM for circuit {}."
        logging.debug(msg.format(circuit_id))

        self.circuit_id = circuit_id
        self._path = path
        self._crypt_path = crypt_path

        self._ntor_handshakes = []
        self._state = State.INIT

        self._ntor_handshakes.append(NTorHandshake(path.entry))
        self._ntor_handshakes.append(NTorHandshake(path.middle))
        self._ntor_handshakes.append(NTorHandshake(path.exit))

    def recvCell(self, cell):
        '''Call a handler function to process *cell* based on this ntor fsm's
        current state.

        :param cell cell: cell received from this ntor fsm's circuit

        :returns: **cell, None** may return either the next cell to send
            to step through handshakes with relays on this path or None if
            no response is required
        '''
        try:
            fn = NTorFSM._response_map[self._state].__get__(self, type(self))
        except KeyError:
            msg = "NTorFSM in unknown state: {}.".format(self._state)
            raise BadHandshakeState(msg)
        response = fn(cell)
        return response

    def getInitiatingCell(self):
        '''Build and return the initiating cell for this ntor fsm - a
        Create2Cell.

        Advance this ntor fsm's state.

        :returns: **oppy.cell.fixedlen.Create2Cell**
        '''
        onion_skin = self._ntor_handshakes[0].createOnionSkin()
        cell = Create2Cell.make(self.circuit_id, hdata=onion_skin)
        self._state = State.EXPECT_CREATED2

        return cell

    @staticmethod
    def _verifyCellCmd(test_cmd, cmd):
        '''Verify that *test_cmd* == *cmd*. If not, or if this cmd is a
        DESTROY_CMD, raise an exception.

        :param int test_cmd: command to check
        :param int cmd: expected command value
        '''
        if test_cmd == DESTROY_CMD:
            msg = "NTorFSM got a DESTROY cell."
            raise ReceivedDestroyCell(msg)
        if test_cmd != cmd:
            msg = "NTorFSM unexpected cell {}, expected {}."
            msg = msg.format(test_cmd, cmd)
            raise UnexpectedCell(msg)

    @dispatch(_response_map, State.EXPECT_CREATED2)
    def _processCreated2(self, cell):
        '''Called when this ntor fsm is receives a cell and is expecting
        an Created2Cell.

            - verify we did in fact receive a valid Created2Cell
            - derive crypto keys
            - create a RelayCrypto object and add to crypt_path
            - create an Extend2 cell and encrypt it
            - advance this ntor fsm's state
            - return the encrypted Extend2 cell

        Fail if we received an invalid or unexpected cell.

        :param cell cell: the received cell
        :returns: **oppy.cell.relay.RelayExtend2Cell**
        '''
        NTorFSM._verifyCellCmd(cell.header.cmd, CREATED2_CMD)

        entry_crypto = self._ntor_handshakes[0].deriveRelayCrypto(cell)
        self._crypt_path.append(entry_crypto)

        relay = self._path.middle
        lspecs = [LinkSpecifier(relay), LinkSpecifier(relay, legacy=True)]
        hdata = self._ntor_handshakes[1].createOnionSkin()

        cell = RelayExtend2Cell.make(self.circuit_id,
                                     nspec=len(lspecs),
                                     lspecs=lspecs,
                                     hdata=hdata)

        response = crypto.encryptCellToTarget(cell, self._crypt_path,
                                              target=0, early=True)
        self._state = State.EXPECT_FIRST_EXTENDED2
        return response

    @dispatch(_response_map, State.EXPECT_FIRST_EXTENDED2)
    def _processFstExtended2(self, cell):
        '''Called when this ntor fsm is receives a cell and is expecting
        its first Extended2 cell.

            - decrypt the incoming cell
            - verify we did in fact receive a valid Extended2 cell
            - derive crypto keys
            - create a RelayCrypto object and add to crypt_path
            - create an Extend2 cell and encrypt it
            - advance this ntor fsm's state
            - return the encrypted Extend2 cell

        Fail if we received an invalid or unexpected cell.

        :param cell cell: the received cell
        :returns: **oppy.cell.relay.RelayExtend2Cell**
        '''
        try:
            cell, origin = crypto.decryptCellUntilRecognized(cell,
                                                             self._crypt_path,
                                                             origin=0)
        except UnrecognizedCell:
            raise HandshakeFailed()

        cmd = cell.header.cmd
        NTorFSM._verifyCellCmd(cmd, RELAY_CMD)
        rcmd = cell.rheader.cmd
        NTorFSM._verifyCellCmd(rcmd, RELAY_EXTENDED2_CMD)

        # Generate crypto material from the received cell.
        middle_crypto = self._ntor_handshakes[1].deriveRelayCrypto(cell)
        self._crypt_path.append(middle_crypto)

        relay = self._path.exit
        lspecs = [LinkSpecifier(relay), LinkSpecifier(relay, legacy=True)]

        hdata = self._ntor_handshakes[2].createOnionSkin()

        cell = RelayExtend2Cell.make(self.circuit_id,
                                     nspec=len(lspecs),
                                     lspecs=lspecs,
                                     hdata=hdata)
        response = crypto.encryptCellToTarget(cell, self._crypt_path,
                                              target=1, early=True)

        self._state = State.EXPECT_SECOND_EXTENDED2
        return response

    @dispatch(_response_map, State.EXPECT_SECOND_EXTENDED2)
    def _processSndExtended2(self, cell):
        '''Called when this ntor fsm is receives a cell and is expecting
        its second Extend2 cell.

            - decrypt the incoming cell
            - verify we did in fact receive a valid Extended2 cell
            - derive crypto keys
            - create a RelayCrypto object and add to crypt_path
            - advance this ntor fsm's state to Done

        Fail if we received an invalid or unexpected cell.

        :param cell cell: the received cell
        '''
        # Decrypt and validate received cell.
        # Decrypt and validate received cell.
        try:
            cell, origin = crypto.decryptCellUntilRecognized(cell,
                                                             self._crypt_path,
                                                             origin=1)
        except UnrecognizedCell:
            raise HandshakeFailed()

        cmd = cell.header.cmd
        NTorFSM._verifyCellCmd(cmd, RELAY_CMD)
        rcmd = cell.rheader.cmd
        NTorFSM._verifyCellCmd(rcmd, RELAY_EXTENDED2_CMD)

        # Generate crypto material from the received cell.
        exit_crypto = self._ntor_handshakes[2].deriveRelayCrypto(cell)
        self._crypt_path.append(exit_crypto)

        self._state = State.DONE
        return None

    def isDone(self):
        '''Return **True** iff this ntor fsm's state is State.DONE

        :returns: **bool** **True** if state is State.DONE
        '''
        return self._state == State.DONE
