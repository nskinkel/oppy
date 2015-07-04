# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

# TODO: fix imports
import logging

from twisted.internet import defer
from twisted.python.failure import Failure

import oppy.crypto.util as crypto
import oppy.path.path as path

from oppy.cell.fixedlen import Create2Cell, Created2Cell, DestroyCell
from oppy.cell.relay import RelayExtend2Cell, RelayExtended2Cell
from oppy.cell.util import LinkSpecifier
from oppy.circuit.circuit import CircuitType, Circuit
from oppy.crypto.ntorhandshake import NTorHandshake
from oppy.path.path import getPath


# Major TODO's:
#               - catch/handle crypto exceptions explicitly
#               - catch/handle connection.send exceptions explicitly
#               - catch/handle specific getPath exceptions
#               - handle cells with unexpected origins
#               - docs
#               - figure out where alreadyCalledError is coming from when
#                 building a path fails
class CircuitBuildTask(object):

    def __init__(self, connection_manager, circuit_manager, netstatus,
                 guard_manager, _id, circuit_type=None, request=None,
                 autobuild=True):
        self._connection_manager = connection_manager
        self._circuit_manager = circuit_manager
        self._netstatus = netstatus
        self._guard_manager = guard_manager
        self.circuit_id = _id
        self.circuit_type = circuit_type
        self.request = request
        self._path = None
        self._conn = None
        self._crypt_path = []
        self._read_queue = defer.DeferredQueue()
        self._autobuild = autobuild
        self._tasks = None
        self._building = False
        self._current_task = None

        if autobuild is True:
            self.build()

    def build(self):
        if self._building is True:
            msg = "Circuit {} already started build process."
            raise RuntimeError(msg.format(self.circuit_id))

        try:
            # TODO: update for stable/fast flags based on circuit_type
            self._tasks = path.getPath(self._netstatus, self._guard_manager,
                                       exit_request=self.request)
        except Exception as e:
            self._buildFailed(e)
            return

        self._current_task = self._tasks
        self._tasks.addCallback(self._build)
        self._tasks.addCallback(self._buildSucceeded)
        self._tasks.addErrback(self._buildFailed)
        self._building = True

    def canHandleRequest(self, request):
        if self._path is None:
            if request.is_host:
                return True
            elif request.is_ipv4:
                return self.circuit_type == CircuitType.IPv4
            else:
                return self.circuit_type == CircuitType.IPv6
        else:
            if request.is_host:
                return self._path.exit.exit_policy.can_exit_to(
                                                            port=request.port, 
                                                            strict=False)
            else:
                return self._path.exit.exit_policy.can_exit_to(
                                       address=request.addr, port=request.port)

    def recv(self, cell):
        self._read_queue.put(cell)

    def destroyCircuitFromManager(self):
        msg = "CircuitBuildTask {} destroyed from manager."
        msg = msg.format(self.circuit_id)
        self._current_task.errback(Failure(Exception(msg)))

    def destroyCircuitFromConnection(self):
        msg = "CircuitBuildTask {} destroyed from connection."
        msg = msg.format(self.circuit_id)
        self._current_task.errback(Failure(Exception(msg)))

    def _recvCell(self, result):
        self._current_task = self._read_queue.get()
        return self._current_task

    # NOTE: no errbacks are added because exceptions thrown in this inner
    #       deferred will fire the errback added to the outer deferred
    def _build(self, path):
        self._path = path
        d = self._getConnection(path.entry)
        self._current_task = d
        d.addCallback(self._sendCreate2Cell, path.entry)
        d.addCallback(self._recvCell)
        d.addCallback(self._deriveCreate2CellSecrets, path.entry)
        for node in path[1:]:
            d.addCallback(self._sendExtend2Cell, node)
            d.addCallback(self._recvCell)
            d.addCallback(self._deriveExtend2CellSecrets, node)
        return d

    def _getConnection(self, node):
        d = self._connection_manager.getConnection(node)
        self._current_task = d
        def addCirc(res):
            self._conn = res
            self._conn.addCircuit(self)
            return res
        d.addCallback(addCirc)
        return d

    def _sendCreate2Cell(self, conn, node):
        self._hs = NTorHandshake(node)
        onion_skin = self._hs.createOnionSkin()
        create2 = Create2Cell.make(self.circuit_id, hdata=onion_skin)
        self._conn.send(create2)

    def _deriveCreate2CellSecrets(self, response, node):
        if isinstance(response, DestroyCell):
            msg = "Destroy cell received from {}.".format(node.fingerprint)
            raise ValueError(msg)
        if not isinstance(response, Created2Cell):
            msg = "Unexpected cell {} received from {}."
            msg = msg.format(response, node.fingerprint)
            destroy = DestroyCell.make(self.circuit_id)
            self._conn.send(destroy)
            raise ValueError(msg)

        self._crypt_path.append(self._hs.deriveRelayCrypto(response))
        self._hs = None

    def _sendExtend2Cell(self, result, node):
        lspecs = [LinkSpecifier(node), LinkSpecifier(node, legacy=True)]
        self._hs = NTorHandshake(node)
        onion_skin = self._hs.createOnionSkin()
        extend2 = RelayExtend2Cell.make(self.circuit_id, nspec=len(lspecs),
                                        lspecs=lspecs, hdata=onion_skin)
        crypt_cell = crypto.encryptCell(extend2, self._crypt_path,
                                        early=True)
        self._conn.send(crypt_cell)

    def _deriveExtend2CellSecrets(self, response, node):
        if isinstance(response, DestroyCell):
            msg = "Destroy cell received from {} on pending circuit {}."
            raise ValueError(msg.format(node.fingerprint, self.circuit_id))

        cell, origin = crypto.decryptCell(response, self._crypt_path)

        if not isinstance(cell, RelayExtended2Cell):
            msg = "Circuit {} received an unexpected cell {}."
            msg = msg.format(self.circuit_id, cell)
            destroy = DestroyCell.make(self.circuit_id)
            self._conn.send(destroy)
            raise ValueError(msg)

        self._crypt_path.append(self._hs.deriveRelayCrypto(cell))
        self._hs = None

    def _buildSucceeded(self, result):
        circuit = Circuit(self._circuit_manager, self.circuit_id, self._conn,
                          self.circuit_type, self._path, self._crypt_path)
        self._conn.addCircuit(circuit)
        self._circuit_manager.circuitOpened(circuit)

    def _buildFailed(self, reason):
        msg = "Pending circuit {} failed. Reason: {}"
        logging.debug(msg.format(self.circuit_id, reason))
        if self._conn is not None:
            self._conn.removeCircuit(self.circuit_id)
        self._circuit_manager.circuitDestroyed(self)
