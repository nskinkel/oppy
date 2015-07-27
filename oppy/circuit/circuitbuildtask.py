# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

# TODO: fix imports
import logging

from twisted.internet import defer
from twisted.python.failure import Failure

import oppy.crypto.util as crypto
import oppy.path.path as path
import crypto.ntor as ntor

from oppy.cell.fixedlen import Create2Cell, Created2Cell, DestroyCell
from oppy.cell.relay import RelayExtend2Cell, RelayExtended2Cell
from oppy.cell.util import LinkSpecifier
from oppy.circuit.circuit import Circuit
from oppy.circuit.definitions import CircuitType


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
        self._hs_state = None
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
            return self._path.exit.microdescriptor.exit_policy.can_exit_to(port=request.port)

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

    def _recvCell(self, _):
        self._current_task = self._read_queue.get()
        return self._current_task

    # NOTE: no errbacks are added because exceptions thrown in this inner
    #       deferred will fire the errback added to the outer deferred
    def _build(self, cpath):
        self._path = cpath
        d = self._getConnection(self._path.entry)
        self._current_task = d
        d.addCallback(self._sendCreate2Cell, self._path.entry)
        d.addCallback(self._recvCell)
        d.addCallback(self._deriveCreate2CellSecrets, self._path.entry)
        for path_node in self._path[1:]:
            d.addCallback(self._sendExtend2Cell, path_node)
            d.addCallback(self._recvCell)
            d.addCallback(self._deriveExtend2CellSecrets, path_node)
        return d

    def _getConnection(self, path_node):

        d = self._connection_manager.getConnection(path_node.router_status_entry)
        self._current_task = d
        def addCirc(res):
            self._conn = res
            self._conn.addCircuit(self)
            return res
        d.addCallback(addCirc)
        return d

    def _sendCreate2Cell(self, _, path_node):
        self._hs_state = ntor.NTorState(path_node.microdescriptor)
        onion_skin = ntor.createOnionSkin(self._hs_state)
        create2 = Create2Cell.make(self.circuit_id, hdata=onion_skin)
        self._conn.send(create2)

    def _deriveCreate2CellSecrets(self, response, path_node):
        if isinstance(response, DestroyCell):
            msg = ("DestroyCell received from {}."
                   .format(path_node.router_status_entry.fingerprint))
            raise ValueError(msg)
        if not isinstance(response, Created2Cell):
            msg = ("Unexpected cell {} received from {}."
                   .format(response,
                           path_node.router_status_entry.fingerprint))
            destroy = DestroyCell.make(self.circuit_id)
            self._conn.send(destroy)
            raise ValueError(msg)

        self._crypt_path.append(ntor.deriveRelayCrypto(self._hs_state,
            response))
        # TODO: implement this
        #self._hs_state.memwipe()
        self._hs_state = None

    def _sendExtend2Cell(self, _, path_node):
        lspecs = [LinkSpecifier(path_node),
                  LinkSpecifier(path_node, legacy=True)]
        self._hs_state = ntor.NTorState(path_node.microdescriptor)
        onion_skin = ntor.createOnionSkin(self._hs_state)
        extend2 = RelayExtend2Cell.make(self.circuit_id, nspec=len(lspecs),
                                        lspecs=lspecs, hdata=onion_skin)
        crypt_cell = crypto.encryptCell(extend2, self._crypt_path,
                                        early=True)
        self._conn.send(crypt_cell)

    def _deriveExtend2CellSecrets(self, response, path_node):
        if isinstance(response, DestroyCell):
            msg = ("Destroy cell received from {} on pending circuit {}."
                   .format(path_node.router_status_entry.fingerprint,
                   self.circuit_id))
            raise ValueError(msg)

        cell, _ = crypto.decryptCell(response, self._crypt_path)

        if not isinstance(cell, RelayExtended2Cell):
            msg = ("CircuitBuildTask {} received an unexpected cell: {}. "
                   "Destroying the circuit."
                   .format(self.circuit_id, type(cell)))
            destroy = DestroyCell.make(self.circuit_id)
            self._conn.send(destroy)
            raise ValueError(msg)

        self._crypt_path.append(ntor.deriveRelayCrypto(self._hs_state, cell))
        # TODO: implement this
        #self._hs_state.memwipe()
        self._hs = None

    def _buildSucceeded(self, _):
        circuit = Circuit(self._circuit_manager, self.circuit_id, self._conn,
                          self.circuit_type, self._path, self._crypt_path)
        self._conn.addCircuit(circuit)
        self._circuit_manager.circuitOpened(circuit)

    def _buildFailed(self, reason):
        msg = ("Pending circuit {} failed. Reason: {}."
               .format(self.circuit_id, reason))
        logging.debug(msg)
        if self._conn is not None:
            self._conn.removeCircuit(self.circuit_id)
        self._circuit_manager.circuitDestroyed(self)
