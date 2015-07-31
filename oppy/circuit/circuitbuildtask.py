# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

# TODO: fix imports
import logging

from twisted.internet import defer
from twisted.python.failure import Failure

import oppy.crypto.util as crypto
import oppy.path.path as path
import oppy.crypto.ntor as ntor

from oppy.cell.fixedlen import Create2Cell, Created2Cell, DestroyCell
from oppy.cell.relay import RelayExtend2Cell, RelayExtended2Cell
from oppy.cell.util import LinkSpecifier
from oppy.circuit.circuit import Circuit
from oppy.circuit.definitions import CircuitType
from oppy.cell.definitions import (
    CREATED2_CMD,
    DESTROY_CMD,
    RELAY_EXTENDED2_CMD,
)


class BuildTaskDestroyed(Exception):
    pass


# Major TODO's:
#               - handle cells with unexpected origins
#               - docs
#               - figure out where alreadyCalledError is coming from when
#                 building a path fails
class CircuitBuildTask(object):

    def __init__(self, connection_manager, circuit_manager, netstatus,
        guard_manager, _id, circuit_type=None, request=None, autobuild=True):

        self.connection_manager = connection_manager
        self.circuit_manager = circuit_manager
        self.netstatus = netstatus
        self.guard_manager = guard_manager
        self.id = _id
        self.circuit_type = circuit_type
        self.request = request
        self.handshake_state = None
        self.path = None
        self.conn = None
        self.crypt_path = []
        self._read_queue = defer.DeferredQueue()
        self.autobuild = autobuild
        self.tasks = None
        self.current_task = None
        self._canceled = False

        if autobuild is True:
            self.build()

    def build(self):
        try:
            # TODO: update for stable/fast flags based on circuit_type
            self.tasks = path.getPath(self.netstatus, self.guard_manager,
                exit_request=self.request)
            if self._canceled:
                # we may have been destroyed while waiting for a path
                raise BuildTaskDestroyed()
        except Exception as e:
            _buildFailed(e, self)
            return

        self.current_task = self.tasks
        self.tasks.addCallback(self._build)
        self.tasks.addCallback(_buildSucceeded, self)
        self.tasks.addErrback(_buildFailed, self)

    def _build(self, chosen_path):
        self.path = chosen_path
        d = _getConnection(self, self.path.entry)
        self.current_task = d
        d.addCallback(_sendCreate2Cell, self, self.path.entry)
        d.addCallback(_deriveCreate2CellSecrets, self, self.path.entry)
        for node in self.path[1:]:
            d.addCallback(_sendExtend2Cell, self, node)
            d.addCallback(_deriveExtend2CellSecrets, self, node)
        return d

    def canHandleRequest(self, request):
        if self.path is None:
            if request.is_host:
                return True
            elif request.is_ipv4:
                return self.circuit_type == CircuitType.IPv4
            else:
                return self.circuit_type == CircuitType.IPv6
        else:
            return self.path.exit.microdescriptor.exit_policy.can_exit_to(
                port=request.port)

    def recv(self, cell):
        self._read_queue.put(cell)

    def recvCell(self):
        self.current_task = self._read_queue.get()
        return self.current_task

    def destroyCircuitFromManager(self):
        if self.current_task:
            self.current_task.errback(Failure(BuildTaskDestroyed(
                "CircuitBuildTask {} destroyed from manager.".format(self.id))))
        self._canceled = True

    def destroyCircuitFromConnection(self):
        if self.current_task:
            self.current_task.errback(Failure(BuildTaskDestroyed(
                "CircuitBuildTask {} destroyed from connection.".format(self.id))))
        self._canceled = True


def _getConnection(task, node):
    d = task.connection_manager.getConnection(node.router_status_entry)
    task.current_task = d
    def addCircuit(connection_result):
        task.conn = connection_result
        task.conn.addCircuit(task)
    d.addCallback(addCircuit)
    return d


def _buildSucceeded(_, task):
    circuit = Circuit(task.circuit_manager, task.id, task.conn,
        task.circuit_type, task.path, task.crypt_path)
    task.conn.addCircuit(circuit)
    task.circuit_manager.circuitOpened(circuit)


def _buildFailed(reason, task):
    logging.debug("Pending circuit {} failed. Reason: {}."
                  .format(task.id, reason))
    if task.conn is not None:
        task.conn.removeCircuit(task.id)
    task.circuit_manager.circuitDestroyed(task)


def _sendCreate2Cell(_, task, node):
    task.handshake_state = ntor.NTorState(node.microdescriptor)
    onion_skin = ntor.createOnionSkin(task.handshake_state)
    create2 = Create2Cell.make(task.id, hdata=onion_skin)
    task.conn.send(create2)
    return task.recvCell()


def _sendExtend2Cell(_, task, node):
    lspecs = [LinkSpecifier(node), LinkSpecifier(node, legacy=True)]
    task.handshake_state = ntor.NTorState(node.microdescriptor)
    onion_skin = ntor.createOnionSkin(task.handshake_state)
    extend2 = RelayExtend2Cell.make(task.id, nspec=len(lspecs), lspecs=lspecs,
        hdata=onion_skin)
    crypt_cell = crypto.encryptCell(extend2, task.crypt_path, early=True)
    task.conn.send(crypt_cell)
    return task.recvCell()


def _deriveCreate2CellSecrets(response, task, node):
    _checkResponseCmd(response, node, task, cmd=CREATED2_CMD)
    crypt_node = ntor.deriveRelayCrypto(task.handshake_state, response)
    task.crypt_path.append(crypt_node)


def _deriveExtend2CellSecrets(response, task, node):
    cell, _ = crypto.decryptCell(response, task.crypt_path)
    _checkResponseCmd(cell, node, task, rcmd=RELAY_EXTENDED2_CMD)
    crypt_node = ntor.deriveRelayCrypto(task.handshake_state, cell)
    task.crypt_path.append(crypt_node)


def _checkResponseCmd(response, node, task, cmd=None, rcmd=None):
    fprint = node.router_status_entry.fingerprint
    if response.header.cmd == DESTROY_CMD:
        raise ValueError("DestroyCell received from {}".format(fprint))
    fail = False
    if (cmd and response.header.cmd != cmd) or \
       (rcmd and response.rheader.cmd != rcmd):
        destroy = DestroyCell.make(task.id)
        task.conn.send(destroy)
        raise ValueError("Unexpected {} received from {}.".format(
            type(response), fprint))
