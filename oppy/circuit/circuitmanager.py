# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

'''
.. topic:: Details

    CircuitManager manages a pool of circuits. CircuitManager knows about all
    open and pending circuits and can make choices about how and when
    circuits are built and destroyed.

    Currently, it's up to CircuitManager to:

        - Create an initial pool of circuits (currently 4 IPv4 and 1 IPv6
          initial circuits by default)
        - Handle incoming requests for open circuits (made by streams) and
          assign suitable circuits to handle the requests
        - Decide when and if a circuit should be destroyed when its stream
          count drops to zero
        - Replenish the circuit pool when a circuit is destroyed and, if
          necessary, build new circuits to handle any (now orphaned) pending
          streams
        - Assign pending streams to newly opened circuits when the circuits
          complete their extension process
        - Destroy all open and pending circuits when oppy shuts down

'''
import logging
import random

from collections import namedtuple

from twisted.internet import defer

from oppy.circuit.circuit import Circuit, CircuitType
from oppy.circuit.circuitbuildtask import CircuitBuildTask
from oppy.circuit.definitions import (
    DEFAULT_OPEN_IPv4,
    DEFAULT_OPEN_IPv6,
    MAX_STREAMS_V3,
)
from oppy.util.tools import ctr


PendingStream = namedtuple("PendingStream", (
    "stream",
    "deferred",
))


# Major TODO's:


class CircuitManager(object):
    '''Manage a pool of circuits.'''

    def __init__(self, connection_pool, autobuild=True):
        logging.debug("Creating circuit manager.")
        self._connection_pool = connection_pool
        self._ctr = ctr(MAX_STREAMS_V3)
        self._open_circuit_dict = {}
        self._circuit_build_task_dict = {}
        self._pending_stream_list = []
        self._min_IPv4_count = DEFAULT_OPEN_IPv4
        self._min_IPv6_count = DEFAULT_OPEN_IPv6
        self._sent_open_message = False

        if autobuild is True:
            self._buildCircuits(self._min_IPv4_count,
                                circuit_type=CircuitType.IPv4)
            self._buildCircuits(self._min_IPv6_count,
                                circuit_type=CircuitType.IPv6)

    # TODO: fix documentation
    def getOpenCircuit(self, stream):
        '''Return a deferred that will fire with an open circuit that can
        handle the stream's request.


        There are three general cases to handle when a new open circuit
        request comes in:

            1. An open circuit exists that can handle this request. In this
               case, choose a random circuit from the set of open circuits
               that can handle this request and immediately callback the
               deferred with the chosen open circuit.

            2. A pending circuit exists that, when open, can handle this
               request. In this case, add the request to a pool of pending
               requests. Whenever a circuit opens, circuit manager checks all
               pending requests and assigns any pending requests that the
               newly opened circuit can handle to that circuit. So when a
               pending circuit opens that can handle this stream, the
               stream's deferred will be called back with the fresly opened
               circuit.

            3. No open or pending circuits exist that can handle the request.
               In this case, begin building a new circuit that can. Add the
               request to a pending request pool and, when a circuit opens
               that can handle the request, callback this stream's deferred
               with the newly opened circuit.

        :param oppy.stream.stream.Stream stream: the stream that is
            requesting an open circuit
        :returns: **twisted.internet.defer.Deferred** which will fire when
            a circuit has opened that can handle this stream's request.
        '''
        logging.debug("Circuit manager got an open circuit request.")
        request = stream.request
        d = defer.Deferred()

        try:
            c = random.choice(self._getOpenCandidates(request))
            msg = "Assigning request to circuit {}.".format(c.circuit_id)
            logging.debug(msg)
            d.callback(c)
        except IndexError:
            if len(self._getPendingCandidates(request)) == 0:
                msg = "Building a new circuit to handle request."
                self._buildCircuit(request=request)
            else:
                msg = "A CircuitBuildTask can eventually handle request."

            logging.debug(msg)
            self._pending_stream_list.append(PendingStream(stream, d))

        return d

    def shouldDestroyCircuit(self, circuit):
        '''Return **True** iff CircuitManager thinks the calling circuit
        should be destroyed.

        Circuits call shouldDestroyCircuit() when their number of open
        streams drops to zero. Since CircuitManager knows about all open
        and pending circuits, it can make an informed judgement about whether
        the calling circuit should be destroyed or remain open.

        Currently, CircuitManager maintains at least 4 open or pending IPv4
        circuits and one open or pending IPv6 circuit. If the number of
        streams on any circuit drops to zero and it can be closed while still
        satisfying these basic constraints, then CircuitManager tells it
        to begin destroying itself (returns True).

        :param oppy.circuit.circuit.Circuit circuit: circuit to
            consider destroying.
        :returns: **bool** **True** if CircuitManager decides this circuit
            should be destroyed, **False** otherwise.
        '''
        # TODO: update for more kinds of circuits
        if circuit.circuit_type == CircuitType.IPv4:
            return self._totalIPv4Count()-1 > self._min_IPv4_count
        else:
            return self._totalIPv6Count()-1 > self._min_IPv6_count

    # TODO: fix docs to reflect CircuitBuildTask changes
    def circuitDestroyed(self, circuit):
        '''Circuits call circuitDestroyed() when they have cleaned up after
        themselves and closed.

        Circuits may need to do a number of things before references to
        them are completely removed. Exactly what steps a circuit needs to
        take before being fully destroyed depend on both the circuit's state
        and the state of the whole program. After a circuit has fully cleaned
        up after itself and taken all necessary closing actions, it calls
        CircuitManager.circuitDestroyed().

        circuitDestroyed() does three things:

            1. Remove the closed circuit from any internal maps.

            2. Check the pool of pending requests. If any pending requests
               exist that cannot be handled by any open or pending circuits,
               begin building a new circuit to handle these orphaned requests.
               This can happen when a circuit is built to handle a particular
               request but is then destroyed/an error occurs while it is being
               built.

            3. Check CircuitManager's basic open and pending circuit
               requirements to see if a new circuit of a certain type should
               be built. For instance, if an IPv4 circuit closes and the
               number of open and pending IPv4 circuits is below
               self._min_IPv4_count, a new IPv4 circuit will be built.

        :param circuit_id: id of circuit to be destroyed
        :type circuit_id: int
        '''
        cid = circuit.circuit_id
        try:
            del self._circuit_build_task_dict[cid]
            msg = "Destroyed CircuitBuildTask {}.".format(cid)
            logging.debug(msg)
        except KeyError:
            try:
                del self._open_circuit_dict[cid]
                msg = "Destroyed open circuit {}.".format(cid)
                logging.debug(msg)
            except KeyError:
                logging.debug("Circuit manager was notified that circuit {} "
                              "was destroyed, but manager has no reference to "
                              "that circuit.".format(cid))
                return

        self._assignAllPossiblePendingRequests()
        self._buildCircuitsForOrphanedPendingRequests()
        self._replenishCircuits()

    # TODO: fix/update docs
    def circuitOpened(self, circuit):
        '''Circuits call circuitOpened() when they have successfully
        completed their build process and are ready to handle incoming
        streams.

        When a circuit opens, CircuitManager:

            - removes it from the pending circuit map
            - adds it to the open circuit map
            - assigns any pending requests that this circuit can handle to
              this freshly opened circuit
            - if this is the first circuit successfully opened, send a nice
              message to the user letting them know oppy is ready to forward
              traffic

        :param oppy.circuit.circuit.Circuit circuit: circuit that
            has just opened.
        '''
        msg = "Circuit manager notified that circuit {} opened."
        logging.debug(msg.format(circuit.circuit_id))

        try:
            del self._circuit_build_task_dict[circuit.circuit_id]
        except KeyError:
            logging.debug("Circuit manager has no reference to circuit {}."
                          .format(circuit.circuit_id))
            return

        self._open_circuit_dict[circuit.circuit_id] = circuit
        self._assignPossiblePendingRequestsToCircuit(circuit)
        self._notifyUserCircuitOpened()

    def destroyAllCircuits(self, destroy_pending_streams=True):
        '''Destroy all open and pending circuits **and** remove all pending
        requests.
        '''
        msg = "Destroying all open and pending connections, circuits, and "
        msg += "streams."
        logging.debug(msg)

        if destroy_pending_streams is True:
            self._pending_stream_list = []

        for circuit in self._open_circuit_dict.values():
            circuit.destroyCircuitFromManager()

        for circuit in self._circuit_build_task_dict.values():
            circuit.destroyCircuitFromManager()

    def _buildCircuitsForOrphanedPendingRequests(self):
        orphaned_streams = [s for s in self._pending_stream_list
                            if len(self._getPendingCandidates(s.request)) == 0]
        self._buildCircuitsForPendingStreams(orphaned_streams)

    def _notifyUserCircuitOpened(self):
        if self._sent_open_message is False:
            msg = "Circuit built successfully! oppy is ready to forward "
            msg += "traffic :)"
            logging.info(msg)
            self._sent_open_message = True

    def _assignAllPossiblePendingRequests(self):
        for circuit in self._open_circuit_dict.values():
            self._assignPossiblePendingRequestsToCircuit(circuit)

    def _buildCircuit(self, circuit_type=CircuitType.IPv4, request=None,
                      autobuild=True):
        _id = next(self._ctr)
        task = CircuitBuildTask(self._connection_pool, self, _id,
                                circuit_type=circuit_type, request=request,
                                autobuild=autobuild)
        self._circuit_build_task_dict[_id] = task

    def _buildCircuits(self, count, circuit_type=CircuitType.IPv4,
                       request=None, autobuild=True):
        for _ in xrange(count):
            self._buildCircuit(circuit_type=circuit_type, request=request,
                               autobuild=autobuild)

    def _buildCircuitsForPendingStreams(self, pending_streams):
        for p in pending_streams:
            self._buildCircuit(request=p.request)

    def _assignPossiblePendingRequestsToCircuit(self, circuit):
        '''Check all pending requests and assign any requests to *circuit*
        that it can handle.

        If a pending request is assigned to *circuit*, remove that request
        from the pending request pool.

        :param oppy.circuit.circuit.Circuit circuit: circuit to try assigning
            pending requests to
        '''
        for pending_stream in self._pending_stream_list[:]:
            request = pending_stream.stream.request
            if circuit.canHandleRequest(request):
                msg = "Assigning pending request to opened circuit {}."
                logging.debug(msg.format(circuit.circuit_id))
                pending_stream.deferred.callback(circuit)
                self._pending_stream_list.remove(pending_stream)

    def _replenishCircuits(self):
        '''Decide whether or not to build a new circuit - called when a
        circuit is destroyed.

        Check CircuitManager's basic requirements for open/pending circuits.
        If they are not satisfied, build a new circuit.
        '''
        if self._totalIPv4Count() < self._min_IPv4_count:
            msg = "Replenishing circuit pool with a new IPv4 circuit."
            logging.debug(msg)
            self._buildCircuit(circuit_type=CircuitType.IPv4)

        if self._totalIPv6Count() < self._min_IPv6_count:
            msg = "Replenishing circuit pool with a new IPv6 circuit."
            logging.debug(msg)
            self._buildCircuit(circuit_type=CircuitType.IPv6)

    def _openIPv4Count(self):
        '''Return the number of open IPv4 circuits.

        :returns: **int** number of open IPv4 circuits
        '''
        return len([i for i in self._open_circuit_dict.values()
                    if i.circuit_type == CircuitType.IPv4])

    def _openIPv6Count(self):
        '''Return the number of open IPv6 circuits.

        :returns: **int** number of open IPv6 circuits.
        '''
        return len([i for i in self._open_circuit_dict.values()
                    if i.circuit_type == CircuitType.IPv6])

    def _pendingIPv4Count(self):
        '''Return the number of pending IPv4 circuits.

        :returns: **int** number of pending IPv4 circuits.
        '''
        return len([i for i in self._circuit_build_task_dict.values()
                   if i.circuit_type == CircuitType.IPv4])

    def _pendingIPv6Count(self):
        '''Return the number of pending IPv6 circuits.

        :returns: **int** number of pending IPv6 circuits
        '''
        return len([i for i in self._circuit_build_task_dict.values()
                    if i.circuit_type == CircuitType.IPv6])

    def _totalIPv4Count(self):
        '''Return the total (open + pending) IPv4 circuits.

        :returns: **int** total IPv4 circuits
        '''
        return self._openIPv4Count() + self._pendingIPv4Count()

    def _totalIPv6Count(self):
        '''Return the total (open + pending) IPv6 circuits.

        :returns: **int** total IPv6 circuits
        '''
        return self._openIPv6Count() + self._pendingIPv6Count()

    def _getOpenCandidates(self, request):
        '''Return a list of circuits whose exit relay claims to allow the
        *request*.

        :returns: **list, oppy.circuit.circuit.Circuit** open circuits whose
            exit relay can handle the request
        '''
        return [i for i in self._open_circuit_dict.values()
                if i.canHandleRequest(request)]

    def _getPendingCandidates(self, request):
        '''Return a list of pending circuits that claim to handle the
        request.

        .. note:: Since a pending circuit may not yet have an exit relay,
            whether or not this circuit can *actually* handle the request
            is just an informed guess. It may turn out that it can't
            **actually** handle the request once the circuit is open.

        :returns: **list, oppy.circuit.circuit.Circuit** pending circuits
            that can (probably) handle the request
        '''
        return [i for i in self._circuit_build_task_dict.values()
                if i.canHandleRequest(request)]
