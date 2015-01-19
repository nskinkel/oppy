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

from oppy.circuit.circuit import Circuit, CType
from oppy.path.path import PathConstraints
from oppy.path.defaults import (
    DEFAULT_ENTRY_FLAGS,
    DEFAULT_MIDDLE_FLAGS,
    DEFAULT_EXIT_FLAGS,
)


PendingStream = namedtuple("PendingStream", (
    "stream",
    "deferred",
))


DEFAULT_OPEN_IPv4 = 4
DEFAULT_OPEN_IPv6 = 1


DEFAULT_IPv4_CONSTRAINTS = PathConstraints(
    # add guard here with 'fingerprint': 'value' arg for exit
    entry={'flags': DEFAULT_ENTRY_FLAGS, 'ntor': True},
    middle={'flags': DEFAULT_MIDDLE_FLAGS, 'ntor': True},
    exit={'flags': DEFAULT_EXIT_FLAGS, 'ntor': True},
)
DEFAULT_IPv6_CONSTRAINTS = PathConstraints(
    entry={'flags': DEFAULT_ENTRY_FLAGS, 'ntor': True},
    middle={'flags': DEFAULT_MIDDLE_FLAGS, 'ntor': True},
    exit={'flags': DEFAULT_EXIT_FLAGS, 'ntor': True,
          'exit_IPv6': True},
)


class CircuitManager(object):
    '''Manage a pool of circuits.'''

    def __init__(self):
        logging.debug("Creating circuit manager.")
        self._open_circuit_map = {}
        self._pending_circuit_map = {}
        self._pending_stream_pool = []
        self._id_counter = 1
        self._min_IPv4_count = DEFAULT_OPEN_IPv4
        self._min_IPv6_count = DEFAULT_OPEN_IPv6
        self._sent_open_message = False
        # create default circuit pool
        for i in xrange(self._min_IPv4_count):
            self._buildNewCircuit(DEFAULT_IPv4_CONSTRAINTS)

        for i in xrange(self._min_IPv6_count):
            self._buildNewCircuit(DEFAULT_IPv6_CONSTRAINTS)

    def requestOpenCircuit(self, stream):
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
        # list of currently open circuits that can handle the given request
        open_candidates = self._getOpenCandidates(request)
        # choose a random open circuit for this request if we can
        if len(open_candidates) > 0:
            circuit_choice = random.choice(open_candidates)
            msg = "Assigning request to circuit {}."
            logging.debug(msg.format(circuit_choice.circuit_id))
            d.callback(circuit_choice)
        else:
            # list of circuits currently being built that can handle the
            # given request
            pending_candidates = self._getPendingCandidates(request)
            # if we have no pending circuits that can handle this request,
            # start building a new one that can
            if len(pending_candidates) == 0:
                msg = "Building a new circuit to handle the new request."
                logging.debug(msg)
                self._buildNewCircuitForRequest(request)

            self._pending_stream_pool.append(PendingStream(stream, d))

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
        if circuit.ctype == CType.IPv4:
            if self._totalIPv4Count() - 1 < self._min_IPv4_count:
                return False
            return True

        if self._totalIPv6Count() - 1 < self._min_IPv6_count:
            return False
        return True

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
        if cid not in self._pending_circuit_map and cid not in self._open_circuit_map:
            msg = "Circuit manager was notified that circuit {} was destroyed,"
            msg += " but manager has no reference to this circuit."
            logging.debug(msg)
            return

        try:
            del self._pending_circuit_map[cid]
            msg = "Destroyed pending circuit {}.".format(cid)
            logging.debug(msg)
        except KeyError:
            del self._open_circuit_map[cid]
            msg = "Destroyed open circuit {}.".format(cid)
            logging.debug(msg)

        # assign any pending stream requests we can to open circuits
        for circ in self._open_circuit_map.values():
            self._assignPossiblePendingRequests(circ)

        # build new circuits to handle any pending requests that can't
        # currently be satisfied.
        for pending_stream in self._pending_stream_pool:
            request = pending_stream.stream.request
            if len(self._getPendingCandidates(request)) == 0:
                msg = "After destroying circuit {}, a pending request has no "
                msg += "circuits that can handle it. Creating a new circuit."
                logging.debug(msg.format(cid))
                self._buildNewCircuitForRequest(request)

        # if we've dropped below the default number of circuits that should
        # be open, start building a new circuit
        self._considerReplenishingCircuitPool()

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
        # remove circuit from pending map
        try:
            del self._pending_circuit_map[circuit.circuit_id]
        except KeyError:
            msg = "Circuit manager was notified circuit {} opened, but "
            msg += "manager has no reference to this circuit."
            logging.debug(msg.format(circuit.circuit_id))
            return

        # add to open map
        self._open_circuit_map[circuit.circuit_id] = circuit
        # assign new circuit any pending streams it can handle
        self._assignPossiblePendingRequests(circuit)

        # send a nice message letting the user know we opened a circuit if
        # we haven't done so yet
        if self._sent_open_message is False:
            msg = "Circuit built successfully! oppy is ready to forward "
            msg += "traffic :)"
            logging.info(msg)
            self._sent_open_message = True

    def destroyAllCircuits(self):
        '''Destroy all open and pending circuits **and** remove all pending
        requests.
        '''
        msg = "Destroying all open and pending connections, circuits, and "
        msg += "streams."
        logging.debug(msg)

        self._pending_stream_pool = []

        for circuit in self._open_circuit_map.values():
            circuit.destroyCircuitFromManager()

        for circuit in self._pending_circuit_map.values():
            circuit.destroyCircuitFromManager()

    def _assignPossiblePendingRequests(self, circuit):
        '''Check all pending requests and assign any requests to *circuit*
        that it can handle.

        If a pending request is assigned to *circuit*, remove that request
        from the pending request pool.

        :param oppy.circuit.circuit.Circuit circuit: circuit to try assigning
            pending requests to
        '''
        # register any pending streams that this circuit can handle
        for pending_stream in self._pending_stream_pool[:]:
            request = pending_stream.stream.request
            # if this circuit can handle a request, callback with this circuit
            if circuit.canHandleRequest(request):
                msg = "Assigning pending request to opened circuit {}."
                logging.debug(msg.format(circuit.circuit_id))
                pending_stream.deferred.callback(circuit)
                self._pending_stream_pool.remove(pending_stream)

    def _buildNewCircuit(self, path_constraints):
        '''Build a new circuit, using a path that satisfies
        *path_constraints*.

        Assign an ID to the new circuit and add it to the pending circuit
        map.

        :param oppy.path.path.PathConstraints path_constraints: The path
            constraints that the new circuit's path should satisfy.
        '''
        msg = "Building a new circuit with id {}."
        logging.debug(msg.format(self._id_counter))
        new_circuit = Circuit(self._id_counter, path_constraints)
        self._pending_circuit_map[new_circuit.circuit_id] = new_circuit
        self._id_counter += 1

    def _buildNewCircuitForRequest(self, request):
        '''Build a new circuit such that the circuit's exit relay claims to
        allow the *request*.

        :param oppy.util.exitrequest.ExitRequest request: The request that
            the new circuit's exit relay should allow.
        '''
        # build a new circuit with default flags and ntor that has an exit
        # node that can handle request
        dest = request.addr + ':' + str(request.port)
        entry = {'flags': DEFAULT_ENTRY_FLAGS, 'ntor': True}
        middle = {'flags': DEFAULT_MIDDLE_FLAGS, 'ntor': True}

        if request.is_ipv4:
            exit = {'flags': DEFAULT_EXIT_FLAGS, 'ntor': True,
                    'exit_to_IP_and_port': dest}
        else:
            exit = {'flags': DEFAULT_EXIT_FLAGS, 'ntor': True,
                    'exit_IPv6': True, 'exit_to_IP_and_port': dest}

        constraints = PathConstraints(entry=entry, middle=middle, exit=exit)
        self._buildNewCircuit(constraints)

    def _considerReplenishingCircuitPool(self):
        '''Decide whether or not to build a new circuit - called when a
        circuit is destroyed.

        Check CircuitManager's basic requirements for open/pending circuits.
        If they are not satisfied, build a new circuit.
        '''
        # check if we're below the threshold of either IPv4 or IPv6 circuits
        # we should have open or pending. if so, build a new circuit of
        # the required type
        if self._totalIPv4Count() < self._min_IPv4_count:
            msg = "Replenishing circuit pool with a new IPv4 circuit."
            logging.debug(msg)
            self._buildNewCircuit(DEFAULT_IPv4_CONSTRAINTS)

        if self._totalIPv6Count() < self._min_IPv6_count:
            msg = "Replenishing circuit pool with a new IPv6 circuit."
            logging.debug(msg)
            self._buildNewCircuit(DEFAULT_IPv6_CONSTRAINTS)

    def _openIPv4Count(self):
        '''Return the number of open IPv4 circuits.

        :returns: **int** number of open IPv4 circuits
        '''
        return len([i for i in self._open_circuit_map.values()
                    if i.ctype == CType.IPv4])

    def _openIPv6Count(self):
        '''Return the number of open IPv6 circuits.

        :returns: **int** number of open IPv6 circuits.
        '''
        return len([i for i in self._open_circuit_map.values()
                    if i.ctype == CType.IPv6])

    def _pendingIPv4Count(self):
        '''Return the number of pending IPv4 circuits.

        :returns: **int** number of pending IPv4 circuits.
        '''
        return len([i for i in self._pending_circuit_map.values()
                   if i.ctype == CType.IPv4])

    def _pendingIPv6Count(self):
        '''Return the number of pending IPv6 circuits.

        :returns: **int** number of pending IPv6 circuits
        '''
        return len([i for i in self._pending_circuit_map.values()
                    if i.ctype == CType.IPv6])

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
        return [i for i in self._open_circuit_map.values()
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
        return [i for i in self._pending_circuit_map.values()
                if i.canHandleRequest(request)]
