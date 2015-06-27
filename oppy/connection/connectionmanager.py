# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

'''
.. topic:: Details

    The ConnectionPool manages a pool of TLS connections to entry nodes. The
    main job of the ConnectionPool is to hand out TLS connections to
    requesting circuits and keep track of all the open connections. TLS
    connections to the same entry nodes are shared among circuits.

'''
import logging

from twisted.internet import defer, endpoints
from twisted.internet.ssl import ClientContextFactory

from OpenSSL import SSL

from oppy.connection.connection import Connection
from oppy.connection.connectionbuildtask import ConnectionBuildTask
from oppy.connection.definitions import V3_CIPHER_STRING


class TLSClientContextFactory(ClientContextFactory):
    
    isClient = 1
    method = SSL.TLSv1_METHOD
    _contextFactory = SSL.Context

    def getContext(self):
        context = self._contextFactory(self.method)
        context.set_cipher_list(V3_CIPHER_STRING)
        return context


# TODO: when things are shut down from CTRL-C, it's ugly and should be fixed
class ConnectionManager(object):
    '''A pool of TLS connections to entry nodes.'''

    def __init__(self):
        logging.debug('Connection manager created.')
        self._connection_dict = {}
        self._pending_request_dict = {}

    # TODO: fix docs
    def getConnection(self, relay):
        '''Return a deferred which will fire (if connection attempt is
        successful) with a Connection Protocol made to *relay*.

        There are three general cases to handle for incoming connection
        requests:

            1. We already have an open TLS connection to the requested relay.
               In this case, immediately callback the deferred with the
               open connection.
            2. We're currently trying to connect to this relay. In this case,
               add the request to a pending request list for this relay.
               When the connection is made successfully, callback all
               pending request deferreds with the Connection, or errback
               all pending request deferreds on failure.
            3. We have no open or pending connections to this relay (i.e.
               this is the first connection request to this relay). In this
               case, create a new list of pending requests for this connection
               and add the current request. Create an SSL endpoint and add an
               appropriate callback and errback. If the request is successful,
               callback all pending requests with the open connection when
               it opens; errback all pending requests on failure.
        
        :param stem.descriptor.server_descriptor.RelayDescriptor relay:
            relay to make a TLS connection to
        :returns: **twisted.internet.defer.Deferred** which, on success, will
            callback with an oppy.connection.connection.Connection Protocol
            object

        XXX raises:
        '''
        from twisted.internet import reactor
        
        d = defer.Deferred()
        
        if relay.fingerprint in self._connection_dict:
            d.callback(self._connection_dict[relay.fingerprint])
        elif relay.fingerprint in self._pending_request_dict:
            self._pending_request_dict[relay.fingerprint].append(d)
        else:
            try:
                f = endpoints.connectProtocol(
                        endpoints.SSL4ClientEndpoint(reactor, relay.address,
                                                     relay.or_port,
                                                     TLSClientContextFactory()),
                        ConnectionBuildTask(self, relay))
                f.addErrback(self._initialConnectionFailed, relay.fingerprint)
                self._pending_request_dict[relay.fingerprint] = [d]
            except Exception as e:
                self._initialConnectionFailed(e, relay.fingerprint)

        return d

    # called when the initial connection fails
    # TODO: track these and timeout if we get too many failures
    def _initialConnectionFailed(self, reason, fingerprint):
        self.connectionTaskFailed(None, reason, fingerprint)

    def connectionTaskSucceeded(self, connection_task):
        '''For every pending request for this connection, callback the request
        deferred with this open connection, then remove this connection
        from the pending map and add to the connection map.
        
        Called when the TLS connection to the IP of relay with
        *fingerprint* opens successfully.

        :param oppy.connection.connection.Connection result: the successfully
            opened connection
        :param str fingerprint: fingerprint of relay we have connected to
        '''
        fprint = connection_task.relay.fingerprint

        if fprint not in self._pending_request_dict:
            msg = ("ConnectionManager notified that a connection to {} "
                   "was made successfully, but ConnectionManager has no "
                   "reference to this connection. Dropping.".format(fprint))
            logging.debug(msg)
            return

        connection = Connection(self, connection_task)
        self._connection_dict[fprint] = connection
        # We need to re-assign the transport from the ConnectionBuildTask
        # to the new Connection. This is fragile and should be updated after
        # Twisted bug #3204 is fixed: http://twistedmatrix.com/trac/ticket/3204
        connection.transport = connection_task.transport
        connection_task.transport = None
        connection.transport.wrappedProtocol = connection

        for request in self._pending_request_dict[fprint]:
            request.callback(connection)
        del self._pending_request_dict[fprint]

    def connectionTaskFailed(self, connection_task, reason, fprint=None):
        '''For every pending request for this connection, errback the request
        deferred. Remove this connection from the pending map.

        Called when the TLS connection to the IP of relay with
        *fingerprint* fails.

        :param reason reason: reason this connection failed
        :param str fingerprint: fingerprint of the relay this connection
            failed to
        '''
        # XXX update what args we're calling the errback here with
        fprint = fprint or connection_task.relay.fingerprint
        try:
            for request in self._pending_request_dict[fprint]:
                request.errback(reason)
            del self._pending_request_dict[fprint]
        except KeyError:
            msg = ("ConnectionManager notified that a connection to {} "
                   "failed, but ConnectionManager has no reference to this "
                   "connection. Dropping.".format(fprint))
            logging.debug(msg)

    def removeConnection(self, connection):
        '''Remove the connection to relay with *fingerprint* from the
        connection pool.

        :param str fingerprint: fingerprint of connection to remove
        '''
        fprint = connection.relay.fingerprint
        try:
            del self._connection_dict[connection.relay.fingerprint]
            logging.debug("ConnectionManager removed a connection to {}"
                          .format(fprint))
        except KeyError:
            logging.debug("ConnectionManager received a request to remove a "
                          "connection to {}, but CircuitManager has no "
                          "reference to that connection."
                          .format(fprint))

    def shouldDestroyConnection(self, connection):
        '''Return **True** if ConnectionPool thinks we should destroy the
        TLS connection to relay with *fingerprint*.

        Called when the number of circuits on a connection drops to zero.

        .. note:: For now, we always return True. Eventually, we may
            want to maintain a connection to any guards, even if there are
            no currently open circuits.

        :param str fingerprint: fingerprint of connection to check
        :returns: **bool** **True** if we think this connection should be
            destroyed
        '''
        return True
