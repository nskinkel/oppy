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
from oppy.connection.definitions import V3_CIPHER_STRING


class TLSClientContextFactory(ClientContextFactory):
    
    isClient = 1
    method = SSL.TLSv1_METHOD
    _contextFactory = SSL.Context

    def getContext(self):
        context = self._contextFactory(self.method)
        context.set_cipher_list(V3_CIPHER_STRING)
        return context


class ConnectionPool(object):
    '''A pool of TLS connections to entry nodes.'''

    def __init__(self):
        logging.debug('Connection pool created.')
        self._connection_map = {}
        self._pending_map = {}

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
        '''
        from twisted.internet import reactor
        
        d = defer.Deferred()
        # case 1
        if relay.fingerprint in self._connection_map:
            d.callback(self._connection_map[relay.fingerprint])
        # case 2
        elif relay.fingerprint in self._pending_map:
            self._pending_map[relay.fingerprint].append(d)
        # case 3
        else:
            connection_defer = endpoints.connectProtocol(
                        endpoints.SSL4ClientEndpoint(reactor, relay.address,
                                                     relay.or_port,
                                                     TLSClientContextFactory()),
                        Connection(relay)
            )
            connection_defer.addCallback(self._connectionSucceeded,
                                         relay.fingerprint)
            connection_defer.addErrback(self._connectionFailed,
                                        relay.fingerprint)
            self._pending_map[relay.fingerprint] = []
            self._pending_map[relay.fingerprint].append(d)

        return d

    def _connectionSucceeded(self, result, fingerprint):
        '''For every pending request for this connection, callback the request
        deferred with this open connection, then remove this connection
        from the pending map and add to the connection map.
        
        Called when the TLS connection to the IP of relay with
        *fingerprint* opens successfully.

        :param oppy.connection.connection.Connection result: the successfully
            opened connection
        :param str fingerprint: fingerprint of relay we have connected to
        '''
        for request in self._pending_map[fingerprint]:
            request.callback(result)
        del self._pending_map[fingerprint]
        self._connection_map[fingerprint] = result

    def _connectionFailed(self, reason, fingerprint):
        '''For every pending request for this connection, errback the request
        deferred. Remove this connection from the pending map.

        Called when the TLS connection to the IP of relay with
        *fingerprint* fails.

        :param reason reason: reason this connection failed
        :param str fingerprint: fingerprint of the relay this connection
            failed to
        '''
        msg = "Connection to {} failed: {}.".format(fingerprint, reason)
        logging.debug(msg)
        for request in self._pending_map[fingerprint]:
            request.errback(reason)
        del self._pending_map[fingerprint]

    def removeConnection(self, fingerprint):
        '''Remove the connection to relay with *fingerprint* from the
        connection pool.

        :param str fingerprint: fingerprint of connection to remove
        '''
        if fingerprint in self._connection_map:
            del self._connection_map[fingerprint]

    def shouldDestroyConnection(self, fingerprint):
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
