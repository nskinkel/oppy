import mock

from twisted.trial import unittest

from OpenSSL import SSL

from oppy.connection import connectionmanager


class ConnectionManagerTest(unittest.TestCase):

    def setUp(self):
        self.cm = connectionmanager.ConnectionManager()

    # TODO: test that cipher list is set properly for v3 protocol
    def test_TLSClientContextFactory_v3(self):
        t = connectionmanager.TLSClientContextFactory()

        self.assertEqual(t.isClient, 1)
        self.assertEqual(t.method, SSL.TLSv1_METHOD)
        self.assertEqual(t._contextFactory, SSL.Context)

    @mock.patch('twisted.internet.endpoints', autospec=True)
    def test_getConnection_have_connection(self, mock_endpoints):
        mock_relay = mock.Mock()
        mock_relay.fingerprint = 'test'
        mock_connection = mock.Mock()
        self.cm._connection_dict['test'] = mock_connection

        d = self.cm.getConnection(mock_relay)

        self.assertEqual(mock_connection, self.successResultOf(d))
        self.assertEqual(mock_endpoints.connectProtocol.call_count, 0)

    @mock.patch('twisted.internet.endpoints', autospec=True)
    def test_getConnection_have_pending_connection(self, mock_endpoints):
        mock_relay = mock.Mock()
        mock_relay.fingerprint = 'test'
        self.cm._pending_request_dict['test'] = []

        d = self.cm.getConnection(mock_relay)

        self.assertEqual(self.cm._pending_request_dict['test'], [d])
        self.assertEqual(len(self.cm._pending_request_dict), 1)
        self.assertEqual(mock_endpoints.connectProtocol.call_count, 0)

    @mock.patch('twisted.internet.reactor')
    @mock.patch('oppy.connection.connectionmanager.endpoints', autospec=True)
    @mock.patch('oppy.connection.connectionmanager.ConnectionBuildTask',
                autospec=True)
    @mock.patch('oppy.connection.connectionmanager.TLSClientContextFactory')
    def test_getConnection_build_new_connection(self, mock_tls_ctx, mock_cbt,
                                                mock_endpoints, mock_reactor):
        mock_deferred = mock.Mock()
        mock_deferred.addErrback = mock.Mock()
        mock_endpoints.connectProtocol.return_value = mock_deferred
        mock_endpoints.SSL4ClientEndpoint.return_value = 'testval1'
        mock_cbt_instance = mock_cbt.return_value

        mock_relay = mock.Mock()
        mock_relay.fingerprint = 'test'
        mock_relay.or_port = 0
        mock_relay.address = 'address'

        mock_ctx = mock_tls_ctx.return_value

        d = self.cm.getConnection(mock_relay)

        self.assertEqual(mock_endpoints.connectProtocol.call_count, 1)
        self.assertEqual(mock_endpoints.connectProtocol.call_args_list,
                                [mock.call('testval1', mock_cbt_instance)])
        self.assertEqual(mock_endpoints.SSL4ClientEndpoint.call_count, 1)
        self.assertEqual(mock_endpoints.SSL4ClientEndpoint.call_args_list,
                        [mock.call(mock_reactor, 'address', 0, mock_ctx)])
        self.assertEqual(mock_cbt.call_count, 1)
        self.assertEqual(mock_cbt.call_args_list,
                                            [mock.call(self.cm, mock_relay)])
        self.assertEqual(mock_deferred.addErrback.call_count, 1)
        self.assertEqual(mock_deferred.addErrback.call_args_list,
                        [mock.call(self.cm._initialConnectionFailed, 'test')])
        self.assertEqual(self.cm._pending_request_dict['test'], [d])

    @mock.patch('twisted.internet.reactor')
    @mock.patch('oppy.connection.connectionmanager.endpoints', autospec=True)
    @mock.patch('oppy.connection.connectionmanager.ConnectionBuildTask',
                autospec=True)
    @mock.patch('oppy.connection.connectionmanager.TLSClientContextFactory')
    def test_getConnection_connection_failed(self, mock_tls_ctx, mock_cbt,
                                                mock_endpoints, mock_reactor):
        mock_deferred = mock.Mock()
        mock_deferred.addErrback = mock.Mock()
        mock_endpoints.connectProtocol.return_value = mock_deferred
        exc = Exception()
        mock_endpoints.SSL4ClientEndpoint.side_effect = exc
        mock_cbt_instance = mock_cbt.return_value

        mock_relay = mock.Mock()
        mock_relay.fingerprint = 'test'
        mock_relay.or_port = 0
        mock_relay.address = 'address'

        mock_ctx = mock_tls_ctx.return_value

        self.cm._initialConnectionFailed = mock.Mock()

        d = self.cm.getConnection(mock_relay)

        self.assertEqual(self.cm._initialConnectionFailed.call_count, 1)
        self.assertEqual(self.cm._initialConnectionFailed.call_args_list,
                        [mock.call(exc, 'test')])

    def test_initialConnectionFailed(self):
        self.cm.connectionTaskFailed = mock.Mock()

        self.cm._initialConnectionFailed('t1', 't2')

        self.assertEqual(self.cm.connectionTaskFailed.call_count, 1)
        self.assertEqual(self.cm.connectionTaskFailed.call_args_list,
                        [mock.call(None, 't1', 't2')])

    @mock.patch('oppy.connection.connectionmanager.Connection', autospec=True)
    def test_connectionTaskSucceeded(self, mock_connection):
        mock_cbt = mock.Mock()
        mock_transport = mock.Mock()
        mock_cbt.transport = mock_transport
        mock_cbt.micro_status_entry = mock.Mock()
        mock_cbt.micro_status_entry.fingerprint = 'test'
        mock_request_1 = mock.Mock()
        mock_request_1.callback = mock.Mock()
        mock_request_2 = mock.Mock()
        mock_request_2.callback = mock.Mock()
        self.cm._pending_request_dict['test'] = [mock_request_1,
                                                 mock_request_2]

        mock_conn_instance = mock_connection.return_value

        self.cm.connectionTaskSucceeded(mock_cbt)

        self.assertEqual(self.cm._connection_dict['test'], mock_conn_instance)
        self.assertEqual(mock_conn_instance.transport, mock_transport)
        self.assertEqual(mock_conn_instance.transport.wrappedProtocol,
                         mock_conn_instance)
        mock_request_1.callback.assert_called_once_with(mock_conn_instance)
        mock_request_2.callback.assert_called_once_with(mock_conn_instance)
        self.assertTrue(mock_cbt not in self.cm._pending_request_dict)
        self.assertTrue('test' not in self.cm._pending_request_dict.keys())

    @mock.patch('oppy.connection.connectionmanager.logging', autospec=True)
    def test_connectionTaskSucceeded_no_reference(self, mock_logging):
        mock_cbt = mock.Mock()
        mock_cbt.micro_status_entry = mock.Mock()
        mock_cbt.micro_status_entry.fingerprint = 'test'

        self.cm.connectionTaskSucceeded(mock_cbt)

        self.assertTrue(mock_cbt not in self.cm._connection_dict)
        self.assertEqual(mock_logging.debug.call_count, 1)

    def test_connectionTaskFailed(self):
        mock_cbt = mock.Mock()
        mock_cbt.micro_status_entry = mock.Mock()
        mock_cbt.micro_status_entry.fingerprint = 'test'
        mock_request_1 = mock.Mock()
        mock_request_1.errback = mock.Mock()
        mock_request_2 = mock.Mock()
        mock_request_2.errback = mock.Mock()
        self.cm._pending_request_dict['test'] = [mock_request_1,
                                                 mock_request_2]

        self.cm.connectionTaskFailed(mock_cbt, 'reason')

        self.assertTrue('test' not in self.cm._pending_request_dict)
        mock_request_1.errback.assert_called_once_with('reason')
        mock_request_2.errback.assert_called_once_with('reason')

    @mock.patch('oppy.connection.connectionmanager.logging', autospec=True)
    def test_connectionTaskFailed_no_reference(self, mock_logging):
        mock_cbt = mock.Mock()
        mock_cbt.micro_status_entry = mock.Mock()
        mock_cbt.micro_status_entry.fingerprint = 'test'

        self.cm.connectionTaskFailed(mock_cbt, 'reason')

        self.assertEqual(mock_logging.debug.call_count, 1)

    def test_removeConnection(self):
        mock_connection = mock.Mock()
        mock_connection.micro_status_entry = mock.Mock()
        mock_connection.micro_status_entry.fingerprint = 'test'

        self.cm._connection_dict['test'] = mock_connection

        self.cm.removeConnection(mock_connection)

        self.assertTrue(mock_connection not in self.cm._connection_dict)
        self.assertEqual(len(self.cm._connection_dict), 0)

    @mock.patch('oppy.connection.connectionmanager.logging', autospec=True)
    def test_removeConnection_no_reference(self, mock_logging):
        mock_connection = mock.Mock()
        mock_connection.micro_status_entry = mock.Mock()
        mock_connection.micro_status_entry.fingerprint = 'test'

        self.cm.removeConnection(mock_connection)
        self.assertEqual(mock_logging.debug.call_count, 1)

    def test_shouldDestroyConnection(self):
        self.assertTrue(self.cm.shouldDestroyConnection(mock.Mock()))
