import mock

from twisted.internet import defer
from twisted.trial import unittest

from oppy.circuit.circuitbuildtask import CircuitBuildTask
from oppy.circuit.definitions import CircuitType
from oppy.cell.fixedlen import Created2Cell, DestroyCell
from oppy.cell.relay import RelayExtended2Cell
from oppy.path.path import Path
from oppy.util.exitrequest import ExitRequest


ID = 0


class CircuitBuildTaskTest(unittest.TestCase):

    @mock.patch('oppy.circuit.circuitbuildtask.logging', autospec=True)
    @mock.patch('oppy.connection.connectionpool.ConnectionPool', autospec=True)
    @mock.patch('oppy.circuit.circuitmanager.CircuitManager', autospec=True)
    def setUp(self, cm, cp, ml):
        self.cm = cm
        self.cp = cp
        self.circuit = CircuitBuildTask(self.cp, self.cm, ID,
                                        CircuitType.IPv4,
                                        autobuild=False)
        self.mock_logging = ml

    def test_canHandleRequest_ipv4_yes_no_path(self):
        self.circuit.circuit_type = CircuitType.IPv4
        request = ExitRequest('\x01\xbb', addr=u'127.0.0.1')
        self.assertTrue(self.circuit.canHandleRequest(request))

    def test_canHandleRequest_ipv4_no_no_path(self):
        self.circuit.circuit_type = CircuitType.IPv4
        request = ExitRequest('\x01\xbb', addr=u'2001:db8::')
        self.assertFalse(self.circuit.canHandleRequest(request))

    def test_canHandleRequest_ipv6_yes_no_path(self):
        self.circuit.circuit_type = CircuitType.IPv6
        request = ExitRequest('\x01\xbb', addr=u'2001:db8::')
        self.assertTrue(self.circuit.canHandleRequest(request))

    def test_canHandleRequest_ipv6_no_no_path(self):
        self.circuit.circuit_type = CircuitType.IPv4
        request = ExitRequest('\x01\xbb', addr=u'2001:db8::')
        self.assertFalse(self.circuit.canHandleRequest(request))

    def test_canHandleRequest_host_yes_no_path(self):
        self.circuit.circuit_type = CircuitType.IPv4
        request = ExitRequest('\x01\xbb', host='https://riseup.net')
        self.assertTrue(self.circuit.canHandleRequest(request))

    def test_canHandleRequest_host_path(self):
        mock_request = mock.Mock()
        mock_request.is_host = True
        mock_port = mock.Mock()
        mock_request.port = mock_port
        path_mock = mock.Mock()
        mock_exit = mock.Mock()
        mock_exit.exit_policy = mock.Mock()
        mock_exit.exit_policy.can_exit_to = mock.Mock()
        path_mock.exit = mock_exit
        self.circuit._path = path_mock
        self.circuit.circuit_type = CircuitType.IPv4

        self.circuit.canHandleRequest(mock_request)

        mock_exit.exit_policy.can_exit_to.assert_called_once_with(
                                                       port=mock_request.port,
                                                       strict=False)

    def test_canHandleRequest_ip_path(self):
        mock_request = mock.Mock()
        mock_request.is_host = False
        mock_port = mock.Mock()
        mock_request.port = mock_port
        mock_addr = mock.Mock()
        mock_request.addr = mock_addr
        path_mock = mock.Mock()
        mock_exit = mock.Mock()
        mock_exit.exit_policy = mock.Mock()
        mock_exit.exit_policy.can_exit_to = mock.Mock()
        path_mock.exit = mock_exit
        self.circuit._path = path_mock
        self.circuit.circuit_type = CircuitType.IPv4

        self.circuit.canHandleRequest(mock_request)

        mock_exit.exit_policy.can_exit_to.assert_called_once_with(
                                                       port=mock_request.port,
                                                    address=mock_request.addr)

    def test_recv(self):
        cell = mock.Mock()
        self.circuit._read_queue = mock.Mock()
        self.circuit.recv(cell)
        self.circuit._read_queue.put.assert_called_once_with(cell)

    @mock.patch('oppy.path.path.getPath')
    def test_destroyCircuitFromManager_before_chain(self, mock_getPath):
        d = defer.Deferred()
        mock_getPath.return_value = d
        self.circuit._buildFailed = mock.Mock()
        self.circuit._buildSucceeded = mock.Mock()

        self.circuit.build()
        self.circuit.destroyCircuitFromManager()

        self.assertEqual(self.circuit._buildFailed.call_count, 1)
        self.assertEqual(self.circuit._buildSucceeded.call_count, 0)

    @mock.patch('oppy.path.path.getPath')
    def test_destroyCircuitFromManager_in_callback_chain(self, mock_getPath):
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()
        mock_path = Path(mock.Mock(), mock.Mock(), mock.Mock())
        d = defer.Deferred()
        dx = defer.Deferred()
        dy = defer.Deferred()
        mock_getPath.return_value = d

        self.circuit._getConnection = mock.Mock()
        self.circuit._getConnection.return_value = dx
        self.circuit._sendCreate2Cell = mock.Mock()
        self.circuit._sendCreate2Cell.return_value = 'test'

        self.circuit.build()
        d.callback(mock_path)
        dx.callback('test')
        self.circuit.destroyCircuitFromManager()

        self.assertEqual(self.circuit._buildSucceeded.call_count, 0)
        self.assertEqual(self.circuit._buildFailed.call_count, 1)

    @mock.patch('oppy.path.path.getPath')
    def test_destroyCircuitFromConnection_before_chain(self, mock_getPath):
        d = defer.Deferred()
        mock_getPath.return_value = d
        self.circuit._buildFailed = mock.Mock()
        self.circuit._buildSucceeded = mock.Mock()

        self.circuit.build()
        self.circuit.destroyCircuitFromConnection()

        self.assertEqual(self.circuit._buildFailed.call_count, 1)
        self.assertEqual(self.circuit._buildSucceeded.call_count, 0)

    @mock.patch('oppy.path.path.getPath')
    def test_destroyCircuitFromConnection_in_callback_chain(self,
                                                            mock_getPath):
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()
        mock_path = Path(mock.Mock(), mock.Mock(), mock.Mock())
        d = defer.Deferred()
        dx = defer.Deferred()
        dy = defer.Deferred()
        mock_getPath.return_value = d

        self.circuit._getConnection = mock.Mock()
        self.circuit._getConnection.return_value = dx
        self.circuit._sendCreate2Cell = mock.Mock()
        self.circuit._sendCreate2Cell.return_value = 'test'

        self.circuit.build()
        d.callback(mock_path)
        dx.callback('test')
        self.circuit.destroyCircuitFromConnection()

        self.assertEqual(self.circuit._buildSucceeded.call_count, 0)
        self.assertEqual(self.circuit._buildFailed.call_count, 1)

    @mock.patch('oppy.path.path.getPath')
    def test_build_public(self, mock_getPath):
        d = defer.Deferred()
        dx = defer.Deferred()
        mock_getPath.return_value = d
        self.circuit._build = mock.Mock()
        self.circuit._build.return_value = dx
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()

        self.circuit.build()

        d.callback('test')
        dx.callback('test')

        self.assertEqual(self.circuit._buildSucceeded.call_count, 1)
        self.assertEqual(self.circuit._buildFailed.call_count, 0)

    @mock.patch('oppy.path.path.getPath')
    def test_build_already_called_fail(self, mock_getPath):
        d = defer.Deferred()
        mock_getPath.return_value = d

        self.circuit.build()

        self.assertRaises(RuntimeError, self.circuit.build)

    @mock.patch('oppy.path.path.getPath')
    def test_build_getPath_fail(self, mock_getPath):
        mock_getPath.side_effect = Exception
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()

        self.circuit.build()

        self.assertEqual(self.circuit._buildSucceeded.call_count, 0)
        self.assertEqual(self.circuit._buildFailed.call_count, 1)

    @mock.patch('oppy.path.path.getPath')
    def test_build_build_fail(self, mock_getPath):
        d = defer.Deferred()
        mock_getPath.return_value = d
        self.circuit._build = mock.Mock()
        self.circuit._build.side_effect = Exception
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()

        self.circuit.build()
        d.callback('test')

        self.assertEqual(self.circuit._buildSucceeded.call_count, 0)
        self.assertEqual(self.circuit._buildFailed.call_count, 1)

    @mock.patch('oppy.path.path.Path', autospec=True)
    @mock.patch('oppy.path.path.getPath')
    def test_build_private(self, mock_getPath, mock_path):
        dx = defer.Deferred()
        mock_getPath.return_value = dx
        self.circuit._getConnection = mock.Mock()
        self.circuit._sendCreate2Cell = mock.Mock()
        self.circuit._recvCell = mock.Mock()
        self.circuit._deriveCreate2CellSecrets = mock.Mock()
        self.circuit._sendExtend2Cell = mock.Mock()
        self.circuit._deriveExtend2CellSecrets = mock.Mock()
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()

        t = 'succeed'
        d = defer.Deferred()
        mock_path.entry = mock.Mock()
        mock_path.middle = mock.Mock()
        mock_path.exit = mock.Mock()

        self.circuit._getConnection.return_value = d
        self.circuit._sendCreate2Cell.return_value = t
        self.circuit._recvCell.return_value = t
        self.circuit._deriveCreate2CellSecrets.return_value = t
        self.circuit._sendExtend2Cell.return_value = t
        self.circuit._deriveExtend2CellSecrets.return_value = t

        self.circuit.build()
        dx.callback(mock_path)
        d.callback(t)

        self.assertEqual(self.circuit._buildSucceeded.call_count, 1)
        self.assertEqual(self.circuit._buildFailed.call_count, 0)

    @mock.patch('oppy.circuit.circuitbuildtask.getConstraints', autospec=True)
    @mock.patch('oppy.path.path.Path', autospec=True)
    @mock.patch('oppy.path.path.getPath')
    def test_build_self_getConnection_fail(self, mock_getPath, mock_path,
                                           mock_constraints):
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()
        mock_path.entry = mock.Mock()
        d = defer.Deferred()
        mock_getPath.return_value = d

        self.circuit._getConnection = mock.Mock()
        self.circuit._getConnection.side_effect = Exception

        # need to call public build to make sure errback is added correctly
        # to the build() callback chain
        self.circuit.build()
        d.callback(mock_path)

        self.assertEqual(self.circuit._buildSucceeded.call_count, 0)
        self.assertEqual(self.circuit._buildFailed.call_count, 1)

    @mock.patch('oppy.path.path.Path', autospec=True)
    @mock.patch('oppy.path.path.getPath')
    def test_build_conn_getConnection_fail(self, mock_getPath, mock_path):
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()
        mock_path.entry = mock.Mock()
        d = defer.Deferred()
        mock_getPath.return_value = d

        self.circuit._connection_pool.getConnection = mock.Mock()
        self.circuit._connection_pool.getConnection.side_effect = Exception

        self.circuit.build()
        d.callback(mock_path)

        self.assertEqual(self.circuit._buildSucceeded.call_count, 0)
        self.assertEqual(self.circuit._buildFailed.call_count, 1)

    @mock.patch('oppy.path.path.Path', autospec=True)
    @mock.patch('oppy.path.path.getPath')
    def test_build_sendCreate2Cell_fail(self, mock_getPath, mock_path):
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()
        mock_path.entry = mock.Mock()
        d = defer.Deferred()
        dx = defer.Deferred()
        mock_getPath.return_value = d

        self.circuit._getConnection = mock.Mock()
        self.circuit._getConnection.return_value = dx
        self.circuit._sendCreate2Cell = mock.Mock()
        self.circuit._sendCreate2Cell.side_effect = Exception

        self.circuit.build()
        d.callback(mock_path)
        dx.callback('test')

        self.assertEqual(self.circuit._buildSucceeded.call_count, 0)
        self.assertEqual(self.circuit._buildFailed.call_count, 1)

    @mock.patch('oppy.path.path.Path', autospec=True)
    @mock.patch('oppy.path.path.getPath')
    def test_build_recvCell_fail(self, mock_getPath, mock_path):
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()
        mock_path.entry = mock.Mock()
        d = defer.Deferred()
        dx = defer.Deferred()
        mock_getPath.return_value = d

        self.circuit._getConnection = mock.Mock()
        self.circuit._getConnection.return_value = dx
        self.circuit._sendCreate2Cell = mock.Mock()
        self.circuit._sendCreate2Cell.return_value = 'test'
        self.circuit._recvCell = mock.Mock()
        self.circuit._recvCell.side_effect = Exception

        self.circuit.build()
        d.callback(mock_path)
        dx.callback('test')

        self.assertEqual(self.circuit._buildSucceeded.call_count, 0)
        self.assertEqual(self.circuit._buildFailed.call_count, 1)

    @mock.patch('oppy.path.path.Path', autospec=True)
    @mock.patch('oppy.path.path.getPath')
    def test_build_deriveCreate2CellSecrets_fail(self, mock_getPath,
                                                 mock_path):
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()
        mock_path.entry = mock.Mock()
        d = defer.Deferred()
        dx = defer.Deferred()
        mock_getPath.return_value = d

        self.circuit._getConnection = mock.Mock()
        self.circuit._getConnection.return_value = dx
        self.circuit._sendCreate2Cell = mock.Mock()
        self.circuit._sendCreate2Cell.return_value = 'test'
        self.circuit._recvCell = mock.Mock()
        self.circuit._recvCell.return_value = 'test'
        self.circuit._deriveCreate2CellSecrets = mock.Mock()
        self.circuit._deriveCreate2CellSecrets.side_effect = Exception

        self.circuit.build()
        d.callback(mock_path)
        dx.callback('test')

        self.assertEqual(self.circuit._buildSucceeded.call_count, 0)
        self.assertEqual(self.circuit._buildFailed.call_count, 1)

    @mock.patch('oppy.path.path.getPath')
    def test_build_sendExtend2Cell_fail(self, mock_getPath):
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()
        mock_path = Path(mock.Mock(), mock.Mock(), mock.Mock())
        d = defer.Deferred()
        dx = defer.Deferred()
        mock_getPath.return_value = d

        self.circuit._getConnection = mock.Mock()
        self.circuit._getConnection.return_value = dx
        self.circuit._sendCreate2Cell = mock.Mock()
        self.circuit._sendCreate2Cell.return_value = 'test'
        self.circuit._recvCell = mock.Mock()
        self.circuit._recvCell.return_value = 'test'
        self.circuit._deriveCreate2CellSecrets = mock.Mock()
        self.circuit._deriveCreate2CellSecrets.return_value = 'test'
        self.circuit._sendExtend2Cell = mock.Mock()
        self.circuit._sendExtend2Cell.side_effect = Exception

        self.circuit.build()
        d.callback(mock_path)
        dx.callback('test')

        self.assertEqual(self.circuit._buildSucceeded.call_count, 0)
        self.assertEqual(self.circuit._buildFailed.call_count, 1)

    @mock.patch('oppy.path.path.getPath')
    def test_build_deriveExtend2CellSecrets_fail(self, mock_getPath):
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()
        mock_path = Path(mock.Mock(), mock.Mock(), mock.Mock())
        d = defer.Deferred()
        dx = defer.Deferred()
        mock_getPath.return_value = d

        self.circuit._getConnection = mock.Mock()
        self.circuit._getConnection.return_value = dx
        self.circuit._sendCreate2Cell = mock.Mock()
        self.circuit._sendCreate2Cell.return_value = 'test'
        self.circuit._recvCell = mock.Mock()
        self.circuit._recvCell.return_value = 'test'
        self.circuit._deriveCreate2CellSecrets = mock.Mock()
        self.circuit._deriveCreate2CellSecrets.return_value = 'test'
        self.circuit._sendExtend2Cell = mock.Mock()
        self.circuit._sendExtend2Cell.return_value = 'test'
        self.circuit._deriveExtend2CellSecrets = mock.Mock()
        self.circuit._deriveExtend2CellSecrets.side_effect = Exception

        self.circuit.build()
        d.callback(mock_path)
        dx.callback('test')

        self.assertEqual(self.circuit._buildSucceeded.call_count, 0)
        self.assertEqual(self.circuit._buildFailed.call_count, 1)

    @mock.patch('oppy.path.path.getPath')
    def test_build_buildSucceeded_fail(self, mock_getPath):
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildFailed = mock.Mock()
        mock_path = Path(mock.Mock(), mock.Mock(), mock.Mock())
        d = defer.Deferred()
        dx = defer.Deferred()
        mock_getPath.return_value = d

        self.circuit._getConnection = mock.Mock()
        self.circuit._getConnection.return_value = dx
        self.circuit._sendCreate2Cell = mock.Mock()
        self.circuit._sendCreate2Cell.return_value = 'test'
        self.circuit._recvCell = mock.Mock()
        self.circuit._recvCell.return_value = 'test'
        self.circuit._deriveCreate2CellSecrets = mock.Mock()
        self.circuit._deriveCreate2CellSecrets.return_value = 'test'
        self.circuit._sendExtend2Cell = mock.Mock()
        self.circuit._sendExtend2Cell.return_value = 'test'
        self.circuit._deriveExtend2CellSecrets = mock.Mock()
        self.circuit._deriveExtend2CellSecrets.return_value = 'test'
        self.circuit._buildSucceeded = mock.Mock()
        self.circuit._buildSucceeded.side_effect = Exception

        self.circuit.build()
        d.callback(mock_path)
        dx.callback('test')

        self.assertEqual(self.circuit._buildSucceeded.call_count, 1)
        self.assertEqual(self.circuit._buildFailed.call_count, 1)

    @mock.patch('oppy.connection.connection.Connection', autospec=True)
    def test_getConnection(self, conn):
        node = mock.Mock()
        d = defer.Deferred()
        self.circuit._connection_pool.getConnection.return_value = d
        ret_val = self.circuit._getConnection(node)

        d.callback(conn)

        conn.addCircuit.assert_called_with(self.circuit)
        self.assertEqual(conn, self.successResultOf(ret_val))

    # TODO: make this test better; it's kinda shitty.
    @mock.patch('oppy.circuit.circuitbuildtask.NTorHandshake', autospec=True)
    @mock.patch('oppy.circuit.circuitbuildtask.Create2Cell', autospec=True)
    @mock.patch('oppy.connection.connection.Connection', autospec=True)
    def test_sendCreate2Cell(self, conn, c2c, nths):
        create2 = mock.Mock()
        c2c.make.return_value = create2
        self.circuit._conn = conn

        self.circuit._sendCreate2Cell(conn, mock.Mock())

        self.assertTrue(self.circuit._hs.createOnionSkin.called)
        self.assertTrue(c2c.make.called)
        self.circuit._conn.send.assert_called_with(create2)

    def test_deriveCreate2CellSecrets(self):
        self.circuit._hs = mock.Mock()
        self.circuit._hs.deriveRelayCrypto.return_value = 'test'

        cell = Created2Cell.make(ID, hdata='\x00'*84)

        self.circuit._deriveCreate2CellSecrets(cell, mock.Mock())

        self.assertEqual(self.circuit._hs, None)
        self.assertEqual(self.circuit._crypt_path, ['test'])

    @mock.patch('oppy.connection.connection.Connection', autospec=True)
    def test_deriveCreate2CellSecrets_DestroyCell(self, conn):
        self.circuit._conn = conn
        self.circuit._hs = mock.Mock()
        self.circuit._hs.deriveRelayCrypto.return_value = 'test'

        cell = DestroyCell.make(ID)

        self.assertRaises(ValueError,
                          self.circuit._deriveCreate2CellSecrets,
                          cell,
                          mock.Mock())
        self.assertEqual(self.circuit._conn.send.call_count, 0)

    @mock.patch('oppy.connection.connection.Connection', autospec=True)
    @mock.patch('oppy.circuit.circuitbuildtask.DestroyCell.make')
    def test_deriveCreate2CellSecrets_unexpected_cell(self, dcm, conn):
        self.circuit._conn = conn
        ret = mock.Mock()
        dcm.return_value = ret
        self.circuit._hs = mock.Mock()
        self.circuit._hs.deriveRelayCrypto.return_value = 'test'

        cell = RelayExtended2Cell('test')

        self.assertRaises(ValueError,
                          self.circuit._deriveCreate2CellSecrets,
                          cell,
                          mock.Mock())
        self.circuit._conn.send.assert_called_once_with(ret)

    @mock.patch('oppy.connection.connection.Connection', autospec=True)
    @mock.patch('oppy.circuit.circuitbuildtask.LinkSpecifier', autospec=True)
    @mock.patch('oppy.circuit.circuitbuildtask.NTorHandshake', autospec=True)
    @mock.patch('oppy.circuit.circuitbuildtask.RelayExtend2Cell.make')
    @mock.patch('oppy.crypto.util.encryptCell')
    def test_sendExtend2Cell(self, enc, re2m, nths, lspec, conn):
        mock_cell = mock.Mock()
        enc.return_value = mock_cell
        self.circuit._conn = conn
        
        self.circuit._sendExtend2Cell(None, mock.Mock())

        self.circuit._conn.send.assert_called_once_with(mock_cell)

    # mock: decrypt, derive relay crypto
    @mock.patch('oppy.crypto.util.decryptCell')
    @mock.patch('oppy.circuit.circuitbuildtask.NTorHandshake', autospec=True)
    def test_deriveExtend2CellSecrets(self, nths, dec):
        cell = RelayExtended2Cell(ID)
        self.circuit._hs = nths
        self.circuit._hs.deriveRelayCrypto.return_value = 'tval'
        self.circuit._crypt_path = []
        mock_response = mock.Mock()
        dec.return_value = (cell, 1)

        self.circuit._deriveExtend2CellSecrets(mock_response, 'test')

        dec.assert_called_once_with(mock_response, ['tval'])
        self.assertTrue(self.circuit._crypt_path == ['tval'])
        self.assertEqual(self.circuit._hs, None)

    @mock.patch('oppy.connection.connection.Connection', autospec=True)
    def test_deriveExtend2CellSecrets_DestroyCell(self, conn):
        self.circuit._conn = conn
        response = DestroyCell.make(ID)

        self.assertRaises(ValueError,
                          self.circuit._deriveExtend2CellSecrets,
                          response,
                          mock.Mock())
        self.assertEqual(self.circuit._conn.send.call_count, 0)

    
    @mock.patch('oppy.connection.connection.Connection', autospec=True)
    @mock.patch('oppy.circuit.circuitbuildtask.DestroyCell.make')
    @mock.patch('oppy.crypto.util.decryptCell')
    def test_deriveExtend2CellSecrets_unexpected_cell(self, dec, dcm, conn):
        cell = Created2Cell.make(ID, hdata='\x00'*84)
        dec.return_value = (cell, 2)
        self.circuit._conn = conn
        ret = mock.Mock()
        dcm.return_value = ret
        self.circuit._crypt_path = []

        self.assertRaises(ValueError,
                          self.circuit._deriveExtend2CellSecrets,
                          cell,
                          mock.Mock())
        self.circuit._conn.send.assert_called_once_with(ret)

    @mock.patch('oppy.connection.connection.Connection', autospec=True)
    @mock.patch('oppy.circuit.circuitbuildtask.Circuit', autospec=True)
    def test_buildSucceeded(self, circ, conn):
        self.circuit._conn = conn
        ret = mock.Mock()
        circ.return_value = ret

        self.circuit._buildSucceeded('test')

        self.circuit._conn.addCircuit.assert_called_once_with(ret)
        self.circuit._circuit_manager.circuitOpened.assert_called_once_with(ret)

    @mock.patch('oppy.connection.connection.Connection', autospec=True)
    def test_buildFailed(self, conn):
        self.circuit._conn = conn
        self.circuit._buildFailed('test')

        self.circuit._conn.removeCircuit.assert_called_once_with(ID)
        self.circuit._circuit_manager.circuitDestroyed.assert_called_once_with(self.circuit)

    def test_buildFailed_no_conn(self):
        self.circuit._conn = None
        self.circuit._buildFailed('test')

        self.circuit._circuit_manager.circuitDestroyed.assert_called_once_with(self.circuit)
