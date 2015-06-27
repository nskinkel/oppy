import mock

from twisted.internet import defer
from twisted.trial import unittest

from oppy.cell.definitions import MAX_RPAYLOAD_LEN
from oppy.cell.fixedlen import Create2Cell, DestroyCell, EncryptedCell
from oppy.cell.relay import (
    RelayDataCell,
    RelayEndCell,
    RelayConnectedCell,
    RelaySendMeCell,
    RelayExtendedCell,
    RelayTruncatedCell,
    RelayDropCell,
    RelayResolvedCell,
    RelayExtended2Cell,
    RelayExtendCell,
)
from oppy.circuit.circuit import Circuit
from oppy.circuit.definitions import (
    CState,
    CircuitType,
    SENDME_THRESHOLD,
    WINDOW_SIZE
)
from oppy.util.exitrequest import ExitRequest
from oppy.util.tools import ctr


ID = 0
TEST_MAX_STREAMS = 10


class CircuitTest(unittest.TestCase):

    @mock.patch('oppy.circuit.circuitmanager.CircuitManager', autospec=True)
    @mock.patch('oppy.connection.connection.Connection', autospec=True)
    @mock.patch('oppy.path.path.Path', autospec=True)
    def setUp(self, path, conn, cm):
        crypt_path = [mock.Mock(), mock.Mock(), mock.Mock()]
        self.circuit = Circuit(cm, ID, conn, CircuitType.IPv4,
                               path, crypt_path, TEST_MAX_STREAMS)
        self.circuit_ipv6 = Circuit(cm, ID, conn, CircuitType.IPv6,
                                    path, crypt_path)

    # TODO: for all of these, construct an *Actual* exit policy object
    #       to use
    def test_canHandleRequest_ipv4_yes(self):
        self.circuit._path.exit.exit_policy.can_exit_to.return_value = True
        request = ExitRequest('\x01\xbb', addr=u'127.0.0.1')
        self.assertTrue(self.circuit.canHandleRequest(request))

    def test_canHandleRequest_ipv6_yes(self):
        self.circuit_ipv6._path.exit.exit_policy.can_exit_to.return_value = True
        request = ExitRequest('\x01\xbb', addr=u'2001:db8::')
        self.assertTrue(self.circuit_ipv6.canHandleRequest(request))

    def test_canHandleRequest_host_yes(self):
        self.circuit._path.exit.exit_policy.can_exit_to.return_value = True
        request = ExitRequest('\x01\xbb', host='https://riseup.net')
        self.assertTrue(self.circuit.canHandleRequest(request))

    def test_canHandleRequest_ipv4_no(self):
        self.circuit._path.exit.exit_policy.can_exit_to.return_value = False
        request = ExitRequest('\x01\xbb', addr=u'127.0.0.1')
        self.assertFalse(self.circuit.canHandleRequest(request))

    def test_canHandleRequest_ipv6_no(self):
        self.circuit_ipv6._path.exit.exit_policy.can_exit_to.return_value = False
        request = ExitRequest('\x01\xbb', addr=u'2001:db8::')
        self.assertFalse(self.circuit_ipv6.canHandleRequest(request))

    def test_canHandleRequest_host_no(self):
        self.circuit._path.exit.exit_policy.can_exit_to.return_value = False
        request = ExitRequest('\x01\xbb', host='https://riseup.net')
        self.assertFalse(self.circuit.canHandleRequest(request))

    def test_canHandleRequest_buffering_no(self):
        # TODO: rename CSTATE
        self.circuit._state = CState.BUFFERING
        request = ExitRequest('\x01\xbb', addr=u'127.0.0.1')
        self.assertFalse(self.circuit.canHandleRequest(request))

    def test_canHandleRequest_max_streams_no(self):
        self.circuit._streams = {k: mock.Mock() for k in xrange(1, TEST_MAX_STREAMS+1)}
        request = ExitRequest('\x01\xbb', host='https://riseup.net')
        self.assertFalse(self.circuit.canHandleRequest(request))

    @mock.patch('twisted.internet.defer.DeferredQueue', autospec=True)
    def test_send(self, mock_dq):
        self.circuit._write_queue = mock_dq
        mock_stream = mock.Mock()
        mock_stream.stream_id = 6
        self.circuit.send('test', mock_stream)
        self.assertEqual(self.circuit._write_queue.put.call_count, 1)

    def test_send_too_long(self):
        s = 'a' * MAX_RPAYLOAD_LEN
        s += 'a'
        self.assertRaises(ValueError, self.circuit.send, s, 6)

    @mock.patch('twisted.internet.defer.DeferredQueue', autospec=True)
    def test_recv(self, mock_dq):
        self.circuit._read_queue = mock_dq
        self.circuit.recv('test')
        self.assertEqual(self.circuit._read_queue.put.call_count, 1)

    # TODO: test that the relayendcell actually has the correct stream_id
    @mock.patch('oppy.stream.stream.Stream', autospec=True)
    @mock.patch('oppy.circuit.circuit.RelayEndCell', autospec=True)
    def test_removeStream_more_remain(self, mock_relay_end_cell, mock_stream):
        cell = mock.Mock()
        mock_relay_end_cell.make.return_value = cell
        mock_stream.stream_id = ID
        self.circuit._streams = {ID+1: mock.Mock(), ID: mock_stream}
        self.circuit._encryptAndSendCell = mock.Mock()
        
        self.circuit.removeStream(mock_stream)

        self.assertTrue(mock_stream not in self.circuit._streams)
        self.assertEqual(len(self.circuit._streams), 1)
        self.circuit._encryptAndSendCell.assert_called_once_with(cell)
        self.assertEqual(
             self.circuit._circuit_manager.shouldDestroyCircuit.call_count, 0)

    # TODO: test that the relayendcell actually has the correct stream_id
    @mock.patch('oppy.stream.stream.Stream', autospec=True)
    @mock.patch('oppy.circuit.circuit.RelayEndCell', autospec=True)
    def test_removeStream_zero_remain_destroy_no(self, mock_relay_end_cell,
                                                 mock_stream):
        cell = mock.Mock()
        mock_relay_end_cell.make.return_value = cell
        mock_stream.stream_id = ID
        self.circuit._streams = {ID: mock_stream}
        self.circuit._circuit_manager.shouldDestroyCircuit.return_value = False
        self.circuit._encryptAndSendCell = mock.Mock()
        self.circuit._sendDestroyCell = mock.Mock()
        self.circuit._closeCircuit = mock.Mock()
        
        self.circuit.removeStream(mock_stream)

        self.assertTrue(mock_stream not in self.circuit._streams)
        self.circuit._encryptAndSendCell.assert_called_once_with(cell)
        self.assertEqual(self.circuit._sendDestroyCell.call_count, 0)
        self.assertEqual(self.circuit._closeCircuit.call_count, 0)

    @mock.patch('oppy.stream.stream.Stream', autospec=True)
    @mock.patch('oppy.circuit.circuit.RelayEndCell', autospec=True)
    def test_removeStream_zero_remain_destroy_yes(self, mock_relay_end_cell,
                                                  mock_stream):
        cell = mock.Mock()
        mock_relay_end_cell.make.return_value = cell
        mock_stream.stream_id = ID
        self.circuit._streams = {ID: mock_stream}
        self.circuit._circuit_manager.shouldDestroyCircuit.return_value = True
        self.circuit._encryptAndSendCell = mock.Mock()
        self.circuit._sendDestroyCell = mock.Mock()
        self.circuit._closeCircuit = mock.Mock()
        
        self.circuit.removeStream(mock_stream)

        self.assertTrue(mock_stream not in self.circuit._streams)
        self.circuit._encryptAndSendCell.assert_called_once_with(cell)
        self.assertEqual(self.circuit._sendDestroyCell.call_count, 1)
        self.assertEqual(self.circuit._closeCircuit.call_count, 1)

    # TODO: better test, this doesn't really test anything
    def test_removeStream_nonexistent(self):
        mock_stream = mock.Mock()
        mock_stream.stream_id = 1
        self.circuit._streams = {}

        self.circuit.removeStream(mock_stream)

    # TODO: test
    def test_removeStream_conn_send_fail(self):
        pass

    # TODO: make sure relayendcell has correct stream_id
    @mock.patch('oppy.circuit.circuit.RelayBeginCell', autospec=True)
    def test_beginStream(self, mock_relay_begin_cell):
        mock_stream = mock.Mock()
        mock_stream.stream_id = ID
        mock_stream.request = mock.Mock()
        cell = mock.Mock()
        mock_relay_begin_cell.make.return_value = cell
        self.circuit._encryptAndSendCell = mock.Mock()

        self.circuit.beginStream(mock_stream)
        self.circuit._encryptAndSendCell.assert_called_once_with(cell)

    # TODO: test
    def test_beginStream_conn_send_fail(self):
        pass

    def test_addStreamAndSetStreamID(self):
        mock_stream = mock.Mock() 
        self.circuit.addStreamAndSetStreamID(mock_stream)
        self.assertEqual(mock_stream.stream_id, 1)
        self.assertTrue(self.circuit._streams[1] == mock_stream)

    def test_addStreamAndSetStreamID_ctr_find_next_free_id(self):
        self.circuit._streams = {}
        for i in xrange(1, TEST_MAX_STREAMS-3):
            self.circuit._streams[i] = mock.Mock()

        mock_stream = mock.Mock() 
        self.circuit.addStreamAndSetStreamID(mock_stream)

        self.assertEqual(mock_stream.stream_id, TEST_MAX_STREAMS-3)
        self.assertEqual(self.circuit._streams[TEST_MAX_STREAMS-3], mock_stream)

    def test_addStreamAndSetStreamID_ctr_rollover_find_next_free_id(self):
        self.circuit._ctr = ctr(TEST_MAX_STREAMS)
        for i in xrange(1, TEST_MAX_STREAMS-4):
            next(self.circuit._ctr)

        self.circuit._streams[TEST_MAX_STREAMS-4] = mock.Mock()
        self.circuit._streams[TEST_MAX_STREAMS-3] = mock.Mock()
        self.circuit._streams[TEST_MAX_STREAMS-2] = mock.Mock()
        self.circuit._streams[TEST_MAX_STREAMS-1] = mock.Mock()
        self.circuit._streams[TEST_MAX_STREAMS] = mock.Mock()
        self.circuit._streams[1] = mock.Mock()
        self.circuit._streams[2] = mock.Mock()
        self.circuit._streams[3] = mock.Mock()

        mock_stream = mock.Mock() 
        self.circuit.addStreamAndSetStreamID(mock_stream)

        self.assertEqual(mock_stream.stream_id, 4)
        self.assertTrue(self.circuit._streams[4] == mock_stream)

    def test_addStreamAndSetStreamID_max_streams_full(self):
        self.circuit._max_streams = 0
        mock_stream = mock.Mock() 

        self.assertRaises(RuntimeError,
                          self.circuit.addStreamAndSetStreamID,
                          mock.Mock())

    # TODO: test cell is made with correct stream_id
    @mock.patch('oppy.circuit.circuit.RelaySendMeCell', autospec=True)
    def test_sendStreamSendMe(self, mock_relay_sendme_cell):
        cell = mock.Mock()
        mock_relay_sendme_cell.make.return_value = cell
        mock_stream = mock.Mock()
        mock_stream.stream_id = ID
        self.circuit._encryptAndSendCell = mock.Mock()

        self.circuit.sendStreamSendMe(mock_stream)
        self.circuit._encryptAndSendCell.assert_called_once_with(cell)

    # TODO: test
    def test_sendStreamSendMe_conn_send_fail(self):
        pass

    def test_destroyCircuitFromManager(self):
        self.circuit._sendDestroyCell = mock.Mock()
        self.circuit._closeAllStreams = mock.Mock()
        self.circuit._connection.removeCircuit = mock.Mock()

        self.circuit.destroyCircuitFromManager()

        self.assertEqual(self.circuit._sendDestroyCell.call_count, 1)
        self.assertEqual(self.circuit._closeAllStreams.call_count, 1)
        self.assertEqual(self.circuit._connection.removeCircuit.call_count, 1)

    # TODO: test
    def test_destroyCircuitFromManager_conn_send_fail(self):
        pass

    def test_destroyCircuitFromConnection(self):
        self.circuit._sendDestroyCell = mock.Mock()
        self.circuit._closeCircuit = mock.Mock()

        self.circuit.destroyCircuitFromConnection()

        self.assertEqual(self.circuit._sendDestroyCell.call_count, 0)
        self.assertEqual(self.circuit._closeCircuit.call_count, 1)

    # test deferred is properly assigned
    # test that correct callback is called when succeeding
    @mock.patch('twisted.internet.defer.DeferredQueue', autospec=True)
    def test_pollReadQueue(self, mock_dq):
        d = defer.Deferred()
        self.circuit._read_queue = mock_dq
        self.circuit._read_queue.get.return_value = d
        self.circuit._recvCell = mock.Mock()

        self.circuit._pollReadQueue()

        self.assertEqual(self.circuit._read_task, d)

        self.circuit._read_task.callback('test')
        self.circuit._recvCell.assert_called_once_with('test')

    @mock.patch('twisted.internet.defer.DeferredQueue', autospec=True)
    def test_pollWriteQueue(self, mock_dq):
        d = defer.Deferred()
        self.circuit._write_queue = mock_dq
        self.circuit._write_queue.get.return_value = d
        self.circuit._writeData = mock.Mock()

        self.circuit._pollWriteQueue()

        self.assertEqual(self.circuit._write_task, d)

        self.circuit._write_task.callback('test')
        self.circuit._writeData.assert_called_once_with('test')

    # TODO: check that cell has correct id and data
    @mock.patch('oppy.circuit.circuit.RelayDataCell', autospec=True)
    def test_writeData(self, mock_relay_data_cell):
        cell = mock.Mock()
        mock_relay_data_cell.make.return_value = cell
        self.circuit._encryptAndSendCell = mock.Mock()
        self.circuit._decPackageWindow = mock.Mock()

        self.circuit._writeData(('test', ID))

        self.circuit._encryptAndSendCell.assert_called_once_with(cell)
        self.assertEqual(self.circuit._decPackageWindow.call_count, 1)

    # TODO: test
    def test_writeData_conn_send_fail(self):
        pass
        
    def test_recvCell_relay_cell(self):
        self.circuit._recvRelayCell = mock.Mock()
        self.circuit._pollReadQueue = mock.Mock()
        cell = EncryptedCell.make(ID, 'a'*509)

        self.circuit._recvCell(cell)

        self.circuit._recvRelayCell.assert_called_once_with(cell)
        self.assertEqual(self.circuit._pollReadQueue.call_count, 1)

    @mock.patch('oppy.circuit.circuit.logging', autospec=True)
    def test_recvCell_non_backward_cell_fail(self, mock_logging):
        self.circuit._recvRelayCell = mock.Mock()
        self.circuit._pollReadQueue = mock.Mock()
        self.circuit._sendDestroyCell = mock.Mock()
        self.circuit._closeCircuit = mock.Mock()
        cell = Create2Cell.make(ID, hdata=84*'a')

        self.circuit._recvCell(cell)

        self.assertEqual(self.circuit._sendDestroyCell.call_count, 1)
        self.assertEqual(self.circuit._closeCircuit.call_count, 1)
        self.assertEqual(self.circuit._recvRelayCell.call_count, 0)
        self.assertEqual(self.circuit._pollReadQueue.call_count, 0)
        self.assertTrue(mock_logging.warning.called)

    def test_recvCell_destroy_cell(self):
        self.circuit._recvRelayCell = mock.Mock()
        self.circuit._pollReadQueue = mock.Mock()
        self.circuit._sendDestroyCell = mock.Mock()
        self.circuit._closeCircuit = mock.Mock()
        cell = DestroyCell.make(ID)

        self.circuit._recvCell(cell)

        self.assertEqual(self.circuit._sendDestroyCell.call_count, 0)
        self.assertEqual(self.circuit._closeCircuit.call_count, 1)
        self.assertEqual(self.circuit._recvRelayCell.call_count, 0)
        self.assertEqual(self.circuit._pollReadQueue.call_count, 0)

    @mock.patch('oppy.crypto.util.decryptCell')
    @mock.patch('oppy.circuit.circuit.logging', autospec=True)
    def test_recvRelayCell_nonbackward_cell(self, mock_logging, mock_decrypt):
        cell = RelayExtendCell('test')
        mock_decrypt.return_value = (cell, 2)
        self.circuit._sendDestroyCell = mock.Mock()
        self.circuit._closeCircuit = mock.Mock()

        self.circuit._recvRelayCell(cell)

        self.assertEqual(self.circuit._sendDestroyCell.call_count, 1)
        self.assertEqual(self.circuit._closeCircuit.call_count, 1)
        self.assertTrue(mock_logging.warning.called)

    @mock.patch('oppy.crypto.util.decryptCell')
    @mock.patch('oppy.circuit.circuit.logging', autospec=True)
    def test_recvCell_relay_cell_decrypt_fail(self, mock_logging,
                                              mock_decrypt):
        mock_decrypt.side_effect = Exception
        self.circuit._sendDestroyCell = mock.Mock()
        self.circuit._closeCircuit = mock.Mock()
        self.circuit._processRelayDataCell = mock.Mock()
        self.circuit._processRelayEndCell = mock.Mock()
        self.circuit._processRelayResolvedCell = mock.Mock()
        self.circuit._processRelayTruncatedCell = mock.Mock()
        self.circuit._processRelayConnectedCell = mock.Mock()
        self.circuit._processRelaySendMeCell = mock.Mock()
        self.circuit._processRelayDropCell = mock.Mock()
        cell = EncryptedCell.make(ID, 'a'*509)

        self.circuit._recvRelayCell(cell)

        self.assertTrue(mock_logging.debug.call_count, 1)
        self.assertEqual(self.circuit._sendDestroyCell.call_count, 0)
        self.assertEqual(self.circuit._closeCircuit.call_count, 0)
        self.assertEqual(self.circuit._processRelayDataCell.call_count, 0)
        self.assertEqual(self.circuit._processRelayEndCell.call_count, 0)
        self.assertEqual(self.circuit._processRelayConnectedCell.call_count,
                         0)
        self.assertEqual(self.circuit._processRelayResolvedCell.call_count, 0)
        self.assertEqual(self.circuit._processRelayTruncatedCell.call_count,
                         0)
        self.assertEqual(self.circuit._processRelaySendMeCell.call_count, 0)
        self.assertEqual(self.circuit._processRelayDropCell.call_count, 0)

    @mock.patch('oppy.crypto.util.decryptCell')
    @mock.patch('oppy.circuit.circuit.logging', autospec=True)
    def test_recvCell_relay_unexpected_cell_fail(self, mock_logging,
                                                 mock_decrypt):
        mock_decrypt.return_value = (RelayExtended2Cell('test'), 2)
        self.circuit._sendDestroyCell = mock.Mock()
        self.circuit._closeCircuit = mock.Mock()
        self.circuit._processRelayDataCell = mock.Mock()
        self.circuit._processRelayEndCell = mock.Mock()
        self.circuit._processRelayResolvedCell = mock.Mock()
        self.circuit._processRelayTruncatedCell = mock.Mock()
        self.circuit._processRelayConnectedCell = mock.Mock()
        self.circuit._processRelaySendMeCell = mock.Mock()
        self.circuit._processRelayDropCell = mock.Mock()
        cell = EncryptedCell.make(ID, 'a'*509)

        self.circuit._recvRelayCell(cell)

        self.assertTrue(mock_logging.debug.call_count, 1)
        self.assertEqual(self.circuit._sendDestroyCell.call_count, 0)
        self.assertEqual(self.circuit._closeCircuit.call_count, 0)
        self.assertEqual(self.circuit._processRelayDataCell.call_count, 0)
        self.assertEqual(self.circuit._processRelayEndCell.call_count, 0)
        self.assertEqual(self.circuit._processRelayConnectedCell.call_count,
                         0)
        self.assertEqual(self.circuit._processRelayResolvedCell.call_count, 0)
        self.assertEqual(self.circuit._processRelayTruncatedCell.call_count,
                         0)
        self.assertEqual(self.circuit._processRelaySendMeCell.call_count, 0)
        self.assertEqual(self.circuit._processRelayDropCell.call_count, 0)
        
    @mock.patch('oppy.crypto.util.decryptCell')
    def test_recvRelayCell_data_cell(self, mock_decrypt):
        cell = RelayDataCell.make(ID, ID, 'a')
        mock_decrypt.return_value = (cell, 2)
        self.circuit._processRelayDataCell = mock.Mock()

        self.circuit._recvRelayCell(cell)

        self.circuit._processRelayDataCell.assert_called_once_with(cell, 2)

    @mock.patch('oppy.crypto.util.decryptCell')
    def test_recvRelayCell_end_cell(self, mock_decrypt):
        cell = RelayEndCell(ID, ID)
        mock_decrypt.return_value = (cell, 2)
        self.circuit._processRelayEndCell = mock.Mock()

        self.circuit._recvRelayCell(cell)

        self.circuit._processRelayEndCell.assert_called_once_with(cell, 2)
    
    @mock.patch('oppy.crypto.util.decryptCell')
    def test_recvRelayCell_connected_cell(self, mock_decrypt):
        cell = RelayConnectedCell('test')
        mock_decrypt.return_value = (cell, 2)
        self.circuit._processRelayConnectedCell = mock.Mock()

        self.circuit._recvRelayCell(cell)

        self.circuit._processRelayConnectedCell.assert_called_once_with(cell,
                                                                        2)

    @mock.patch('oppy.crypto.util.decryptCell')
    def test_recvRelayCell_sendme_cell(self, mock_decrypt):
        cell = RelaySendMeCell.make(ID, ID)
        mock_decrypt.return_value = (cell, 2)
        self.circuit._processRelaySendMeCell = mock.Mock()

        self.circuit._recvRelayCell(cell)

        self.circuit._processRelaySendMeCell.assert_called_once_with(cell, 2)

    @mock.patch('oppy.crypto.util.decryptCell')
    def test_recvRelayCell_truncated_cell(self, mock_decrypt):
        cell = RelayTruncatedCell('test')
        mock_decrypt.return_value = (cell, 2)
        self.circuit._processRelayTruncatedCell = mock.Mock()

        self.circuit._recvRelayCell(cell)

        self.circuit._processRelayTruncatedCell.assert_called_once_with(cell,
                                                                        2)

    @mock.patch('oppy.crypto.util.decryptCell')
    def test_recvRelayCell_drop_cell(self, mock_decrypt):
        cell = RelayDropCell('test')
        mock_decrypt.return_value = (cell, 2)
        self.circuit._processRelayDropCell = mock.Mock()

        self.circuit._recvRelayCell(cell)

        self.circuit._processRelayDropCell.assert_called_once_with(cell, 2)

    @mock.patch('oppy.crypto.util.decryptCell')
    def test_recvRelayCell_resolved_cell(self, mock_decrypt):
        cell = RelayResolvedCell('test')
        mock_decrypt.return_value = (cell, 2)
        self.circuit._processRelayResolvedCell = mock.Mock()

        self.circuit._recvRelayCell(cell)

        self.circuit._processRelayResolvedCell.assert_called_once_with(cell,
                                                                       2)

    def test_processRelayDataCell(self):
        cell = mock.Mock()
        cell.rheader.stream_id = ID
        mock_rpayload = mock.Mock()
        cell.rpayload = mock_rpayload
        mock_stream = mock.Mock()
        self.circuit._streams = {ID: mock_stream}
        self.circuit._decDeliverWindow = mock.Mock()
        origin = 2

        self.circuit._processRelayDataCell(cell, origin)

        mock_stream.recv.assert_called_once_with(mock_rpayload)
        self.assertEqual(self.circuit._decDeliverWindow.call_count, 1)

    @mock.patch('oppy.circuit.circuit.logging', autospec=True)
    def test_processRelayDataCell_no_stream(self, mock_logging):
        cell = mock.Mock()
        cell.rheader.stream_id = ID
        mock_stream = mock.Mock()
        self.circuit._streams = {ID+1: mock_stream}
        self.circuit._decDeliverWindow = mock.Mock()
        origin = 2

        self.circuit._processRelayDataCell(cell, origin)

        self.assertEqual(mock_stream.recv.call_count, 0)
        self.assertEqual(self.circuit._decDeliverWindow.call_count, 0)
        self.assertTrue(mock_logging.debug.called)

    def test_processRelayEndCell(self):
        cell = mock.Mock()
        cell.rheader.stream_id = ID
        mock_stream = mock.Mock()
        self.circuit._streams = {ID: mock_stream}
        origin = 2

        self.circuit._processRelayEndCell(cell, origin)

        self.assertEqual(mock_stream.closeFromCircuit.call_count, 1)

    @mock.patch('oppy.circuit.circuit.logging', autospec=True)
    def test_processRelayEndCell_no_stream(self, mock_logging):
        self.circuit._streams = {}
        cell = mock.Mock()
        cell.rheader.stream_id = 1

        self.circuit._processRelayEndCell(cell, 2)

        self.assertTrue(mock_logging.debug.called)

    def test_processRelayConnectedCell(self):
        cell = mock.Mock()
        cell.rheader.stream_id = ID
        mock_stream = mock.Mock()
        self.circuit._streams = {ID: mock_stream}
        origin = 2

        self.circuit._processRelayConnectedCell(cell, origin)

        self.assertEqual(mock_stream.streamConnected.call_count, 1)

    @mock.patch('oppy.circuit.circuit.logging', autospec=True)
    def test_processRelayConnectedCell_no_stream(self, mock_logging):
        cell = mock.Mock()
        cell.rheader.stream_id = ID
        mock_stream = mock.Mock()
        self.circuit._streams = {}

        self.circuit._processRelayConnectedCell(cell, 2)

        self.assertTrue(mock_logging.debug.called)

    def test_processRelaySendMe_circuit_level(self):
        cell = mock.Mock()
        cell.rheader.stream_id = 0
        self.circuit._incPackageWindow = mock.Mock()
        origin = 2

        self.circuit._processRelaySendMeCell(cell, origin)

        self.assertEqual(self.circuit._incPackageWindow.call_count, 1)

    def test_processRelaySendMe_stream_level(self):
        cell = mock.Mock()
        cell.rheader.stream_id = 1
        mock_stream = mock.Mock()
        mock_stream.stream_id = 1
        self.circuit._streams = {1: mock_stream}
        origin = 2

        self.circuit._processRelaySendMeCell(cell, origin)

        self.assertEqual(mock_stream.incPackageWindow.call_count, 1)

    @mock.patch('oppy.circuit.circuit.logging', autospec=True)
    def test_processRelaySendMe_stream_level_no_stream(self, mock_logging):
        cell = mock.Mock()
        cell.rheader.stream_id = 1
        self.circuit._streams = {}

        self.circuit._processRelaySendMeCell(cell, 2)

        self.assertTrue(mock_logging.debug.called)

    def test_processRelayTruncatedCell(self):
        cell = mock.Mock()
        self.circuit._sendDestroyCell = mock.Mock()
        self.circuit._closeCircuit = mock.Mock()
        origin = 2

        self.circuit._processRelayTruncatedCell(cell, origin)

        self.assertEqual(self.circuit._sendDestroyCell.call_count, 1)
        self.assertEqual(self.circuit._closeCircuit.call_count, 1)

    @mock.patch('oppy.circuit.circuit.logging', autospec=True)
    def test_processRelayDropCell(self, mock_logging):
        self.circuit._processRelayDropCell('test', 2)

        self.assertTrue(mock_logging.debug.called)

    @mock.patch('oppy.circuit.circuit.logging', autospec=True)
    def test_processRelayResolvedCell(self, mock_logging):
        cell = mock.Mock()
        cell.rheader = mock.Mock()
        cell.rheader.stream_id = 1

        self.circuit._processRelayResolvedCell(cell, 2)

        self.assertTrue(mock_logging.debug.called)

    @mock.patch('oppy.circuit.circuit.RelaySendMeCell', autospec=True)
    def test_decDeliverWindow_at_threshold(self, mock_relay_sendme_cell):
        cell = mock.Mock()
        mock_relay_sendme_cell.make.return_value = cell
        self.circuit._encryptAndSendCell = mock.Mock()
        self.circuit._encryptAndSendCell.return_value = cell
        self.circuit._deliver_window = SENDME_THRESHOLD + 1

        self.circuit._decDeliverWindow()

        self.circuit._encryptAndSendCell.assert_called_once_with(cell)
        self.assertEqual(self.circuit._deliver_window,
                         SENDME_THRESHOLD+WINDOW_SIZE)

    def test_decDeliverWindow_above_threshold(self):
        self.circuit._encryptAndSendCell = mock.Mock()
        self.circuit._deliver_window = SENDME_THRESHOLD + 2

        self.circuit._decDeliverWindow()

        self.assertEqual(self.circuit._encryptAndSendCell.call_count, 0)
        self.assertEqual(self.circuit._deliver_window, SENDME_THRESHOLD+1)

    @mock.patch('oppy.circuit.circuit.RelaySendMeCell', autospec=True)
    def test_decDeliverWindow_below_threshold(self, mock_relay_sendme_cell):
        cell = mock.Mock()
        mock_relay_sendme_cell.make.return_value = cell
        self.circuit._encryptAndSendCell = mock.Mock()
        self.circuit._encryptAndSendCell.return_value = cell
        self.circuit._deliver_window = SENDME_THRESHOLD - 1

        self.circuit._decDeliverWindow()

        self.circuit._encryptAndSendCell.assert_called_once_with(cell)
        self.assertEqual(self.circuit._deliver_window,
                         SENDME_THRESHOLD-2+WINDOW_SIZE)
        
    # TODO: test
    def test_decDeliverWindow_at_threshold_conn_send_fail(self):
        pass

    def test_decPackageWindow_above_threshold(self):
        self.circuit._package_window = SENDME_THRESHOLD + 2
        self.circuit._pollWriteQueue = mock.Mock()

        self.circuit._decPackageWindow()

        self.assertEqual(self.circuit._package_window, SENDME_THRESHOLD+1)
        self.assertEqual(self.circuit._pollWriteQueue.call_count, 1)

    def test_decPackageWindow_at_threshold(self):
        self.circuit._package_window = 1
        self.circuit._pollWriteQueue = mock.Mock()
        self.circuit._state = CState.OPEN

        self.circuit._decPackageWindow()

        self.assertEqual(self.circuit._package_window, 0)
        self.assertEqual(self.circuit._pollWriteQueue.call_count, 0)
        self.assertEqual(self.circuit._state, CState.BUFFERING)
        self.assertEqual(self.circuit._write_task, None)

    def test_decPackageWindow_below_threshold(self):
        self.circuit._package_window = 0
        self.circuit._pollWriteQueue = mock.Mock()
        self.circuit._state = CState.OPEN

        self.circuit._decPackageWindow()

        self.assertEqual(self.circuit._pollWriteQueue.call_count, 0)
        self.assertEqual(self.circuit._state, CState.BUFFERING)
        self.assertEqual(self.circuit._write_task, None)

    def test_incPackageWindow_state_open(self):
        self.circuit._package_window = 1
        self.circuit._pollWriteQueue = mock.Mock()
        self.circuit._state = CState.OPEN
        self.circuit._write_task = None

        self.circuit._incPackageWindow()

        self.assertEqual(self.circuit._package_window, WINDOW_SIZE+1)
        self.assertEqual(self.circuit._pollWriteQueue.call_count, 0)
        self.assertEqual(self.circuit._state, CState.OPEN)

    def test_incPackageWindow_state_buffer_below_zero(self):
        self.circuit._package_window = -WINDOW_SIZE - 1
        self.circuit._pollWriteQueue = mock.Mock()
        self.circuit._state = CState.BUFFERING
        self.circuit._write_task = None

        self.circuit._incPackageWindow()

        self.assertEqual(self.circuit._package_window, -1)
        self.assertEqual(self.circuit._pollWriteQueue.call_count, 0)
        self.assertEqual(self.circuit._state, CState.BUFFERING)
        self.assertEqual(self.circuit._write_task, None)

    def test_incPackageWindow_state_buffer_at_zero(self):
        self.circuit._package_window = 0
        self.circuit._pollWriteQueue = mock.Mock()
        self.circuit._state = CState.BUFFERING
        self.circuit._write_task = None

        self.circuit._incPackageWindow()

        self.assertEqual(self.circuit._package_window, WINDOW_SIZE)
        self.assertEqual(self.circuit._pollWriteQueue.call_count, 1)
        self.assertEqual(self.circuit._state, CState.OPEN)

    def test_incPackageWindow_state_buffer_above_zero(self):
        self.circuit._package_window = 100
        self.circuit._pollWriteQueue = mock.Mock()
        self.circuit._state = CState.OPEN
        self.circuit._write_task = None

        self.circuit._incPackageWindow()

        self.assertEqual(self.circuit._package_window, WINDOW_SIZE+100)
        self.assertEqual(self.circuit._pollWriteQueue.call_count, 0)
        self.assertEqual(self.circuit._state, CState.OPEN)

    # TODO: check for correct circuit id in cell
    @mock.patch('oppy.circuit.circuit.DestroyCell', autospec=True)
    def test_sendDestroyCell(self, mock_destroy_cell):
        cell = mock.Mock()
        mock_destroy_cell.make.return_value = cell

        self.circuit._sendDestroyCell()

        self.circuit._connection.send.assert_called_once_with(cell)

    # TODO: test
    def test_sendDestroyCell_conn_send_fail(self):
        pass

    def test_closeAllStreams(self):
        stream0 = mock.Mock()
        stream0.closeAllStreams = mock.Mock()
        stream1 = mock.Mock()
        stream1.closeAllStreams = mock.Mock()
        self.circuit._streams = {0: stream0, 1:stream1}

        self.circuit._closeAllStreams()

        for stream in self.circuit._streams.values():
            self.assertEqual(stream.closeFromCircuit.call_count, 1)

    def test_closeCircuit(self):
        self.circuit._closeAllStreams = mock.Mock()

        self.circuit._closeCircuit()

        self.assertEqual(self.circuit._closeAllStreams.call_count, 1)
        self.circuit._circuit_manager.circuitDestroyed.assert_called_once_with(self.circuit)
        self.circuit._connection.removeCircuit.assert_called_once_with(self.circuit)

    @mock.patch('oppy.crypto.util.encryptCell')
    def test_encryptAndSendCell(self, mock_encrypt):
        cell = mock.Mock()
        encrypted = mock.Mock()
        mock_encrypt.return_value = encrypted
        self.circuit._crypt_path = []

        self.circuit._encryptAndSendCell(cell)

        mock_encrypt.assert_called_once_with(cell, [])
        self.circuit._connection.send.assert_called_once_with(encrypted)

    @mock.patch('oppy.crypto.util.encryptCell')
    @mock.patch('oppy.circuit.circuit.logging', autospec=True)
    def test_encryptAndSendCell_crypto_fail(self, mock_logging, mock_encrypt):
        cell = mock.Mock()
        mock_encrypt.side_effect = Exception
        self.circuit._crypt_path = []

        self.circuit._encryptAndSendCell(cell)

        mock_encrypt.assert_called_once_with(cell, [])
        self.assertEqual(self.circuit._connection.send.call_count, 0)
        self.assertTrue(mock_logging.debug.called)

    # TODO: test
    def test_encryptAndSendCell_send_fail(self):
        pass
