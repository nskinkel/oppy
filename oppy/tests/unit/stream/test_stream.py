import mock

from twisted.trial import unittest

from oppy.stream import stream


class StreamTest(unittest.TestCase):

    @mock.patch('oppy.circuit.circuitmanager.CircuitManager', autospec=True)
    @mock.patch('oppy.socks.socks.OppySOCKSProtocol', autospec=True)
    @mock.patch('oppy.util.exitrequest.ExitRequest', autospec=True)
    @mock.patch('twisted.internet.defer.DeferredQueue', autospec=True)
    def setUp(self, mock_dq, mock_er, mock_osp, mock_cm):
        self.mock_er = mock_er
        self.mock_osp = mock_osp
        self.mock_cm = mock_cm
        self.mock_dq = mock_dq
        self.stream = stream.Stream(self.mock_cm, self.mock_er, self.mock_osp)
        self.log_patch = mock.patch('oppy.stream.stream.logging')
        self.mock_log = self.log_patch.start()

    def test_recv(self):
        self.stream.recv('test')
        self.stream._read_queue.put.assert_called_once_with('test')

    @mock.patch('oppy.stream.stream._chunkRelayData', return_value=['c1', 'c2'])
    def test_send(self, mock_crd):
        self.stream.send('test')
        self.assertEqual(self.stream._write_queue.put.call_count, 2)
        self.assertEqual(self.stream._write_queue.put.call_args_list,
                         [mock.call('c1'), mock.call('c2')])

    def test_incrementPackageWindow_normal(self):
        self.stream._pollWriteQueue = mock.Mock()
        self.stream._write_deferred = 'wd'
        self.stream._package_window = 1
        self.stream.incrementPackageWindow()

        self.assertEqual(self.stream._package_window,
                         stream.STREAM_WINDOW_SIZE+1)
        self.assertEqual(self.stream._pollWriteQueue.call_count, 0)

    def test_incrementPackageWindow_buffering(self):
        self.stream._pollWriteQueue = mock.Mock()
        self.stream._write_deferred = None
        self.stream._package_window = 0
        self.stream.incrementPackageWindow()

        self.assertEqual(self.stream._package_window,
                         stream.STREAM_WINDOW_SIZE)
        self.assertEqual(self.stream._pollWriteQueue.call_count, 1)

    def test_streamConnected(self):
        self.stream._pollWriteQueue = mock.Mock()
        self.stream.streamConnected()
        self.assertEqual(self.stream._pollWriteQueue.call_count, 1)

    def test_closeFromCircuit(self):
        self.stream.circuit = mock.Mock()
        self.stream.circuit_id = 'test'
        self.stream.closeFromCircuit()
        self.assertEqual(self.stream.socks.closeFromStream.call_count, 1)
        self.assertTrue(self.stream._closed)

    def test_closeFromSOCKS_no_circuit(self):
        self.stream.circuit = None
        self.stream.closeFromSOCKS()
        self.assertTrue(self.stream._closed)

    def test_closeFromSOCKS_circuit(self):
        self.stream.circuit = mock.Mock()
        self.stream.circuit.removeStream = mock.Mock()

        self.stream.closeFromSOCKS()
        self.stream.circuit.removeStream.assert_called_once_with(self.stream)
        self.assertTrue(self.stream._closed)

    def test_registerNewStream_closed(self):
        mock_circuit = mock.Mock()
        mock_circuit.addStreamAndSetStreamID = mock.Mock()
        self.stream._closed = True

        self.stream._registerNewStream(mock_circuit)
        self.assertEqual(mock_circuit.addStreamAndSetStreamID.call_count, 0)

    def test_registerNewStream(self):
        mock_circuit = mock.Mock()
        mock_circuit.addStreamAndSetStreamID = mock.Mock()
        mock_circuit.beginStream = mock.Mock()
        self.stream._pollReadQueue = mock.Mock()
        self.stream._circuit_request = 'test'

        self.stream._registerNewStream(mock_circuit)
        self.assertEqual(self.stream.circuit, mock_circuit)
        self.assertEqual(self.stream._circuit_request, None)
        mock_circuit.addStreamAndSetStreamID.assert_called_once_with(
            self.stream)
        mock_circuit.beginStream.assert_called_once_with(self.stream)
        self.assertEqual(self.stream._pollReadQueue.call_count, 1)

    def test_pollWriteQueue(self):
        mock_wd = mock.Mock()
        mock_wd.addCallback = mock.Mock()
        self.stream._write_queue.get.return_value = mock_wd

        self.stream._pollWriteQueue()

        self.assertEqual(self.stream._write_deferred, mock_wd)
        mock_wd.addCallback.assert_called_once_with(self.stream._writeData)

    def test_pollReadQueue(self):
        mock_rd = mock.Mock()
        mock_rd.addCallback = mock.Mock()
        self.stream._read_queue.get.return_value = mock_rd

        self.stream._pollReadQueue()

        self.assertEqual(self.stream._read_deferred, mock_rd)
        mock_rd.addCallback.assert_called_once_with(self.stream._recvData)

    def test_writeData(self):
        self.stream._decPackageWindow = mock.Mock()
        self.stream.circuit = mock.Mock()
        self.stream.circuit.send = mock.Mock()
        self.stream._writeData('test')
        self.stream.circuit.send.assert_called_once_with('test', self.stream)
        self.assertEqual(self.stream._decPackageWindow.call_count, 1)

    def test_recvData(self):
        self.stream._decDeliverWindow = mock.Mock()
        self.stream._recvData('test')
        self.stream.socks.recv.assert_called_once_with('test')
        self.assertEqual(self.stream._decDeliverWindow.call_count, 1)

    def test_decDeliverWindow_above_threshold(self):
        self.stream._deliver_window = 500
        self.stream._pollReadQueue = mock.Mock()
        self.stream._decDeliverWindow()
        self.assertEqual(self.stream._deliver_window, 499)
        self.assertEqual(self.stream._pollReadQueue.call_count, 1)

    def test_decDeliverWindow_at_threshold(self):
        self.stream._deliver_window = 451
        self.stream.circuit = mock.Mock()
        self.stream.circuit.sendStreamSendMe = mock.Mock()
        self.stream._pollReadQueue = mock.Mock()
        self.stream._decDeliverWindow()
        self.assertEqual(self.stream._deliver_window, 500)
        self.stream.circuit.sendStreamSendMe.assert_called_once_with(
            self.stream)
        self.assertEqual(self.stream._pollReadQueue.call_count, 1)

    def test_decPackageWindow_above_threshold(self):
        self.stream._package_window = 2
        self.stream._pollWriteQueue = mock.Mock()
        self.stream._decPackageWindow()
        self.assertEqual(self.stream._package_window, 1)
        self.assertEqual(self.stream._pollWriteQueue.call_count, 1)

    def test_packageWindow_at_threshold(self):
        self.stream._package_window = 1
        self.stream._pollWriteQueue = mock.Mock()
        self.stream._decPackageWindow()
        self.assertEqual(self.stream._package_window, 0)
        self.assertEqual(self.stream._pollWriteQueue.call_count, 0)
        self.assertEqual(self.stream._write_deferred, None)

    def test_chunkRelayData(self):
        data = '\x00'*(stream.MAX_RPAYLOAD_LEN*2)
        data += '\x00'*(stream.MAX_RPAYLOAD_LEN-1)

        ret = stream._chunkRelayData(data)
        self.assertEqual(ret,
            ['\x00'*stream.MAX_RPAYLOAD_LEN, '\x00'*stream.MAX_RPAYLOAD_LEN,
             '\x00'*(stream.MAX_RPAYLOAD_LEN-1)])

    def tearDown(self):
        self.log_patch.stop()
