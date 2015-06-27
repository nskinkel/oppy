import mock

from twisted.trial import unittest

from oppy.circuit.circuitmanager import CircuitManager
from oppy.circuit.definitions import (
    CircuitType,
    DEFAULT_OPEN_IPv4,
    DEFAULT_OPEN_IPv6,
)
from oppy.path.path import Path


ID = 0


class CircuitManagerTest(unittest.TestCase):

    @mock.patch('oppy.connection.connectionmanager.ConnectionManager',
                autospec=True)
    def setUp(self, cp,):
        self.cp = cp
        self.cm = CircuitManager(cp, autobuild=False)
    
    @mock.patch('oppy.stream.stream.Stream', autospec=True)
    def test_getOpenCircuit_open_circuit(self, mock_stream):
        c = mock.Mock()
        r = mock.Mock()
        mock_stream.request = r
        self.cm._getOpenCandidates = mock.Mock()
        self.cm._getOpenCandidates.return_value = [c]
        self.cm._buildCircuit = mock.Mock()
        self.cm._pending_stream_list = []

        d = self.cm.getOpenCircuit(mock_stream)

        self.assertEqual(self.successResultOf(d), c)
        self.cm._getOpenCandidates.assert_called_once_with(r)
        self.assertEqual(self.cm._buildCircuit.call_count, 0)
        self.assertEqual(self.cm._pending_stream_list, [])

    # TODO: test that the specific correct stream is added to pending list
    @mock.patch('oppy.stream.stream.Stream', autospec=True)
    def test_getOpenCircuit_pending_circuit(self, mock_stream):
        c = mock.Mock()
        r = mock.Mock()
        mock_stream.request = r
        self.cm._getOpenCandidates = mock.Mock()
        self.cm._getOpenCandidates.return_value = []
        self.cm._getPendingCandidates = mock.Mock()
        self.cm._getPendingCandidates.return_value = [c]
        self.cm._buildCircuit = mock.Mock()
        self.cm._pending_stream_list = []

        _ = self.cm.getOpenCircuit(mock_stream)

        self.cm._getOpenCandidates.assert_called_once_with(r)
        self.cm._getPendingCandidates.assert_called_once_with(r)
        self.assertEqual(self.cm._buildCircuit.call_count, 0)
        self.assertEqual(len(self.cm._pending_stream_list), 1)

    # TODO: test _buildCircuit is called with correct args
    #       test specific correct stream added to pending streams
    @mock.patch('oppy.stream.stream.Stream', autospec=True)
    def test_getOpenCircuit_no_circuit(self, mock_stream):
        r = mock.Mock()
        mock_stream.request = r
        self.cm._getOpenCandidates = mock.Mock()
        self.cm._getOpenCandidates.return_value = []
        self.cm._getPendingCandidates = mock.Mock()
        self.cm._getPendingCandidates.return_value = []
        self.cm._buildCircuit = mock.Mock()
        self.cm._pending_stream_list = []

        _ = self.cm.getOpenCircuit(mock_stream)

        self.cm._getOpenCandidates.assert_called_once_with(r)
        self.cm._getPendingCandidates.assert_called_once_with(r)
        self.assertEqual(self.cm._buildCircuit.call_count, 1)
        self.assertEqual(len(self.cm._pending_stream_list), 1)

    def test_shouldDestroyCircuit_ipv4_yes(self):
        c = mock.Mock()
        c.circuit_type = CircuitType.IPv4
        self.cm._totalIPv4Count = mock.Mock()
        self.cm._totalIPv4Count.return_value = DEFAULT_OPEN_IPv4+2

        self.assertTrue(self.cm.shouldDestroyCircuit(c))

    def test_shouldDestroyCircuit_ipv4_no(self):
        c = mock.Mock()
        c.circuit_type = CircuitType.IPv4
        self.cm._totalIPv4Count = mock.Mock()
        self.cm._totalIPv4Count.return_value = DEFAULT_OPEN_IPv4

        self.assertFalse(self.cm.shouldDestroyCircuit(c))

    def test_shouldDestroyCircuit_ipv6_yes(self):
        c = mock.Mock()
        c.circuit_type = CircuitType.IPv6
        self.cm._totalIPv6Count = mock.Mock()
        self.cm._totalIPv6Count.return_value = DEFAULT_OPEN_IPv6+2

        self.assertTrue(self.cm.shouldDestroyCircuit(c))

    def test_shouldDestroyCircuit_ipv6_no(self):
        c = mock.Mock()
        c.circuit_type = CircuitType.IPv6
        self.cm._totalIPv6Count = mock.Mock()
        self.cm._totalIPv6Count.return_value = DEFAULT_OPEN_IPv6

        self.assertFalse(self.cm.shouldDestroyCircuit(c))

    def test_circuitDestroyed_open(self):
        c = mock.Mock()
        c.circuit_id = 10
        self.cm._open_circuit_dict[10] = c
        self.cm._assignAllPossiblePendingRequests = mock.Mock()
        self.cm._buildCircuitsForOrphanedPendingRequests = mock.Mock()
        self.cm._replenishCircuits = mock.Mock()

        self.cm.circuitDestroyed(c)

        self.assertTrue(c not in self.cm._open_circuit_dict.values())
        self.assertEqual(self.cm._assignAllPossiblePendingRequests.call_count,
                         1)
        self.assertEqual(
                  self.cm._buildCircuitsForOrphanedPendingRequests.call_count,
                  1)
        self.assertEqual(self.cm._replenishCircuits.call_count, 1)

    def test_circuitDestroyed_pending(self):
        c = mock.Mock()
        c.circuit_id = 10
        self.cm._circuit_build_task_dict[10] = c
        self.cm._assignAllPossiblePendingRequests = mock.Mock()
        self.cm._buildCircuitsForOrphanedPendingRequests = mock.Mock()
        self.cm._replenishCircuits = mock.Mock()

        self.cm.circuitDestroyed(c)

        self.assertTrue(c not in self.cm._circuit_build_task_dict.values())
        self.assertEqual(self.cm._assignAllPossiblePendingRequests.call_count,
                         1)
        self.assertEqual(
                  self.cm._buildCircuitsForOrphanedPendingRequests.call_count,
                  1)
        self.assertEqual(self.cm._replenishCircuits.call_count, 1)

    @mock.patch('oppy.circuit.circuitmanager.logging', autospec=True)
    def test_circuitDestroyed_no_reference(self, mock_logging):
        c = mock.Mock()
        c.circuit_id = 10
        self.cm._assignAllPossiblePendingRequests = mock.Mock()
        self.cm._buildCircuitsForOrphanedPendingRequests = mock.Mock()
        self.cm._replenishCircuits = mock.Mock()

        self.cm.circuitDestroyed(c)

        self.assertTrue(mock_logging.debug.called)
        self.assertFalse(self.cm._assignAllPossiblePendingRequests.called)
        self.assertFalse(
                  self.cm._buildCircuitsForOrphanedPendingRequests.called)
        self.assertFalse(self.cm._replenishCircuits.called)

    def test_circuitOpened(self):
        c = mock.Mock()
        c.circuit_id = 10
        self.cm._assignPossiblePendingRequestsToCircuit = mock.Mock()
        self.cm._notifyUserCircuitOpened = mock.Mock()

        self.cm._circuit_build_task_dict[10] = c

        self.cm.circuitOpened(c)

        self.assertTrue(c not in self.cm._circuit_build_task_dict.values())
        self.assertTrue(c in self.cm._open_circuit_dict.values())
        self.assertEqual(
                self.cm._assignPossiblePendingRequestsToCircuit.call_count, 1)
        self.assertEqual(self.cm._notifyUserCircuitOpened.call_count, 1)

    @mock.patch('oppy.circuit.circuitmanager.logging', autospec=True)
    def test_circuitOpened_no_reference(self, mock_logging):
        c = mock.Mock()
        c.circuit_id = 10
        self.cm._assignPossiblePendingRequestsToCircuit = mock.Mock()
        self.cm._notifyUserCircuitOpened = mock.Mock()

        self.cm.circuitOpened(c)

        self.assertTrue(c not in self.cm._open_circuit_dict.values())
        self.assertFalse(
                       self.cm._assignPossiblePendingRequestsToCircuit.called)
        self.assertFalse(self.cm._notifyUserCircuitOpened.called)
        self.assertEqual(mock_logging.debug.call_count, 2)

    def test_destroyAllCircuits_with_streams(self):
        mock_stream = mock.Mock()
        self.cm._pending_stream_list = [mock_stream]
        mock_open_circuit = mock.Mock()
        self.cm._open_circuit_dict = {1: mock_open_circuit}
        mock_circuit_build_task = mock.Mock()
        self.cm._circuit_build_task_dict = {2: mock_circuit_build_task}

        self.cm.destroyAllCircuits()

        self.assertEqual(len(self.cm._pending_stream_list), 0)
        self.assertEqual(
                    mock_open_circuit.destroyCircuitFromManager.call_count, 1)
        self.assertEqual(
                 mock_circuit_build_task.destroyCircuitFromManager.call_count,
                 1)

    def test_destroyAllCircuits_without_streams(self):
        mock_stream = mock.Mock()
        self.cm._pending_stream_list = [mock_stream]
        mock_open_circuit = mock.Mock()
        self.cm._open_circuit_dict = {1: mock_open_circuit}
        mock_circuit_build_task = mock.Mock()
        self.cm._circuit_build_task_dict = {2: mock_circuit_build_task}

        self.cm.destroyAllCircuits(destroy_pending_streams=False)

        self.assertTrue(mock_stream in self.cm._pending_stream_list)
        self.assertEqual(
                    mock_open_circuit.destroyCircuitFromManager.call_count, 1)
        self.assertEqual(
                 mock_circuit_build_task.destroyCircuitFromManager.call_count,
                 1)

    def test_buildCircuitsForOrphanedRequests(self):
        mock_stream = mock.Mock()
        mock_stream.request = mock.Mock()
        self.cm._pending_stream_list = [mock_stream]
        self.cm._getPendingCandidates = mock.Mock()
        self.cm._getPendingCandidates.return_value = []
        self.cm._buildCircuitsForPendingStreams = mock.Mock()

        self.cm._buildCircuitsForOrphanedPendingRequests()

        self.cm._buildCircuitsForPendingStreams.assert_called_once_with(
                                                                [mock_stream])

    @mock.patch('oppy.circuit.circuitmanager.logging', autospec=True)
    def test_notifyUserCircuitOpened_not_notified_yet(self, mock_logging):
        self.cm._sent_open_message = False
        
        self.cm._notifyUserCircuitOpened()

        self.assertEqual(mock_logging.info.call_count, 1)
        self.assertTrue(self.cm._sent_open_message)
        

    @mock.patch('oppy.circuit.circuitmanager.logging', autospec=True)
    def test_notifyUserCircuitOpened_notified_already(self, mock_logging):
        self.cm._sent_open_message = True
        
        self.cm._notifyUserCircuitOpened()

        self.assertEqual(mock_logging.info.call_count, 0)
        self.assertTrue(self.cm._sent_open_message)

    @mock.patch('oppy.circuit.circuitmanager.PendingStream', autospec=True)
    def test_assignPossiblePendingRequestsToCircuit_yes(self,
                                                        mock_pending_stream):
        mock_request = mock.Mock()
        mock_deferred = mock.Mock()
        mock_pending_stream.stream.request = mock_request
        mock_pending_stream.deferred = mock_deferred
        mock_circuit = mock.Mock()
        mock_circuit.canHandleRequest = mock.Mock()
        mock_circuit.canHandleRequest.return_value = True
        self.cm._pending_stream_list = [mock_pending_stream]

        self.cm._assignPossiblePendingRequestsToCircuit(mock_circuit)

        mock_circuit.canHandleRequest.assert_called_once_with(mock_request)
        mock_deferred.callback.assert_called_once_with(mock_circuit)
        self.assertTrue(mock_pending_stream not in 
                        self.cm._pending_stream_list)
        self.assertEqual(len(self.cm._pending_stream_list), 0)

    @mock.patch('oppy.circuit.circuitmanager.PendingStream', autospec=True)
    def test_assignPossiblePendingRequests_none(self, mock_pending_stream):
        mock_request = mock.Mock()
        mock_deferred = mock.Mock()
        mock_pending_stream.stream.request = mock_request
        mock_pending_stream.deferred = mock_deferred
        mock_circuit = mock.Mock()
        mock_circuit.canHandleRequest = mock.Mock()
        mock_circuit.canHandleRequest.return_value = False
        self.cm._pending_stream_list = [mock_pending_stream]

        self.cm._assignPossiblePendingRequestsToCircuit(mock_circuit)

        mock_circuit.canHandleRequest.assert_called_once_with(mock_request)
        self.assertEqual(mock_deferred.callback.call_count, 0)
        self.assertTrue(mock_pending_stream in
                        self.cm._pending_stream_list)
        self.assertEqual(len(self.cm._pending_stream_list), 1)

    @mock.patch('oppy.circuit.circuitmanager.PendingStream', autospec=True)
    def test_assignAllPossiblePendingRequests(self, mock_pending_stream):
        mock_circuit_1 = mock.Mock()
        mock_circuit_2 = mock.Mock()
        self.cm._open_circuit_dict = {1: mock_circuit_1, 2: mock_circuit_2}
        self.cm._assignPossiblePendingRequestsToCircuit = mock.Mock()

        self.cm._assignAllPossiblePendingRequests()

        self.assertEqual(
                self.cm._assignPossiblePendingRequestsToCircuit.call_count, 2)

    @mock.patch('oppy.circuit.circuitmanager.CircuitBuildTask', autospec=True)
    def test_buildCircuit(self, mock_circuit_build_task):
        self.cm._buildCircuit()

        self.assertEqual(mock_circuit_build_task.call_count, 1)
        self.assertEqual(len(self.cm._circuit_build_task_dict), 1)

    def test_buildCircuits(self):
        self.cm._buildCircuit = mock.Mock()

        self.cm._buildCircuits(5)

        self.assertEqual(self.cm._buildCircuit.call_count, 5)

    def test_buildCircuitsForPendingStreams(self):
        mock_pending_stream = mock.Mock()
        mock_request = mock.Mock()
        mock_pending_stream.request = mock_request
        self.cm._buildCircuit = mock.Mock()

        self.cm._buildCircuitsForPendingStreams([mock_pending_stream])

        self.assertEqual(self.cm._buildCircuit.call_count, 1)

    def test_replenishCircuits_none(self):
        self.cm._buildCircuit = mock.Mock()

        self.cm._totalIPv4Count = mock.Mock()
        self.cm._totalIPv4Count.return_value = self.cm._min_IPv4_count

        self.cm._totalIPv6Count = mock.Mock()
        self.cm._totalIPv6Count.return_value = self.cm._min_IPv6_count

        self.cm._replenishCircuits()

        self.assertEqual(self.cm._buildCircuit.call_count, 0)
    
    # TODO: check call_args for correct type
    def test_replenishCircuits_ipv4(self):
        self.cm._buildCircuit = mock.Mock()

        self.cm._totalIPv4Count = mock.Mock()
        self.cm._totalIPv4Count.return_value = self.cm._min_IPv4_count-1

        self.cm._totalIPv6Count = mock.Mock()
        self.cm._totalIPv6Count.return_value = self.cm._min_IPv6_count

        self.cm._replenishCircuits()

        self.assertEqual(self.cm._buildCircuit.call_count, 1)

    def test_replenishCircuits_ipv6(self):
        self.cm._buildCircuit = mock.Mock()

        self.cm._totalIPv4Count = mock.Mock()
        self.cm._totalIPv4Count.return_value = self.cm._min_IPv4_count

        self.cm._totalIPv6Count = mock.Mock()
        self.cm._totalIPv6Count.return_value = self.cm._min_IPv6_count-1

        self.cm._replenishCircuits()

        self.assertEqual(self.cm._buildCircuit.call_count, 1)

    def test_replenishCircuits_both(self):
        self.cm._buildCircuit = mock.Mock()

        self.cm._totalIPv4Count = mock.Mock()
        self.cm._totalIPv4Count.return_value = self.cm._min_IPv4_count-1

        self.cm._totalIPv6Count = mock.Mock()
        self.cm._totalIPv6Count.return_value = self.cm._min_IPv6_count-1

        self.cm._replenishCircuits()

        self.assertEqual(self.cm._buildCircuit.call_count, 2)

    def test_openIPv4Count(self):
        mock_circuit_1 = mock.Mock()
        mock_circuit_1.circuit_type = CircuitType.IPv4
        mock_circuit_2 = mock.Mock()
        mock_circuit_2.circuit_type = CircuitType.IPv6
        self.cm._open_circuit_dict = {1: mock_circuit_1, 2: mock_circuit_2}

        self.assertEqual(self.cm._openIPv4Count(), 1)

    def test_openIPv6Count(self):
        mock_circuit_1 = mock.Mock()
        mock_circuit_1.circuit_type = CircuitType.IPv4
        mock_circuit_2 = mock.Mock()
        mock_circuit_2.circuit_type = CircuitType.IPv6
        self.cm._open_circuit_dict = {1: mock_circuit_1, 2: mock_circuit_2}

        self.assertEqual(self.cm._openIPv6Count(), 1)

    def test_pendingIPv4Count(self):
        mock_circuit_1 = mock.Mock()
        mock_circuit_1.circuit_type = CircuitType.IPv4
        mock_circuit_2 = mock.Mock()
        mock_circuit_2.circuit_type = CircuitType.IPv6
        self.cm._circuit_build_task_dict = {1: mock_circuit_1,
                                            2: mock_circuit_2}

        self.assertEqual(self.cm._pendingIPv4Count(), 1)

    def test_pendingIPv6Count(self):
        mock_circuit_1 = mock.Mock()
        mock_circuit_1.circuit_type = CircuitType.IPv4
        mock_circuit_2 = mock.Mock()
        mock_circuit_2.circuit_type = CircuitType.IPv6
        self.cm._circuit_build_task_dict = {1: mock_circuit_1,
                                            2: mock_circuit_2}

        self.assertEqual(self.cm._pendingIPv6Count(), 1)

    def test_totalIPv4Count(self):
        mock_circuit_1 = mock.Mock()
        mock_circuit_1.circuit_type = CircuitType.IPv4
        mock_circuit_2 = mock.Mock()
        mock_circuit_2.circuit_type = CircuitType.IPv6
        self.cm._circuit_build_task_dict = {1: mock_circuit_1,
                                            2: mock_circuit_2}
        self.cm._open_circuit_dict = {1: mock_circuit_1, 2: mock_circuit_2}

        self.assertEqual(self.cm._totalIPv4Count(), 2)

    def test_totalIPv6Count(self):
        mock_circuit_1 = mock.Mock()
        mock_circuit_1.circuit_type = CircuitType.IPv4
        mock_circuit_2 = mock.Mock()
        mock_circuit_2.circuit_type = CircuitType.IPv6
        self.cm._circuit_build_task_dict = {1: mock_circuit_1,
                                            2: mock_circuit_2}
        self.cm._open_circuit_dict = {1: mock_circuit_1, 2: mock_circuit_2}

        self.assertEqual(self.cm._totalIPv6Count(), 2)

    def test_getOpenCandidates(self):
        mock_circuit_1 = mock.Mock()
        mock_circuit_2 = mock.Mock()
        mock_circuit_3 = mock.Mock()
        mock_circuit_1.canHandleRequest = mock.Mock()
        mock_circuit_2.canHandleRequest = mock.Mock()
        mock_circuit_3.canHandleRequest = mock.Mock()
        mock_circuit_1.canHandleRequest.return_value = True
        mock_circuit_2.canHandleRequest.return_value = True
        mock_circuit_3.canHandleRequest.return_value = False

        self.cm._open_circuit_dict = {1: mock_circuit_1,
                                      2: mock_circuit_2,
                                      3: mock_circuit_3,}

        test_val = [mock_circuit_1, mock_circuit_2]

        self.assertEqual(self.cm._getOpenCandidates(mock.Mock()), test_val)

    def test_getPendingCandidates(self):
        mock_circuit_1 = mock.Mock()
        mock_circuit_2 = mock.Mock()
        mock_circuit_3 = mock.Mock()
        mock_circuit_1.canHandleRequest = mock.Mock()
        mock_circuit_2.canHandleRequest = mock.Mock()
        mock_circuit_3.canHandleRequest = mock.Mock()
        mock_circuit_1.canHandleRequest.return_value = True
        mock_circuit_2.canHandleRequest.return_value = True
        mock_circuit_3.canHandleRequest.return_value = False

        self.cm._circuit_build_task_dict = {1: mock_circuit_1,
                                            2: mock_circuit_2,
                                            3: mock_circuit_3,}

        test_val = [mock_circuit_1, mock_circuit_2]

        self.assertEqual(self.cm._getPendingCandidates(mock.Mock()), test_val)
