import mock

from twisted.trial import unittest

from oppy.cell.definitions import (
    CREATE2_CMD,
    PADDING_CMD,
    VPADDING_CMD,
)

from oppy.connection import connection


class ConnectionTest(unittest.TestCase):

    @mock.patch('oppy.connection.connectionbuildtask.ConnectionBuildTask',
                autospec=True)
    @mock.patch('oppy.connection.connectionmanager.ConnectionManager',
                autospec=True)
    def setUp(self, cm, cbt):
        cbt.micro_status_entry = mock.Mock()
        self.cbt = cbt
        self.cm = cm
        self.connection = connection.Connection(cm, cbt)

    def test_send(self):
        self.connection.transport = mock.Mock()
        self.connection.transport.write = mock.Mock()

        mock_cell = mock.Mock()
        mock_cell.get_bytes = mock.Mock()

        self.connection.send(mock_cell)

        self.connection.transport.write.assert_called_once_with(
                                                         mock_cell.getBytes())

    # TODO: test dataReceived

    def test_recv_no_padding_have_circuit(self):
        mock_cell = mock.Mock()
        mock_cell.header = mock.Mock()
        mock_cell.header.circ_id = 0
        mock_cell.header.cmd = CREATE2_CMD
        mock_circuit = mock.Mock()
        mock_circuit.recv = mock.Mock()

        self.connection._circuit_dict[0] = mock_circuit

        self.connection._recv(mock_cell)

        mock_circuit.recv.assert_called_once_with(mock_cell)

    def test_recvCell_padding_fixed(self):
        mock_cell = mock.Mock()
        mock_cell.header = mock.Mock()
        mock_cell.header.circ_id = 0
        mock_cell.header.cmd = PADDING_CMD
        mock_circuit = mock.Mock()
        mock_circuit.recv = mock.Mock()

        self.connection._circuit_dict[0] = mock_circuit

        self.connection._recv(mock_cell)

        self.assertEqual(mock_circuit.recv.call_count, 0)

    def test_recvCell_padding_varlen(self):
        mock_cell = mock.Mock()
        mock_cell.header = mock.Mock()
        mock_cell.header.circ_id = 0
        mock_cell.header.cmd = VPADDING_CMD
        mock_circuit = mock.Mock()
        mock_circuit.recv = mock.Mock()

        self.connection._circuit_dict[0] = mock_circuit

        self.connection._recv(mock_cell)

        self.assertEqual(mock_circuit.recv.call_count, 0)

    def test_recvCell_no_circuit(self):
        mock_cell = mock.Mock()
        mock_cell.header = mock.Mock()
        mock_cell.header.circ_id = 0
        mock_cell.header.cmd = VPADDING_CMD
        mock_circuit = mock.Mock()
        mock_circuit.recv = mock.Mock()

        self.connection._circuit_dict[1] = mock_circuit

        self.connection._recv(mock_cell)

        self.assertEqual(mock_circuit.recv.call_count, 0)

    def test_addCircuit(self):
        mock_circuit = mock.Mock()
        mock_circuit.circuit_id = 0

        self.connection.addCircuit(mock_circuit)

        self.assertEqual(self.connection._circuit_dict[0], mock_circuit)

    def test_closeConnection(self):
        self.connection._destroyAllCircuits = mock.Mock()
        self.connection._connection_manager.removeConnection = mock.Mock()
        self.connection.transport = mock.Mock()
        self.connection.transport.loseConnection = mock.Mock()

        self.connection.closeConnection()

        self.assertTrue(self.connection._closed)
        self.assertEqual(self.connection._destroyAllCircuits.call_count, 1)
        self.connection._connection_manager.removeConnection.\
                                    assert_called_once_with(self.connection)
        self.assertEqual(self.connection.transport.loseConnection.call_count,
                         1)

    @mock.patch('oppy.connection.connection.logging')
    def test_connectionLost_not_closed(self, _):
        self.connection._destroyAllCircuits = mock.Mock()
        self.connection._connection_manager.removeConnection = mock.Mock()

        self.connection.connectionLost(None)
        
        self.assertTrue(self.connection._closed)
        self.assertEqual(self.connection._destroyAllCircuits.call_count, 1)
        self.connection._connection_manager.removeConnection.\
                                    assert_called_once_with(self.connection)

    def test_connectionLost_closed(self):
        self.connection._closed = True
        self.connection._destroyAllCircuits = mock.Mock()
        self.connection._connection_manager.removeConnection = mock.Mock()

        self.connection.connectionLost(None)
        
        self.assertTrue(self.connection._closed)
        self.assertEqual(self.connection._destroyAllCircuits.call_count, 0)
        self.assertEqual(
              self.connection._connection_manager.removeConnection.call_count,
              0)

    def test_destroyAllCircuits(self):
        mock_circuit_1 = mock.Mock()
        mock_circuit_1.destroyCircuitFromConnection = mock.Mock()
        mock_circuit_2 = mock.Mock()
        mock_circuit_2.destroyCircuitFromConnection = mock.Mock()

        self.connection._circuit_dict = {
                1: mock_circuit_1,
                2: mock_circuit_2,
        }

        self.connection._destroyAllCircuits()

        self.assertEqual(
                       mock_circuit_1.destroyCircuitFromConnection.call_count,
                       1)
        self.assertEqual(
                       mock_circuit_2.destroyCircuitFromConnection.call_count,
                       1)

    def test_removeCircuit_have_circuit_more_left(self):
        mock_circuit_1 = mock.Mock()
        mock_circuit_1.circuit_id = 1
        mock_circuit_2 = mock.Mock()
        mock_circuit_2.circuit_id = 2
        self.connection._circuit_dict = {
                1: mock_circuit_1,
                2: mock_circuit_2,
        }
        self.connection._connection_manager.shouldDestroyConnection = mock.Mock()

        self.connection.removeCircuit(mock_circuit_1)

        self.assertTrue(mock_circuit_1 not in self.connection._circuit_dict)
        self.assertEqual(self.connection._circuit_dict[2], mock_circuit_2)
        self.assertEqual(
          self.connection._connection_manager.shouldDestroyConnection.call_count,
          0)

    def test_removeCircuit_have_circuit_none_left_dont_destroy(self):
        mock_circuit_1 = mock.Mock()
        mock_circuit_1.circuit_id = 1
        self.connection._circuit_dict = {
                1: mock_circuit_1,
        }
        self.connection._connection_manager.shouldDestroyConnection = mock.Mock()
        self.connection._connection_manager.shouldDestroyConnection.return_value = False
        self.connection.closeConnection = mock.Mock()

        self.connection.removeCircuit(mock_circuit_1)

        self.assertTrue(mock_circuit_1 not in self.connection._circuit_dict)
        self.assertEqual(self.connection.closeConnection.call_count, 0)

    def test_removeCircuit_have_circuit_none_left_do_destroy(self):
        mock_circuit_1 = mock.Mock()
        mock_circuit_1.circuit_id = 1
        self.connection._circuit_dict = {
                1: mock_circuit_1,
        }
        self.connection._connection_manager.shouldDestroyConnection = mock.Mock()
        self.connection._connection_manager.shouldDestroyConnection.return_value = True
        self.connection.closeConnection = mock.Mock()

        self.connection.removeCircuit(mock_circuit_1)

        self.assertTrue(mock_circuit_1 not in self.connection._circuit_dict)
        self.assertEqual(self.connection.closeConnection.call_count, 1)

    def test_removeCircuit_no_circuit(self):
        mock_circuit = mock.Mock()
        mock_circuit.circuit_id = 0
        self.connection._connection_manager.shouldDestroyConnection = mock.Mock()
        self.connection.closeConnection = mock.Mock()

        self.connection.removeCircuit(mock_circuit)

        self.assertEqual(self.connection._connection_manager.shouldDestroyConnection.call_count, 0)
        self.assertEqual(self.connection.closeConnection.call_count, 0)
