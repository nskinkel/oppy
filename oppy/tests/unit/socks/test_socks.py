import mock

from twisted.trial import unittest

from oppy.socks import socks


class SOCKSTest(unittest.TestCase):
    
    @mock.patch('oppy.circuit.circuitmanager.CircuitManager', autospec=True)
    def setUp(self, mock_cm):
        self.mock_cm = mock_cm
        self.socksp = socks.OppySOCKSProtocol(self.mock_cm)
        self.log_patch = mock.patch('oppy.socks.socks.logging')
        self.mock_log = self.log_patch.start()


    def test_init(self):
        self.assertEqual(self.socksp.state, socks.State.HANDSHAKE)

    def test_dataReceived_handshake_state(self):
        self.socksp._handleHandshake = mock.Mock()
        self.socksp.dataReceived('test')
        self.socksp._handleHandshake.assert_called_once_with('test')

    def test_dataReceived_request_state(self):
        self.socksp._handleRequest = mock.Mock()
        self.socksp.state = socks.State.REQUEST
        self.socksp.dataReceived('test')
        self.socksp._handleRequest.assert_called_once_with('test')

    def test_dataReceived_forwarding_state(self):
        self.socksp.stream = mock.Mock()
        self.socksp.stream.send = mock.Mock()
        self.socksp.state = socks.State.FORWARDING
        self.socksp.dataReceived('test')
        self.socksp.stream.send.assert_called_once_with('test')

    def test_recv(self):
        self.socksp.transport = mock.Mock()
        self.socksp.transport.write = mock.Mock()
        self.socksp.recv('test')
        self.socksp.transport.write.assert_called_once_with('test')

    def test_closeFromStream(self):
        self.socksp.transport = mock.Mock()
        self.socksp.transport.loseConnection = mock.Mock()
        self.socksp.closeFromStream()
        self.assertEqual(self.socksp.transport.loseConnection.call_count, 1)

    @mock.patch('oppy.socks.socks._parseHandshake', side_effect=socks.MalformedSOCKSHandshake)
    def test_handleHandshake_malformed(self, mock_ph):
        self.socksp.transport = mock.Mock()
        self.socksp.transport.loseConnection = mock.Mock()

        self.socksp._handleHandshake('test')
        self.assertEqual(self.socksp.transport.loseConnection.call_count, 1)

    @mock.patch('oppy.socks.socks._parseHandshake', side_effect=socks.NoSupportedMethods)
    def test_handleHandshake_no_supported_methods(self, mock_ph):
        self.socksp.transport = mock.Mock()
        self.socksp.transport.loseConnection = mock.Mock()

        self.socksp._handleHandshake('test')
        self.assertEqual(self.socksp.transport.loseConnection.call_count, 1)

    @mock.patch('oppy.socks.socks._parseHandshake', side_effect=socks.UnsupportedVersion)
    def test_handleHandshake_unsupported_version(self, mock_ph):
        self.socksp.transport = mock.Mock()
        self.socksp.transport.loseConnection = mock.Mock()

        self.socksp._handleHandshake('test')
        self.assertEqual(self.socksp.transport.loseConnection.call_count, 1)

    @mock.patch('oppy.socks.socks._parseHandshake', return_value='\x01\x02\x03')
    def test_handleHandshake_not_no_auth(self, mock_ph):
        self.socksp.transport = mock.Mock()
        self.socksp.transport.loseConnection = mock.Mock()
        self.socksp.transport.write = mock.Mock()

        self.socksp._handleHandshake('test')
        self.socksp.transport.write.assert_called_once_with('\x05\xFF')
        self.assertEqual(self.socksp.transport.loseConnection.call_count, 1)

    @mock.patch('oppy.socks.socks._parseHandshake', return_value='\x00\x01\x02')
    def test_handleHandshake_ok(self, mock_ph):
        self.socksp.transport = mock.Mock()
        self.socksp.transport.loseConnection = mock.Mock()
        self.socksp.transport.write = mock.Mock()

        self.socksp._handleHandshake('test')
        self.socksp.transport.write.assert_called_once_with('\x05\x00')
        self.assertEqual(self.socksp.transport.loseConnection.call_count, 0)
        self.assertEqual(self.socksp.state, socks.State.REQUEST)

    @mock.patch('oppy.socks.socks._parseSOCKSRequestHeader', side_effect=socks.MalformedSOCKSRequest)
    def test_handleRequest_malformed(self, mock_prh):
        self.socksp._sendReply = mock.Mock()
        self.socksp.transport = mock.Mock()
        self.socksp.transport.loseConnection = mock.Mock()
        self.socksp._handleRequest('test')
        self.socksp._sendReply.assert_called_once_with('\x01')
        self.assertEqual(self.socksp.transport.loseConnection.call_count, 1)

    @mock.patch('oppy.socks.socks._parseSOCKSRequestHeader', side_effect=socks.UnsupportedCommand)
    def test_handleRequest_unsupported_command(self, mock_prh):
        self.socksp._sendReply = mock.Mock()
        self.socksp.transport = mock.Mock()
        self.socksp.transport.loseConnection = mock.Mock()
        self.socksp._handleRequest('test')
        self.socksp._sendReply.assert_called_once_with('\x07')
        self.assertEqual(self.socksp.transport.loseConnection.call_count, 1)

    @mock.patch('oppy.socks.socks._parseSOCKSRequestHeader', side_effect=socks.UnsupportedVersion)
    def test_handleRequest_unsupported_version(self, mock_prh):
        self.socksp._sendReply = mock.Mock()
        self.socksp.transport = mock.Mock()
        self.socksp.transport.loseConnection = mock.Mock()
        self.socksp._handleRequest('test')
        self.socksp._sendReply.assert_called_once_with('\x01')
        self.assertEqual(self.socksp.transport.loseConnection.call_count, 1)

    
    @mock.patch('oppy.socks.socks._parseSOCKSRequestHeader', return_value=1)
    @mock.patch('oppy.socks.socks._parseRequest', side_effect=socks.MalformedSOCKSRequest)
    def test_handleRequest_malformed_2(self, mock_pr, mock_prh):
        self.socksp._sendReply = mock.Mock()
        self.socksp.transport = mock.Mock()
        self.socksp.transport.loseConnection = mock.Mock()
        self.socksp._handleRequest('test')
        self.socksp._sendReply.assert_called_once_with('\x01')
        self.assertEqual(self.socksp.transport.loseConnection.call_count, 1)

    @mock.patch('oppy.socks.socks._parseSOCKSRequestHeader', return_value=1)
    @mock.patch('oppy.socks.socks._parseRequest', side_effect=socks.UnsupportedAddressType)
    def test_handleRequest_unsupported_address_type(self, mock_pr, mock_prh):
        self.socksp._sendReply = mock.Mock()
        self.socksp.transport = mock.Mock()
        self.socksp.transport.loseConnection = mock.Mock()
        self.socksp._handleRequest('test')
        self.socksp._sendReply.assert_called_once_with('\x08')
        self.assertEqual(self.socksp.transport.loseConnection.call_count, 1)

    @mock.patch('oppy.socks.socks._parseSOCKSRequestHeader', return_value=1)
    @mock.patch('oppy.socks.socks._parseRequest', return_value='testrequest')
    @mock.patch('oppy.socks.socks.Stream', return_value='teststream')
    def test_handleRequest_ok(self, mock_stream, mock_pr, mock_prh):
        self.socksp._sendReply = mock.Mock()
        self.socksp.transport = mock.Mock()
        self.socksp.transport.loseConnection = mock.Mock()
        self.socksp._handleRequest('test2')
        
        mock_prh.assert_called_once_with('test2')
        mock_pr.assert_called_once_with('2', 1)
        mock_stream.assert_called_once_with(self.mock_cm, 'testrequest', self.socksp)
        self.assertEqual(self.socksp.stream, 'teststream')
        self.assertEqual(self.socksp.state, socks.State.FORWARDING)
        self.socksp._sendReply.assert_called_once_with('\x00')

    def test_sendReply(self):
        self.socksp.transport = mock.Mock()
        self.socksp.transport.write = mock.Mock()
        self.socksp._sendReply('testreply')
        self.socksp.transport.write.assert_called_once_with(
            '\x05testreply\x00\x01\x7f\x00\x00\x01\x00\x00')

    def test_connectionLost_no_stream(self):
        self.socksp.stream = None
        # just make sure we don't crash
        self.socksp.connectionLost('reason')

    def test_connectionList_no_stream_id(self):
        self.socksp.stream = mock.Mock()
        self.socksp.stream.stream_id = None
        self.socksp.connectionLost('reason')

    def test_connectionLost_stream(self):
        self.socksp.stream = mock.Mock()
        self.socksp.stream.stream_id = 0
        self.socksp.stream.closeFromSOCKS = mock.Mock()
        self.socksp.connectionLost('reason')
        self.assertEqual(self.socksp.stream.closeFromSOCKS.call_count, 1)

    def test_connectionMade(self):
        # we don't do anything here right now
        self.socksp.connectionMade()

    def test_parseHandshake_too_short(self):
        self.assertRaises(socks.MalformedSOCKSHandshake,
                          socks._parseHandshake,
                          '')

    def test_parseHandshake_unsupported_version(self):
        self.assertRaises(socks.UnsupportedVersion,
                          socks._parseHandshake,
                          '\x04\x01')

    def test_parseHandshake_no_supported_methods(self):
        self.assertRaises(socks.NoSupportedMethods,
                          socks._parseHandshake,
                          '\x05\x00')

    def test_parseHandshake_not_enough_methods(self):
        self.assertRaises(socks.MalformedSOCKSHandshake,
                          socks._parseHandshake,
                          '\x05\x02\x01')

    def test_parseHandshake_ok(self):
        ret = socks._parseHandshake('\x05\x02\x01\x00')
        self.assertEqual(ret, '\x01\x00')

    def test_parseSOCKSRequestHeader_too_short(self):
        self.assertRaises(socks.MalformedSOCKSRequest,
                          socks._parseSOCKSRequestHeader,
                          '')

    def test_parseSOCKSRequestHeader_unsupported_version(self):
        self.assertRaises(socks.UnsupportedVersion,
                          socks._parseSOCKSRequestHeader,
                          '\x04\x01\x00\x01')

    def test_parseSOCKSRequestHeader_unsupported_command(self):
        self.assertRaises(socks.UnsupportedCommand,
                          socks._parseSOCKSRequestHeader,
                          '\x05\x02\x00\x01')

    def test_parseSOCKSRequestHeader_rsv_non_zero(self):
        self.assertRaises(socks.MalformedSOCKSRequest,
                          socks._parseSOCKSRequestHeader,
                          '\x05\x01\x01\x01')

    def test_parseSOCKSRequestHeader_ok(self):
        ret = socks._parseSOCKSRequestHeader('\x05\x01\x00\xff')
        self.assertEqual(ret, '\xff')

    def test_parseRequest_unsuported_address_type(self):
        self.assertRaises(socks.UnsupportedAddressType,
                          socks._parseRequest,
                          '',
                          '\x02')

    @mock.patch('oppy.socks.socks._parseIPv4Request', return_value='ret')
    def test_parseRequest_ipv4(self, mock_p4):
        ret = socks._parseRequest('test', '\x01')
        mock_p4.assert_called_once_with('test')
        self.assertEqual(ret, 'ret')

    @mock.patch('oppy.socks.socks._parseHostRequest', return_value='ret')
    def test_parseRequest_host(self, mock_h):
        ret = socks._parseRequest('test', '\x03')
        mock_h.assert_called_once_with('test')
        self.assertEqual(ret, 'ret')

    @mock.patch('oppy.socks.socks._parseIPv6Request', return_value='ret')
    def test_parseRequest_ipv6(self, mock_p6):
        ret = socks._parseRequest('test', '\x04')
        mock_p6.assert_called_once_with('test')
        self.assertEqual(ret, 'ret')

    def test_parseIPv4Request_too_short(self):
        self.assertRaises(socks.MalformedSOCKSRequest,
                          socks._parseIPv4Request,
                          '\x00'*5)

    @mock.patch('oppy.socks.socks.ExitRequest', return_value='ret')
    def test_parseIPv4Request_ok(self, mock_er):
        ret = socks._parseIPv4Request('012345')
        mock_er.assert_called_once_with('45', addr='0123')
        self.assertEqual(ret, 'ret')

    def test_parseHost_too_short_1(self):
        self.assertRaises(socks.MalformedSOCKSRequest,
                          socks._parseHostRequest,
                          '')

    def test_parseHost_too_short_2(self):
        self.assertRaises(socks.MalformedSOCKSRequest,
                          socks._parseHostRequest,
                          '\x05\x01\x02\x03\x04\x05\x06')

    @mock.patch('oppy.socks.socks.ExitRequest', return_value='ret')
    def test_parseHost_ok(self, mock_er):
        ret = socks._parseHostRequest('\x051234567')
        mock_er.assert_called_once_with('67', host='12345')
        self.assertEqual(ret, 'ret')

    def test_parseIPv6Request_too_short(self):
        self.assertRaises(socks.MalformedSOCKSRequest,
                          socks._parseIPv6Request,
                          '\x00'*17)

    @mock.patch('oppy.socks.socks.ExitRequest', return_value='ret')
    def test_parseIPv6Request_ok(self, mock_er):
        ret = socks._parseIPv6Request(''.join([chr(i) for i in range(18)]))
        mock_er.assert_called_once_with('\x10\x11',
            addr=''.join([chr(i) for i in range(16)]))
        self.assertEqual(ret, 'ret')

    def tearDown(self):
        self.log_patch.stop()


class OppySOCKSProtocolFactoryTest(unittest.TestCase):

    def test_construction(self):
        mock_cm = mock.Mock()
        pf = socks.OppySOCKSProtocolFactory(mock_cm)
        self.assertEqual(pf.circuit_manager, mock_cm)

    @mock.patch('oppy.socks.socks.OppySOCKSProtocol', return_value='ret')
    def test_buildProtocol(self, mock_osp):
        mock_cm = mock.Mock()
        pf = socks.OppySOCKSProtocolFactory(mock_cm)
        ret = pf.buildProtocol(mock_cm)
        mock_osp.assert_called_once_with(mock_cm)
        self.assertEqual(ret, 'ret')
