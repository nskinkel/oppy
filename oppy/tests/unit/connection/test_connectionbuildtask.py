import mock

from twisted.internet import defer
from twisted.trial import unittest

from OpenSSL import crypto

import oppy.connection.connectionbuildtask as connectionbuildtask
from oppy.connection.definitions import (
    LINK_CERT_TYPE,
    ID_CERT_TYPE,
    OPENSSL_RSA_KEY_TYPE,
)

from oppy.cell.fixedlen import NetInfoCell
from oppy.cell.varlen import AuthChallengeCell, CertsCell, VersionsCell
from oppy.cell.util import CertsCellPayloadItem

from cert_der import test_cert_der


class ConnectionBuildTaskTest(unittest.TestCase):

    @mock.patch('oppy.connection.connectionmanager.ConnectionManager', autospec=True)
    def setUp(self, cm):
        self.cm = cm
        self.cbt = connectionbuildtask.ConnectionBuildTask(cm, mock.Mock())

    @mock.patch('twisted.internet.defer.Deferred', autospec=True)
    def test_connectionMade(self, mock_deferred):
        mock_sendVersionsCell = mock.Mock()
        mock_sendVersionsCell.return_value = mock_deferred
        self.cbt._sendVersionsCell = mock_sendVersionsCell

        self.cbt.connectionMade()

        self.assertEqual(mock_sendVersionsCell.call_count, 1)
        self.assertEqual(self.cbt._tasks.addCallback.call_count, 6)
        self.assertTrue(mock.call(self.cbt._processVersionsCell) in
                        self.cbt._tasks.addCallback.call_args_list)
        self.assertTrue(mock.call(self.cbt._processCertsCell) in
                        self.cbt._tasks.addCallback.call_args_list)
        self.assertTrue(mock.call(self.cbt._processAuthChallengeCell) in
                        self.cbt._tasks.addCallback.call_args_list)
        self.assertTrue(mock.call(self.cbt._processNetInfoCell) in
                        self.cbt._tasks.addCallback.call_args_list)
        self.assertTrue(mock.call(self.cbt._sendNetInfoCell) in
                        self.cbt._tasks.addCallback.call_args_list)
        self.assertTrue(mock.call(self.cbt._connectionSucceeded) in
                        self.cbt._tasks.addCallback.call_args_list)
        self.cbt._tasks.addErrback.assert_called_once_with(
                                                   self.cbt._connectionFailed)

    def test_connectionMade_send_versions_fail(self):
        self.cbt._sendVersionsCell = mock.Mock()
        self.cbt._sendVersionsCell.side_effect = Exception
        self.cbt._connectionFailed = mock.Mock()
        self.cbt._connectionSucceeded = mock.Mock()

        self.cbt.connectionMade()

        self.assertEqual(self.cbt._connectionFailed.call_count, 1)
        self.assertEqual(self.cbt._connectionSucceeded.call_count, 0)

    def test_connectionMade_callback_fail(self):
        d = defer.Deferred()
        self.cbt._sendVersionsCell = mock.Mock()
        self.cbt._sendVersionsCell.return_value = d
        self.cbt._processVersionsCell = mock.Mock()
        self.cbt._processVersionsCell.return_value = 'test'
        self.cbt._processCertsCell = mock.Mock()
        self.cbt._processCertsCell.return_value = 'test'
        self.cbt._processAuthChallengeCell = mock.Mock()
        self.cbt._processAuthChallengeCell.side_effect = Exception
        self.cbt._processNetInfoCell = mock.Mock()
        self.cbt._sendNetInfoCell = mock.Mock()
        self.cbt._connectionSucceeded = mock.Mock()
        self.cbt._connectionFailed = mock.Mock()

        self.cbt.connectionMade()

        d.callback('test')

        self.assertEqual(self.cbt._connectionFailed.call_count, 1)
        self.assertEqual(self.cbt._connectionSucceeded.call_count, 0)

    def test_connectionLost_not_failed_with_current_task(self):
        self.cbt._current_task = mock.Mock()
        self.cbt._current_task.errback = mock.Mock()
        self.cbt._connectionFailed = mock.Mock()

        self.cbt.connectionLost(mock.Mock())

        self.assertTrue(self.cbt._failed)
        self.assertEqual(self.cbt._connectionFailed.call_count, 0)
        self.assertEqual(self.cbt._current_task.errback.call_count, 1)

    def test_connectionLost_not_failed_no_current_task(self):
        self.cbt._current_task = None
        self.cbt._connectionFailed = mock.Mock()

        self.cbt.connectionLost(mock.Mock())

        self.assertTrue(self.cbt._failed)
        self.assertEqual(self.cbt._connectionFailed.call_count, 1)

    def test_connectionLost_failed(self):
        self.cbt._failed = True

        self.cbt._current_task = mock.Mock()
        self.cbt._current_task.errback = mock.Mock()
        self.cbt._connectionFailed = mock.Mock()

        self.cbt.connectionLost(mock.Mock())

        self.assertTrue(self.cbt._failed)
        self.assertEqual(self.cbt._connectionFailed.call_count, 0)
        self.assertEqual(self.cbt._current_task.errback.call_count, 0)

    # TODO: test dataReceived(). blocked by fixing cell parsing code.

    def test_recvCell(self):
        self.cbt._read_queue = mock.Mock()
        self.cbt._read_queue.get = mock.Mock()
        ret = mock.Mock()
        self.cbt._read_queue.get.return_value = ret

        r = self.cbt._recvCell()

        self.assertEqual(r, ret)
        self.assertEqual(ret, self.cbt._current_task)

    @mock.patch('oppy.connection.connectionbuildtask.VersionsCell',
                autospec=True)
    def test_sendVersionsCell(self, mock_versions):
        mock_cell = mock.Mock()
        mock_bytes = mock.Mock()
        mock_cell.getBytes.return_value = mock_bytes
        mock_versions.make.return_value = mock_cell
        self.cbt.transport = mock.Mock()
        self.cbt.transport.write = mock.Mock()
        self.cbt._recvCell = mock.Mock()
        ret = mock.Mock()
        self.cbt._recvCell.return_value = ret

        r = self.cbt._sendVersionsCell()

        self.cbt.transport.write.assert_called_once_with(mock_bytes)
        self.assertEqual(r, ret)

    @mock.patch('oppy.connection.connectionbuildtask._connectionSupportsHandshake')
    def test_processVersionsCell(self, csh):
        csh.return_value = True
        cell = VersionsCell.make([3])
        self.cbt.transport = mock.Mock()
        self.cbt.transport.getPeerCertificate = mock.Mock()
        self.cbt.transport.getPeerCertificate.return_value = 'test'
        self.cbt._recvCell = mock.Mock()
        self.cbt._recvCell.return_value = 't'

        self.assertEqual(self.cbt._processVersionsCell(cell), 't')
        self.assertEqual(self.cbt._connection_cert, 'test')
        self.assertEqual(self.cbt._link_protocol, 3)
        self.assertEqual(self.cbt._recvCell.call_count, 1)

    def test_processVersionsCell_wrong_cell_type(self):
        cell = NetInfoCell.make(0, '127.0.0.1', ['127.0.0.1'])

        self.assertRaises(TypeError,
                          self.cbt._processVersionsCell,
                          cell)

    
    @mock.patch('oppy.connection.connectionbuildtask._connectionSupportsHandshake')
    def test_processVersionsCell_unsupported_handshake(self, csh):
        self.cbt.transport = mock.Mock()
        self.cbt.transport.getPeerCertificate = mock.Mock()
        self.cbt.transport.getPeerCertificate.return_value = 'test'
        csh.return_value = False
        cell = VersionsCell.make([3])

        self.assertRaises(ValueError,
                          self.cbt._processVersionsCell,
                          cell)

    @mock.patch('oppy.connection.connectionbuildtask._connectionSupportsHandshake')
    def test_processVersionsCell_no_versions_in_common(self, csh):
        self.cbt.transport = mock.Mock()
        self.cbt.transport.getPeerCertificate = mock.Mock()
        self.cbt.transport.getPeerCertificate.return_value = 'test'
        csh.return_value = True
        cell = VersionsCell(None, [2])
        
        self.assertRaises(ValueError,
                          self.cbt._processVersionsCell,
                          cell)

    @mock.patch('oppy.connection.connectionbuildtask._getCertsFromCell',
                return_value=(mock.Mock(), mock.Mock()))
    @mock.patch('oppy.connection.connectionbuildtask._certsHaveValidTime',
                return_value=True)
    @mock.patch('oppy.connection.connectionbuildtask._ASN1KeysEqual',
                return_value=True)
    @mock.patch('oppy.connection.connectionbuildtask._isRSA1024BitKey',
                return_value=True)
    @mock.patch('oppy.crypto.util.verifyCertSig', return_value=True)
    def test_processCertsCell(self, gcfc, chvt, ake, irbk, crypto):
        self.cbt._connection_cert = mock.Mock()

        self.cbt._recvCell = mock.Mock()
        self.cbt._recvCell.return_value = 'test'

        cell = CertsCell(None)

        self.assertEqual(self.cbt._processCertsCell(cell), 'test')
        self.assertEqual(self.cbt._recvCell.call_count, 1)

    def test_processCertsCell_wrong_cell_type(self):
        cell = NetInfoCell.make(0, '127.0.0.1', ['127.0.0.1'])

        self.assertRaises(TypeError,
                          self.cbt._processCertsCell,
                          cell)

    @mock.patch('oppy.connection.connectionbuildtask._getCertsFromCell',
                return_value=(mock.Mock(), mock.Mock()))
    @mock.patch('oppy.connection.connectionbuildtask._certsHaveValidTime',
                return_value=False)
    def test_processCertsCell_invalid_cert_time(self, gcfc, chvt):
        cell = CertsCell(None)

        self.assertRaises(ValueError,
                          self.cbt._processCertsCell,
                          cell)

    @mock.patch('oppy.connection.connectionbuildtask._getCertsFromCell',
                return_value=(mock.Mock(), mock.Mock()))
    @mock.patch('oppy.connection.connectionbuildtask._certsHaveValidTime',
                return_value=True)
    @mock.patch('oppy.connection.connectionbuildtask._ASN1KeysEqual',
                return_value=False)
    def test_processCertsCell_keys_neq(self, gcfc, chvt, ake):
        self.cbt._connection_cert = mock.Mock()
        cell = CertsCell(None)

        self.assertRaises(ValueError,
                          self.cbt._processCertsCell,
                          cell)

    @mock.patch('oppy.connection.connectionbuildtask._getCertsFromCell',
                return_value=(mock.Mock(), mock.Mock()))
    @mock.patch('oppy.connection.connectionbuildtask._certsHaveValidTime',
                return_value=True)
    @mock.patch('oppy.connection.connectionbuildtask._ASN1KeysEqual',
                return_value=True)
    @mock.patch('oppy.connection.connectionbuildtask._isRSA1024BitKey',
                return_value=False)
    def test_processCertsCell_not_RSA_1024(self, gcfc, chvt, ake, irbk):
        self.cbt._connection_cert = mock.Mock()
        cell = CertsCell(None)

        self.assertRaises(ValueError,
                          self.cbt._processCertsCell,
                          cell)

    @mock.patch('oppy.connection.connectionbuildtask._getCertsFromCell',
                return_value=(mock.Mock(), mock.Mock()))
    @mock.patch('oppy.connection.connectionbuildtask._certsHaveValidTime',
                return_value=True)
    @mock.patch('oppy.connection.connectionbuildtask._ASN1KeysEqual',
                return_value=True)
    @mock.patch('oppy.connection.connectionbuildtask._isRSA1024BitKey',
                return_value=True)
    @mock.patch('oppy.crypto.util.verifyCertSig', return_value=False)
    def test_processCertsCell_cert_not_signed(self, gcfc, chvt, ake, irbk, c):
        self.cbt._connection_cert = mock.Mock()
        cell = CertsCell(None)

        self.assertRaises(ValueError,
                          self.cbt._processCertsCell,
                          cell)

    def test_processAuthChallengeCell(self):
        cell = AuthChallengeCell(None)
        self.cbt._recvCell = mock.Mock()
        self.cbt._recvCell.return_value = 'test'

        self.assertEqual(self.cbt._processAuthChallengeCell(cell), 'test')
        self.assertEqual(self.cbt._recvCell.call_count, 1)

    def test_processAuthChallengeCell_wrong_cell_type(self):
        cell = CertsCell(None)

        self.assertRaises(TypeError,
                          self.cbt._processAuthChallengeCell,
                          cell)

    def test_processNetInfoCell(self):
        cell = NetInfoCell.make(0, '127.0.0.1', ['127.0.0.2'])
        
        self.assertEqual(self.cbt._processNetInfoCell(cell),
                         ('127.0.0.1', '127.0.0.2'))

    def test_processNetInfoCell_wrong_type(self):
        self.assertRaises(TypeError,
                          self.cbt._processNetInfoCell,
                          CertsCell(None))

    @mock.patch('oppy.connection.connectionbuildtask.NetInfoCell.getBytes',
                return_value='test')
    def test_sendNetInfoCell(self, cell):
        self.cbt.transport = mock.Mock()
        self.cbt.transport.write = mock.Mock()

        self.cbt._sendNetInfoCell(('127.0.0.1', '127.0.0.2'))

        self.cbt.transport.write.assert_called_once_with('test')

    def test_connectionSucceeded(self):
        self.cbt._connectionSucceeded(None)

        self.cm.connectionTaskSucceeded.assert_called_once_with(self.cbt)

    def test_connectionFailed_not_failed_yet(self):
        self.cbt._failed = False
        self.cbt.transport = mock.Mock()
        self.cbt.transport.abortConnection = mock.Mock()

        self.cbt._connectionFailed(None)

        self.assertTrue(self.cbt._failed)
        self.assertEqual(self.cbt.transport.abortConnection.call_count, 1)
        self.assertEqual(self.cm.connectionTaskFailed.call_count, 1)

    def test_connectionFailed_already_failed(self):
        self.cbt._failed = True
        self.cbt.transport = mock.Mock()
        self.cbt.transport.abortConnection = mock.Mock()

        self.cbt._connectionFailed(None)

        self.assertTrue(self.cbt._failed)
        self.assertEqual(self.cbt.transport.abortConnection.call_count, 0)
        self.assertEqual(self.cm.connectionTaskFailed.call_count, 1)

    @mock.patch('oppy.crypto.util.verifyCertSig', return_value=True)
    def test_connectionSupportsHandshake_self_signed(self, _):
        c = mock.Mock()

        mock_issuer = mock.Mock()
        mock_issuer.get_components.return_value = [('CN', None)]
        mock_issuer.commonName = 'foo.net'
        c.get_issuer.return_value = mock_issuer

        mock_subject = mock.Mock()
        mock_subject.get_components.return_value = [('CN', None)]
        mock_subject.commonName = 'bar.net'
        c.get_subject.return_value = mock_subject

        b = mock.Mock()
        c.get_pubkey.bits = mock.Mock(return_value=b)
        b.bits.return_value = 1024

        self.assertTrue(connectionbuildtask._connectionSupportsHandshake(c))

    @mock.patch('oppy.crypto.util.verifyCertSig', return_value=False)
    def test_connectionSupportsHandshake_issuer_CN(self, _):
        c = mock.Mock()

        mock_issuer = mock.Mock()
        mock_issuer.get_components.return_value = [('XX', None)]
        mock_issuer.commonName = 'foo.net'
        c.get_issuer.return_value = mock_issuer

        mock_subject = mock.Mock()
        mock_subject.get_components.return_value = [('CN', None)]
        mock_subject.commonName = 'bar.net'
        c.get_subject.return_value = mock_subject

        b = mock.Mock()
        c.get_pubkey.bits = mock.Mock(return_value=b)
        b.bits.return_value = 1024

        self.assertTrue(connectionbuildtask._connectionSupportsHandshake(c))
        
    @mock.patch('oppy.crypto.util.verifyCertSig', return_value=False)
    def test_connectionSupportsHandshake_subject_CN(self, c):
        c = mock.Mock()

        mock_issuer = mock.Mock()
        mock_issuer.get_components.return_value = [('CN', None)]
        mock_issuer.commonName = 'foo.net'
        c.get_issuer.return_value = mock_issuer

        mock_subject = mock.Mock()
        mock_subject.get_components.return_value = [('XX', None)]
        mock_subject.commonName = 'bar.net'
        c.get_subject.return_value = mock_subject

        b = mock.Mock()
        c.get_pubkey.bits = mock.Mock(return_value=b)
        b.bits.return_value = 1024

        self.assertTrue(connectionbuildtask._connectionSupportsHandshake(c))

    @mock.patch('oppy.crypto.util.verifyCertSig', return_value=False)
    def test_connectionSupportsHandshake_issuer_net(self, c):
        c = mock.Mock()

        mock_issuer = mock.Mock()
        mock_issuer.get_components.return_value = [('CN', None)]
        mock_issuer.commonName = 'foo.com'
        c.get_issuer.return_value = mock_issuer

        mock_subject = mock.Mock()
        mock_subject.get_components.return_value = [('CN', None)]
        mock_subject.commonName = 'bar.net'
        c.get_subject.return_value = mock_subject

        b = mock.Mock()
        c.get_pubkey.bits = mock.Mock(return_value=b)
        b.bits.return_value = 1024

        self.assertTrue(connectionbuildtask._connectionSupportsHandshake(c))

    @mock.patch('oppy.crypto.util.verifyCertSig', return_value=False)
    def test_connectionSupportsHandshake_subject_net(self, c):
        c = mock.Mock()

        mock_issuer = mock.Mock()
        mock_issuer.get_components.return_value = [('CN', None)]
        mock_issuer.commonName = 'foo.net'
        c.get_issuer.return_value = mock_issuer

        mock_subject = mock.Mock()
        mock_subject.get_components.return_value = [('CN', None)]
        mock_subject.commonName = 'bar.com'
        c.get_subject.return_value = mock_subject

        b = mock.Mock()
        c.get_pubkey.bits = mock.Mock(return_value=b)
        b.bits.return_value = 1024

        self.assertTrue(connectionbuildtask._connectionSupportsHandshake(c))

    @mock.patch('oppy.crypto.util.verifyCertSig', return_value=False)
    def test_connectionSupportsHandshake_longer_1024(self, c):
        c = mock.Mock()

        mock_issuer = mock.Mock()
        mock_issuer.get_components.return_value = [('CN', None)]
        mock_issuer.commonName = 'foo.net'
        c.get_issuer.return_value = mock_issuer

        mock_subject = mock.Mock()
        mock_subject.get_components.return_value = [('CN', None)]
        mock_subject.commonName = 'bar.net'
        c.get_subject.return_value = mock_subject

        b = mock.Mock()
        c.get_pubkey.bits = mock.Mock(return_value=b)
        b.bits.return_value = 2048

        self.assertTrue(connectionbuildtask._connectionSupportsHandshake(c))

    @mock.patch('oppy.crypto.util.verifyCertSig', return_value=False)
    def test_connectionSupportsHandshake_all_fail(self, c):
        c = mock.Mock()

        mock_issuer = mock.Mock()
        mock_issuer.get_components.return_value = [('CN', None)]
        mock_issuer.commonName = 'foo.net'
        c.get_issuer.return_value = mock_issuer

        mock_subject = mock.Mock()
        mock_subject.get_components.return_value = [('CN', None)]
        mock_subject.commonName = 'bar.net'
        c.get_subject.return_value = mock_subject

        b = mock.Mock()
        c.get_pubkey.bits = mock.Mock(return_value=b)
        b.bits.return_value = 1024

        self.assertTrue(connectionbuildtask._connectionSupportsHandshake(c))

    def test_getCertsFromCell(self):
        lc = test_cert_der
        link_cert = CertsCellPayloadItem(LINK_CERT_TYPE, len(lc), lc)
        ic = test_cert_der
        id_cert = CertsCellPayloadItem(ID_CERT_TYPE, len(ic), ic)

        cell = CertsCell.make(0, [link_cert, id_cert])

        res1 = crypto.load_certificate(crypto.FILETYPE_ASN1, lc)
        res2 = crypto.load_certificate(crypto.FILETYPE_ASN1, ic)

        l, i = connectionbuildtask._getCertsFromCell(cell)

        self.assertEqual(crypto.dump_certificate(crypto.FILETYPE_ASN1, l), lc)
        self.assertEqual(crypto.dump_certificate(crypto.FILETYPE_ASN1, i), ic)

    def test_getCertsFromCell_invalid_count(self):
        lc = test_cert_der
        link_cert = CertsCellPayloadItem(LINK_CERT_TYPE, len(lc), lc)

        cell = CertsCell.make(0, [link_cert])

        self.assertRaises(ValueError,
                          connectionbuildtask._getCertsFromCell,
                          cell)

    def test_getCertsFromCell_malformed_cert(self):
        lc = test_cert_der
        link_cert = CertsCellPayloadItem(LINK_CERT_TYPE, len(lc), lc)
        ic = test_cert_der[:len(test_cert_der)-1]
        id_cert = CertsCellPayloadItem(ID_CERT_TYPE, len(ic), ic)

        cell = CertsCell.make(0, [link_cert, id_cert])

        self.assertRaises(ValueError,
                          connectionbuildtask._getCertsFromCell,
                          cell)

    def test_getCertsFromCell_invalid_cert_type(self):
        lc = test_cert_der
        link_cert = CertsCellPayloadItem(LINK_CERT_TYPE, len(lc), lc)
        ic = test_cert_der
        id_cert = CertsCellPayloadItem(LINK_CERT_TYPE, len(ic), ic)

        cell = CertsCell.make(0, [link_cert, id_cert])

        self.assertRaises(ValueError,
                          connectionbuildtask._getCertsFromCell,
                          cell)

    @mock.patch('oppy.crypto.util.validCertTime', return_value=True)
    def test_certsHaveValidTime_fail(self, vct):
        mock_cert = mock.Mock()
        certs = [mock_cert]

        self.assertTrue(connectionbuildtask._certsHaveValidTime(certs))
        vct.assert_called_once_with(mock_cert)

    @mock.patch('oppy.crypto.util.validCertTime', return_value=False)
    def test_certsHaveValidTime_fail(self, vct):
        mock_cert = mock.Mock()
        certs = [mock_cert]

        self.assertFalse(connectionbuildtask._certsHaveValidTime(certs))
        vct.assert_called_once_with(mock_cert)
        
    @mock.patch('oppy.crypto.util.constantStrEqual', return_value=True)
    @mock.patch('OpenSSL.crypto.dump_privatekey', autospec=True)
    def test_ASN1KeysEqual(self, dpk, cse):
        mock_asn1_key = mock.Mock()

        self.assertTrue(connectionbuildtask._ASN1KeysEqual(mock_asn1_key,
                                                           mock_asn1_key))
        self.assertEqual(cse.call_count, 1)

    @mock.patch('oppy.crypto.util.constantStrEqual', return_value=False)
    @mock.patch('OpenSSL.crypto.dump_privatekey', autospec=True)
    def test_ASN1KeysEqual_neq(self, dpk, cse):
        mock_asn1_key = mock.Mock()

        self.assertFalse(connectionbuildtask._ASN1KeysEqual(mock_asn1_key,
                                                            mock_asn1_key))
        self.assertEqual(cse.call_count, 1)

    def test_isRSA1024BitKey(self):
        key = mock.Mock()
        key.type.return_value = OPENSSL_RSA_KEY_TYPE
        key.bits.return_value = 1024

        self.assertTrue(connectionbuildtask._isRSA1024BitKey(key))

    def test_isRSA1024BitKey_not_RSA(self):
        key = mock.Mock()
        key.type.return_value = OPENSSL_RSA_KEY_TYPE - 1
        key.bits.return_value = 1024

        self.assertFalse(connectionbuildtask._isRSA1024BitKey(key))

    def test_isRSA1024BitKey_not_1024(self):
        key = mock.Mock()
        key.type.return_value = OPENSSL_RSA_KEY_TYPE
        key.bits.return_value = 2048

        self.assertFalse(connectionbuildtask._isRSA1024BitKey(key))
