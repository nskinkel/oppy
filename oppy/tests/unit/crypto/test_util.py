import hashlib
import mock

import OpenSSL

from Crypto.Cipher import AES
from twisted.trial import unittest

from oppy.crypto import util


class CryptoUtilTest(unittest.TestCase):

    def setUp(self):
        pass

    def test_constantStrEqual_have_compare_digest(self):
        try:
            import hmac.compare_digest
        except ImportError:
            return

        str1 = 'test1'
        str2 = 'test2'
        with mock.patch('hmac.compare_digest', return_value='ret') as mock_cd:
            ret = util.constantStrEqual(str1, str2)
            mock_cd.assert_called_once_with(str1, str2)
            self.assertEqual(ret, 'ret')

    def test_constantStrEqual_eq(self):
        str1 = 'test'
        str2 = 'test'

        try:
            import hmac.compare_digest
            with mock.patch('hmac.compare_digest', side_effect=ImportError()) as _:
                self.assertTrue(util.constantStrEqual(str1, str2))
        except ImportError:
            self.assertTrue(util.constantStrEqual(str1, str2))

    def test_constantStrEqual_neq(self):
        str1 = 'test '
        str2 = 'test'

        try:
            import hmac.compare_digest
            with mock.patch('hmac.compare_digest', side_effect=ImportError()) as _:
                self.assertFalse(util.constantStrEqual(str1, str2))
        except ImportError:
            self.assertFalse(util.constantStrEqual(str1, str2))

    def test_constantStrEqual_zero_len(self):
        str1 = ''
        str2 = 'test'

        try:
            import hmac.compare_digest
            with mock.patch('hmac.compare_digest', side_effect=ImportError()) as _:
                self.assertFalse(util.constantStrEqual(str1, str2))
        except ImportError:
            self.assertFalse(util.constantStrEqual(str1, str2))

    @mock.patch('oppy.crypto.util.constantStrEqual', return_value='ret')
    def test_constantStrAllZero(self, mock_cse):
        ret = util.constantStrAllZero('\x00')
        mock_cse.assert_called_once_with('\x00', '\x00')
        self.assertEqual(ret, 'ret')

    def test_constantStrAllZero_yes(self):
        self.assertTrue(util.constantStrAllZero('\x00'*5446))

    def test_constantStrAllZero_no(self):
        self.assertFalse(util.constantStrAllZero('\x00'*37 + '\x01' + '\x00'*19))

    @mock.patch('oppy.crypto.util.Counter.new')
    @mock.patch('oppy.crypto.util.AES.new')
    def test_makeAES123CTRCipher_default(self, mock_aes, mock_counter):
        mock_counter.return_value = 'ctr'
        mock_aes.return_value = 'ret'
        ret = util.makeAES128CTRCipher('key')
        mock_counter.assert_called_once_with(128, initial_value=0)
        mock_aes.assert_called_once_with('key', AES.MODE_CTR, counter='ctr')
        self.assertEqual(ret, 'ret')

    @mock.patch('oppy.crypto.util.Counter.new')
    @mock.patch('oppy.crypto.util.AES.new')
    def test_makeAES123CTRCipher_iv(self, mock_aes, mock_counter):
        mock_counter.return_value = 'ctr'
        mock_aes.return_value = 'ret'
        ret = util.makeAES128CTRCipher('key', 'iv')
        mock_counter.assert_called_once_with(128, initial_value='iv')
        mock_aes.assert_called_once_with('key', AES.MODE_CTR, counter='ctr')
        self.assertEqual(ret, 'ret')

    @mock.patch('hmac.new')
    def test_makeHMACSHA256(self, mock_hmac):
        mock_m = mock.Mock()
        mock_m.digest = mock.Mock()
        mock_m.digest.return_value = 'digest'
        mock_hmac.return_value = mock_m
        ret = util.makeHMACSHA256('msg', 'key')
        mock_hmac.assert_called_once_with(msg='msg', key='key',
            digestmod=hashlib.sha256)
        self.assertEqual(ret, 'digest') 

    def test_makePayloadWithDigest_custom(self):
        payload = ''.join([chr(i) for i in range(256)])
        digest = '\xff\xff\xff\xff'
        new_payload = util._makePayloadWithDigest(payload, digest=digest)
        self.assertEqual(new_payload,
            ''.join([chr(i) for i in range(5)]) + digest +
            ''.join([chr(i) for i in range(9, 256)]))

    def test_makePayloadWithDigest_default_empty(self):
        '''
        payload = ''.join[chr(i) for i in range(514)]
        digest = '\xff\xff\xff\xff'
        new_payload = util._makePayloadWithDigest(payload, digest=digest)
        '''
        payload = ''.join([chr(i) for i in range(256)])
        default_empty = '\x00\x00\x00\x00'
        new_payload = util._makePayloadWithDigest(payload)
        self.assertEqual(new_payload,
            ''.join([chr(i) for i in range(5)]) + default_empty +
            ''.join([chr(i) for i in range(9, 256)]))

    def test_makePayloadWithDigest_too_short(self):
        self.assertRaises(AssertionError,
                          util._makePayloadWithDigest,
                          'payload')
        self.assertRaises(AssertionError,
                          util._makePayloadWithDigest,
                          '12345678910', 'dig')

    @mock.patch('oppy.crypto.util.EncryptedCell.make', return_value='ret')
    def test_encryptCell_one_node(self, mock_ecm):
        mock_cell = mock.Mock()
        mock_cell.header = mock.Mock()
        mock_cell.header.circ_id = 0
        mock_cell.rheader = mock.Mock()
        mock_cell.rheader.digest = '\x00\x00\x00\x00'
        mock_cell.getPayload = mock.Mock()
        mock_cell.getPayload.return_value = 'payload'

        mock_cnode1 = mock.Mock()
        mock_cnode1.forward_digest = mock.Mock()
        mock_cnode1.forward_digest.update = mock.Mock()
        mock_cnode1.forward_digest.digest = mock.Mock()
        mock_cnode1.forward_digest.digest.return_value = '\x01\x02\x03\x04'
        mock_cnode1.forward_cipher.encrypt = mock.Mock()
        mock_cnode1.forward_cipher.encrypt.return_value = 'enc_payload'

        mock_crypt_path = [mock_cnode1]

        ret = util.encryptCell(mock_cell, mock_crypt_path)

        mock_cnode1.forward_digest.update.assert_called_once_with('payload')
        self.assertEqual(mock_cell.rheader.digest, '\x01\x02\x03\x04')
        mock_cnode1.forward_cipher.encrypt.assert_called_once_with('payload')
        mock_ecm.assert_called_once_with(0, 'enc_payload', early=False)
        self.assertEqual(ret, 'ret')

    @mock.patch('oppy.crypto.util.EncryptedCell.make', return_value='ret')
    def test_encryptCell_one_node_early(self, mock_ecm):
        mock_cell = mock.Mock()
        mock_cell.header = mock.Mock()
        mock_cell.header.circ_id = 0
        mock_cell.rheader = mock.Mock()
        mock_cell.rheader.digest = '\x00\x00\x00\x00'
        mock_cell.getPayload = mock.Mock()
        mock_cell.getPayload.return_value = 'payload'

        mock_cnode1 = mock.Mock()
        mock_cnode1.forward_digest = mock.Mock()
        mock_cnode1.forward_digest.update = mock.Mock()
        mock_cnode1.forward_digest.digest = mock.Mock()
        mock_cnode1.forward_digest.digest.return_value = '\x01\x02\x03\x04'
        mock_cnode1.forward_cipher.encrypt = mock.Mock()
        mock_cnode1.forward_cipher.encrypt.return_value = 'enc_payload'

        mock_crypt_path = [mock_cnode1]

        ret = util.encryptCell(mock_cell, mock_crypt_path, early=True)

        mock_cnode1.forward_digest.update.assert_called_once_with('payload')
        self.assertEqual(mock_cell.rheader.digest, '\x01\x02\x03\x04')
        mock_cnode1.forward_cipher.encrypt.assert_called_once_with('payload')
        mock_ecm.assert_called_once_with(0, 'enc_payload', early=True)
        self.assertEqual(ret, 'ret')

    @mock.patch('oppy.crypto.util.EncryptedCell.make', return_value='ret')
    def test_encryptCell_two_nodes(self, mock_ecm):
        mock_cell = mock.Mock()
        mock_cell.header = mock.Mock()
        mock_cell.header.circ_id = 0
        mock_cell.rheader = mock.Mock()
        mock_cell.rheader.digest = '\x00\x00\x00\x00'
        mock_cell.getPayload = mock.Mock()
        mock_cell.getPayload.return_value = 'payload'

        mock_cnode1 = mock.Mock()
        mock_cnode1.forward_digest = mock.Mock()
        mock_cnode1.forward_digest.update = mock.Mock()
        mock_cnode1.forward_digest.digest = mock.Mock()
        mock_cnode1.forward_digest.digest.return_value = '\x01\x02\x03\x04'
        mock_cnode1.forward_cipher.encrypt = mock.Mock()
        mock_cnode1.forward_cipher.encrypt.return_value = 'enc_payload1'

        mock_cnode2 = mock.Mock()
        mock_cnode2.forward_digest = mock.Mock()
        mock_cnode2.forward_digest.update = mock.Mock()
        mock_cnode2.forward_digest.digest = mock.Mock()
        mock_cnode2.forward_digest.digest.return_value = '\x05\x06\x07\x08'
        mock_cnode2.forward_cipher.encrypt = mock.Mock()
        mock_cnode2.forward_cipher.encrypt.return_value = 'enc_payload2'

        mock_crypt_path = [mock_cnode1, mock_cnode2]

        ret = util.encryptCell(mock_cell, mock_crypt_path)

        mock_cnode2.forward_digest.update.assert_called_once_with('payload')
        self.assertEqual(mock_cnode1.forward_digest.update.call_count, 0)
        self.assertEqual(mock_cell.rheader.digest, '\x05\x06\x07\x08')
        mock_cnode1.forward_cipher.encrypt.assert_called_once_with('enc_payload2')
        mock_cnode2.forward_cipher.encrypt.assert_called_once_with('payload')
        mock_ecm.assert_called_once_with(0, 'enc_payload1', early=False)
        self.assertEqual(ret, 'ret')
        
    @mock.patch('oppy.crypto.util.EncryptedCell.make', return_value='ret')
    def test_encryptCell_three_nodes(self, mock_ecm):
        mock_cell = mock.Mock()
        mock_cell.header = mock.Mock()
        mock_cell.header.circ_id = 0
        mock_cell.rheader = mock.Mock()
        mock_cell.rheader.digest = '\x00\x00\x00\x00'
        mock_cell.getPayload = mock.Mock()
        mock_cell.getPayload.return_value = 'payload'

        mock_cnode1 = mock.Mock()
        mock_cnode1.forward_digest = mock.Mock()
        mock_cnode1.forward_digest.update = mock.Mock()
        mock_cnode1.forward_digest.digest = mock.Mock()
        mock_cnode1.forward_digest.digest.return_value = '\x01\x02\x03\x04'
        mock_cnode1.forward_cipher.encrypt = mock.Mock()
        mock_cnode1.forward_cipher.encrypt.return_value = 'enc_payload1'

        mock_cnode2 = mock.Mock()
        mock_cnode2.forward_digest = mock.Mock()
        mock_cnode2.forward_digest.update = mock.Mock()
        mock_cnode2.forward_digest.digest = mock.Mock()
        mock_cnode2.forward_digest.digest.return_value = '\x05\x06\x07\x08'
        mock_cnode2.forward_cipher.encrypt = mock.Mock()
        mock_cnode2.forward_cipher.encrypt.return_value = 'enc_payload2'

        mock_cnode3 = mock.Mock()
        mock_cnode3.forward_digest = mock.Mock()
        mock_cnode3.forward_digest.update = mock.Mock()
        mock_cnode3.forward_digest.digest = mock.Mock()
        mock_cnode3.forward_digest.digest.return_value = '\x09\x0a\x0b\x0c'
        mock_cnode3.forward_cipher.encrypt = mock.Mock()
        mock_cnode3.forward_cipher.encrypt.return_value = 'enc_payload3'

        mock_crypt_path = [mock_cnode1, mock_cnode2, mock_cnode3]

        ret = util.encryptCell(mock_cell, mock_crypt_path)

        mock_cnode3.forward_digest.update.assert_called_once_with('payload')
        self.assertEqual(mock_cnode2.forward_digest.update.call_count, 0)
        self.assertEqual(mock_cnode1.forward_digest.update.call_count, 0)
        self.assertEqual(mock_cell.rheader.digest, '\x09\x0a\x0b\x0c')
        mock_cnode1.forward_cipher.encrypt.assert_called_once_with('enc_payload2')
        mock_cnode2.forward_cipher.encrypt.assert_called_once_with('enc_payload3')
        mock_cnode3.forward_cipher.encrypt.assert_called_once_with('payload')
        mock_ecm.assert_called_once_with(0, 'enc_payload1', early=False)
        self.assertEqual(ret, 'ret')

    def test_encryptCell_nonempty_digest_fail(self):
        mock_cell = mock.Mock()
        mock_cell.header = mock.Mock()
        mock_cell.header.circ_id = 0
        mock_cell.rheader = mock.Mock()
        mock_cell.rheader.digest = '\x00\x00\x00\x01'
        mock_cell.getPayload = mock.Mock()
        mock_cell.getPayload.return_value = 'payload'

        self.assertRaises(AssertionError,
                          util.encryptCell,
                          mock_cell,
                          [mock.Mock()])

    def test_cellRecognized_not_rec_payload(self):
        payload = '\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
        relay_crypto = mock.Mock()
        relay_crypto.backward_digest = mock.Mock()
        relay_crypto.backward_digest.copy = mock.Mock()
        self.assertFalse(util._cellRecognized(payload, relay_crypto))
        self.assertEqual(relay_crypto.backward_digest.copy.call_count, 0)

    def test_cellRecognized_too_short(self):
        payload = '\x00\x00\x00\x00\x00\x00'
        relay_crypto = mock.Mock()
        relay_crypto.backward_digest = mock.Mock()
        relay_crypto.backward_digest.copy = mock.Mock()
        self.assertFalse(util._cellRecognized(payload, relay_crypto))
        self.assertEqual(relay_crypto.backward_digest.copy.call_count, 0)

    @mock.patch('oppy.crypto.util._makePayloadWithDigest', return_value='test payload')
    def test_cellRecognized_yes(self, mock_mpwd):
        payload = '\x01\x01\x00\x00\x00\x0a\x0a\x0a\x0a'
        relay_crypto = mock.Mock()
        relay_crypto.backward_digest = mock.Mock()
        relay_crypto.backward_digest.copy = mock.Mock()
        mock_td = mock.Mock()
        relay_crypto.backward_digest.copy.return_value = mock_td
        mock_td.update = mock.Mock()
        mock_td.digest = mock.Mock()
        mock_td.digest.return_value = '\x0a\x0a\x0a\x0a'

        ret = util._cellRecognized(payload, relay_crypto)

        mock_td.update.assert_called_once_with('test payload')
        self.assertTrue(ret)
        
    @mock.patch('oppy.crypto.util._makePayloadWithDigest', return_value='test payload')
    def test_cellRecognized_no(self, mock_mpwd):
        payload = '\x01\x01\x00\x00\x00\x0a\x0a\x0a\x0a'
        relay_crypto = mock.Mock()
        relay_crypto.backward_digest = mock.Mock()
        relay_crypto.backward_digest.copy = mock.Mock()
        mock_td = mock.Mock()
        relay_crypto.backward_digest.copy.return_value = mock_td
        mock_td.update = mock.Mock()
        mock_td.digest = mock.Mock()
        mock_td.digest.return_value = '\x0a\x0a\x0a\x0b'

        ret = util._cellRecognized(payload, relay_crypto)

        mock_td.update.assert_called_once_with('test payload')
        self.assertFalse(ret)

    @mock.patch('oppy.crypto.util._cellRecognized', return_value=False)
    def test_decryptCell_not_recognized(self, mock_cr):
        mock_cell = mock.Mock()
        mock_cell.getPayload = mock.Mock()
        mock_cell.getPayload.return_value = '\x00'*10
        mock_cnode1 = mock.Mock()
        mock_cnode1.backward_digest = mock.Mock()
        mock_cnode1.backward_digest.update = mock.Mock()
        mock_cnode1.backward_digest.digest = mock.Mock()
        mock_cnode1.backward_digest.digest.return_value = '\x01\x02\x03\x04'
        mock_cnode1.backward_cipher.decrypt = mock.Mock()
        mock_cnode1.backward_cipher.decrypt.return_value = '\x00'*10

        mock_crypt_path = [mock_cnode1]

        self.assertRaises(util.UnrecognizedCell,
                          util.decryptCell,
                          mock_cell,
                          mock_crypt_path)

    @mock.patch('oppy.crypto.util._cellRecognized', return_value=True)
    @mock.patch('oppy.crypto.util._makePayloadWithDigest')
    @mock.patch('oppy.cell.cell.Cell.parse', return_value = 'dec')
    @mock.patch('struct.pack', return_value='packed')
    def test_decryptCell_origin_2_link_proto_3(self, mock_sp, mock_cellp, mock_mpwd, mock_cr):
        mock_mpwd.return_value = 'updated payload'
        mock_cell = mock.Mock()
        mock_cell.header = mock.Mock()
        mock_cell.header.link_version = 3
        mock_cell.getPayload = mock.Mock()
        mock_cell.getPayload.return_value = 'initial payload'
        mock_cnode2 = mock.Mock()
        mock_cnode2.backward_digest = mock.Mock()
        mock_cnode2.backward_digest.update = mock.Mock()
        mock_cnode2.backward_cipher.decrypt = mock.Mock()
        mock_cnode2.backward_cipher.decrypt.return_value = 'dec payload 2'

        mock_cnode1 = mock.Mock()
        mock_cnode1.backward_digest = mock.Mock()
        mock_cnode1.backward_digest.update = mock.Mock()
        mock_cnode1.backward_cipher.decrypt = mock.Mock()
        mock_cnode1.backward_cipher.decrypt.return_value = 'dec payload 1'

        mock_cnode0 = mock.Mock()
        mock_cnode0.backward_digest = mock.Mock()
        mock_cnode0.backward_digest.update = mock.Mock()
        mock_cnode0.backward_cipher.decrypt = mock.Mock()
        mock_cnode0.backward_cipher.decrypt.return_value = 'dec payload 0'

        mock_crypt_path = [mock_cnode2, mock_cnode1, mock_cnode0]

        ret = util.decryptCell(mock_cell, mock_crypt_path)

        mock_cnode2.backward_cipher.decrypt.assert_called_once_with('initial payload')
        self.assertEqual(mock_cnode1.backward_cipher.decrypt.call_count, 0)
        self.assertEqual(mock_cnode0.backward_cipher.decrypt.call_count, 0)
        mock_mpwd.assert_called_once_with('dec payload 2')
        mock_cnode2.backward_digest.update.assert_called_once_with('updated payload')
        self.assertEqual(mock_cnode1.backward_digest.update.call_count, 0)
        self.assertEqual(mock_cnode0.backward_digest.update.call_count, 0)
        # TODO: check struct.pack calls
        mock_cellp.assert_called_once_with('packedpackeddec payload 2')
        self.assertEqual(ret, ('dec', 0))

    @mock.patch('OpenSSL.crypto.dump_certificate', return_value='asn1cert')
    @mock.patch('oppy.crypto.util.asn1.DerSequence')
    @mock.patch('oppy.crypto.util.asn1.DerObject')
    @mock.patch('OpenSSL.crypto.verify', return_value=True)
    def test_verifyCertSig_yes(self, mock_cv,  mock_do, mock_ds, mock_dc):
        mock_dseq = mock.MagicMock()
        mock_dseq.__getitem__.return_value = 'd'
        mock_dseq.decode = mock.Mock()
        mock_ds.return_value = mock_dseq
        mock_derobj = mock.Mock()
        mock_derobj.payload = '\x00payload'
        mock_do.return_value = mock_derobj

        ret = util.verifyCertSig('idcert', 'verifycert')

        mock_dc.assert_called_once_with(OpenSSL.crypto.FILETYPE_ASN1, 'verifycert')
        mock_dseq.decode.assert_called_once_with('asn1cert')
        self.assertEqual(mock_ds.call_count, 1)
        self.assertEqual(mock_do.call_count, 1)
        mock_cv.assert_called_once_with('idcert', 'payload', 'd', 'sha1')
        self.assertTrue(ret)

    @mock.patch('OpenSSL.crypto.dump_certificate', return_value='asn1cert')
    @mock.patch('oppy.crypto.util.asn1.DerSequence')
    @mock.patch('oppy.crypto.util.asn1.DerObject')
    @mock.patch('OpenSSL.crypto.verify', side_effect=OpenSSL.crypto.Error)
    def test_verifyCertSig_no(self, mock_cv,  mock_do, mock_ds, mock_dc):
        mock_dseq = mock.MagicMock()
        mock_dseq.__getitem__.return_value = 'd'
        mock_dseq.decode = mock.Mock()
        mock_ds.return_value = mock_dseq
        mock_derobj = mock.Mock()
        mock_derobj.payload = '\x00payload'
        mock_do.return_value = mock_derobj

        ret = util.verifyCertSig('idcert', 'verifycert')

        mock_dc.assert_called_once_with(OpenSSL.crypto.FILETYPE_ASN1, 'verifycert')
        mock_dseq.decode.assert_called_once_with('asn1cert')
        self.assertEqual(mock_ds.call_count, 1)
        self.assertEqual(mock_do.call_count, 1)
        mock_cv.assert_called_once_with('idcert', 'payload', 'd', 'sha1')
        self.assertFalse(ret)

    @mock.patch('OpenSSL.crypto.dump_certificate', return_value='asn1cert')
    @mock.patch('oppy.crypto.util.asn1.DerSequence')
    @mock.patch('oppy.crypto.util.asn1.DerObject')
    @mock.patch('OpenSSL.crypto.verify', return_value=True)
    def test_verifyCertSig_not_reserved(self, mock_cv,  mock_do, mock_ds, mock_dc):
        mock_dseq = mock.MagicMock()
        mock_dseq.__getitem__.return_value = 'd'
        mock_dseq.decode = mock.Mock()
        mock_ds.return_value = mock_dseq
        mock_derobj = mock.Mock()
        mock_derobj.payload = '\x01payload'
        mock_do.return_value = mock_derobj

        ret = util.verifyCertSig('idcert', 'verifycert')

        mock_dc.assert_called_once_with(OpenSSL.crypto.FILETYPE_ASN1, 'verifycert')
        mock_dseq.decode.assert_called_once_with('asn1cert')
        self.assertEqual(mock_ds.call_count, 1)
        self.assertEqual(mock_do.call_count, 1)
        self.assertEqual(mock_cv.call_count, 0)
        self.assertFalse(ret)

    @mock.patch('OpenSSL.crypto.dump_certificate', return_value='asn1cert')
    @mock.patch('oppy.crypto.util.asn1.DerSequence')
    @mock.patch('oppy.crypto.util.asn1.DerObject')
    @mock.patch('OpenSSL.crypto.verify', return_value=True)
    def test_verifyCertSig_yes_sha256(self, mock_cv,  mock_do, mock_ds, mock_dc):
        mock_dseq = mock.MagicMock()
        mock_dseq.__getitem__.return_value = 'd'
        mock_dseq.decode = mock.Mock()
        mock_ds.return_value = mock_dseq
        mock_derobj = mock.Mock()
        mock_derobj.payload = '\x00payload'
        mock_do.return_value = mock_derobj

        ret = util.verifyCertSig('idcert', 'verifycert', algo='sha256')

        mock_dc.assert_called_once_with(OpenSSL.crypto.FILETYPE_ASN1, 'verifycert')
        mock_dseq.decode.assert_called_once_with('asn1cert')
        self.assertEqual(mock_ds.call_count, 1)
        self.assertEqual(mock_do.call_count, 1)
        mock_cv.assert_called_once_with('idcert', 'payload', 'd', 'sha256')
        self.assertTrue(ret)

    def test_validCertTime_value_error(self):
        mock_cert = mock.Mock()
        mock_cert.get_notBefore = mock.Mock()
        mock_cert.get_notBefore.return_value = 'not before'
        mock_cert.get_notAfter = mock.Mock()
        mock_cert.get_notAfter.return_value = 'not after'
        
        self.assertFalse(util.validCertTime(mock_cert))
