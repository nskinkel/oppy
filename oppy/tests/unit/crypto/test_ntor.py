import hashlib
import mock

from twisted.trial import unittest

from oppy.crypto import ntor

# NOTE: the test values here are borrowed from tor, specifically the
#       test/test_crypto.c file.


class NTorTest(unittest.TestCase):

    @mock.patch('oppy.crypto.ntor.decodeMicrodescriptorIdentifier',
        return_value='relay_identity')
    @mock.patch('base64.b64decode', return_value='ntor_onion_key')
    @mock.patch('oppy.crypto.ntor.PrivateKey.generate')
    def test_NTorState(self, mock_sk, mock_b64, mock_dmi):
        mock_sk_g = mock.Mock()
        mock_sk_g.public_key = 'pk'
        mock_sk.return_value = mock_sk_g
        mock_sk.public_key = 'pk'
        mock_md = mock.Mock()
        mock_md.ntor_onion_key = 'test'

        n = ntor.NTorState(mock_md)

        mock_dmi.assert_called_once_with(mock_md)
        mock_b64.assert_called_once_with('test')
        self.assertEqual(mock_sk.call_count, 1)
        self.assertEqual(n.relay_identity, 'relay_identity')
        self.assertEqual(n.relay_ntor_onion_key, 'ntor_onion_key')
        self.assertEqual(n.secret_key, mock_sk_g)
        self.assertEqual(n.public_key, 'pk')

    def test_createOnionSkin(self):
        mock_nts = mock.Mock()
        mock_nts.relay_identity = 'ident'
        mock_nts.relay_ntor_onion_key = 'ntork'
        mock_nts.public_key = 'pk'

        self.assertEqual(ntor.createOnionSkin(mock_nts), 'identntorkpk')

    @mock.patch('oppy.crypto.ntor._buildSecretInput',
        return_value=('secret', True))
    @mock.patch('oppy.crypto.util.makeHMACSHA256', return_value='hmac')
    @mock.patch('oppy.crypto.ntor._buildAuthInput', return_value='auth')
    @mock.patch('oppy.crypto.util.constantStrEqual', return_value=False)
    @mock.patch('oppy.crypto.ntor._makeRelayCrypto', return_value='ret')
    def test_deriveRelayCrypto_buildSecreInput_bad(self, mock_mrc, mock_cse,
        mock_bai, mock_mhs, mock_bsi):
        mock_nts = mock.Mock()
        mock_nts.relay_identity = 'ident'
        mock_nts.relay_ntor_onion_key = 'ntork'
        mock_nts.public_key = 'pk'
        mock_cell = mock.Mock()
        mock_cell.hdata = '\x00'*96

        self.assertRaises(ntor.KeyDerivationFailed,
                          ntor.deriveRelayCrypto,
                          mock_nts,
                          mock_cell)

    @mock.patch('oppy.crypto.ntor._buildSecretInput',
        return_value=('secret', False))
    @mock.patch('oppy.crypto.util.makeHMACSHA256', return_value='hmac')
    @mock.patch('oppy.crypto.ntor._buildAuthInput', return_value='auth')
    @mock.patch('oppy.crypto.util.constantStrEqual', return_value=True)
    @mock.patch('oppy.crypto.ntor._makeRelayCrypto', return_value='ret')
    def test_deriveRelayCrypto_auth_bad(self, mock_mrc, mock_cse, mock_bai,
        mock_mhs, mock_bsi):
        mock_nts = mock.Mock()
        mock_nts.relay_identity = 'ident'
        mock_nts.relay_ntor_onion_key = 'ntork'
        mock_nts.public_key = 'pk'
        mock_cell = mock.Mock()
        mock_cell.hdata = '\x00'*96

        self.assertRaises(ntor.KeyDerivationFailed,
                          ntor.deriveRelayCrypto,
                          mock_nts,
                          mock_cell)


    @mock.patch('oppy.crypto.ntor._buildSecretInput',
        return_value=('secret', False))
    @mock.patch('oppy.crypto.util.makeHMACSHA256', return_value='hmac')
    @mock.patch('oppy.crypto.ntor._buildAuthInput', return_value='auth')
    @mock.patch('oppy.crypto.util.constantStrEqual', return_value=False)
    @mock.patch('oppy.crypto.ntor._makeRelayCrypto', return_value='ret')
    def test_deriveRelayCrypto_ok(self, mock_mrc, mock_cse, mock_bai, mock_mhs,
        mock_bsi):
        mock_nts = mock.Mock()
        mock_nts.relay_identity = 'ident'
        mock_nts.relay_ntor_onion_key = 'ntork'
        mock_nts.public_key = 'pk'
        mock_cell = mock.Mock()
        mock_cell.hdata = [chr(i) for i in range(96)]
        hdata = mock_cell.hdata

        ret = ntor.deriveRelayCrypto(mock_nts, mock_cell)

        mock_bsi.assert_called_once_with(mock_nts, hdata[:32])
        self.assertEqual(mock_mhs.call_count, 2)
        self.assertEqual(mock_mhs.call_args_list,
            [mock.call(msg='secret', key='ntor-curve25519-sha256-1:verify'),
             mock.call(msg='auth', key='ntor-curve25519-sha256-1:mac')])
        mock_cse.assert_called_once_with(hdata[32:32+20], 'hmac')
        mock_mrc.assert_called_once_with('secret')
        self.assertEqual(ret, 'ret')

    @mock.patch('oppy.crypto.ntor._EXP', return_value=('\x00', True))
    def test_buildSecretInput_bad_EXP(self, mock_exp):
        mock_nts = mock.Mock()
        mock_nts.relay_identity = 'ident'
        mock_nts.relay_ntor_onion_key = 'ntork'
        mock_nts.public_key = 'pk'
        relay_pk = 'relay_pk'

        v, b = ntor._buildSecretInput(mock_nts, relay_pk)
        self.assertTrue(b)

    @mock.patch('oppy.crypto.ntor._EXP', return_value=('exp', False))
    def test_buildAuthInput(self, mock_exp):
        mock_nts = mock.Mock()
        mock_nts.relay_identity = 'ident'
        mock_nts.relay_ntor_onion_key = 'ntork'
        mock_nts.public_key = 'pk'
        relay_pk = 'relay_pk'

        v, b = ntor._buildSecretInput(mock_nts, relay_pk)
        
        self.assertEqual(mock_exp.call_count, 2)
        self.assertFalse(b)
        self.assertEqual(v,
            'expexpidentntorkpkrelay_pkntor-curve25519-sha256-1')

    @mock.patch('hkdf.hkdf_extract', return_value='prk')
    @mock.patch('hkdf.hkdf_expand', return_value=[chr(i) for i in range(96)])
    @mock.patch('hashlib.sha1', return_value='sha1')
    @mock.patch('oppy.crypto.util.makeAES128CTRCipher', return_value='cipher')
    @mock.patch('oppy.crypto.util.RelayCrypto', return_value='ret')
    def test_makeRelayCrypto(self, mock_rc, mock_maes, mock_sha1, mock_hexp,
        mock_hext):
        secret_input = 'secret input'
        km = [chr(i) for i in range(96)]

        ret = ntor._makeRelayCrypto(secret_input)

        mock_hext.assert_called_once_with(
            salt='ntor-curve25519-sha256-1:key_extract',
            input_key_material='secret input',
            hash=hashlib.sha256)

        mock_hexp.assert_called_once_with(
            pseudo_random_key='prk',
            info='ntor-curve25519-sha256-1:key_expand',
            length=72,
            hash=hashlib.sha256)

        self.assertEqual(mock_sha1.call_count, 2)
        self.assertEqual(mock_sha1.call_args_list,
            [mock.call(km[:20]), mock.call(km[20:40])])
        self.assertEqual(mock_maes.call_count, 2)
        self.assertEqual(mock_maes.call_args_list,
            [mock.call(km[40:56]), mock.call(km[56:72])])
        mock_rc.assert_called_once_with(
            forward_cipher='cipher', forward_digest='sha1',
            backward_cipher='cipher', backward_digest='sha1')
        self.assertEqual(ret, 'ret')

    @mock.patch('nacl.bindings.crypto_scalarmult', return_value='sm')
    @mock.patch('oppy.crypto.ntor.PublicKey', return_value='pk')
    @mock.patch('oppy.crypto.util.constantStrAllZero', return_value=True)
    def test_EXP_bad(self, mock_az, mock_pk, mock_csm):
        ret, bad = ntor._EXP('n', 'p')
        mock_pk.assert_called_once_with('p')
        mock_csm.assert_called_once_with('n', 'pk')
        self.assertTrue(bad)


    @mock.patch('nacl.bindings.crypto_scalarmult', return_value='sm')
    @mock.patch('oppy.crypto.ntor.PublicKey', return_value='pk')
    @mock.patch('oppy.crypto.util.constantStrAllZero', return_value=False)
    def test_EXP(self, mock_az, mock_pk, mock_csm):
        ret, bad = ntor._EXP('n', 'p')
        mock_pk.assert_called_once_with('p')
        mock_csm.assert_called_once_with('n', 'pk')
        mock_az.assert_called_once_with('sm')
        self.assertEqual(ret, 'sm')
        self.assertFalse(bad)
