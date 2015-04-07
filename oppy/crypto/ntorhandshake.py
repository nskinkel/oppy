# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

'''
.. topic:: Details

    NTorHandsake objects provide the methods for doing the ntor handshake
    key derivations and crypto operations. NTorHandshakes objects do the
    following jobs:

        - Create temporary public/private Curve 25519 keys
        - Create the initial onion skin
        - Derive key material from a Created2 or Extended2 cell
        - Create and initialize a RelayCrypto object, ready for use by
          a circuit (RelayCrypto objects are just wrappers around AES128-CTR
          ciphers and SHA-1 running digests, initialized with the derived key
          material)


.. warning:: NTorHandshakes do not safely erase/clear memory of private keys.

'''
import base64
import hashlib
import hkdf

from nacl import bindings
from nacl.public import PrivateKey, PublicKey

from oppy.crypto import util
from oppy.crypto.exceptions import KeyDerivationFailed
from oppy.crypto.relaycrypto import RelayCrypto
from oppy.util import tools


PROTOID     = "ntor-curve25519-sha256-1"
T_MAC       = PROTOID + ":mac"
T_KEY       = PROTOID + ":key_extract"
T_VERIFY    = PROTOID + ":verify"
M_EXPAND    = PROTOID + ":key_expand"
SERVER_STR  = "Server"

CURVE25519_PUBKEY_LEN   = 32
DIGEST_LEN              = 20
KEY_LEN                 = 16
NTOR_ONIONSKIN_LEN      = (2 * CURVE25519_PUBKEY_LEN + DIGEST_LEN)


class NTorHandshake(object):

    def __init__(self, relay):
        '''
        :param stem.descriptor.server_descriptor.RelayDescriptor relay:
            the relay that we're doing an ntor handshake with
        '''
        self._signing_key = tools.signingKeyToSHA1(relay.signing_key)
        self._ntor_onion_key = base64.b64decode(relay.ntor_onion_key)
        self._secret_key = PrivateKey.generate()
        self._public_key = self._secret_key.public_key
        self.is_bad = False

    def createOnionSkin(self):
        '''Build and return an *onion skin* to this handshake's relay.

        .. note:: See tor-spec Section 5.1.4 for more information.

        :returns: **str** raw byte string for this *onion skin*
        '''
        b  = self._signing_key
        b += self._ntor_onion_key
        b += bytes(self._public_key)

        assert len(b) == NTOR_ONIONSKIN_LEN
        return b

    def deriveRelayCrypto(self, cell):
        '''Derive shared key material for this ntor handshake; create and
        return actual cipher and hash instances inside a RelayCrypto object.

        .. note:: See tor-spec Section 5.1.4, 5.2.2 for more details.

        :param cell cell: Created2 cell or Extended2 cell used to derive
            shared keys
        :returns: **oppy.crypto.relaycrypto.RelayCrypto** object initialized
            with the derived key material.
        '''
        self.is_bad = False
        hdata = cell.hdata

        relay_pubkey = cell.hdata[: CURVE25519_PUBKEY_LEN]
        AUTH = hdata[CURVE25519_PUBKEY_LEN: CURVE25519_PUBKEY_LEN + DIGEST_LEN]

        secret_input = self._buildSecretInput(relay_pubkey)
        verify = util.makeHMACSHA256(msg=secret_input, key=T_VERIFY)
        auth_input = self._buildAuthInput(verify, relay_pubkey)
        auth_input = util.makeHMACSHA256(msg=auth_input, key=T_MAC)

        self.is_bad |= util.constantStrEqual(AUTH, auth_input)

        ret = self._makeRelayCrypto(secret_input)

        # don't fail until the very end to avoid leaking timing information
        if self.is_bad:
            raise KeyDerivationFailed()

        return ret

    def _makeRelayCrypto(self, secret_input):
        '''Derive shared key material using HKDF from secret_input.

        :returns: **oppy.crypto.relaycrypto.RelayCrypto** initialized with
            shared key data
        '''
        prk = hkdf.hkdf_extract(salt=T_KEY, input_key_material=secret_input,
                                hash=hashlib.sha256)
        km = hkdf.hkdf_expand(pseudo_random_key=prk, info=M_EXPAND,
                              length=72, hash=hashlib.sha256)

        df = km[: DIGEST_LEN]
        db = km[DIGEST_LEN : DIGEST_LEN * 2]
        kf = km[DIGEST_LEN * 2 : DIGEST_LEN * 2 + KEY_LEN]
        kb = km[DIGEST_LEN * 2 + KEY_LEN : DIGEST_LEN * 2 + KEY_LEN * 2]

        f_digest = hashlib.sha1(df)
        b_digest = hashlib.sha1(db)
        f_cipher = util.makeAES128CTRCipher(kf)
        b_cipher = util.makeAES128CTRCipher(kb)

        return RelayCrypto(forward_digest=f_digest,
                           backward_digest=b_digest,
                           forward_cipher=f_cipher,
                           backward_cipher=b_cipher)

    def _buildAuthInput(self, verify, relay_pubkey):
        '''Build and return auth input as a byte string.

        .. note:: See tor-spec Section 5.1.4 for more details.

        :param str verify: the verification data derived from secret_input
        :param str relay_pubkey: the remote relay's CURVE_25519 public
            key received in the Created2/Extended2 cell
        :returns: **str** auth_input
        '''
        b  = verify
        b += self._signing_key
        b += self._ntor_onion_key
        b += relay_pubkey
        b += bytes(self._public_key)
        b += PROTOID
        b += SERVER_STR
        return b

    def _buildSecretInput(self, relay_pubkey):
        '''Build and return secret input as a byte string.

        .. note:: See tor-spec Section 5.1.4 for more details.

        :param relay_pubkey: the remote relay's CURVE_25519 public key
            received in the Created2/Extended2 cell
        :returns: **str** secret_input
        '''
        b  = self._scalarMult(relay_pubkey)
        b += self._scalarMult(self._ntor_onion_key)
        b += self._signing_key
        b += self._ntor_onion_key
        b += bytes(self._public_key)
        b += relay_pubkey
        b += PROTOID
        return b

    def _scalarMult(self, base):
        '''Perform base**self._secret_key.

        Set self.is_bad if the result is all zeros.

        .. note:: See tor-spec Section 5.1.4 for why this is an adequate
        replacement for checking that none of the EXP() operations produced
        the point at infinity.

        :returns: **str** result
        '''
        # args are: exponent, base
        ret = bindings.crypto_scalarmult(bytes(self._secret_key),
                                         bytes(PublicKey(base)))
        self.is_bad |= util.constantStrAllZero(ret)
        return ret
