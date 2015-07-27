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

from collections import namedtuple

from nacl import bindings
from nacl.public import PrivateKey, PublicKey

from oppy.crypto import util
from oppy.util.tools import decodeMicrodescriptorIdentifier


PROTOID     = "ntor-curve25519-sha256-1"
T_MAC       = PROTOID + ":mac"
T_KEY       = PROTOID + ":key_extract"
T_VERIFY    = PROTOID + ":verify"
M_EXPAND    = PROTOID + ":key_expand"
SERVER_STR  = "Server"

CURVE25519_PUBKEY_LEN   = 32
DIGEST_LEN              = 20
KEY_LEN                 = 16


class KeyDerivationFailed(Exception):
    pass


class NTorState(namedtuple('NTorState',
    ('relay_identity', 'relay_ntor_onion_key', 'secret_key', 'public_key'))):

    __slots__ = ()

    def __new__(cls, microdescriptor):
        relay_identity = decodeMicrodescriptorIdentifier(microdescriptor)
        relay_ntor_onion_key = base64.b64decode(microdescriptor.ntor_onion_key)
        secret_key = PrivateKey.generate()
        public_key = secret_key.public_key
        return super(NTorState, cls).__new__(
            cls, relay_identity, relay_ntor_onion_key, secret_key, public_key)

    # TODO: everything
    def memwipe(self):
        raise NotImplementedError()


def createOnionSkin(ntorstate):
    '''Build and return an *onion skin* to this handshake's relay.

    .. note:: See tor-spec Section 5.1.4 for more information.

    :returns: **str** raw byte string for this *onion skin*
    '''
    ret = ntorstate.relay_identity
    ret += ntorstate.relay_ntor_onion_key
    ret += bytes(ntorstate.public_key)
    return ret


def deriveRelayCrypto(ntorstate, cell):
    '''Derive shared key material for this ntor handshake; create and
    return actual cipher and hash instances inside a RelayCrypto object.

    .. note:: See tor-spec Section 5.1.4, 5.2.2 for more details.

    :param cell cell: Created2 cell or Extended2 cell used to derive
        shared keys
    :returns: **oppy.crypto.relaycrypto.RelayCrypto** object initialized
        with the derived key material.
    '''
    is_bad = False
    hdata = cell.hdata

    relay_pubkey = cell.hdata[:CURVE25519_PUBKEY_LEN]
    AUTH = hdata[CURVE25519_PUBKEY_LEN:CURVE25519_PUBKEY_LEN+DIGEST_LEN]

    secret_input, bad = _buildSecretInput(ntorstate, relay_pubkey)
    is_bad |= bad

    verify = util.makeHMACSHA256(msg=secret_input, key=T_VERIFY)
    auth_input = _buildAuthInput(ntorstate, verify, relay_pubkey)
    auth_input = util.makeHMACSHA256(msg=auth_input, key=T_MAC)

    is_bad |= util.constantStrEqual(AUTH, auth_input)

    ret = _makeRelayCrypto(secret_input)
    # don't fail until the very end to avoid leaking timing information
    # (this might be unnecessary)
    if is_bad is True:
        raise KeyDerivationFailed()
    return ret


def _buildSecretInput(ntorstate, relay_pubkey):
    '''Build and return secret input as a byte string.

    .. note:: See tor-spec Section 5.1.4 for more details.

    :param relay_pubkey: the remote relay's CURVE_25519 public key
        received in the Created2/Extended2 cell
    :returns: **str** secret_input
    '''
    is_bad = False
    v, bad = _EXP(ntorstate.secret_key, relay_pubkey)
    is_bad |= bad
    b = v

    v, bad = _EXP(ntorstate.secret_key, ntorstate.relay_ntor_onion_key)
    is_bad |= bad
    b += v

    b += ntorstate.relay_identity
    b += ntorstate.relay_ntor_onion_key
    b += bytes(ntorstate.public_key)
    b += relay_pubkey
    b += PROTOID
    return (b, is_bad)


def _buildAuthInput(ntorstate, verify, relay_pubkey):
    '''Build and return auth input as a byte string.

    .. note:: See tor-spec Section 5.1.4 for more details.

    :param str verify: the verification data derived from secret_input
    :param str relay_pubkey: the remote relay's CURVE_25519 public
        key received in the Created2/Extended2 cell
    :returns: **str** auth_input
    '''
    b  = verify
    b += ntorstate.relay_identity
    b += ntorstate.relay_ntor_onion_key
    b += relay_pubkey
    b += bytes(ntorstate.public_key)
    b += PROTOID
    b += SERVER_STR
    return b


def _makeRelayCrypto(secret_input):
    '''Derive shared key material using HKDF from secret_input.

    :returns: **oppy.crypto.relaycrypto.RelayCrypto** initialized with
        shared key data
    '''
    prk = hkdf.hkdf_extract(salt=T_KEY, input_key_material=secret_input,
        hash=hashlib.sha256)
    km = hkdf.hkdf_expand(pseudo_random_key=prk, info=M_EXPAND,
        length=72, hash=hashlib.sha256)

    df = km[:DIGEST_LEN]
    db = km[DIGEST_LEN:DIGEST_LEN*2]
    kf = km[DIGEST_LEN*2:DIGEST_LEN*2+KEY_LEN]
    kb = km[DIGEST_LEN*2+KEY_LEN:DIGEST_LEN*2+KEY_LEN*2]

    f_digest = hashlib.sha1(df)
    b_digest = hashlib.sha1(db)
    f_cipher = util.makeAES128CTRCipher(kf)
    b_cipher = util.makeAES128CTRCipher(kb)

    ret = util.RelayCrypto(forward_digest=f_digest, backward_digest=b_digest,
        forward_cipher=f_cipher, backward_cipher=b_cipher)
    return ret


def _EXP(n, p):
    '''
    .. note:: See tor-spec Section 5.1.4 for why this is an adequate
    replacement for checking that none of the EXP() operations produced
    the point at infinity.

    :returns: **str** result
    '''
    ret = bindings.crypto_scalarmult(bytes(n), bytes(PublicKey(p)))
    bad = util.constantStrAllZero(ret)
    return (ret, bad)
