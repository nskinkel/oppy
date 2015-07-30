# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

'''
.. topic:: Details

    Crypto utility functions. Includes:

        - Constant time string comparisons
        - Wrappers around encryption/decryption operations
        - The "recognized" check for incoming cells
        - A couple methods for verifying TLS certificate properties (signatures
          and times)

'''
import hashlib
import hmac
import struct

from collections import namedtuple
from datetime import datetime
from itertools import izip

import OpenSSL

from Crypto.Cipher import AES
from Crypto.Util import asn1, Counter

from oppy.cell.cell import Cell
from oppy.cell.definitions import RECOGNIZED, EMPTY_DIGEST
from oppy.cell.fixedlen import EncryptedCell


class UnrecognizedCell(Exception):
    pass


RelayCrypto = namedtuple("RelayCrypto", ("forward_digest",
                                         "backward_digest",
                                         "forward_cipher",
                                         "backward_cipher"))


def constantStrEqual(str1, str2):
    '''Do a constant-time comparison of str1 and str2, returning **True**
    if they are equal, **False** otherwise.

    :param str str1: first string to compare
    :param str str2: second string to compare
    :returns: **bool** **True** if str1 == str2, **False** otherwise
    '''
    try:
        from hmac import compare_digest
        return compare_digest(str1, str2)
    except ImportError:
        pass

    if len(str1) != len(str2):
        # we've already failed at this point, but loop anyway
        res = 1
        comp1 = bytearray(str2)
        comp2 = bytearray(str2)
    else:
        res = 0
        comp1 = bytearray(str1)
        comp2 = bytearray(str2)
    
    for a, b in izip(comp1, comp2):
        res |= a ^ b

    return res == 0


def constantStrAllZero(s):
    '''Check if *s* consists of all zero bytes.

    :param str s: string to check
    :returns: **bool** **True** if *s* contains all zero bytes, **False**
        otherwise
    '''
    return constantStrEqual(s, '\x00' * len(s))


def makeAES128CTRCipher(key, initial_value=0):
    '''Create and return a new AES128-CTR cipher instance.

    :param str key: key to use for this cipher
    :param initial_value: initial_value to use
    :returns: **Crypto.Cipher.AES.AES**
    '''
    ctr = Counter.new(128, initial_value=initial_value)
    return AES.new(key, AES.MODE_CTR, counter=ctr)


def makeHMACSHA256(msg, key):
    '''Make a new HMAC-SHA256 with *msg* and *key* and return digest byte
    string.

    :param str msg: msg
    :param str key: key to use
    :returns: **str** HMAC digest
    '''
    t = hmac.new(msg=msg, key=key, digestmod=hashlib.sha256)
    return t.digest()


def _makePayloadWithDigest(payload, digest=EMPTY_DIGEST):
    '''Make a new payload with *digest* inserted in the correct position.

    :param str payload: payload in which to insert digest
    :param str digest: digest to insert
    :returns: **str** payload with digest inserted into correct position
    '''
    assert len(payload) >= 9 and len(digest) == 4
    DIGEST_START = 5
    DIGEST_END = 9
    return payload[:DIGEST_START] + digest + payload[DIGEST_END:]


# TODO: fix documentation
def encryptCell(cell, crypt_path, early=False):
    '''Encrypt *cell* to the *target* relay in *crypt_path* and update
    the appropriate forward digest.

    :param cell cell: cell to encrypt
    :param list crypt_path: list of RelayCrypto instances available for
        encryption
    :param int target: target node to encrypt to
    :param bool early: if **True**, use a RELAY_EARLY cmd instead of a
        RELAY cmd
    :returns: **oppy.cell.fixedlen.EncryptedCell**
    '''
    assert cell.rheader.digest == EMPTY_DIGEST

    # 1) update f_digest with cell payload bytes
    crypt_path[-1].forward_digest.update(cell.getPayload())
    # 2) insert first four bytes into new digest position
    cell.rheader.digest = crypt_path[-1].forward_digest.digest()[:4]
    # 3) encrypt payload
    payload = cell.getPayload()
    for node in reversed(crypt_path):
        payload = node.forward_cipher.encrypt(payload)
    # 4) return encrypted relay cell with new payload
    return EncryptedCell.make(cell.header.circ_id, payload, early=early)


def _cellRecognized(payload, relay_crypto):
    '''Return **True** if this payload is *recognized*.

    .. note:: See tor-spec Section 6.1 for details about what it means for a
        cell to be *recognized*.

    :param str payload: payload to check if recognized
    :param oppy.crypto.relaycrypto.RelayCrypto relay_crypto: RelayCrypto
        instance to use for checking if payload is recognized
    :returns: **bool** **True** if this payload is recognized, **False**
        otherwise
    '''
    if len(payload) < 9 or payload[2:4] != RECOGNIZED:
        return False
    digest = payload[5:9]
    test_payload = _makePayloadWithDigest(payload)
    test_digest = relay_crypto.backward_digest.copy()
    test_digest.update(test_payload)
    # no danger of timing attack here since we just
    # drop the cell if it's not recognized
    return test_digest.digest()[:4] == digest


# TODO: fix documentation
def decryptCell(cell, crypt_path):
    '''Decrypt *cell* until it is recognized or we've tried all RelayCrypto's
    in *crypt_path*.

    Attempt to decrypt the cell one hop at a time. Stop if the cell is
    recognized. Raise an exception if the cell is not recognized at all.

    :param cell cell: cell to decrypt
    :param list, oppy.crypto.relaycrypto.RelayCrypto crypt_path: list of
        RelayCrypto instances to use for decryption
    :param int origin: the originating hop we think this cell came from
    :returns: the concrete RelayCell type of this decrypted cell
    '''
    origin = 0
    recognized = False
    payload = cell.getPayload()

    for node in crypt_path:
        payload = node.backward_cipher.decrypt(payload)
        if _cellRecognized(payload, node):
            recognized = True
            break
        origin += 1

    if not recognized:
        raise UnrecognizedCell()

    updated_payload = _makePayloadWithDigest(payload)
    crypt_path[origin].backward_digest.update(updated_payload)
    if cell.header.link_version < 4:
        cid = struct.pack('!H', cell.header.circ_id)
    else:
        cid = struct.pack('!I', cell.header.circ_id)
    cmd = struct.pack('!B', cell.header.cmd)

    dec = Cell.parse(cid + cmd + payload)
    return (dec, origin)


def verifyCertSig(id_cert, cert_to_verify, algo='sha1'):
    '''Verify that the SSL certificate *id_cert* has signed the TLS cert
    *cert_to_verify*.

    :param id_cert: Identification Certificate
    :type id_cert: OpenSSL.crypto.X509
    :param cert_to_verify: certificate to verify signature on
    :type cert_to_verify: OpenSSL.crypto.X509
    :param algo: algorithm to use for certificate verification
    :type algo: str

    :returns: **bool** **True** if the signature of *cert_to_verify* can be
        verified from *id_cert*, **False** otherwise
    '''
    cert_to_verify_ASN1 = OpenSSL.crypto.dump_certificate(
                                OpenSSL.crypto.FILETYPE_ASN1, cert_to_verify)

    der = asn1.DerSequence()
    der.decode(cert_to_verify_ASN1)
    cert_to_verify_DER = der[0]
    cert_to_verify_ALGO = der[1]
    cert_to_verify_SIG = der[2]

    sig_DER = asn1.DerObject()
    sig_DER.decode(cert_to_verify_SIG)

    sig = sig_DER.payload

    # first byte is number of unused bytes. should be zero
    if sig[0] != '\x00':
        return False

    sig = sig[1:]

    try:
        OpenSSL.crypto.verify(id_cert, sig, cert_to_verify_DER, algo)
        return True
    except OpenSSL.crypto.Error:
        return False


# XXX should we check that the time is not later than the current time?
def validCertTime(cert):
    '''Verify that TLS certificate *cert*'s time is not earlier than
    cert.notBefore and not later than cert.notAfter.

    :param OpenSSL.crypto.X509 cert: TLS Certificate to verify times of
    :returns: **bool** **True** if cert.notBefore < now < cert.notAfter,
        **False** otherwise
    '''
    now = datetime.now()
    try:
        validAfter = datetime.strptime(cert.get_notBefore(), '%Y%m%d%H%M%SZ')
        validUntil = datetime.strptime(cert.get_notAfter(), '%Y%m%d%H%M%SZ')
        return validAfter < now < validUntil
    except ValueError:
        return False
