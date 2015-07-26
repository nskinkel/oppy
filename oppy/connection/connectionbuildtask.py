# Copyright 2014, 2015 Nik Kinkel
# See LICENSE for licensing information

import logging
import ssl

import OpenSSL.crypto as SSLCrypto

from twisted.internet import defer
from twisted.internet.protocol import Protocol
from twisted.python.failure import Failure

import oppy.crypto.util as crypto

from oppy.cell.cell import Cell
from oppy.cell.fixedlen import NetInfoCell
from oppy.cell.varlen import (
    AuthChallengeCell,
    CertsCell,
    VersionsCell,
)
# TODO: move link cert type/id cert type to cells
from oppy.connection.definitions import (
    SUPPORTED_LINK_PROTOCOLS,
    LINK_CERT_TYPE,
    ID_CERT_TYPE,
    OPENSSL_RSA_KEY_TYPE,
    V3_KEY_BITS,
)


# TODO: handle destroy cell (i.e. when should we send one)
class ConnectionBuildTask(Protocol):

    # XXX relay is a router_status_entry 
    def __init__(self, connection_manager, micro_status_entry,
                 link_protocol=3):
        msg = ("Creating connection task to {}"
               .format(micro_status_entry.address))
        logging.debug(msg)
        # MAp all circuits using this connections
        self._connection_manager = connection_manager
        self.micro_status_entry = micro_status_entry
        self._link_protocol = link_protocol
        self._read_queue = defer.DeferredQueue()
        self._buffer = ''
        self._connection_cert = None
        self._tasks = None
        self._current_task = None
        self._connection = None
        self._failed = False

    def connectionMade(self):
        msg = "Connection made to {}.".format(self.micro_status_entry.address)
        logging.debug(msg)
        try:
            self._tasks = self._sendVersionsCell()
            self._tasks.addCallback(self._processVersionsCell)
            self._tasks.addCallback(self._processCertsCell)
            self._tasks.addCallback(self._processAuthChallengeCell)
            self._tasks.addCallback(self._processNetInfoCell)
            self._tasks.addCallback(self._sendNetInfoCell)
            self._tasks.addCallback(self._connectionSucceeded)
            self._tasks.addErrback(self._connectionFailed)
        except Exception as e:
            self._connectionFailed(Failure(e))

    def connectionLost(self, reason):
        if self._failed is True:
            return
        self._failed = True
        msg = ("Connection lost to {}. Reason: {}."
               .format(self.micro_status_entry.fingerprint, reason))
        if self._current_task is None:
            self._connectionFailed(msg)
        else:
            self._current_task.errback(Failure(Exception(msg)))

    def dataReceived(self, data):
        self._buffer += data

        # TODO: fix underlying cell parsing code. current code does not
        #       handle malicious inputs properly and can't recover from
        #       weird/broken inputs
        while Cell.enoughDataForCell(self._buffer):
            try:
                cell = Cell.parse(self._buffer)
                self._read_queue.put(cell)
                self._buffer = self._buffer[len(cell):]
            # TODO: catch all exceptions and remove that length
            #       from the buffer
            # TODO: remove len(NotImplementedBytes) from buffer
            except NotImplementedError as e:
                msg = ("Connection to {} received an unexpected cell. {}."
                       .format(self.micro_status_entry.fingerprint, e))
                self._current_task.errback(msg)
                break

    def _recvCell(self):
        self._current_task = self._read_queue.get()
        return self._current_task

    def _sendVersionsCell(self):
        cell = VersionsCell.make(SUPPORTED_LINK_PROTOCOLS)
        self.transport.write(cell.getBytes())
        return self._recvCell()

    def _processVersionsCell(self, cell):
        if not isinstance(cell, VersionsCell):
            msg = ("Connection to {} received a {} cell, expected a "
                   "VersionsCell.".format(self.micro_status_entry.fingerprint,
                                          type(cell)))
            raise TypeError(msg)

        self._connection_cert = self.transport.getPeerCertificate()

        if _connectionSupportsHandshake(self._connection_cert) is False:
            msg = ("Connection to {} does not support our authentication "
                   "handshake. Destroying the connection."
                   .format(self.micro_status_entry.fingerprint))
            raise ValueError(msg)

        try:
            self._link_protocol = max(set(SUPPORTED_LINK_PROTOCOLS)
                                      & set(cell.versions))
        except ValueError:
            msg = ("Relay with fingerprint {} does not support any of our "
                   "known link protocols. Destroying the connection."
                   .format(self.micro_status_entry.fingerprint))
            raise ValueError(msg)

        return self._recvCell()

    def _processCertsCell(self, cell):
        if not isinstance(cell, CertsCell):
            msg = ("Connection to {} received a {} cell, expected a "
                   "CertsCell.".format(self.micro_status_entry.fingerprint,
                                       type(cell)))
            raise TypeError(msg)

        link_cert, id_cert = _getCertsFromCell(cell)

        if not _certsHaveValidTime([link_cert, id_cert]):
            msg = ("Certificates sent by {} do not have a valid time. "
                   "Destroying the connection."
                   .format(self.micro_status_entry.fingerprint))
            raise ValueError(msg)

        if not _ASN1KeysEqual(link_cert.get_pubkey(),
                              self._connection_cert.get_pubkey()):
            msg = ("The public key used for the TLS connection to {} is not "
                   "the same key given in the link certificate in the "
                   "CertsCell. Destroying the connection."
                   .format(self.micro_status_entry.fingerprint))
            raise ValueError(msg)

        if not _isRSA1024BitKey(id_cert.get_pubkey()):
            msg = ("The public key in the ID certificate sent by relay {} "
                   "in the CertsCell is not a 1024-bit RSA key. Destroying "
                   "the connection."
                   .format(self.micro_status_entry.fingerprint))
            raise ValueError(msg)

        if not crypto.verifyCertSig(id_cert, link_cert):
            msg = ("The link certificate is not properly signed by the "
                   "ID certificate sent by {} in a CertsCell. Destroying "
                   "the connection."
                   .format(self.micro_status_entry.fingerprint))
            raise ValueError(msg)

        if not crypto.verifyCertSig(id_cert, id_cert):
            msg = ("The ID certificate sent in a CertsCell by {} is not "
                   "properly self-signed. Destroying the connection."
                   .format(self.micro_status_entry.fingerprint))
            raise ValueError(msg)

        return self._recvCell()

    def _processAuthChallengeCell(self, cell):
        if not isinstance(cell, AuthChallengeCell):
            msg = ("Connection to {} received a {} cell, expected an "
                   "AuthChallengeCell."
                   .format(self.micro_status_entry.fingerprint, type(cell)))
            raise TypeError(msg)
        return self._recvCell()

    def _processNetInfoCell(self, cell):
        # TODO: 
        #       - do we need to verify that the address the OR claims in its
        #         NetInfo cell matches what we think it is or do anything else
        #         with the remote address(es) we get?
        # TODO: - is there a better way we should be figuring out our external
        #         IP address?
        if not isinstance(cell, NetInfoCell):
            msg = ("Connection to {} received a {} cell, expected a "
                   "NetInfoCell."
                   .format(self.micro_status_entry.fingerprint, type(cell)))
            raise TypeError(msg)
        return (cell.other_or_address, cell.this_or_addresses[0])

    def _sendNetInfoCell(self, addresses):
        my_address, other_or_address = addresses
        cell = NetInfoCell.make(0, other_or_address=other_or_address,
                                this_or_addresses=[my_address])
        self.transport.write(cell.getBytes())

    def _connectionSucceeded(self, _):
        msg = ("Completed authentication handshake to {} using Link Protocol "
               "{}. Connection is now ready for circuit traffic."
               .format(self.micro_status_entry.fingerprint,
                       self._link_protocol))
        logging.debug(msg)
        self._connection_manager.connectionTaskSucceeded(self)

    # TODO: should we send a DestroyCell here?
    #       i think so, if this is failing for a reason other than connection
    #       lost
    def _connectionFailed(self, reason):
        msg = ("Authentication handshake to {} failed. Reason: {}."
               .format(self.micro_status_entry.fingerprint, reason))
        logging.debug(msg)
        if self._failed is False:
            self._failed = True
            self.transport.abortConnection()
        self._connection_manager.connectionTaskFailed(
            self, Failure(Exception(reason)))


def _connectionSupportsHandshake(cert):
    supported = False

    issuer = cert.get_issuer()
    subject = cert.get_subject()

    # The certificate is self-signed
    supported |= crypto.verifyCertSig(cert, cert)
    # Some component other than "commonName" ("CN") is set in the subject or
    # issuer DN of the certificate.
    supported |= bool([f for f in issuer.get_components() if f[0] != "CN"])
    supported |= bool([f for f in subject.get_components() if f[0] != "CN"])
    # The commonName of the subject or issuer of the certificate ends
    # with a suffix other than ".net".
    supported |= issuer.commonName.split('.')[-1] != 'net'
    supported |= subject.commonName.split('.')[-1] != 'net'
    # The certificate's public key modulus is longer than 1024 bits.
    supported |= cert.get_pubkey().bits() > V3_KEY_BITS

    return supported


def _getCertsFromCell(cell):
    if cell.num_certs != 2:
        msg = ("Expected 2 certificates in CertsCell, found "
               "{}.".format(cell.num_certs))
        raise ValueError(msg)

    link_cert = None
    id_cert = None

    for cert_item in cell.cert_payload_items:
        try:
            pem_cert = ssl.DER_cert_to_PEM_cert(cert_item.cert)

            if cert_item.cert_type == LINK_CERT_TYPE:
                link_cert = SSLCrypto.load_certificate(SSLCrypto.FILETYPE_PEM,
                                                       pem_cert)
            elif cert_item.cert_type == ID_CERT_TYPE:
                id_cert = SSLCrypto.load_certificate(SSLCrypto.FILETYPE_PEM,
                                                     pem_cert)
            else:
                msg = ("Expected a link certificate type or an id certificate "
                       "type. Got {} certificate type."
                       .format(cert_item.cert_type))
                raise ValueError(msg)
        except SSLCrypto.Error as e:
            raise ValueError("Certificate decoding failed: {}.", e)

    if link_cert is None or id_cert is None:
        msg = ("CertsCell must have both a link certificate and an id "
               "certificate.")
        raise ValueError(msg)

    return (link_cert, id_cert)


def _certsHaveValidTime(certs):
    for cert in certs:
        if not crypto.validCertTime(cert):
            return False
    return True


def _ASN1KeysEqual(key1, key2):
    try:
        key1_ASN1 = SSLCrypto.dump_privatekey(SSLCrypto.FILETYPE_ASN1, key1)
        key2_ASN1 = SSLCrypto.dump_privatekey(SSLCrypto.FILETYPE_ASN1, key2)
        # no need for constant time comparison here because both keys tested
        # are sent to us by the relay. doing it anyway in case i accidentally
        # use this function somewhere else in the future
        return crypto.constantStrEqual(key1_ASN1, key2_ASN1)
    except Exception as e:
        msg = "Failed to parse ASN1 key: {}.".format(e)
        logging.debug(msg)
        return False


def _isRSA1024BitKey(key):
    return (key.type() == OPENSSL_RSA_KEY_TYPE) and (key.bits() == 1024)
