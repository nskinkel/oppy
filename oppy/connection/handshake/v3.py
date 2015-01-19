# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

'''
.. topic:: Details

    A V3FSM steps through the Link Protocol Version 3 connection handshake.
    At each step, a V3FSM expects to receive a certain type of cell. Either
    this cell is received, processed, and (optionally) a response cell is
    returned, or an exception is raised and the associated Connection object
    is destroyed.

'''
import ssl
import struct

import OpenSSL.crypto as SSLCrypto

from oppy.cell.definitions import (
    AUTH_CHALLENGE_CMD,
    CERTS_CMD,
    DESTROY_CMD,
    NETINFO_CMD,
    VERSIONS_CMD,
)
from oppy.cell.fixedlen import NetInfoCell
from oppy.cell.varlen import VersionsCell

from oppy.connection.definitions import V3_KEY_BITS, OPENSSL_RSA_KEY_TYPE
from oppy.connection.handshake.exceptions import (
    BadHandshakeState,
    HandshakeFailed,
    ReceivedDestroyCell,
    UnexpectedCell,
)
from oppy.crypto import util as crypto_util
from oppy.util.tools import dispatch, enum


V3State = enum(
    INIT=0,
    EXPECT_VERSIONS=1,
    EXPECT_CERTS=2,
    EXPECT_AUTH_CHALLENGE=3,
    EXPECT_NETINFO=4,
    DONE=5,
)


class V3FSM(object):

    _response_map = {}

    def __init__(self, transport):
        '''
        :param transport transport: the transport for the associated
            connection. this is needed to get the transport's TLS cert
        '''
        # need the transport so we can call getPeerCertificate()
        self._state = V3State.INIT
        self.transport = transport

    @staticmethod
    def _verifyCellCmd(test_cmd, cmd):
        '''Verify that *test_cmd* is equal to *cmd*.

        If cmds are neq or test_cmd is destroy cmd, raise an exception.

        :param int test_cmd: command to test
        :param int cmd: command to test against
        '''
        if test_cmd == DESTROY_CMD:
            msg = "V3FSM received a DESTROY cell."
            raise ReceivedDestroyCell(msg)
        if test_cmd != cmd:
            msg = "V3FSM unexpected cell {}, expected {}."
            msg = msg.format(test_cmd, cmd)
            raise UnexpectedCell(msg)

    def handshakeSupported(self):
        '''Verify the current connection supports a V3 handshake.

        .. note:: See tor-spec, Section 2 for details.

        :returns: **bool** **True** if at least one of the conditions
            necessary for V3 support is **True** for this connection,
            **False** otherwise
        '''
        conn_cert = self.transport.getPeerCertificate()
        issuer = conn_cert.get_issuer()
        subject = conn_cert.get_subject()
        supported = False

        # The certificate is self-signed
        supported |= crypto_util.verifyCertSig(conn_cert, conn_cert)
        # Some component other than "commonName" is set in the subject or
        # issuer DN of the certificate.
        supported |= len(issuer.get_components()) > 1
        supported |= len(subject.get_components()) > 1
        # The commonName of the subject or issuer of the certificate ends
        # with a suffix other than ".net".
        supported |= issuer.commonName.split('.')[-1] != 'net'
        supported |= subject.commonName.split('.')[-1] != 'net'
        # The certificate's public key modulus is longer than 1024 bits.
        supported |= conn_cert.get_pubkey().bits() > V3_KEY_BITS

        return supported

    def recvCell(self, cell):
        '''Receive and incoming cell and hand off to a processing function
        based on the current fsm state.

        :param cell cell: incoming cell to process
        :returns: a cell to write to this connection's transport as a
            response, or None if no response is required
        '''
        try:
            fn = V3FSM._response_map[self._state].__get__(self, type(self))
        except KeyError:
            msg = "V3 in unknown state: {}.".format(self._state)
            raise BadHandshakeState(msg)
        response = fn(cell)
        return response

    def getInitiatingCell(self):
        '''Return the initiating cell for this connection handshake.

        :returns: **oppy.cell.varlen.VersionsCell**
        '''
        self._state = V3State.EXPECT_VERSIONS
        return VersionsCell.make([3])

    @dispatch(_response_map, V3State.EXPECT_VERSIONS)
    def _processVersions(self, cell):
        '''Process an incoming cell when we're in the V3State.EXPECT_VERSIONS
        state.

        Verify that we did receive a valid Versions cell and both our relay
        and the current TLS connection support V3 handshakes. Advance
        fsm state on success.

        .. note:: See tor-spec, Section 2 for more details.

        :param cell cell: incoming cell we received
        '''
        V3FSM._verifyCellCmd(cell.header.cmd, VERSIONS_CMD)

        if 3 not in cell.versions or self.handshakeSupported() is False:
            msg = 'Relay does not support Link Protocol 3'
            raise HandshakeFailed(msg)
        self._state = V3State.EXPECT_CERTS
        return None

    @dispatch(_response_map, V3State.EXPECT_CERTS)
    def _processCerts(self, cell):
        '''Process an incoming cell when we're in the V3State.EXPECT_CERTS
        state.

        Verify that we did receive a valid Certs cell and the certificates
        satisfy V3 criteria.

        .. note:: See tor-spec, Section 4.2 for details.

        :param cell cell: incoming cell
        '''
        V3FSM._verifyCellCmd(cell.header.cmd, CERTS_CMD)

        if cell.num_certs != 2:
            msg = 'Unexpected number of certificates in Certs cell: {0}'
            raise HandshakeFailed(msg.format(cell.num_certs))

        payload = cell.cert_bytes

        # skip length byte in payload
        id_cert = None
        link_cert = None
        offset = 0

        #   XXX this should be tremendously simplified, and certs cell should
        #       probably already have done this parsing in its construction.

        # The CERTS cell contains exactly one CertType 1 "Link" certificate.
        # The CERTS cell contains exactly one CertType 2 "ID" certificate.
        for i in xrange(cell.num_certs):
            ctype = struct.unpack('!1B', payload[offset:offset + 1])[0]
            offset += 1
            clen = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 2

            if ctype != 1 and ctype != 2:
                msg = 'Unexpected certificate type in Certs cell: {0}'
                raise HandshakeFailed(msg.format(ctype))

            cert = ssl.DER_cert_to_PEM_cert(payload[offset:offset + clen])
            offset += clen

            if ctype == 1:
                link_cert = SSLCrypto.load_certificate(SSLCrypto.FILETYPE_PEM,
                                                       cert)
            else:
                id_cert = SSLCrypto.load_certificate(SSLCrypto.FILETYPE_PEM,
                                                     cert)

        if id_cert is None:
            raise HandshakeFailed('Certs cell missing ID certificate')
        if link_cert is None:
            raise HandshakeFailed('Certs cell missing ID certificate')

        conn_cert = self.transport.getPeerCertificate()

        idKey = id_cert.get_pubkey()
        linkKey = link_cert.get_pubkey()
        connKey = conn_cert.get_pubkey()

        # Both certificates have good validAfter and validUntil dates
        if crypto_util.validCertTime(link_cert) is False:
            msg = "Link certificate has an invalid 'validAfter' or "
            msg += "'validUntil' time."
            raise HandshakeFailed(msg)

        if crypto_util.validCertTime(id_cert) is False:
            msg = "ID certificate has an invalid 'validAfter' or "
            msg += "'validUntil' time."
            raise HandshakeFailed(msg)

        # The certified key in the Link certificate matches the
        # link key that was used to negotiate the TLS connection.
        linkASN1Key = SSLCrypto.dump_privatekey(SSLCrypto.FILETYPE_ASN1,
                                                linkKey)
        connASN1Key = SSLCrypto.dump_privatekey(SSLCrypto.FILETYPE_ASN1,
                                                connKey)
        if linkASN1Key != connASN1Key:
            msg = 'Public key from Link certificate is different from the key'
            msg += 'used to initiate the TLS connection'
            raise HandshakeFailed(msg)

        # The certified key in the ID certificate is a 1024-bit RSA key.
        if idKey.type() != OPENSSL_RSA_KEY_TYPE:
            msg = 'ID certificate key is not RSA. Type: {0}'
            raise HandshakeFailed(msg.format(idKey.type()))
        if idKey.bits() != V3_KEY_BITS:
            msg = 'ID certificate is not 1024 bits. Bits: {0}'
            raise HandshakeFailed(msg.format(idKey.bits()))

        # verify id_cert has properly signed link_cert
        if crypto_util.verifyCertSig(id_cert, link_cert) is not True:
            msg = 'ID certificate has not properly signed Link certificate'
            raise HandshakeFailed(msg)
        # verify id_cert is properly self-signed
        if crypto_util.verifyCertSig(id_cert, id_cert) is not True:
            msg = 'ID certificate is not properly self-signed.'
            raise HandshakeFailed(msg)

        self._state = V3State.EXPECT_AUTH_CHALLENGE
        return None

    @dispatch(_response_map, V3State.EXPECT_AUTH_CHALLENGE)
    def _processAuthChallenge(self, cell):
        '''Process an incoming cell when we're in the
        V3State.EXPECT_AUTH_CHALLENGE state.

        .. note: We do not currently support authentication, so AuthChallenge
        is ignored.

        .. note:: See tor-spec, Section 4.3 for more details.

        :param cell cell: incoming cell
        '''
        V3FSM._verifyCellCmd(cell.header.cmd, AUTH_CHALLENGE_CMD)
        self._state = V3State.EXPECT_NETINFO
        return None

    @dispatch(_response_map, V3State.EXPECT_NETINFO)
    def _processNetInfo(self, cell):
        '''Process an incoming cell when we're in V3State.EXPECT_NETINFO
        state.

        Build and return our own NetInfoCell to write to this connection
        and finish off the handshake on success.

        .. note:: See tor-spec Section 4.5 for more details.

        :returns:  oppy.cell.NetInfoCell
        '''
        # XXX do we need to verify that the address the OR claims in its
        #     NetInfo cell matches what we think it is or do anything else
        #     with the remote address(es) we get?
        # XXX is there a better way we should be figuring out our external
        #     IP address?
        V3FSM._verifyCellCmd(cell.header.cmd, NETINFO_CMD)
        self._state = V3State.DONE
        return NetInfoCell.make(cell.header.circ_id,
                                other_or_address=cell.this_or_addresses[0],
                                this_or_addresses=[cell.other_or_address])

    def isDone(self):
        '''Return **True** iff this V3 fsm's state is V3State.DONE

        :returns: **bool** **True** is this fsm's state is V3State.DONE,
            **False** otherwise
        '''
        return self._state == V3State.DONE
