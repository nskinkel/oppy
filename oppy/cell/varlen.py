# Copyright 2014, 2015, Nik Kinkel and David Johnston
# See LICENSE for licensing information

import struct

import oppy.connection.definitions as CONN_DEFS
import oppy.cell.definitions as DEF

from oppy.cell.cell import Cell
from oppy.cell.exceptions import BadCellHeader, BadPayloadData


class VarLenCell(Cell):
    '''A container class for representing a variable-length cell.'''

    _subclass_map = None

    def __init__(self, header, payload=None):
        '''
        :param :class:`~cell.varlen.VarLenCell.Header` header:
            header to use with this cell.
        :param str payload: payload bytes to use with this cell
        '''
        if not isinstance(header, VarLenCell.Header):
            msg = 'Expected cell header type VarLenCell.Header, but '
            msg += 'received header of type {}'.format(type(header))
            raise BadCellHeader(msg)

        self.header = header
        self.payload = payload

    def getBytes(self, trimmed=False):
        '''Build and return the raw byte string this cell represents.

        :param bool trimmed: ignored for varlen cells
        :returns: **str** raw byte string represented by this cell
        '''
        return self.header.getBytes() + self.payload

    def _parseHeader(self, data):
        # Note that each field of `self.header`, except for `payload_len`,
        # should already be set.
        already_parsed = (self.header.circ_id,
                          self.header.cmd,
                          self.header.link_version)
        for field in already_parsed:
            assert field is not None

        if self.header.link_version <= 3:
            start = DEF.PAYLOAD_START_V3
        else:
            start = DEF.PAYLOAD_START_V4

        end = start + DEF.PAYLOAD_FIELD_LEN
        length = struct.unpack("!H", data[start:end])[0]
        self.header.payload_len = length

    def _parsePayload(self, data):
        start, end = self.payloadRange()
        self.payload = data[start:end]

    def payloadRange(self):
        '''Return a two-tuple indicating the start, end positions of this
        cell's payload.

        :returns: **tuple, int** (start, end) positions of this cell's
            payload
        '''
        circ_len = 2 if self.header.link_version <= 3 else 4
        start = circ_len + 1 + 2
        end = start + self.header.payload_len
        return start, end

    @staticmethod
    def _initSubclassMap():
        VarLenCell._subclass_map = {
            DEF.VERSIONS_CMD        :   VersionsCell,
            DEF.VPADDING_CMD        :   VPaddingCell,
            DEF.CERTS_CMD           :   CertsCell,
            DEF.AUTH_CHALLENGE_CMD  :   AuthChallengeCell,
            DEF.AUTHENTICATE_CMD    :   AuthenticateCell,
            DEF.AUTHORIZE_CMD       :   AuthorizeCell
        }

    class Header(object):
        '''A simple container class for representing the header information of
        a variable-length cell.'''

        def __init__(self, circ_id=None, cmd=None, payload_len=None,
                     link_version=3):
            '''
            :param int circ_id: Circuit ID to use in this header
            :param int cmd: command to use in this cell
            :param int payload_len: length of this cell's payload
            :param int link_version: Link Protocol version in use
            '''
            self.circ_id = circ_id
            self.cmd = cmd
            self.payload_len = payload_len
            self.link_version = link_version

        def getBytes(self):
            '''Build and return the raw byte string represented by this
            header.

            :returns: **str** raw byte string this header represents
            '''
            fmt = "!HBH" if self.link_version <= 3 else "!IBH"
            return struct.pack(fmt, self.circ_id, self.cmd, self.payload_len)

        def __repr__(self):
            fmt = "circ_id={}, cmd={}, payload_len={}, link_version={}"
            fmt = "VarLenCell.Header({})".format(fmt)
            return fmt.format(self.circ_id, self.cmd, self.payload_len,
                              self.link_version)


CHALLENGE_LEN = 32
N_METHODS_LEN = 2


class AuthChallengeCell(VarLenCell):
    '''.. note:: tor-spec, Section 4.3'''

    def __init__(self, header, challenge=None, n_methods=None, methods=None):
        '''
        :param :class:`~cell.varlen.VarLenCell.Header` header:
            header, initialized with values
        :param str challenge: challenge bytes for use with this cell
        :param str n_methods: number of 'methods' in use with this cell
        :param str methods: authentication methods that the responder will
            accept
        '''
        self.header = header
        self.challenge = challenge
        self.n_methods = n_methods
        self.methods = methods

    def getBytes(self, trimmed=False):
        '''Build and return raw byte string representing this cell.

        :param bool trimmed: ignored for varlen cells
        :returns: str -- raw bytes representing this cell.
        '''
        ret = self.header.getBytes()
        return ret + self.challenge + self.n_methods + self.methods

    def _parsePayload(self, data):
        '''Parse data and extract this cell's fields.

        Fill in this cell's attributes.

        :param str data: bytes to parse
        '''
        start, end = self.payloadRange()
        offset = start

        # payload of auth challenge must be even number bytes
        if len(data[start:end]) % 2 != 0:
            msg = 'AuthChallenge cell payload must be an even number '
            msg += 'of bytes.'
            raise BadPayloadData(msg)

        self.challenge = data[offset:offset + CHALLENGE_LEN]
        offset += CHALLENGE_LEN

        self.n_methods = data[offset:offset + N_METHODS_LEN]
        offset += N_METHODS_LEN

        n = struct.unpack('!H', self.n_methods)[0]

        if end - start < CHALLENGE_LEN + N_METHODS_LEN + 2 * n:
            msg = "AuthChallengeCell specified {} bytes of 'methods', but "
            msg += "only {} bytes were available."
            raise BadPayloadData(msg.format(n,
                                 end - start - CHALLENGE_LEN - N_METHODS_LEN))

        self.methods = data[offset:offset + 2 * n]

    def __repr__(self):
        fmt = '{}, challenge={}, n_methods={}, methods={}'
        fmt = 'AuthChallengeCell({})'.format(fmt)
        return fmt.format(repr(self.header), repr(self.challenge),
                          repr(self.n_methods), repr(self.methods))


class AuthenticateCell(VarLenCell):
    '''.. note:: Not Implemented'''
    def __init__(self, header):
        raise NotImplementedError("Can't make AuthenticateCell yet.")


class AuthorizeCell(VarLenCell):
    '''.. note:: Not Implemented'''
    def __init__(self, header):
        raise NotImplementedError("Can't make AuthorizeCell yet.")


NUM_CERT_LEN  = 1
CERT_TYPE_LEN = 1
CERT_LEN_LEN  = 2


class CertsCell(VarLenCell):
    '''.. note:: tor-spec, Section 4.2'''

    def __init__(self, header, num_certs=None, cert_bytes=None):
        '''
        :param :class:`~cell.varlen.VarLenCell.Header` header:
            header to use with this cell
        :param int num_certs: number of certificates in this cell
        :param str cert_bytes: raw bytes representing the certs in this cell
        '''
        self.header = header
        self.num_certs = num_certs
        self.cert_bytes = cert_bytes

    def getBytes(self, trimmed=False):
        '''Build and return raw byte string represeting this cell.

        :param bool trimmed: ignore for varlen cells
        :returns: **str** raw byte string representing this cell.
        '''
        ret = self.header.getBytes()
        return ret + struct.pack('!B', self.num_certs) + self.cert_bytes

    def _parsePayload(self, data):
        '''Parse data and extract this cell's fields.

        Fill in this cell's attributes.

        :param str data: bytes to parse
        '''
        start, end = self.payloadRange()
        offset = start

        if end - start < CERT_TYPE_LEN + CERT_LEN_LEN:
            msg = "CertsCell payload was too few bytes to make a valid "
            msg += "CertsCell."
            raise BadPayloadData(msg)

        self.num_certs = struct.unpack('!B',
                                       data[offset:offset + NUM_CERT_LEN])[0]
        offset += NUM_CERT_LEN

        self.cert_bytes = ''

        try:
            for i in xrange(self.num_certs):
                self.cert_bytes += data[offset:offset + CERT_TYPE_LEN]
                offset += CERT_TYPE_LEN

                clen = data[offset:offset + CERT_LEN_LEN]
                self.cert_bytes += clen
                offset += CERT_LEN_LEN
                clen = struct.unpack('!H', clen)[0]

                self.cert_bytes += data[offset:offset + clen]
                offset += clen
        except IndexError:
            msg = "CertsCell payload was not enough bytes to construct "
            msg += "a valid CertsCell."
            raise BadPayloadData(msg)

    def __repr__(self):
        fmt = 'header={}, num_certs={}, cert_bytes={}'
        fmt = 'CertsCell({})'.format(fmt)
        return fmt.format(repr(self.header), repr(self.num_certs),
                          repr(self.cert_bytes))


VERSIONS_LEN = 2


class VersionsCell(VarLenCell):
    '''.. note:: tor-spec, Section 4.1'''

    def __init__(self, header, versions=None):
        '''
        :param :class:`~cell.varlen.VarLenCell.Header` header:
            header to use with this cell
        :param list, int versions: Link Protocol versions the originator of
            this VersionsCell claims to support
        '''
        self.header = header
        self.versions = versions

    @staticmethod
    def make(versions):
        '''Construct and return a VersionsCell, using default values
        where possible.

        Automatically create and use an appropriate FixedLenCell.Header.

        .. note: A VersionsCell always has len(circ_id_bytes) == 2 for
            backward compatibility (tor-spec, Section 3).

        .. note: oppy can currently only support Link Protocol versions
            3 and 4, so any other versions will be rejected.

        :param list, int versions: Link Protocol versions to indicate support
            for in this VersionsCell
        :returns: :class:`~cell.varlen.VersionsCell`
        '''
        for version in versions:
            if version not in CONN_DEFS.SUPPORTED_LINK_PROTOCOLS:
                msg = "Tried to build a VersionsCell that supports versions "
                msg += "{}, but oppy only supports versions {}."
                msg = msg.format(versions, CONN_DEFS.SUPPORTED_LINK_PROTOCOLS)
                raise BadPayloadData(msg)

        h = VarLenCell.Header(circ_id=0, cmd=DEF.VERSIONS_CMD,
                              payload_len=len(versions) * 2,
                              link_version=3)

        return VersionsCell(h, versions)

    def getBytes(self, trimmed=False):
        '''Build and return raw byte string representing this cell.

        :param bool trimmed: ignored for varlen cells
        :returns: str -- raw byte string representing this cell.
        '''
        ret = self.header.getBytes()
        for i in xrange(len(self.versions)):
            ret += struct.pack('!H', self.versions[i])
        return ret

    def _parsePayload(self, data):
        '''Parse data and extract this cell's fields.

        Fill in this cell's attributes.

        :param str data: bytes to parse
        '''
        start, end = self.payloadRange()
        offset = start

        self.versions = []
        while offset < end:
            v = struct.unpack('!H', data[offset:offset + VERSIONS_LEN])[0]
            if v not in CONN_DEFS.KNOWN_LINK_PROTOCOLS:
                msg = "VersionsCell claims to support an unknown Link "
                msg += "Protocol version {}.".format(v)
                raise BadPayloadData(msg)
            self.versions.append(v)
            offset += VERSIONS_LEN

    def __repr__(self):
        fmt = '{}, versions={}'
        fmt = 'VersionsCell({})'.format(fmt)
        return fmt.format(repr(self.header), repr(self.versions))


class VPaddingCell(VarLenCell):
    '''.. note:: tor-spec, Section 3, 4, 7.2

    .. note: VPadding cells have no fields, so just use fields from the
        parent class.
    '''
    pass
