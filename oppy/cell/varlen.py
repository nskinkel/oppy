# Copyright 2014, 2015, Nik Kinkel and David Johnston
# See LICENSE for licensing information

import struct

import oppy.connection.definitions as CONN_DEFS
import oppy.cell.definitions as DEF

from oppy.cell.cell import Cell
from oppy.cell.exceptions import BadCellHeader, BadPayloadData
from oppy.cell.util import CertsCellPayloadItem


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
NUM_SUPPORTED_METHODS = 1
SUPPORTED_METHODS = (struct.pack('!H', 1),)


class AuthChallengeCell(VarLenCell):
    '''.. note:: tor-spec, Section 4.3'''

    def __init__(self, header, challenge=None, n_methods=None, methods=None):
        '''
        :param :class:`~cell.varlen.VarLenCell.Header` header:
            header, initialized with values
        :param str challenge: challenge bytes for use with this cell
        :param int n_methods: number of 'methods' in use with this cell
        :param str methods: authentication methods that the responder will
            accept
        '''
        self.header = header
        self.challenge = challenge
        self.n_methods = n_methods
        self.methods = methods

    @staticmethod
    def make(circ_id, challenge, methods, link_version=3):

        AuthChallengeCell._checkChallenge(challenge)
        AuthChallengeCell._checkNMethods(len(methods))
        AuthChallengeCell._checkMethods(methods)

        n_methods = len(methods)

        payload_len = len(challenge) + N_METHODS_LEN + n_methods * 2
        h = VarLenCell.Header(circ_id=circ_id, cmd=DEF.AUTH_CHALLENGE_CMD,
                              payload_len=payload_len,
                              link_version=link_version)

        return AuthChallengeCell(h, challenge, n_methods, methods)

    def getBytes(self, trimmed=False):
        '''Build and return raw byte string representing this cell.

        :param bool trimmed: ignored for varlen cells
        :returns: str -- raw bytes representing this cell.
        '''
        ret = self.header.getBytes()
        ret += self.challenge
        ret += struct.pack('!H', self.n_methods)
        for method in self.methods:
            ret += method
        return ret

    def _parsePayload(self, data):
        '''Parse data and extract this cell's fields.

        Fill in this cell's attributes.

        :param str data: bytes to parse
        '''
        start, end = self.payloadRange()
        offset = start

        challenge = data[offset:offset + CHALLENGE_LEN]
        offset += CHALLENGE_LEN

        n_methods = data[offset:offset + N_METHODS_LEN]
        n_methods = struct.unpack("!H", n_methods)[0]
        offset += N_METHODS_LEN

        methods = []
        for method in xrange(n_methods):
            methods.append(data[offset:offset + 2])
            offset += 2

        AuthChallengeCell._checkChallenge(challenge)
        AuthChallengeCell._checkNMethods(len(methods))
        AuthChallengeCell._checkMethods(methods)

        self.challenge = challenge
        self.n_methods = n_methods
        self.methods = methods

    @staticmethod
    def _checkChallenge(challenge):
        if len(challenge) != CHALLENGE_LEN:
            msg = "AuthChallengeCell must have a 'challenge' of length {}."
            msg += " Got challenge of length {}."
            raise BadPayloadData(msg.format(CHALLENGE_LEN, len(challenge)))

    @staticmethod
    def _checkNMethods(n_methods):
        if n_methods != NUM_SUPPORTED_METHODS:
            msg = "AuthChallengeCells currently only support {} methods. "
            msg += "Got {} methods."
            raise BadPayloadData(msg.format(NUM_SUPPORTED_METHODS,
                                            n_methods))

    @staticmethod
    def _checkMethods(methods):
        for method in methods:
            if len(method) != 2:
                msg = "AuthChallengeCell auth methods must be 2 bytes long."
                msg += " Found auth method {} bytes long."
                raise BadPayloadData(msg.format(len(method)))
            if method not in SUPPORTED_METHODS:
                msg = "Tried to use method {}, but oppy only supports method"
                msg += " {}."
                raise BadPayloadData(method, SUPPORTED_METHODS)

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
CERT_LEN_LEN = 2
MAX_CERTS_PER_CELL = 3


class CertsCell(VarLenCell):
    '''.. note:: tor-spec, Section 4.2'''

    def __init__(self, header, num_certs=None, cert_payload_items=None):
        '''
        :param :class:`~cell.varlen.VarLenCell.Header` header:
            header to use with this cell
        :param int num_certs: number of certificates in this cell
        :param list cert_payload_items: a list of
            oppy.cell.util.CertsCellPayloadItems to be included in this cell
        '''
        self.header = header
        self.num_certs = num_certs
        self.cert_payload_items = cert_payload_items

    def getBytes(self, trimmed=False):
        '''Build and return raw byte string represeting this cell.

        :param bool trimmed: ignore for varlen cells
        :returns: **str** raw byte string representing this cell.
        '''
        ret = self.header.getBytes()
        ret += struct.pack('!B', self.num_certs)
        for cert_item in self.cert_payload_items:
            ret += cert_item.getBytes()
        return ret

    @staticmethod
    def make(circ_id, cert_payload_items, link_version=3):
        
        num_certs = len(cert_payload_items)
        if num_certs > MAX_CERTS_PER_CELL:
            msg = "CertsCell cannot have more than {} certificates per cell."
            msg += " Found {}."
            raise BadPayloadData(msg.format(MAX_CERTS_PER_CELL, num_certs))

        payload_len = NUM_CERT_LEN
        for cert_item in cert_payload_items:
            payload_len += len(cert_item)

        h = VarLenCell.Header(circ_id=circ_id, cmd=DEF.CERTS_CMD,
                              payload_len=payload_len,
                              link_version=link_version)

        return CertsCell(h, num_certs, cert_payload_items)

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
        if self.num_certs > MAX_CERTS_PER_CELL:
            msg = "CertsCell cannot have more than {} certificates per cell."
            msg += " Found {}."
            raise BadPayloadData(msg.format(MAX_CERTS_PER_CELL,
                                            self.num_certs))

        self.cert_payload_items = []

        try:
            for i in xrange(self.num_certs):
                cert_payload_item = CertsCellPayloadItem.parse(data, offset)
                offset += len(cert_payload_item)
                self.cert_payload_items.append(cert_payload_item)
                # catch times when the sender 'lies' and sends a cert
                # larger than the claimed payload length of the cell
                if offset > end:
                    raise IndexError
        except IndexError:
            msg = "CertsCell payload was not enough bytes to construct "
            msg += "a valid CertsCell."
            raise BadPayloadData(msg)

    def __repr__(self):
        fmt = 'header={}, num_certs={}, cert_payload_items={}'
        fmt = 'CertsCell({})'.format(fmt)
        return fmt.format(repr(self.header), repr(self.num_certs),
                          repr(self.cert_payload_items))


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

    @staticmethod
    def make(circ_id, padding_len, link_version=3):
        '''Construct and return a VPaddingCell, using default values
        where possible.

        Automatically create and use an appropriate FixedLenCell.Header.

        .. note: oppy can currently only support Link Protocol versions
            3 and 4, so any other versions will be rejected.

        :param int padding_len: how many bytes of padding to use
        :param int link_version: Link Protocol version in use
        :returns: :class:`~cell.varlen.VPaddingCell`
        '''

        h = VarLenCell.Header(circ_id=circ_id, cmd=DEF.VPADDING_CMD,
                              payload_len=padding_len,
                              link_version=link_version)

        return VPaddingCell(h, payload="\x00" * padding_len)
