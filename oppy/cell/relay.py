# Copyright 2014, 2015, Nik Kinkel and David Johnston
# See LICENSE for licensing information

import struct

import oppy.cell.definitions as DEF

from oppy.cell.exceptions import BadRelayCellHeader, BadPayloadData
from oppy.cell.fixedlen import FixedLenCell


RELAY_HEADER_LEN = 11


class RelayCell(FixedLenCell):
    '''A container class for representing relay cells.

    .. note:: All Relay cells are fixed-length (length determined by
        Link Protocol version in use).
    '''

    rheader = None
    rpayload = None
    _subclass_map = None

    def __init__(self, header, rheader=None, rpayload=''):
        '''
        :param :class:`~cell.fixedlen.FixedLenCell.Header` header:
            Initialized fixed-length header to use with this RelayCell.
        :param :class:`~cell.relay.RelayCell.RelayHeader` rheader:
            Initialized RelayCell header to use.
        :param str rpayload: this cell's relay payload
        '''
        self.header = header
        self.rheader = rheader
        self.rpayload = rpayload

    def getBytes(self, trimmed=False):
        '''Construct and return the byte string represented by this cell.

        :param bool trimmed: If **True**, return the non-padded payload.
            Otherwise pad the payload with null bytes to the fixed-size
            length in use according to the Link Protocol version.
        :returns: **str** byte string represented by this cell
        '''
        ret = self.header.getBytes() + self.rheader.getBytes() + self.rpayload
        return FixedLenCell.padCellBytes(ret, self.header.link_version)

    def _parsePayload(self, data):
        self._parseRelayHeader(data)
        self._parseRelayPayload(data)

    def _parseRelayHeader(self, data):
        '''Parse *data* and extract this cell's relay header values.

        :param str data: data string to parse and extract values from
        '''
        start, end = self.relayHeaderRange()
        rheader = struct.unpack(RelayCell.RelayHeader.FORMAT, data[start:end])
        r = RelayCell.RelayHeader(*rheader)

        if r.rpayload_len > DEF.MAX_RPAYLOAD_LEN:
            msg = 'rpayload_len {} found, but max rpayload_len is {}'
            msg = msg.format(r.rpayload_len, DEF.MAX_RPAYLOAD_LEN)
            raise BadRelayCellHeader(msg)

        if r.cmd not in DEF.RELAY_CMD_IDS:
            msg = 'Unrecognized relay cmd {}'.format(r.cmd)
            raise BadRelayCellHeader(msg)

        self.rheader = r

    def _parseRelayPayload(self, data):
        '''Parse *data* and extract this cell's relay payload.

        :param str data: data string to parse and extract values from
        '''
        start, end = self.relayPayloadRange()
        self.rpayload = data[start:end]

    def relayHeaderRange(self):
        '''Return a two-tuple indicating the (start,end) indices of
        this cell's relay header.

        :returns: **tuple, int** (start, end) indices of this cell's
            relay header
        '''
        start, _ = self.payloadRange()
        end = start + RELAY_HEADER_LEN
        return start, end

    def relayPayloadRange(self):
        '''Return a two-tuple indicating the (start,end) indices of
        this cell's relay header.

        :returns: **tuple, int** (start, end) indices of this cell's
            relay payload
        '''
        _, start = self.relayHeaderRange()
        end = start + self.rheader.rpayload_len
        return start, end

    @classmethod
    def _getSubclass(cls, header, data):
        '''Uses *header* to interpret the given cell data. A cell
        type which will be appropriate for encapsulating/representing this cell
        data is then selected and returned.

        :type str header: RelayCell.RelayHeader
        :returns: Concrete subclass of RelayCell
        '''
        if RelayCell._subclass_map is None:
            RelayCell._initSubclassMap()

        cmd = RelayCell._extractRelayCmd(header, data)
        return RelayCell._subclass_map[cmd]

    @staticmethod
    def _initSubclassMap():
        RelayCell._subclass_map = {
            DEF.RELAY_BEGIN_CMD     :   RelayBeginCell,
            DEF.RELAY_DATA_CMD      :   RelayDataCell,
            DEF.RELAY_END_CMD       :   RelayEndCell,
            DEF.RELAY_CONNECTED_CMD :   RelayConnectedCell,
            DEF.RELAY_SENDME_CMD    :   RelaySendMeCell,
            DEF.RELAY_EXTEND_CMD    :   RelayExtendCell,
            DEF.RELAY_EXTENDED_CMD  :   RelayExtendedCell,
            DEF.RELAY_TRUNCATE_CMD  :   RelayTruncateCell,
            DEF.RELAY_TRUNCATED_CMD :   RelayTruncatedCell,
            DEF.RELAY_DROP_CMD      :   RelayDropCell,
            DEF.RELAY_RESOLVE_CMD   :   RelayResolveCell,
            DEF.RELAY_RESOLVED_CMD  :   RelayResolvedCell,
            DEF.RELAY_BEGIN_DIR_CMD :   RelayBeginDirCell,
            DEF.RELAY_EXTEND2_CMD   :   RelayExtend2Cell,
            DEF.RELAY_EXTENDED2_CMD :   RelayExtended2Cell
        }

    @staticmethod
    def _extractRecognized(header, data):
        '''Use *header* to interpret cell data; extract and return
        *recognized* field value.

        :param :class:`~cell.relay.RelayCell.RelayHeader` header:
            relay header in use
        :param str data: data string to extract command from
        :returns: **str** recongnized command
        '''
        circ_len = 2 if header.link_version <= 3 else 4
        start = circ_len + 1 + 1
        end = start + 2
        return data[start:end]

    @staticmethod
    def _extractRelayCmd(header, data):
        '''Use *header* to interpret the given cell data; extract and
        return *relay_cmd* field value.

        :param :class:`cell.relay.RelayCell.RelayHeader` header:
            relay cell header to use
        :param str data: data string to extract values from
        :returns: **int** relay_cmd
        '''
        circ_len = 2 if header.link_version <= 3 else 4
        rh_start = circ_len + 1
        (rcmd,) = struct.unpack("!B", data[rh_start:rh_start + 1])
        return rcmd

    def __repr__(self):
        fmt = type(self).__name__ + "(header={}, rheader={}, rpayload={})"
        return fmt.format(repr(self.header),
                          repr(self.rheader),
                          repr(self.rpayload))

    class RelayHeader(object):
        '''A simple container for relay header information.'''

        FORMAT = "!B2sH4sH"

        cmd = None
        recognized = None
        stream_id = None
        digest = None
        rpayload_len = None

        def __init__(self, cmd, recognized, stream_id, digest, rpayload_len):
            self.cmd = cmd
            self.recognized = recognized
            self.stream_id = stream_id
            self.digest = digest
            self.rpayload_len = rpayload_len

        def getBytes(self):
            '''Construct and return the byte string represented by this
            cell.

            :returns: **str** byte string represented by this cell.
            '''
            fmt = RelayCell.RelayHeader.FORMAT
            return struct.pack(fmt, self.cmd, self.recognized,
                               self.stream_id, self.digest,
                               self.rpayload_len)

        def __repr__(self):
            fmt = "RelayCell.RelayHeader(cmd={}, recognized={}, stream_id={}, "
            fmt += "digest={}, rpayload_len={})"
            return fmt.format(repr(self.cmd), repr(self.recognized),
                              repr(self.stream_id), repr(self.digest),
                              repr(self.rpayload_len))


class RelayBeginDirCell(RelayCell):
    '''.. note:: Not Implemented'''
    def __init__(self, header):
        raise NotImplementedError("Can't make RelayBeginDirCell yet.")


class RelayBeginCell(RelayCell):
    '''.. note:: tor-spec, Section 6.2'''

    def __init__(self, header, rheader=None, addr=None, flags=None):
        '''
        :param :class:`~cell.fixedlen.FixedLenCell.Header` header:
            fixed-length header to use in this cell
        :param :class:`~cell.relay.RelayCell.RelayHeader` rheader:
            relay header to use in this cell
        :param str addr: address to begin a connection to (see tor-spec for
            format)
        :param list, int flags: big-endian integer(s) with bits set to indicate
            addr flags, see tor-spec for details.
        '''
        self.header = header
        self.rheader = rheader
        self.addr = addr
        self.flags = flags

    @staticmethod
    def make(circ_id, stream_id, request, flags=None, link_version=3):
        '''Build and return a RelayBegin cell, filling in default values
        when possible.

        Automatically create a default FixedLenCell.Header and
        RelayCell.RelayHeader.

        :param int circ_id: Circuit ID to use in this cell
        :param int stream_id: Stream ID to use in this cell
        :param oppy.util.ExitRequest request: destination this
            cell will request a connection to
        :param list, int flags: flags to use for this connection
        :param int link_version: Link Protocol version in use on this
            connection
        :returns: :class:`~cell.relay.RelayBeginCell`
        '''
        addr = str(request)

        if flags is None:
            flags = [DEF.BEGIN_FLAG_IPv6_OK]

        f = 0
        for flag in flags:
            if flag not in DEF.RELAY_BEGIN_FLAGS:
                msg = 'Unrecognized Relay Begin flag: {}'.format(flag)
                raise BadPayloadData(msg)
            f |= (1 << (flag - 1))

        flags = struct.pack('!I', f)

        h = FixedLenCell.Header(circ_id=circ_id,
                                cmd=DEF.RELAY_CMD,
                                link_version=link_version)
        r = RelayCell.RelayHeader(cmd=DEF.RELAY_BEGIN_CMD,
                                  recognized=DEF.RECOGNIZED,
                                  stream_id=stream_id,
                                  digest=DEF.EMPTY_DIGEST,
                                  rpayload_len=len(addr + flags))

        return RelayBeginCell(h, rheader=r, addr=addr, flags=flags)

    def getBytes(self, trimmed=False):
        '''Build and return the raw byte string this cell represents.

        :param bool trimmed: If **True**, do not pad this cell's payload.
        :returns: **str** raw byte string represented by this cell
        '''
        ret = self.header.getBytes() + self.rheader.getBytes()
        ret += self.addr
        ret += self.flags
        if trimmed is True:
            return ret
        else:
            return FixedLenCell.padCellBytes(ret, self.header.link_version)

    def _parseRelayPayload(self, data):
        # Not yet implemented because of low-priority (OP does not receive
        # relay begin cells). In fact, we must immediately tear down a circuit
        # if we receive a RELAY_BEGIN cell since it's a forward cell.
        raise NotImplementedError()

    def __repr__(self):
        fmt = "RelayBeginCell({}, rheader={}, addr={}, flags={})"
        return fmt.format(repr(self.header), repr(self.rheader),
                          repr(self.addr), repr(self.flags))


ZERO_ADDR_STR  = '\x00\x00\x00\x00'
ADDR_TYPE_LEN  = 1
TTL_LEN        = 4


class RelayConnectedCell(RelayCell):
    '''.. note:: tor-spec, Section 6.2'''

    def __init__(self, header, rheader=None, addr_type=None, addr=None,
                 ttl=None):
        '''
        :param :class:`~oppy.cell.fixedlen.FixedLenCell.Header` header:
            fixed-length header to use in this cell
        :param :class:`~oppy.cell.relay.RelayCell.RelayHeader` rheader:
            relay header to use in this cell
        :param str addr_type: type of IP address sent (only set if IPv6)
        :param str addr: address a connection has been made to
        :param str ttl: number of seconds the address can be cached
        '''
        self.header = header
        self.rheader = rheader
        self.addr_type = addr_type
        self.addr = addr
        self.ttl = ttl

    def getBytes(self, trimmed=False):
        '''Build and return the raw byte string this cell represents.

        :param bool trimmed: if **True**, do not pad payload bytes
        :returns: **str** raw bytes this cell represents
        '''
        ret = self.header.getBytes() + self.rheader.getBytes()
        ret += self.addr + self.addr_type + self.ttl
        if trimmed is True:
            return ret
        else:
            return FixedLenCell.padCellBytes(ret, self.header.link_version)

    def _parseRelayPayload(self, data):
        '''Parse the string *data* and extract cell fields.

        :param str data: string to parse
        '''
        start, _ = self.relayPayloadRange()
        offset = start
        self.addr = data[offset:offset + DEF.IPv4_ADDR_LEN]
        offset += DEF.IPv4_ADDR_LEN

        # ZERO_ADDR_STR indicates we have an IPv6 address
        if self.addr == ZERO_ADDR_STR:
            self.addr_type = data[offset:offset + ADDR_TYPE_LEN]
            offset += ADDR_TYPE_LEN
            self.addr = data[offset:offset + DEF.IPv6_ADDR_LEN]
            offset += DEF.IPv6_ADDR_LEN
        else:
            self.addr_type = ''

        self.ttl = data[offset:offset + TTL_LEN]

    def __repr__(self):
        fmt = '{}, rheader={}, addr_type={}, addr={}, ttl={}'
        fmt = 'RelayConnectedCell=({})'.format(fmt)
        return fmt.format(repr(self.header), repr(self.rheader),
                          repr(self.addr_type), repr(self.addr),
                          repr(self.ttl))


class RelayDataCell(RelayCell):
    '''.. note:: tor-spec, Section 6.2

    .. note: RelayDataCell's don't have any fields beyond the header
        and relay header, so the payload is just treated as a blob.
    '''

    @staticmethod
    def make(circ_id, stream_id, rpayload, link_version=3):
        '''Construct and return a RelayData cell, using default values
        where possible.

        Create a FixedLenCell.Header and a RelayCell.RelayHeader.

        :param int circ_id: Circuit ID to use in this cell
        :param int stream_id: Stream ID to use in this cell
        :param str rpayload: data to use as the relay payload
        :param int link_version: Link Protocol version in use
        '''
        if len(rpayload) > DEF.MAX_RPAYLOAD_LEN:
            raise BadPayloadData()
        h = FixedLenCell.Header(circ_id=circ_id,
                                cmd=DEF.RELAY_CMD,
                                link_version=link_version)
        r = RelayCell.RelayHeader(cmd=DEF.RELAY_DATA_CMD,
                                  recognized=DEF.RECOGNIZED,
                                  stream_id=stream_id,
                                  digest=DEF.EMPTY_DIGEST,
                                  rpayload_len=len(rpayload))
        return RelayDataCell(h, rheader=r, rpayload=rpayload)


class RelayDropCell(RelayCell):
    '''.. note:: tor-spec, Section 6.2

    .. note: RelayDropCell is a long-range dummy cell and they are immediately
        dropped upon receipt.
    '''
    pass


REASON_SIZE = 1


class RelayEndCell(RelayCell):
    '''.. note:: tor-spec, Section 6.3'''

    def __init__(self, header, rheader=None, reason=None, reason_data=None):
        '''
        :param :class:`~oppy.cell.fixedlen.FixedLenCell.Header` header:
            fixed-length header to use in this cell
        :param :class:`~oppy.cell.relay.RelayCell.RelayHeader` rheader:
            relay header to use in this cell
        :param int reason: Single byte that describes the reason this stream
            was closed
        :param str reason_data: with REASON_EXITPOLICY, this optional field
            may be filled in
        '''
        self.header = header
        self.rheader = rheader
        self.reason = reason
        self.reason_data = reason_data

    @staticmethod
    def make(circ_id, stream_id, reason=DEF.REASON_DONE, reason_data='',
             link_version=3):
        '''Construct and return a RelayEnd cell, using default values where
        possible.

        Create a FixedLenCell.Header and a RelayCell.RelayHeader.

        :param int circ_id: Circuit ID to use in this cell
        :param int stream_id: Stream ID to use in this cell
        :param int reason: Single byte that describes the reason this stream
            was closed
        :param str reason_data: with REASON_EXITPOLICY, this optional field
            may be filled in
        :returns: :class:`~oppy.cell.relay.RelayEndCell`
        '''
        h = FixedLenCell.Header(circ_id=circ_id,
                                cmd=DEF.RELAY_CMD,
                                link_version=link_version)
        r = RelayCell.RelayHeader(cmd=DEF.RELAY_END_CMD,
                                  recognized=DEF.RECOGNIZED,
                                  stream_id=stream_id,
                                  digest=DEF.EMPTY_DIGEST,
                                  rpayload_len=REASON_SIZE + len(reason_data))
        return RelayEndCell(h, rheader=r, reason=reason,
                            reason_data=reason_data)

    def getBytes(self, trimmed=False):
        '''Build and return the raw byte string this cell represents.

        :param bool trimmed: if **True**, do not pad payload bytes
        :returns: **str** raw byte string this cell represents
        '''
        ret = self.header.getBytes() + self.rheader.getBytes()
        ret += struct.pack('!B', self.reason)
        ret += self.reason_data
        if trimmed is True:
            return ret
        else:
            return FixedLenCell.padCellBytes(ret, self.header.link_version)

    def _parseRelayPayload(self, data):
        '''Parse the string *data* and extract RelayEndCell payload values.

        Fill in this cell's fields with values.

        :param str data: data string to parse
        '''
        start, end = self.relayPayloadRange()
        offset = start
        self.reason = struct.unpack('!B', data[offset:offset + REASON_SIZE])[0]
        offset += REASON_SIZE

        if self.reason == DEF.REASON_EXITPOLICY:
            self.reason_data = data[offset:end]
        else:
            self.reason_data = ''

    def __repr__(self):
        fmt = '{}, rheader={}, reason={}, reason_data={}'
        fmt = 'RelayBeginCell({})'.format(fmt)
        return fmt.format(repr(self.header), repr(self.rheader),
                          repr(self.reason), repr(self.reason_data))


NSPEC_LEN   = 1
LSTYPE_LEN  = 1
LSLEN_LEN   = 1
HTYPE_LEN   = 2
HLEN_LEN    = 2


class RelayExtend2Cell(RelayCell):
    '''.. note:: tor-spec, Section 5.1.2'''

    def __init__(self, header, rheader=None, nspec=None, lspecs=None,
                 htype=None, hlen=None, hdata=None):
        '''
        :param :class:`~oppy.cell.fixedlen.FixedLenCell.Header` header:
            fixed-length header to use in this cell
        :param :class:`~oppy.cell.relay.RelayCell.RelayHeader` rheader:
            relay header to use in this cell
        :param int nspec: the number of Link Specifiers in this cell
        :param list, :class:`~oppy.cell.util.LinkSpecifier` lspecs: list of
            Link Specifiers to include in this cell
        :param int htype: Type of handshake in use
        :param int hlen: length of the handshake data field
        :param str hdata: handshake data (*onion skin*)
        '''
        self.header = header
        self.rheader = rheader
        self.nspec = nspec
        self.lspecs = lspecs
        self.htype = htype
        self.hlen = hlen
        self.hdata = hdata

    @staticmethod
    def make(circ_id, stream_id=0, nspec=None, lspecs=None,
             htype=DEF.NTOR_HTYPE, hlen=DEF.NTOR_HLEN, hdata='',
             link_version=3, early=True):
        '''Construct and return a RelayExtend2Cell, using default values where
        possible.

        Create a FixedLenCell.Header and a RelayCell.RelayHeader for use
        in this cell.

        .. note:: oppy currently only supports the NTor handshake and will
            reject unrecognized htype's and hlen's.

        :param int circ_id: Circuit ID to use in this cell
        :param int stream_id: Stream ID to use in this cell (should be zero)
        :param int nspec: the number of Link Specifiers in this cell
        :param list, oppy.cell.util.LinkSpecifier lspecs: list of
            Link Specifiers to include in this cell
        :param int htype: Type of handshake in use
        :param int hlen: length of the handshake data field
        :param str hdata: handshake data (*onion skin*)
        :param int link_version: Link Protocol version in use
        :param bool early: if **True**, use a RELAY_EARLY cmd instead of
            RELAY cmd
        :returns: :class:`~oppy.cell.relay.RelayExtend2Cell`
        '''
        if lspecs is None:
            lspecs = []

        if stream_id != 0:
            msg = "EXTEND2 cells should use stream_id=0."
            raise BadPayloadData(msg)

        if htype != DEF.NTOR_HTYPE:
            msg = 'htype was {}, but we currently only support '
            msg += '{} (NTor) handshakes.'
            msg = msg.format(htype, DEF.NTOR_HTYPE)
            raise BadPayloadData(msg)

        if hlen != DEF.NTOR_HLEN:
            msg = 'htype was NTor and hlen was {} but expecting {}'
            msg = msg.format(hlen, DEF.NTOR_HLEN)
            raise BadPayloadData(msg)

        if hlen != len(hdata):
            msg = 'hlen {} neq len(hdata) {}'.format(hlen, len(hdata))
            raise BadPayloadData(msg)

        cmd = DEF.RELAY_EARLY_CMD if early is True else DEF.RELAY_CMD

        h = FixedLenCell.Header(circ_id=circ_id,
                                cmd=cmd,
                                link_version=link_version)

        if nspec is None:
            nspec = len(lspecs)

        if len(lspecs) == 0:
            msg = 'No Link Specifiers found. At least 1 Link Specifier '
            msg += 'is required.'
            raise BadPayloadData(msg)

        if nspec != len(lspecs):
            msg = 'Expected {} LinkSpecifiers but found {}'
            msg = msg.format(nspec, len(lspecs))
            raise BadPayloadData(msg)

        rpayload_len = NSPEC_LEN
        for lspec in lspecs:
            rpayload_len += len(lspec)
        rpayload_len += HTYPE_LEN + HLEN_LEN + hlen

        r = RelayCell.RelayHeader(cmd=DEF.RELAY_EXTEND2_CMD,
                                  recognized=DEF.RECOGNIZED,
                                  stream_id=stream_id,
                                  digest=DEF.EMPTY_DIGEST,
                                  rpayload_len=rpayload_len)

        return RelayExtend2Cell(h, rheader=r, nspec=nspec, lspecs=lspecs,
                                htype=htype, hlen=hlen, hdata=hdata)

    def getBytes(self, trimmed=False):
        '''Build and return the raw byte string this cell represents.

        :param bool trimmed: if **True**, do not pad payload bytes
        :returns: **str** raw byte string this cell represents
        '''
        ret = self.header.getBytes() + self.rheader.getBytes()
        ret += struct.pack('!B', self.nspec)

        for lspec in self.lspecs:
            ret += lspec.getBytes()

        ret += struct.pack('!H', self.htype)
        ret += struct.pack('!H', self.hlen)
        ret += self.hdata
        if trimmed is True:
            return ret
        else:
            return FixedLenCell.padCellBytes(ret, self.header.link_version)

    def _parseRelayPayload(self, data):
        '''Parse the string *data* and extract Extend2 fields.

        Fill in this cell's values.

        :param str data: data string to parse
        '''
        start, _ = self.relayPayloadRange()
        offset = start

        self.nspec = struct.unpack('!B', data[offset:offset + NSPEC_LEN])[0]
        offset += NSPEC_LEN

        # Find the start and end of the lspecs slice.
        lspecs_start = offset
        for idx in xrange(self.nspec):
            offset += LSTYPE_LEN  # skipped lstype
            lslen = struct.unpack('!B', data[offset:offset + LSLEN_LEN])[0]
            offset += LSLEN_LEN  # consumed lslen
            offset += lslen  # skipped lspec
        lspecs_end = offset
        self.lspecs = data[lspecs_start:lspecs_end]

        # Parse each of the handshake fields.
        self.htype = struct.unpack('!H', data[offset:offset + HTYPE_LEN])[0]
        offset += HTYPE_LEN
        self.hlen  = struct.unpack('!H', data[offset:offset + HLEN_LEN])[0]
        offset += HLEN_LEN

        self.hdata = data[offset:offset + self.hlen]

    def __repr__(self):
        fmt = '{}, rheader={}, nspec={}, lspecs={}, htype={}, hlen={}, '
        fmt += 'hdata={}'
        fmt = 'RelayExtend2Cell({})'.format(fmt)
        return fmt.format(repr(self.header), repr(self.rheader),
                          repr(self.nspec), repr(self.lspecs),
                          repr(self.htype), repr(self.hlen),
                          repr(self.hdata))


class RelayExtended2Cell(RelayCell):
    '''.. note:: tor-spec, Section 5.1, 5.1.2'''

    def __init__(self, header, rheader=None, hlen=None, hdata=None):
        '''
        :param :class:`~oppy.cell.fixedlen.FixedLenCell.Header` header:
            header to use in this cell
        :param :class:`~oppy.cell.relay.RelayCell.RelayHeader` rheader:
            relay header to use in this cell
        :param int hlen: length of the handshake data field
        :param str hdata: handshake data (onion skin)
        '''
        self.header = header
        self.rheader = rheader
        self.hlen = hlen
        self.hdata = hdata

    def getBytes(self, trimmed=False):
        '''Build and return the raw byte string this cell represents.

        :param bool trimmed: if **True**, do not pad payload bytes
        :returns: **str** raw byte string this cell represents
        '''
        ret = self.header.getBytes() + self.rheader.getBytes()
        ret += struct.pack('!H', self.hlen)
        ret += self.hdata
        if trimmed is True:
            return ret
        else:
            return FixedLenCell.padCellBytes(ret, self.header.link_version)

    def _parseRelayPayload(self, data):
        '''Parse the string *data* and extract Extended2 fields.

        Fill in this cell's attributes.

        :param str data: data string to parse
        '''
        start, _ = self.relayPayloadRange()
        offset = start

        self.hlen = struct.unpack('!H', data[offset:offset + HLEN_LEN])[0]
        offset += HLEN_LEN

        try:
            self.hdata = data[offset:offset + self.hlen]
        except IndexError:
            raise BadPayloadData('Not enough hdata bytes.')

    def __repr__(self):
        fmt = 'RelayExtended2Cell({}, rheader={}, hlen={}, hdata={})'
        return fmt.format(repr(self.header), repr(self.rheader),
                          repr(self.hlen), repr(self.hdata))


class RelayExtendedCell(RelayCell):
    '''.. note:: Not Implemented'''
    def __init__(self, header):
        raise NotImplementedError("Can't make RelayExtendedCell yet.")


class RelayExtendCell(RelayCell):
    '''.. note:: Not Implemented'''
    def __init__(self, header):
        raise NotImplementedError("Can't make RelayExtendCell yet.")


class RelayResolvedCell(RelayCell):
    '''.. note:: Not Implemented'''
    def __init__(self, header):
        raise NotImplementedError("Can't make RelayResolvedCell yet.")


class RelayResolveCell(RelayCell):
    '''.. note:: Not Implemented'''
    def __init__(self, header):
        raise NotImplementedError("Can't make RelayResolveCell yet.")


class RelaySendMeCell(RelayCell):
    '''.. note:: tor-spec, Section 7.3, 7.4

    .. note: There are no fields in a SendMe cell's payload, so
        we just use parent class fields and methods.
    '''

    # convenience function to simplify construction
    @staticmethod
    def make(circ_id, stream_id=0, link_version=3):
        '''Construct and return a RelaySendMeCell, using default values
        where possible.

        Create a FixedLenCell.Header and a RelayCell.RelayHeader for use
        in this cell.

        :param int circ_id: Circuit ID to use in this cell
        :param int stream_id: Stream ID to use in this cell. A Stream ID of
            zero indicates a 'circuit-level' SendMe cell, and a non-zero
            Stream ID indicates a 'stream-level' SendMe cell.
        :param int link_version: Link Protocol version in use
        :returns: :class:`~oppy.cell.relay.RelaySendMeCell`
        '''
        h = FixedLenCell.Header(circ_id=circ_id,
                                cmd=DEF.RELAY_CMD,
                                link_version=link_version)
        r = RelayCell.RelayHeader(cmd=DEF.RELAY_SENDME_CMD,
                                  recognized=DEF.RECOGNIZED,
                                  stream_id=stream_id,
                                  digest=DEF.EMPTY_DIGEST,
                                  rpayload_len=0)
        return RelaySendMeCell(h, r)


class RelayTruncatedCell(RelayCell):
    '''.. note:: tor-spec, Section 5.4'''

    def __init__(self, header, rheader=None, reason=None):
        '''
        :param :class:`~oppy.cell.fixedlen.FixedLenCell.Header` header:
            header to use in this cell
        :param :class:`~oppy.cell.relay.RelayCell.RelayHeader` rheader:
            relay header to use in this cell
        :param int reason: A single byte describing the reason this
            RelayTruncatedCell was sent.
        '''
        self.header = header
        self.rheader = rheader
        self.reason = reason

    def getBytes(self, trimmed=False):
        '''Build and return the raw byte string this cell represents.

        :param bool trimmed: if **True**, do not pad payload bytes
        :returns: **str** raw bytes this cell represents
        '''
        ret = self.header.getBytes() + self.rheader.getBytes()
        ret += struct.pack('!B', self.reason)
        if trimmed is True:
            return ret
        else:
            return FixedLenCell.padCellBytes(ret, self.header.link_version)

    def _parseRelayPayload(self, data):
        '''Parse the string *data* and extract RelayTruncatedCell fields.

        Fill in this cell's attributes.

        :param str data: data string to parse
        '''
        start, _ = self.relayPayloadRange()
        self.reason = struct.unpack('!B', data[start:start + REASON_SIZE])[0]

    def __repr__(self):
        fmt = 'RelayTruncatedCell=({}, rheader={}, reason={})'
        return fmt.format(repr(self.header), repr(self.rheader),
                          repr(self.reason))


class RelayTruncateCell(RelayCell):
    '''.. note:: Not Implemented'''
    def __init__(self, header, rheader=None, reason=None):
        raise NotImplementedError("Can't make RelayTruncateCell yet.")
