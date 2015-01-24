# Copyright 2014, 2015, Nik Kinkel and David Johnston
# See LICENSE for licensing information

import struct
import time

from oppy.cell.cell import Cell
import oppy.cell.definitions as DEF

from oppy.cell.exceptions import BadCellHeader, BadPayloadData
from oppy.cell.util import TLVTriple


class FixedLenCell(Cell):
    '''A container class for representing fixed-length cells.'''

    _subclass_map = None

    def __init__(self, header, payload=None):
        '''Create a :class:`~oppy.cell.fixedlen.FixedLenCell` with the
        using *header*.

        :param :class:`oppy.cell.fixedlen.FixedLenCell.Header` header: The
            cell header information to be used.
        :param str payload: Cell payload to be used.
        '''
        if not isinstance(header, FixedLenCell.Header):
            msg = 'Expected cell header type FixedLenCell.Header, but '
            msg += 'received header of type: {}'.format(type(header))
            raise BadCellHeader(msg)

        self.header = header
        self.payload = payload

    @staticmethod
    def padCellBytes(cell_bytes, link_version=3):
        '''Pad cell_bytes to uniform length.

        Length depends on the Link Protocol version in use.

        :param str cell_bytes: byte string to pad
        :param int link_version: Link Protocol version in use
        :returns: **str** cell_bytes padded to a fixed-length
        '''
        PAD_BYTE = '\x00'
        if link_version <= 3:
            pad_len = DEF.FIXED_LEN_V3_LEN
        else:
            pad_len = DEF.FIXED_LEN_V4_LEN
        return cell_bytes + PAD_BYTE * (pad_len - len(cell_bytes))

    def getBytes(self, trimmed=False):
        '''Build and return the raw bytes this cell represents.

        :param bool trimmed: ignored
        :returns: **str** byte representation of this cell.
        '''
        return self.header.getBytes() + self.payload

    def payloadRange(self):
        '''Return a two-tuple representing the (start, end) positions of this
        cell's payload data (based on Link Protocol version in use).

        :returns: **tuple, int** (start, end) indices of payload.
        '''
        if 1 <= self.header.link_version <= 3:
            return DEF.PAYLOAD_START_V3, DEF.FIXED_LEN_V3_LEN
        elif self.header.link_version <= 4:
            return DEF.PAYLOAD_START_V4, DEF.FIXED_LEN_V4_LEN
        else:
            fmt = "The cell's link version is invalid: {}"
            raise ValueError(fmt.format(self.header.link_version))

    def _parseHeader(self, data):
        # This check is only useful for debugging purposes. For fixed-length
        # cells, this method actually doesn't need to do anything, because
        # all header fields have already been parsed.
        already_parsed = (self.header.circ_id,
                          self.header.cmd,
                          self.header.link_version)
        for field in already_parsed:
            assert field is not None

    def _parsePayload(self, data):
        start, end = self.payloadRange()
        self.payload = data[start:end]

    @staticmethod
    def _initSubclassMap():
        FixedLenCell._subclass_map = {
            DEF.PADDING_CMD     :   PaddingCell,
            DEF.CREATE_CMD      :   CreateCell,
            DEF.CREATED_CMD     :   CreatedCell,
            DEF.RELAY_CMD       :   EncryptedCell,
            DEF.DESTROY_CMD     :   DestroyCell,
            DEF.CREATE_FAST_CMD :   CreateFastCell,
            DEF.CREATED_FAST_CMD:   CreatedFastCell,
            DEF.NETINFO_CMD     :   NetInfoCell,
            DEF.RELAY_EARLY_CMD :   EncryptedCell,
            DEF.CREATE2_CMD     :   Create2Cell,
            DEF.CREATED2_CMD    :   Created2Cell
        }

    @staticmethod
    def _extractCmd(data, header):
        return header.cmd

    class Header(object):
        '''A simple container class for representing the header information of
        a fixed-length cell.'''

        def __init__(self, circ_id=None, cmd=None, link_version=3):
            self.circ_id = circ_id
            self.cmd = cmd
            self.link_version = link_version

        def getBytes(self):
            '''Return the raw bytes of this header.

            :returns: **str** byte representation of this header
            '''
            fmt = "!HB" if self.link_version <= 3 else "!IB"
            return struct.pack(fmt, self.circ_id, self.cmd)

        def __repr__(self):
            fmt = "FixedLenCell.Header(circ_id={}, cmd={}, link_version={})"
            return fmt.format(self.circ_id, self.cmd, self.link_version)

        def __eq__(self, other):
            if type(other) is type(self):
                return self.__dict__ == other.__dict__
            return False


HTYPE_LEN = 2
HLEN_LEN  = 2


class Create2Cell(FixedLenCell):
    '''.. note:: tor-spec, Section 5.1'''

    def __init__(self, header, htype=None, hlen=None, hdata=None):
        '''
        :param :class:`~oppy.cell.fixedlen.FixedLenCell.Header` header:
            initialized header to use with this cell
        :param int htype: Handshake type in use
        :param int hlen: Length of the handshake data
        :param str hdata: Actual handshake data to use (onion skin)
        '''
        self.header = header
        self.htype = htype
        self.hlen = hlen
        self.hdata = hdata

    @staticmethod
    def make(circ_id, htype=DEF.NTOR_HTYPE, hlen=DEF.NTOR_HLEN, hdata='',
             link_version=3):
        '''Build and return a Create2 cell, using default values where
        possible.

        Automatically create and use an appropriate FixedLenCell.Header.

        .. note: oppy only supports the NTor handshake, so *make()* will
            currently reject any *htype*'s or *hlen*'s that are not
            recognized as used in the NTor handshake.

        :param int circ_id: Circuit ID to use for this cell
        :param int hlen: Length of **hdata** segment
        :param str hdata: Actual handshake data to use (an *onion skin*)
        :param int link_version: Link Protocol version in use
        :returns: :class:`~oppy.cell.fixedlen.Create2Cell`
        '''
        if htype != DEF.NTOR_HTYPE:
            msg = 'htype was {}, but we currently only can do '
            msg += '{} (NTor)'
            raise BadPayloadData(msg.format(htype, DEF.NTOR_HTYPE))

        if hlen != DEF.NTOR_HLEN:
            msg = 'htype was NTor but hlen was {}, expected {}.'
            raise BadPayloadData(msg.format(hlen, DEF.NTOR_HLEN))

        if hlen != len(hdata):
            msg = 'hlen was {}, but len(hdata) was {}.'
            raise BadPayloadData(msg.format(hlen, len(hdata)))

        h = FixedLenCell.Header(circ_id=circ_id,
                                cmd=DEF.CREATE2_CMD,
                                link_version=link_version)

        return Create2Cell(h, htype=htype, hlen=hlen, hdata=hdata)

    def getBytes(self, trimmed=False):
        '''Construct and return the byte string represented by this cell.

        :param bool trimmed: If **True**, return just the cell bytes with no
            padding.  Otherwise, pad cell bytes out to fixed-length size
            according to Link Protocol version in use.
        :returns: **str** formatted byte string represented by this cell
        '''
        ret = self.header.getBytes()
        ret += struct.pack('!H', self.htype) + struct.pack('!H', self.hlen)
        ret += self.hdata
        if trimmed is True:
            return ret
        else:
            return FixedLenCell.padCellBytes(ret, self.header.link_version)

    def _parsePayload(self, data):
        '''Parse the string *data* and extract cell fields.

        Set this cell's attributes from extracted values.

        :param str data: string to parse
        '''
        start, end = self.payloadRange()
        offset = start

        if end - start < HTYPE_LEN + HLEN_LEN:
            msg = "Create2Cell payload was not enough bytes to construct "
            msg += "a valid Create2Cell."
            raise BadPayloadData(msg)

        self.htype = struct.unpack('!H', data[offset:offset + HTYPE_LEN])[0]

        if self.htype != DEF.NTOR_HTYPE:
            msg = "Create2 got htype: {}, but oppy only supports ntor: {}."
            raise BadPayloadData(msg.format(self.htype, DEF.NTOR_HTYPE))

        offset += HTYPE_LEN

        self.hlen = struct.unpack('!H', data[offset:offset + HLEN_LEN])[0]

        if self.hlen != DEF.NTOR_HLEN:
            msg = "Create2 got hlen: {}, but oppy only supports ntor hlen: {}."
            raise BadPayloadData(msg.format(self.hlen, DEF.NTOR_HLEN))

        offset += HLEN_LEN

        try:
            self.hdata = data[offset:offset + self.hlen]
        except IndexError:
            msg = "Create2 hlen was specified to be {} bytes, but actual "
            msg += "hdata was {} bytes."
            raise BadPayloadData(msg.format(self.hlen, len(data) - offset))

    def __repr__(self):
        fmt = '{}, htype={}, hlen={}, hdata={}'
        fmt = 'Create2Cell({})'.format(fmt)
        return fmt.format(repr(self.header), repr(self.htype),
                          repr(self.hlen), repr(self.hdata))


class Created2Cell(FixedLenCell):
    '''.. note:: tor-spec, Section 5.1'''

    def __init__(self, header, hlen=None, hdata=None):
        '''
        :param :class:`~oppy.cell.fixedlen.FixedLenCell.Header` header:
            Initialized header to use in this cell.
        :param int hlen: Length of this cell's hdata field
        :param str hdata: Actual handshake data (*onion skin*)
        '''
        self.header = header
        self.hlen = hlen
        self.hdata = hdata

    def getBytes(self, trimmed=False):
        '''Construct and return the byte string represented by this cell.

        :param bool trimmed: If **True**, return just the bytes without
            padding. Otherwise, pad length out to fixed-length cell size
            according to Link Protocol version in use.
        :returns: **str** raw byte string this cell represents.
        '''
        ret = self.header.getBytes()
        ret += struct.pack('!H', self.hlen)
        ret += self.hdata
        if trimmed is True:
            return ret
        else:
            return FixedLenCell.padCellBytes(ret, self.header.link_version)

    @staticmethod
    def make(circ_id, hlen=DEF.NTOR_HLEN, hdata='', link_version=3):
        '''Build and return a Created2 cell, using default values where
        possible.

        Automatically create and use an appropriate FixedLenCell.Header.

        .. note: oppy only supports the NTor handshake, so *make()* will
            currently reject any *htype*'s or *hlen*'s that are not
            recognized as used in the NTor handshake.

        :param int circ_id: Circuit ID to use for this cell
        :param int hlen: Length of **hdata** segment
        :param str hdata: Actual handshake data to use (an *onion skin*)
        :param int link_version: Link Protocol version in use
        :returns: :class:`~oppy.cell.fixedlen.Created2Cell`
        '''
        if hlen != DEF.NTOR_HLEN:
            msg = 'hlen was {}, expected {}.'
            raise BadPayloadData(msg.format(hlen, DEF.NTOR_HLEN))

        if hlen != len(hdata):
            msg = 'hlen was {}, but len(hdata) was {}.'
            raise BadPayloadData(msg.format(hlen, len(hdata)))

        h = FixedLenCell.Header(circ_id=circ_id,
                                cmd=DEF.CREATED2_CMD,
                                link_version=link_version)

        return Created2Cell(h, hlen=hlen, hdata=hdata)

    def _parsePayload(self, data):
        '''Parse the string *data* and extract cell fields.

        Set the attributes of this cell.

        :param str data: string to parse
        '''
        start, _ = self.payloadRange()
        offset = start

        self.hlen = struct.unpack('!H', data[offset:offset + HLEN_LEN])[0]
        offset += HLEN_LEN

        self.hdata = data[offset:offset + self.hlen]

    def __repr__(self):
        fmt = '{}, hlen={}, hdata={}'
        fmt = 'Created2Cell({})'.format(fmt)
        return fmt.format(repr(self.header), repr(self.hlen),
                          repr(self.hdata))


class CreatedFastCell(FixedLenCell):
    '''.. note:: Not Implemented.'''
    def __init__(self, header):
        raise NotImplementedError("Can't make CreatedFastCell yet.")


class CreatedCell(FixedLenCell):
    '''.. note:: Not Implemented.'''
    def __init__(self, header):
        raise NotImplementedError("Can't make CreatedCell yet.")


class CreateFastCell(FixedLenCell):
    '''.. note:: Not Implemented.'''
    def __init__(self, header):
        raise NotImplementedError("Can't make CreateFastCell yet.")


class CreateCell(FixedLenCell):
    '''.. note:: Not Implemented.'''
    def __init__(self, header):
        raise NotImplementedError("Can't make CreateCell yet.")


REASON_LEN = 1


class DestroyCell(FixedLenCell):
    '''.. note:: tor-spec, Section 5.4'''

    def __init__(self, header, reason=None):
        '''
        :param :class:`~oppy.cell.fixedlen.FixedLenCell.Header` header:
            Initialized header to use in this cell
        :param int reason: Reason this DestroyCell was being sent.
        '''
        self.header = header
        self.reason = reason

    # DESTROY_NONE should always be sent forward to avoid leaking version
    @staticmethod
    def make(circ_id, reason=DEF.DESTROY_NONE, link_version=3):
        '''Build and return a Destroy cell, using default values where
        possible.

        Automatically create and use an appropriate FixedLenCell.Header.

        .. warning: reason 0 (DESTROY_NONE in oppy.cell.definitions)
            should always be sent forward to avoid leaking version
            information.

        :param int circ_id: Circuit ID to use for this cell
        :param int reason: Reason this DESTROY cell is being sent
        :param int link_version: Link Protocol version in use
        :returns: :class:`~oppy.cell.fixedlen.DestroyCell`
        '''
        h = FixedLenCell.Header(circ_id=circ_id,
                                cmd=DEF.DESTROY_CMD,
                                link_version=link_version)

        if reason not in DEF.DESTROY_TRUNCATE_REASONS:
            msg = 'Unrecognized DESTROY reason: {}'.format(reason)
            raise BadPayloadData(msg)

        return DestroyCell(h, reason=reason)

    def getBytes(self, trimmed=False):
        '''Construct and return the byte string represented by this cell.

        :param bool trimmed: If **True**, return just the bytes without
            padding. Otherwise, pad length out to fixed-length cell size
            according to Link Protocol version in use.
        :returns: **str** raw byte string this cell represents
        '''
        ret = self.header.getBytes()
        ret += struct.pack('!B', self.reason)
        if trimmed is True:
            return ret
        else:
            return FixedLenCell.padCellBytes(ret, self.header.link_version)

    def _parsePayload(self, data):
        '''Parse the string *data* and extract cell fields.

        Set this cell's attributes.

        :param str data: string to parse
        '''
        start, _ = self.payloadRange()
        self.reason = struct.unpack('!B', data[start:start + REASON_LEN])[0]
        if self.reason not in DEF.DESTROY_TRUNCATE_REASONS:
            msg = 'Unrecognized DESTROY reason: {}'.format(self.reason)
            raise BadPayloadData(msg)

    def __repr__(self):
        fmt = '{}, reason={}'
        fmt = 'DestroyCell({})'.format(fmt)
        return fmt.format(repr(self.header), repr(self.reason))


class EncryptedCell(FixedLenCell):
    '''
    .. note::
        EncryptedCell is not a defined cell type in tor-spec, but
        we use it as a convenient way to represent RELAY cells or
        RELAY_EARLY cells that have either been encrypted by oppy or
        received from the network and have not been decrypted yet.
    '''

    def __init__(self, header, enc_payload=None):
        '''
        :param :class:`~oppy.cell.fixedlen.FixedLenCell.Header` header:
            header to use with this cell
        :param str enc_payload: encrypted payload for use with this cell
        '''
        self.header = header
        self.enc_payload = enc_payload

    @staticmethod
    def make(circ_id, payload, link_version=3, early=False):
        '''Build and return a Destroy cell, using default values where
        possible.

        Automatically create and use an appropriate FixedLenCell.Header. The
        *early* parameter specifies whether we should send a RELAY cell or
        a RELAY_EARLY cell.

        .. warning::

            RELAY_EARLY cells should always be used during circuit creation
            to avoid certain classes of attacks. That is, whenever oppy
            sends a relay EXTEND2 cell, it would be sent as a RELAY_EARLY
            cell instead of a RELAY cell.

            Reference: tor-spec, Section 5.6

        .. note: *payload* field should be fully padded and equal to
            maximum relay cell payload length (498).

        :param int circ_id: Circuit ID to use for this cell
        :param str payload: Payload bytes to use in this cell
        :param int link_version: Link Protocol version in use
        :param bool early: Dictate whether or not to use a RELAY_EARLY cell
        :returns: :class:`~oppy.cell.fixedlen.EncryptedCell`
        '''
        if len(payload) != DEF.MAX_PAYLOAD_LEN:
            msg = 'EncryptedCell enc_payload should be padding to length {}; '
            msg += 'found enc_payload length {} instead.'
            msg = msg.format(DEF.FIXED_LEN_V3_LEN, len(payload))
            raise BadPayloadData(msg)

        cmd = DEF.RELAY_EARLY_CMD if early is True else DEF.RELAY_CMD

        h = FixedLenCell.Header(circ_id=circ_id, cmd=cmd,
                                link_version=link_version)

        return EncryptedCell(h, enc_payload=payload)

    def getBytes(self, trimmed=False):
        '''Construct and return the byte string represented by this cell.

        :param bool trimmed: ignored, encrypted cell's don't know anything
            about their payload or its length
        :returns: **str** raw byte string this cell represents
        '''
        return self.header.getBytes() + self.enc_payload

    def _parsePayload(self, data):
        '''Parse the string *data* and extract cell fields.

        .. note::

            EncryptedCell does not try to interpret the payload,
            assuming that it is encrypted and unreadable and will be
            decrypted and parsed somewhere else.

        :param str data: string to parse
        '''
        start, end = self.payloadRange()
        self.enc_payload = data[start:end]

    def __repr__(self):
        fmt = "EncryptedCell({}, enc_payload={})"
        return fmt.format(repr(self.header), repr(self.enc_payload))


TIMESTAMP_LEN     = 4
NUM_ADDRESSES_LEN = 1


class NetInfoCell(FixedLenCell):
    '''.. note:: tor-spec.txt, Section 4.5'''

    def __init__(self, header, timestamp=None, other_or_address=None,
                 num_addresses=None, this_or_addresses=None):
        '''
        .. note: Addresses here are represented as type/length/value
            structures, defined in :class:`~oppy.cell.util.TLVTriple`.

            Reference: tor-spec.txt, Section 6.4

        :param :class:`~oppy.cell.fixedlen.FixedLenCell.Header` header:
            header to use with this cell
        :param str timestamp: Time this NetInfoCell was created. Big-endian
            unsigned integer of seconds since the Unix epoch (in packed
            byte format).
        :param :class:`~oppy.cell.util.TLVTriple` other_or_address: Remote
            address associated with this NetInfoCell. If we are the
            initiator of this cell, this is the relay's address that we're
            communicating with. If we are the recipient, this is our public
            IP address.
        :param int num_addresses: the number of this_or_addresses included
            in this NetInfoCell.
        :param list, `~oppy.cell.util.TLVTriple` this_or_addresses: List of
            originating public IP addresses of this NetInfoCell.
        '''
        self.header = header
        self.timestamp = timestamp
        self.other_or_address = other_or_address
        self.num_addresses = num_addresses
        self.this_or_addresses = this_or_addresses

    @staticmethod
    def make(circ_id, other_or_address, this_or_addresses, timestamp=None,
             link_version=3):
        '''Build and return a Destroy cell, using default values where
        possible.

        Automatically create and use an appropriate FixedLenCell.Header.

        :param int circ_id: Circuit ID to use for this cell
        :param str timestamp: Time this `NetInfoCell` was created. Big-endian
            unsigned integer of seconds since the Unix epoch (packed
            format).
        :param oppy.cell.util.TLVTriple other_or_address: Public IP
            address of the recipient of this NetInfoCell.
        :param list, oppy.cell.util.TLVTriple this_or_addresses: List
            of the public IP address(es) of the originator of this
            NetInfoCell.
        :returns: :class:`~oppy.cell.fixedlen.NetInfoCell`
        '''
        h = FixedLenCell.Header(circ_id=circ_id,
                                cmd=DEF.NETINFO_CMD,
                                link_version=link_version)

        if timestamp is None:
            timestamp = struct.pack('!I', int(time.time()))

        return NetInfoCell(h, timestamp=timestamp,
                           other_or_address=other_or_address,
                           num_addresses=len(this_or_addresses),
                           this_or_addresses=this_or_addresses)

    def getBytes(self, trimmed=False):
        '''Construct and return the byte string represented by this cell.

        :param bool trimmed: Whether or not we should pad this cell's bytes.
            If **True**, pad based on Link Protocol version in use.
        :returns: **str** raw bytes this cell represents
        '''
        ret = self.header.getBytes()
        ret += self.timestamp
        ret += self.other_or_address.getBytes()
        ret += struct.pack('!B', self.num_addresses)

        for TLVaddr in self.this_or_addresses:
            ret += TLVaddr.getBytes()

        if trimmed is True:
            return ret
        else:
            return FixedLenCell.padCellBytes(ret, self.header.link_version)

    def _parsePayload(self, data):
        '''Parse the string data and extract cell fields.

        :param str data: string to parse
        '''
        start, _ = self.payloadRange()
        offset = start

        self.timestamp = data[offset:offset + TIMESTAMP_LEN]
        offset += TIMESTAMP_LEN

        self.other_or_address = TLVTriple.parse(data, offset)
        offset += len(self.other_or_address)

        self.num_addresses = data[offset:offset + NUM_ADDRESSES_LEN]
        self.num_addresses = struct.unpack('!B', self.num_addresses)[0]
        offset += NUM_ADDRESSES_LEN

        self.this_or_addresses = []
        for i in xrange(self.num_addresses):
            t = TLVTriple.parse(data, offset)
            self.this_or_addresses.append(t)
            offset += len(t)

    def __repr__(self):
        fmt = '{}, timestamp={}, other_or_address={}, '
        fmt += 'num_addresses={}, this_or_addresses={}'
        fmt = 'NetInfoCell({})'.format(fmt)
        return fmt.format(repr(self.header), repr(self.timestamp),
                          repr(self.other_or_address),
                          repr(self.num_addresses),
                          repr(self.this_or_addresses))


class PaddingCell(FixedLenCell):
    '''.. note:: tor-spec, Section 3, 7.2.

    .. note:: Padding has no cell payload fields so, we just use inherited
        fields.

    '''
    pass
