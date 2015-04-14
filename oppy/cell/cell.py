# Copyright 2014, 2015, Nik Kinkel and David Johnston
# See LICENSE for licensing information

import abc
import struct

import oppy.cell.definitions as DEF

from oppy.cell.exceptions import NotEnoughBytes, UnknownCellCommand


class Cell(object):
    '''An abstract base class for other kinds of cells.'''

    __metaclass__ = abc.ABCMeta
    _subclass_map = None

    def getPayload(self):
        '''Return just the payload bytes of a cell.

        For fixed-length cells, pad with null bytes to the appropriate length
        according to Link Protocol version. Primarily useful for encrypting or
        decrypting cells.

        :returns: **str** cell payload bytes
        '''
        start, _ = self.payloadRange()
        return self.getBytes()[start:]

    @abc.abstractmethod
    def payloadRange(self):
        '''Return the (start, end) indices of this cell's payload as a
        2-tuple.

        :returns: **tuple, int** (start, end) payload indices.'''
        pass

    @staticmethod
    def enoughDataForCell(data, link_version=3):
        '''Return True iff the str **data** contains enough bytes to build a
        cell.

        The command byte is checked to determine the general type of
        cell to look for. For fixed-length cells, this is enough to know
        how much data is required. For variable-length cells, additionally
        check the length bytes.

        :param str data: The raw string to check.
        :param int link_version: Link Protocol version in use. In version
            3, 512 bytes are required for a fixed-length cell. In version
            4, 514 bytes are required.
        :returns: **bool** that's **True** iff data is long enough to
            build the type of cell indicated by the command byte.
        '''
        if link_version < 4:
            fmt = "!HB"
            header_len = DEF.PAYLOAD_START_V3
            required_length = DEF.FIXED_LEN_V3_LEN
        else:
            fmt = "!IB"
            header_len = DEF.PAYLOAD_START_V4
            required_length = DEF.FIXED_LEN_V4_LEN

        fmt = "!HB" if link_version <= 3 else "!IB"
        header_len = struct.calcsize(fmt)

        if len(data) < header_len:
            return False
        _, cmd = struct.unpack(fmt, data[:header_len])
        if cmd in DEF.FIXED_LEN_CMD_IDS:
            return len(data) >= required_length
        elif cmd in DEF.VAR_LEN_CMD_IDS:
            required_len = struct.unpack('!H',
                                         data[header_len:header_len + 2])[0]
            return len(data) >= required_len
        else:
            msg = "Unknown cell cmd: {}.".format(cmd)
            raise UnknownCellCommand(msg)

    @staticmethod
    def parse(data, link_version=3, encrypted=False):
        '''Return an instance of a cell constructed from the str data.

        If encrypted is True and the type if cell is RELAY or RELAY_EARLY,
        don't try to parse the payload and just return a
        :class:`~oppy.cell.fixedlen.EncryptedCell`.
        Otherwise, instantiate and return the appropriate cell type.

        .. note:: *data* str is not modified.

        :param str data: raw bytes to parse and extract a cell from
        :param int link_version: Link Protocol version in use. For fixed-
            length cells, this parameter dictates whether we expect 512
            bytes (Link Protocol <= 3) or 514 bytes.
        :param bool encrypted: whether or not we think this cell is
            encrypted. If True and we see a RELAY or RELAY_EARLY command
            do not attempt to parse payload.

        :returns: instantiated cell type as dictated by the command byte,
            parsed and extracted from data.
        '''
        if not 1 <= link_version <= 4:
            msg = "link_version must be leq 4, but found {} instead"
            raise ValueError(msg.format(link_version))

        # Handle the case where the circuit id represented as two octets and
        # the case where it is four octets:
        fmt = "!HB" if link_version <= 3 else "!IB"
        header_len = struct.calcsize(fmt)

        if len(data) < header_len:
            raise NotEnoughBytes()
        circ_id, cmd = struct.unpack(fmt, data[:header_len])

        if cmd not in DEF.CELL_CMD_IDS:
            msg = "When parsing cell data, found an unknown cmd: {}."
            raise UnknownCellCommand(msg.format(cmd))

        cls = None
        if cmd in DEF.VAR_LEN_CMD_IDS:
            from oppy.cell.varlen import VarLenCell
            cls = VarLenCell
        # only try to create a concrete relay cell subclass if payload
        # is not encrypted
        elif encrypted is False and (cmd == DEF.RELAY_CMD or cmd == DEF.RELAY_EARLY_CMD):
            from oppy.cell.relay import RelayCell
            cls = RelayCell
        else:
            from oppy.cell.fixedlen import FixedLenCell
            cls = FixedLenCell

        # Instantiate the appropriate kind of header, variable-length or fixed-
        # length.
        h = cls.Header(circ_id=circ_id, cmd=cmd, link_version=link_version)
        return cls._parse(data, h)

    @classmethod
    def _parse(cls, data, header):
        '''Use the given cell data and (partial) cell header information to
        instantiate a cell object of the appropriate type.

        .. note:: *header.cmd* and *header.link_version* must be set by the
            caller.

        This is expected to be called only by *Cell.parse()*. *cls* is
        expected to be one of the three abstract types of cells:

            - :class:`~oppy.cell.fixedlen.FixedLenCell`
            - :class:`~oppy.cell.varlen.VarLenCell`
            - :class:`~oppy.cell.relay.RelayCell`

        This function uses attributes of the *cls* object to parse
        the given data.

        :param str data: The data to be converted into a cell instance.
        :param :class:`~oppy.cell.cell.Cell.Header` header: header
            containing some previously parsed info (may be either a
            :class:`~oppy.cell.fixedlen.FixedLenCell.Header` or
            :class:`~oppy.cell.varlen.VarLenCell.Header`).
        '''

        if not isinstance(header, cls.Header):
            raise TypeError("The given header object has the wrong type.")
        if header.cmd is None or header.link_version is None:
            raise ValueError("Fields of the given header object are invalid.")

        # Construct a cell of the appropriate concrete type.
        subclass = cls._getSubclass(header, data)
        cell = subclass(header)

        # Parse additional information from data and add it to the new cell.
        cell._parseHeader(data)
        if len(data) < len(cell):
            fmt = "Needed {} bytes to finish parsing data; only found {}."
            msg = fmt.format(len(cell), len(data))
            raise NotEnoughBytes(msg)
        cell._parsePayload(data)
        return cell

    @classmethod
    def _getSubclass(cls, header, data):
        '''Use *header* to interpret the given cell data.

        A cell type which will be appropriate for encapsulating/representing
        this cell data is then selected and returned.

        :param cls.Header header: the header in use for this cell
        :param str data: raw str to parse
        :returns: Concrete subclass of *cls*
        '''
        if cls._subclass_map is None:
            cls._initSubclassMap()
        return cls._subclass_map[header.cmd]

    @abc.abstractmethod
    def _parseHeader(self, data):
        '''Parse any remaining header information from *data*.
        '''
        pass

    @abc.abstractmethod
    def _parsePayload(self, data):
        '''Parse payload information from *data*.

        This process depends upon the header-parsing process being complete.
        '''
        pass

    def __repr__(self):
        fmt = type(self).__name__ + "(header={}, payload={})"
        return fmt.format(self.header, repr(self.payload))

    def __len__(self):
        _, end = self.payloadRange()
        return end

    def __eq__(self, other):
        if type(self) is type(other):
            return self.__dict__ == other.__dict__
        return False

    class Header(object):
        '''A dummy header type that exists only to be overridden by classes
        that inherit from :class:`~oppy.cell.cell.Cell`.'''
        def __init__(self):
            raise NotImplementedError("This is an abstract class.")
