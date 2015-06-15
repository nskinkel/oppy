import struct
import unittest

from collections import OrderedDict

from oppy.cell.fixedlen import (
    FixedLenCell,
    Create2Cell,
    Created2Cell,
    CreatedFastCell,
    CreatedCell,
    CreateFastCell,
    CreateCell,
    DestroyCell,
    EncryptedCell,
    NetInfoCell,
    PaddingCell,
)
from oppy.cell.util import TLVTriple
from oppy.tests.integration.cell.cellbase import FixedLenTestBase


CIRC_ID = 1

# Unit tests and constants for Create2Cell

CREATE2_CMD = 10
CREATE2_NTOR_HTYPE = 2
CREATE2_NTOR_HLEN = 84
CREATE2_NTOR_HDATA_DUMMY = "\x00" * CREATE2_NTOR_HLEN

create2_bytes_good = struct.pack(
    "!HBHH{}s".format(CREATE2_NTOR_HLEN),
    CIRC_ID, CREATE2_CMD,
    CREATE2_NTOR_HTYPE, CREATE2_NTOR_HLEN, CREATE2_NTOR_HDATA_DUMMY,
)
create2_bytes_good_padded = FixedLenCell.padCellBytes(create2_bytes_good)
assert len(create2_bytes_good_padded) == 512

create2_parse_bad_htype = struct.pack(
    "!HBHH{}s".format(CREATE2_NTOR_HLEN),
    CIRC_ID, CREATE2_CMD,
    # ntor should be 2
    1, CREATE2_NTOR_HLEN, CREATE2_NTOR_HDATA_DUMMY,
)
create2_parse_bad_htype = FixedLenCell.padCellBytes(create2_parse_bad_htype)
assert len(create2_parse_bad_htype) == 512

create2_parse_bad_hlen = struct.pack(
    "!HBHH{}s".format(CREATE2_NTOR_HLEN),
    CIRC_ID, CREATE2_CMD,
    # hlen should be 84 for ntor
    CREATE2_NTOR_HTYPE, 83, CREATE2_NTOR_HDATA_DUMMY,
)
create2_parse_bad_hlen = FixedLenCell.padCellBytes(create2_parse_bad_hlen)
assert len(create2_parse_bad_hlen) == 512

# htype should be 2 for ntor
create2_make_bad_htype = (CIRC_ID, 1, CREATE2_NTOR_HLEN,
                          CREATE2_NTOR_HDATA_DUMMY)

# htype should be int not str
create2_make_bad_htype_2 = (CIRC_ID, str(CREATE2_NTOR_HTYPE),
                            CREATE2_NTOR_HLEN,
                            CREATE2_NTOR_HDATA_DUMMY)

# hlen should be 84 for ntor
create2_make_bad_hlen = (CIRC_ID, CREATE2_NTOR_HTYPE, 83,
                         CREATE2_NTOR_HDATA_DUMMY)

# len(hdata) == hlen must be true
create2_make_bad_hdata = (CIRC_ID, CREATE2_NTOR_HTYPE, CREATE2_NTOR_HLEN,
                          "\x00")


class Create2CellTests(FixedLenTestBase, unittest.TestCase):

    # NOTE: Twisted unfortunately does not support `setUpClass()`, so we
    #       do actually need to call this before every test
    def setUp(self):
        self.cell_constants = {
            'cell-bytes-good': create2_bytes_good_padded,
            'cell-type': Create2Cell,
            'cell-bytes-good-nopadding': create2_bytes_good,
        }

        self.cell_header = OrderedDict()
        self.cell_header['circ_id'] = CIRC_ID
        self.cell_header['cmd'] = CREATE2_CMD
        self.cell_header['link_version'] = 3

        self.cell_attributes = OrderedDict()
        self.cell_attributes['htype'] = CREATE2_NTOR_HTYPE
        self.cell_attributes['hlen'] = CREATE2_NTOR_HLEN
        self.cell_attributes['hdata'] = CREATE2_NTOR_HDATA_DUMMY

        self.bad_parse_inputs = (create2_parse_bad_htype,
                                 create2_parse_bad_hlen)

        self.bad_make_inputs = (create2_make_bad_htype,
                                create2_make_bad_htype_2,
                                create2_make_bad_hlen,
                                create2_make_bad_hdata)

        self.encrypted = False


# Unit tests and constants for Created2Cell
# we can reuse most of the values from Create2Cell for some constants

CREATED2_CMD = 11

created2_bytes_good = struct.pack(
    "!HBH{}s".format(CREATE2_NTOR_HLEN),
    CIRC_ID, CREATED2_CMD,
    CREATE2_NTOR_HLEN, CREATE2_NTOR_HDATA_DUMMY,
)
created2_bytes_good_padded = FixedLenCell.padCellBytes(created2_bytes_good)
assert len(created2_bytes_good_padded) == 512

created2_parse_bad_hlen = struct.pack(
    "!HBH{}s".format(CREATE2_NTOR_HLEN),
    CIRC_ID, CREATE2_CMD,
    # hlen should be 84 for ntor
    83, CREATE2_NTOR_HDATA_DUMMY,
)
created2_parse_bad_hlen = FixedLenCell.padCellBytes(created2_parse_bad_hlen)
assert len(created2_parse_bad_hlen) == 512

# hlen should be 84 for ntor
created2_make_bad_hlen = (CIRC_ID, 83, CREATE2_NTOR_HDATA_DUMMY)

# len(hdata) == hlen must be true
created2_make_bad_hdata = (CIRC_ID, CREATE2_NTOR_HLEN, "\x00")


class Created2CellTests(FixedLenTestBase, unittest.TestCase):

    def setUp(self):
        self.cell_constants = {
            'cell-bytes-good': created2_bytes_good_padded,
            'cell-type': Created2Cell,
            'cell-bytes-good-nopadding': created2_bytes_good,
        }

        self.cell_header = OrderedDict()
        self.cell_header['circ_id'] = CIRC_ID
        self.cell_header['cmd'] = CREATED2_CMD
        self.cell_header['link_version'] = 3

        self.cell_attributes = OrderedDict()
        self.cell_attributes['hlen'] = CREATE2_NTOR_HLEN
        self.cell_attributes['hdata'] = CREATE2_NTOR_HDATA_DUMMY

        self.bad_parse_inputs = (created2_parse_bad_hlen,)

        self.bad_make_inputs = (created2_make_bad_hlen,
                                created2_make_bad_hdata,)

        self.encrypted = False


# for unimplemented cells, just verify they fail when we try to create them

class CreatedFastCellTests(unittest.TestCase):

    def test_init_fail(self):
        self.assertRaises(NotImplementedError, CreatedFastCell, 'dummy')


class CreatedCellTests(unittest.TestCase):

    def test_init_fail(self):
        self.assertRaises(NotImplementedError, CreatedCell, 'dummy')


class CreateFastCellTests(unittest.TestCase):

    def test_init_fail(self):
        self.assertRaises(NotImplementedError, CreateFastCell, 'dummy')


class CreateCellTests(unittest.TestCase):

    def test_init_fail(self):
        self.assertRaises(NotImplementedError, CreateCell, 'dummy')


# Unit tests and constants for DestroyCell

DESTROY_CMD = 4

destroy_bytes_good = struct.pack(
    "!HBB",
    CIRC_ID, DESTROY_CMD,
    0,
)
destroy_bytes_good_padded = FixedLenCell.padCellBytes(destroy_bytes_good)
assert len(destroy_bytes_good_padded) == 512

destroy_parse_bad_reason = struct.pack(
    "!HBB",
    CIRC_ID, DESTROY_CMD,
    # 13 is not a valid reason
    13,
)
destroy_parse_bad_reason = FixedLenCell.padCellBytes(destroy_parse_bad_reason)
assert len(destroy_parse_bad_reason) == 512

destroy_make_bad_reason = (CIRC_ID, 13)

encrypted_bytes_good = struct.pack(
    "!HBB",
    CIRC_ID, DESTROY_CMD,
    0,
)
destroy_bytes_good_padded = FixedLenCell.padCellBytes(destroy_bytes_good)
assert len(destroy_bytes_good_padded) == 512


class DestroyCellTests(FixedLenTestBase, unittest.TestCase):

    def setUp(self):
        self.cell_constants = {
            'cell-bytes-good': destroy_bytes_good_padded,
            'cell-type': DestroyCell,
            'cell-bytes-good-nopadding': destroy_bytes_good,
        }

        self.cell_header = OrderedDict()
        self.cell_header['circ_id'] = CIRC_ID
        self.cell_header['cmd'] = DESTROY_CMD
        self.cell_header['link_version'] = 3

        self.cell_attributes = OrderedDict()
        self.cell_attributes['reason'] = 0

        self.bad_parse_inputs = (destroy_parse_bad_reason,)

        self.bad_make_inputs = (destroy_make_bad_reason,)

        self.encrypted = False


# Unit tests and constants for EncryptedCell

# since the payload of an encrypted cell prior to decryption is, from oppy's
# perspective, just a black box, the only type of "bad" payload data is
# a payload passed to "make()" that is too large for a relay cell

RELAY_CMD = 3

encrypted_bytes_good = struct.pack(
    "!HB57s",
    CIRC_ID, RELAY_CMD,
    "\x00" * 509,
)
encrypted_bytes_good_padded = FixedLenCell.padCellBytes(encrypted_bytes_good)
assert len(encrypted_bytes_good_padded) == 512

encrypted_make_bad_payload_len_long = (CIRC_ID, "\x00" * 510)
encrypted_make_bad_payload_len_short = (CIRC_ID, "\x00" * 508)


class EncryptedCellTests(FixedLenTestBase, unittest.TestCase):

    def setUp(self):
        self.cell_constants = {
            'cell-bytes-good': encrypted_bytes_good_padded,
            'cell-type': EncryptedCell,
            'cell-bytes-good-nopadding': encrypted_bytes_good,
        }

        self.cell_header = OrderedDict()
        self.cell_header['circ_id'] = CIRC_ID
        self.cell_header['cmd'] = RELAY_CMD
        self.cell_header['link_version'] = 3

        self.cell_attributes = {'enc_payload': "\x00" * 509, }

        self.bad_parse_inputs = ()

        self.bad_make_inputs = (encrypted_make_bad_payload_len_long,
                                encrypted_make_bad_payload_len_short,)

        self.encrypted = True

    def test_getBytes_trimmed(self):
        # encrypted cells don't know what's in their payload, so
        # "trimmed" arg doesn't make sense for them
        pass

# NetInfoCell (IPv4 type/length/value) unittests and constant values

NETINFO_CMD = 8

# IPv4 type type/length/value
netinfo_bytes_good = struct.pack(
    '!HBIBB4sBBB4s',
    CIRC_ID, NETINFO_CMD,
    0, 4, 4, "\x7f\x00\x00\x01",  # 127.0.0.1
    1, 4, 4, "\x7f\x00\x00\x01",
)
netinfo_bytes_good_padded = FixedLenCell.padCellBytes(netinfo_bytes_good)
assert len(netinfo_bytes_good_padded) == 512

netinfo_parse_bad_num_addresses = netinfo_bytes_good_padded[:13]
netinfo_parse_bad_num_addresses += struct.pack('!B', 200)
netinfo_parse_bad_num_addresses += netinfo_bytes_good_padded[14:]
assert len(netinfo_parse_bad_num_addresses) == 512

netinfo_make_bad_num_addresses = (CIRC_ID, TLVTriple(u'127.0.0.1'),
                                  [TLVTriple(u'127.0.0.1') for i in xrange(50)])


class NetInfoCellIPv4Tests(FixedLenTestBase, unittest.TestCase):

    def setUp(self):
        self.cell_constants = {
            'cell-bytes-good': netinfo_bytes_good_padded,
            'cell-type': NetInfoCell,
            'cell-bytes-good-nopadding': netinfo_bytes_good,
        }

        self.cell_header = OrderedDict()
        self.cell_header['circ_id'] = CIRC_ID
        self.cell_header['cmd'] = NETINFO_CMD
        self.cell_header['link_version'] = 3

        self.cell_attributes = OrderedDict()
        self.cell_attributes['other_or_address'] = TLVTriple(u'127.0.0.1')
        self.cell_attributes['this_or_addresses'] = [TLVTriple(u'127.0.0.1')]
        self.cell_attributes['timestamp'] = struct.pack('!I', 0)

        self.bad_parse_inputs = (netinfo_parse_bad_num_addresses,)

        self.bad_make_inputs = (netinfo_make_bad_num_addresses,)

        self.encrypted = False


# IPv6 type type/length/value
netinfo_bytes_good_ipv6 = struct.pack(
    '!HBIBB16sBBB16s',
    CIRC_ID, NETINFO_CMD,
    0, 6, 16, "\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x02\xb3\xff\xfe\x1e\x83)",
    1, 6, 16, "\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x02\xb3\xff\xfe\x1e\x83)",
)
netinfo_bytes_good_padded_ipv6 = FixedLenCell.padCellBytes(netinfo_bytes_good_ipv6)
assert len(netinfo_bytes_good_padded_ipv6) == 512


class NetInfoCellIPv6Tests(FixedLenTestBase, unittest.TestCase):

    def setUp(self):
        self.cell_constants = {
            'cell-bytes-good': netinfo_bytes_good_padded_ipv6,
            'cell-type': NetInfoCell,
            'cell-bytes-good-nopadding': netinfo_bytes_good_ipv6,
        }

        self.cell_header = OrderedDict()
        self.cell_header['circ_id'] = CIRC_ID
        self.cell_header['cmd'] = NETINFO_CMD
        self.cell_header['link_version'] = 3

        self.cell_attributes = OrderedDict()
        self.cell_attributes['other_or_address'] = TLVTriple(u'fe80:0000:0000:0000:0202:b3ff:fe1e:8329')
        self.cell_attributes['this_or_addresses'] = [TLVTriple(u'fe80:0000:0000:0000:0202:b3ff:fe1e:8329')]
        self.cell_attributes['timestamp'] = struct.pack('!I', 0)

        self.bad_parse_inputs = ()

        self.bad_make_inputs = ()

        self.encrypted = False


# PaddingCell unittests and constant values

PADDING_CMD = 0

padding_bytes_good = struct.pack(
    '!HB509s',
    CIRC_ID, PADDING_CMD,
    "\x00" * 509,
)
padding_bytes_good_padded = padding_bytes_good
assert len(padding_bytes_good_padded) == 512


class PaddingCellTests(FixedLenTestBase, unittest.TestCase):

    def setUp(self):
        self.cell_constants = {
            'cell-bytes-good': padding_bytes_good_padded,
            'cell-type': PaddingCell,
            'cell-bytes-good-nopadding': padding_bytes_good,
        }

        self.cell_header = OrderedDict()
        self.cell_header['circ_id'] = CIRC_ID
        self.cell_header['cmd'] = PADDING_CMD
        self.cell_header['link_version'] = 3

        # padding cells don't have any attributes, and they don't really
        # have 'bad' inputs, as the payload must be ignored
        self.cell_attributes = {}
        self.bad_parse_inputs = ()
        self.bad_make_inputs = ()
        self.encrypted = False
