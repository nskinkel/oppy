import struct
import unittest

from collections import OrderedDict

from oppy.cell.varlen import (
    AuthChallengeCell,
    AuthenticateCell,
    AuthorizeCell,
    CertsCell,
    VersionsCell,
    VPaddingCell,
)
from oppy.cell.util import CertsCellPayloadItem
from oppy.tests.cell.cellbase import VarLenTestBase


CIRC_ID = 1

# Unit tests and constants for AuthChallengeCell
# only support one method right now

AUTH_CHALLENGE_CMD = 130
AUTH_CHALLENGE_CHALLENGE_DUMMY = "\x00" * 32
AUTH_CHALLENGE_NMETHODS = 1
AUTH_CHALLENGE_METHODS_DUMMY = struct.pack('!H', 1)
AUTH_CHALLENGE_LEN = 32 + 2 + 2

authchallenge_bytes_good = struct.pack(
    "!HBH32sH2s",
    CIRC_ID, AUTH_CHALLENGE_CMD, AUTH_CHALLENGE_LEN,
    AUTH_CHALLENGE_CHALLENGE_DUMMY,
    AUTH_CHALLENGE_NMETHODS, AUTH_CHALLENGE_METHODS_DUMMY,
)

# too many nmethods: only 1 is specified in tor-spec
authchallenge_parse_bad_nmethods = struct.pack(
    "!HBH32sH4s",
    CIRC_ID, AUTH_CHALLENGE_CMD, AUTH_CHALLENGE_LEN + 2,
    AUTH_CHALLENGE_CHALLENGE_DUMMY,
    AUTH_CHALLENGE_NMETHODS + 1, "\x00" * 4,
)

# methods too short for nmethods, should be len(methods) == len(nmethods) * 2
authchallenge_parse_bad_methods_short = struct.pack(
    "!HBH32sH1s",
    CIRC_ID, AUTH_CHALLENGE_CMD, AUTH_CHALLENGE_LEN - 1,
    AUTH_CHALLENGE_CHALLENGE_DUMMY,
    AUTH_CHALLENGE_NMETHODS, "\x00",
)

# methods too long for nmethods, should be len(methods) == len(nmethods) * 2
authchallenge_parse_bad_methods_long = struct.pack(
    "!HBH32sH3s",
    CIRC_ID, AUTH_CHALLENGE_CMD, AUTH_CHALLENGE_LEN + 1,
    AUTH_CHALLENGE_CHALLENGE_DUMMY,
    AUTH_CHALLENGE_NMETHODS, "\x00" * 3,
)

# invalid method 2, only recognize 1
authchallenge_parse_bad_methods_long = struct.pack(
    "!HBH32sH2s",
    CIRC_ID, AUTH_CHALLENGE_CMD, AUTH_CHALLENGE_LEN,
    AUTH_CHALLENGE_CHALLENGE_DUMMY,
    AUTH_CHALLENGE_NMETHODS, struct.pack('!H', 2),
)

# challenge must be 32 bytes
authchallenge_make_bad_challenge = (CIRC_ID, "\x00" * 31,
                                    [AUTH_CHALLENGE_METHODS_DUMMY])

# only support one auth method
authchallenge_make_bad_nmethods = (CIRC_ID, "\x00" * 31,
                                   [AUTH_CHALLENGE_METHODS_DUMMY,
                                    AUTH_CHALLENGE_METHODS_DUMMY])

# only support auth method 1
authchallenge_make_bad_methods = (CIRC_ID, "\x00" * 31,
                                  [struct.pack('!H', 2)])


class AuthChallengeCellTests(VarLenTestBase, unittest.TestCase):

    # NOTE: Twisted unfortunately does not support `setUpClass()`, so we
    #       do actually need to call this before every test
    def setUp(self):
        self.cell_constants = {
            'cell-bytes-good': authchallenge_bytes_good,
            'cell-type': AuthChallengeCell,
        }

        self.cell_header = OrderedDict()
        self.cell_header['circ_id'] = CIRC_ID
        self.cell_header['cmd'] = AUTH_CHALLENGE_CMD
        self.cell_header['payload_len'] = AUTH_CHALLENGE_LEN
        self.cell_header['link_version'] = 3

        self.cell_attributes = OrderedDict()
        self.cell_attributes['challenge'] = AUTH_CHALLENGE_CHALLENGE_DUMMY
        self.cell_attributes['methods'] = [AUTH_CHALLENGE_METHODS_DUMMY]

        self.bad_parse_inputs = (authchallenge_parse_bad_nmethods,
                                 authchallenge_parse_bad_methods_short,
                                 authchallenge_parse_bad_methods_long,)

        self.bad_make_inputs = (authchallenge_make_bad_challenge,
                                authchallenge_make_bad_nmethods,
                                authchallenge_make_bad_methods,)

        self.encrypted = False


class AuthenticateCellTests(unittest.TestCase):
    def test_init_fail(self):
        self.assertRaises(NotImplementedError, AuthenticateCell, 'dummy')


class AuthorizeCellTests(unittest.TestCase):
    def test_init_fail(self):
        self.assertRaises(NotImplementedError, AuthorizeCell, 'dummy')


# Unit tests and constants for CertsCell

CERTS_CMD = 129
CERTS_CELL_LEN = 76

# tests for certs cell with a single link key certificate
CERT_COUNT = 1
CERT_TYPE = 1
CERT_LEN = 72
CERT_BYTES = "\x00" * CERT_LEN


certs_bytes_good = struct.pack(
    '!HBHBBH72s',
    CIRC_ID, CERTS_CMD, CERTS_CELL_LEN,
    CERT_COUNT,
    CERT_TYPE, CERT_LEN, CERT_BYTES,
)

# invalid cert type
cert_parse_bad_cert_type = struct.pack(
    '!HBHBBH72s',
    CIRC_ID, CERTS_CMD, CERTS_CELL_LEN,
    CERT_COUNT,
    4, CERT_LEN, CERT_BYTES,
)

# this means we 'lie' about the length. claim a longer length in the certs
# payload length than we have space for given cell payload_len
cert_parse_bad_cert_len = struct.pack(
    '!HBHBBH74s',
    CIRC_ID, CERTS_CMD, CERTS_CELL_LEN,
    CERT_COUNT,
    CERT_TYPE, CERT_LEN + 2, CERT_BYTES + "\x00\x00",
)

# try passing in too many certs
cp = CertsCellPayloadItem(CERT_TYPE, CERT_LEN, CERT_BYTES)
certs_make_bad_cert_num = (CIRC_ID, [cp, cp, cp, cp])


# test a certs cell with just one cert
class CertsCellTests1(VarLenTestBase, unittest.TestCase):

    def setUp(self):
        self.cell_constants = {
            'cell-bytes-good': certs_bytes_good,
            'cell-type': CertsCell,
        }

        self.cell_header = OrderedDict()
        self.cell_header['circ_id'] = CIRC_ID
        self.cell_header['cmd'] = CERTS_CMD
        self.cell_header['payload_len'] = CERTS_CELL_LEN
        self.cell_header['link_version'] = 3

        self.cell_attributes = OrderedDict()
        cp = CertsCellPayloadItem(CERT_TYPE, CERT_LEN, CERT_BYTES)
        self.cell_attributes['cert_payload_items'] = [cp]

        self.bad_parse_inputs = (cert_parse_bad_cert_type,
                                 cert_parse_bad_cert_len,)

        self.bad_make_inputs = (certs_make_bad_cert_num,)

        self.encrypted = False


CERT_TYPE_2 = 2
CERTS_CELL_LEN_2 = CERTS_CELL_LEN + 1 + 2 + CERT_LEN
CERT_COUNT_2 = 2

# a byte string with 2 certs
certs_bytes_good_2 = struct.pack(
    '!HBHBBH72sBH72s',
    CIRC_ID, CERTS_CMD, CERTS_CELL_LEN_2,
    CERT_COUNT_2,
    CERT_TYPE, CERT_LEN, CERT_BYTES,
    CERT_TYPE_2, CERT_LEN, CERT_BYTES,
)


# test a certs cell with 2 types of certs in one cell
class CertsCellTests2(VarLenTestBase, unittest.TestCase):

    def setUp(self):
        self.cell_constants = {
            'cell-bytes-good': certs_bytes_good_2,
            'cell-type': CertsCell,
        }

        self.cell_header = OrderedDict()
        self.cell_header['circ_id'] = CIRC_ID
        self.cell_header['cmd'] = CERTS_CMD
        self.cell_header['payload_len'] = CERTS_CELL_LEN_2
        self.cell_header['link_version'] = 3

        self.cell_attributes = OrderedDict()
        cp = CertsCellPayloadItem(CERT_TYPE, CERT_LEN, CERT_BYTES)
        cp2 = CertsCellPayloadItem(CERT_TYPE_2, CERT_LEN, CERT_BYTES)
        self.cell_attributes['cert_payload_items'] = [cp, cp2]

        self.bad_parse_inputs = ()

        self.bad_make_inputs = ()

        self.encrypted = False


VERSIONS_CMD = 7
VERSIONS_CELL_LEN = 2
VERSION = 3

versions_bytes_good = struct.pack(
    '!HBHH',
    0, VERSIONS_CMD, VERSIONS_CELL_LEN,
    VERSION,
)

# invalid link protocol version 5
versions_parse_bad_version = struct.pack(
    '!HBHH',
    0, VERSIONS_CMD, VERSIONS_CELL_LEN,
    5,
)

# invalid link protocol version 5
versions_make_bad_version = ([5],)


class VersionsCellTests(VarLenTestBase, unittest.TestCase):

    def setUp(self):
        self.cell_constants = {
            'cell-bytes-good': versions_bytes_good,
            'cell-type': VersionsCell,
        }

        self.cell_header = OrderedDict()
        self.cell_header['circ_id'] = 0
        self.cell_header['cmd'] = VERSIONS_CMD
        self.cell_header['payload_len'] = VERSIONS_CELL_LEN
        self.cell_header['link_version'] = 3

        self.cell_attributes = OrderedDict()
        self.cell_attributes['versions'] = [3]

        self.bad_parse_inputs = (versions_parse_bad_version,)

        self.bad_make_inputs = (versions_make_bad_version,)

        self.encrypted = False

    def test_make(self):
        cell = VersionsCell.make(versions=[3])
        assert isinstance(cell, VersionsCell)
        assert cell.getBytes() == versions_bytes_good
        assert cell.header.__dict__ == self.cell_header

    def test_len(self):
        from oppy.cell.cell import Cell
        cell = Cell.parse(versions_bytes_good)
        cell_2 = VersionsCell.make(versions=[3])
        assert len(cell) == len(cell_2)
        assert len(cell) == VERSIONS_CELL_LEN + 2 + 1 + 2


VPADDING_CMD = 128
VPADDING_CELL_LEN = 15

vpadding_bytes_good = struct.pack(
    '!HBH15s',
    CIRC_ID, VPADDING_CMD, VPADDING_CELL_LEN,
    "\x00" * VPADDING_CELL_LEN
)


class VPaddingCellTests(VarLenTestBase, unittest.TestCase):

    def setUp(self):
        self.cell_constants = {
            'cell-bytes-good': vpadding_bytes_good,
            'cell-type': VPaddingCell,
        }

        self.cell_header = OrderedDict()
        self.cell_header['circ_id'] = CIRC_ID
        self.cell_header['cmd'] = VPADDING_CMD
        self.cell_header['payload_len'] = VPADDING_CELL_LEN
        self.cell_header['link_version'] = 3

        # vpadding cells don't have any attributes, and they don't really
        # have 'bad' inputs, as the payload must be ignored
        self.cell_attributes = {}
        self.bad_parse_inputs = ()
        self.bad_make_inputs = ()
        self.encrypted = False

    def test_make(self):
        cell = VPaddingCell.make(CIRC_ID, padding_len=VPADDING_CELL_LEN)
        assert isinstance(cell, VPaddingCell)
        assert cell.getBytes() == vpadding_bytes_good
        assert cell.header.__dict__ == self.cell_header

    def test_len(self):
        from oppy.cell.cell import Cell
        cell = Cell.parse(vpadding_bytes_good)
        cell_2 = VPaddingCell.make(CIRC_ID, padding_len=VPADDING_CELL_LEN)
        assert len(cell) == len(cell_2)
        assert len(cell) == VPADDING_CELL_LEN + 2 + 1 + 2
