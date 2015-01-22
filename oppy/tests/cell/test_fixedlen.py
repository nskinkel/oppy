import struct
import unittest

from oppy.cell.cell import Cell
from oppy.cell.exceptions import (
    BadPayloadData,
    NotEnoughBytes,
)
from oppy.cell.fixedlen import (
    FixedLenCell,
    Create2Cell,
)

CIRC_ID = 1


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


class Create2CellTests(unittest.TestCase):

    # test that we can correctly parse a create2 cell from a byte string
    def test_parse(self):
        create2 = Cell.parse(create2_bytes_good_padded)
        assert isinstance(create2, Create2Cell)
        self.assertEqual(create2.header.circ_id, CIRC_ID)
        self.assertEqual(create2.header.cmd, CREATE2_CMD)
        self.assertEqual(create2.htype, CREATE2_NTOR_HTYPE)
        self.assertEqual(create2.hlen, CREATE2_NTOR_HLEN)
        self.assertEqual(create2.hdata, CREATE2_NTOR_HDATA_DUMMY)

    # test that we detect bad input when parsing
    # bad input for a create2 is an invalid htype or hlen.
    # we don't know what hdata should look like so we can't check the
    # content, and if hdata is too short it will get caught by
    # NotEnoughBytes
    def test_parse_bad_input(self):
        create2_bad_htype = struct.pack(
            "!HBHH{}s".format(CREATE2_NTOR_HLEN),
            CIRC_ID, CREATE2_CMD,
            # ntor should be 2
            1, CREATE2_NTOR_HLEN, CREATE2_NTOR_HDATA_DUMMY,
        )
        create2_bad_htype = FixedLenCell.padCellBytes(create2_bad_htype)

        self.assertRaises(BadPayloadData,
                          Cell.parse,
                          create2_bad_htype)

        create2_bad_hlen = struct.pack(
            "!HBHH{}s".format(CREATE2_NTOR_HLEN),
            CIRC_ID, CREATE2_CMD,
            # hlen should be 84 for ntor
            CREATE2_NTOR_HTYPE, 83, CREATE2_NTOR_HDATA_DUMMY,
        )
        create2_bad_hlen = FixedLenCell.padCellBytes(create2_bad_hlen)

        self.assertRaises(BadPayloadData,
                          Cell.parse,
                          create2_bad_hlen)

    # test that we can correctly get the byte string create2 represents
    def test_getBytes(self):
        create2 = Cell.parse(create2_bytes_good_padded)
        self.assertEqual(create2_bytes_good_padded, create2.getBytes())

    # test we can get just the bytes with no padding
    def test_getBytes_trimmed(self):
        create2 = Cell.parse(create2_bytes_good_padded)
        self.assertEqual(len(create2.getBytes(trimmed=True)),
                         2 + 1 + 2 + 2 + 84)

    # test we can build a create2 using the make helper
    def test_make_good_input(self):
        create2 = Create2Cell.make(
            CIRC_ID,
            htype=CREATE2_NTOR_HTYPE,
            hlen=CREATE2_NTOR_HLEN,
            hdata=CREATE2_NTOR_HDATA_DUMMY,
        )
        assert isinstance(create2, Create2Cell)
        self.assertEqual(create2.getBytes(), create2_bytes_good_padded)

    # test that make catches a bad htype
    def test_make_bad_htype(self):
        self.assertRaises(BadPayloadData,
                          Create2Cell.make,
                          CIRC_ID,
                          # ntor should be htype=2
                          1,
                          CREATE2_NTOR_HLEN,
                          CREATE2_NTOR_HDATA_DUMMY)

        self.assertRaises(BadPayloadData,
                          Create2Cell.make,
                          CIRC_ID,
                          str(CREATE2_NTOR_HTYPE),
                          CREATE2_NTOR_HLEN,
                          CREATE2_NTOR_HDATA_DUMMY)

    # test that make catches a bad hlen
    def test_make_bad_hlen(self):
        self.assertRaises(BadPayloadData,
                          Create2Cell.make,
                          CIRC_ID,
                          CREATE2_NTOR_HTYPE,
                          # ntor hlen should be 84
                          83,
                          CREATE2_NTOR_HDATA_DUMMY)

    # test that make catches bad (too short) hdata
    def test_make_bad_hdata(self):
        # should fail when len(hdata) != hlen
        self.assertRaises(BadPayloadData,
                          Create2Cell.make,
                          CIRC_ID,
                          CREATE2_NTOR_HTYPE,
                          CREATE2_NTOR_HLEN,
                          "\x00")

    # test that make constructs a good header
    def test_make_header(self):
        create2 = Create2Cell.make(CIRC_ID,
                                   CREATE2_NTOR_HTYPE,
                                   CREATE2_NTOR_HLEN,
                                   CREATE2_NTOR_HDATA_DUMMY)
        self.assertEqual(create2.header.circ_id, CIRC_ID)
        self.assertEqual(create2.header.cmd, CREATE2_CMD)

    # test that our len is correct with both make and parse
    def test_len(self):
        create2 = Create2Cell.make(CIRC_ID,
                                   CREATE2_NTOR_HTYPE,
                                   CREATE2_NTOR_HLEN,
                                   CREATE2_NTOR_HDATA_DUMMY)
        create2_2 = Cell.parse(create2_bytes_good_padded)
        self.assertEqual(len(create2), len(create2_2))
        self.assertEqual(len(create2), 512)

    # test that we fail if passed too few bytes when parsing
    def test_too_few_bytes(self):
        create2_too_short1 = create2_bytes_good
        create2_too_short2 = create2_bytes_good_padded[1:]

        self.assertRaises(NotEnoughBytes,
                          Cell.parse,
                          create2_too_short1)

        self.assertRaises(NotEnoughBytes,
                          Cell.parse,
                          create2_too_short2)

    # test that repr can be used to create a new object
    def test_repr(self):
        create2 = Cell.parse(create2_bytes_good_padded)
        create2_r = eval(repr(create2))

        self.assertEqual(create2.getBytes(), create2_r.getBytes())
        self.assertEqual(create2.htype, create2_r.htype)
        self.assertEqual(create2.hlen, create2_r.hlen)
        self.assertEqual(create2.hdata, create2_r.hdata)
        self.assertEqual(create2.header.circ_id, create2_r.header.circ_id)
        self.assertEqual(create2.header.cmd, create2_r.header.cmd)
        self.assertEqual(len(create2), len(create2_r))
