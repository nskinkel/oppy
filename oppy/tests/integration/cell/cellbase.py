from oppy.cell.cell import Cell
from oppy.cell.exceptions import BadPayloadData

# base class for cell tests.
# a number of tests for cell methods differ only in what type of concrete
# cell is instantiated, so we can get rid of a bunch of boiler-plate test
# code with a bit of inheritance.
#
# tests for concrete types are mostly written declaratively by defining
# the byte strings the cells should operate on and the attributes cells
# should have as well as "bad" values that should raise exceptions.
#
# concrete test classes define the following fields:
#
# cell_constants (dict):
#   - 'cell-bytes-good': a valid byte string for this cell to test against
#   - 'cell-type': the type of this cell (e.g. Create2Cell)
#   - 'cell-bytes-good-nopadding': a valid byte string for this cell
#      without padding added (ignore or varlen cells)
#
# cell_header (OrderedDict):
#   - 'circ_id': circuit id for this cell
#   - 'cmd': command for this cell
#   - 'link_version': link version for this cell
#
# cell_attributes (OrderedDict):
#   - define all attributes here a cell should have using good/valid values
#     (e.g. for Create2Cell, you would define 'htype', 'hlen', and 'hdata')
#
# bad_parse_inputs (tuple):
#   - a tuple of byte strings to test against that are invalid in some way
#     each string listed here will be tested using Cell.parse, expecting to
#     raise a BadPayloadData exception
#
# bad_make_inputs (tuple):
#   - a tuple of tuples of arguments to `cell_type`.make() that should
#     raise a BadPayloadData exception (e.g. one of the arguments given
#     is an invalid value for the make() method for that cell)
#
# encrypted (bool):
#   - whether or not this cell should be parsed as if it was encrypted
#     (note that this is meaningless for VarLenCells and all FixedLenCells
#      except EncryptedCell)
#
# with those fields defined, all the following tests will be run for each
# cell using the defined values

CIRC_ID = 1


class CellTestBase(object):

    def test_parse(self):
        '''Try to parse concrete cell type from a byte string and verify
        we read the correct cell attributes.
        '''
        cell = Cell.parse(self.cell_constants['cell-bytes-good'],
                          encrypted=self.encrypted)
        assert isinstance(cell, self.cell_constants['cell-type'])
        assert cell.header.__dict__ == self.cell_header
        for key in self.cell_attributes:
            assert getattr(cell, key) == self.cell_attributes[key]
        cell2 = Cell.parse(cell.getBytes(), encrypted=self.encrypted)
        assert cell.getBytes() == cell2.getBytes()
        assert cell == cell2

    def test_parse_bad(self):
        '''Try to parse each bad_input and check that they raise
        BadPayloadData.'''
        for bad_input in self.bad_parse_inputs:
            self.assertRaises(BadPayloadData, Cell.parse, bad_input,
                              encrypted=self.encrypted)

    def test_getBytes(self):
        '''Verify that cell's 'getBytes()' method returns the correct byte
        string when cell is parsed from a string.
        '''
        cell = Cell.parse(self.cell_constants['cell-bytes-good'],
                          encrypted=self.encrypted)
        assert cell.getBytes() == self.cell_constants['cell-bytes-good']

    def test_make(self):
        '''Verify that cell-building helper method 'make' can correctly
        assemble a cell.
        '''
        cell = self.cell_constants['cell-type'].make(
                                              self.cell_header['circ_id'],
                                              *self.cell_attributes.values())
        assert isinstance(cell, self.cell_constants['cell-type'])
        assert cell.getBytes() == self.cell_constants['cell-bytes-good']
        assert cell.header.__dict__ == self.cell_header
        for key in self.cell_attributes:
            assert getattr(cell, key) == self.cell_attributes[key]

    def test_make_bad(self):
        '''Check that bad inputs to a cell's make() method raise a
        BadPayloadData exception.'''
        for bad_input in self.bad_make_inputs:
            self.assertRaises(BadPayloadData,
                              self.cell_constants['cell-type'].make,
                              *bad_input)
        
    def test_repr(self):
        '''Verify that a cell's repr can be used to create the same cell.
        '''
        from oppy.cell.fixedlen import (
            FixedLenCell,
            Create2Cell,
            Created2Cell,
            DestroyCell,
            EncryptedCell,
            NetInfoCell,
            PaddingCell,
        )
        from oppy.cell.varlen import (
            VarLenCell,
            AuthChallengeCell,
            CertsCell,
            VersionsCell,
            VPaddingCell,
        )
        from oppy.cell.util import (
            TLVTriple,
            CertsCellPayloadItem,
        )
        # XXX should realy just define eq method on cells...
        cell = Cell.parse(self.cell_constants['cell-bytes-good'],
                          encrypted=self.encrypted)
        cell2 = eval(repr(cell))
        assert cell.getBytes() == cell2.getBytes()
        assert len(cell) == len(cell2)
        assert cell == cell2


class FixedLenTestBase(CellTestBase):

    def test_getBytes_trimmed(self):
        cell = Cell.parse(self.cell_constants['cell-bytes-good'],
                          encrypted=self.encrypted)
        assert cell.getBytes(trimmed=True) == self.cell_constants['cell-bytes-good-nopadding']

    def test_len(self):
        '''Verify that len(cell) works properly.'''
        cell = Cell.parse(self.cell_constants['cell-bytes-good'],
                          encrypted=self.encrypted)
        cell_2 = self.cell_constants['cell-type'].make(
                                              self.cell_header['circ_id'],
                                              *self.cell_attributes.values())
        assert len(cell) == len(cell_2)
        assert len(cell) == len(self.cell_constants['cell-bytes-good'])
        if cell.header.link_version < 4:
            assert len(cell) == 512
        else:
            assert len(cell) == 514


class VarLenTestBase(CellTestBase):

    def test_len(self):
        '''Verify that len(cell) works properly.'''
        cell = Cell.parse(self.cell_constants['cell-bytes-good'],
                          encrypted=self.encrypted)
        cell_2 = self.cell_constants['cell-type'].make(
                                              self.cell_header['circ_id'],
                                              *self.cell_attributes.values())
        assert len(cell) == len(cell_2)
        assert len(cell) == len(self.cell_constants['cell-bytes-good'])
