# Copyright 2014, 2015, Nik Kinkel and David Johnston
# See LICENSE for licensing information

class NotEnoughBytes(Exception):
    pass


class UnknownCellCommand(Exception):
    pass


class BadCellPayloadLength(Exception):
    pass


class BadPayloadData(Exception):
    pass


class BadLinkSpecifier(Exception):
    pass


class BadCellHeader(Exception):
    pass


class BadRelayCellHeader(Exception):
    pass
