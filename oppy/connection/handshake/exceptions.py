# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information


class BadHandshakeState(Exception):
    pass


class HandshakeFailed(Exception):
    pass


class ReceivedDestroyCell(Exception):
    pass


class UnexpectedCell(Exception):
    pass
