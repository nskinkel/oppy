# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

from stem import Flag

DEFAULT_ENTRY_FLAGS = [
    Flag.GUARD,
    Flag.RUNNING,
    Flag.STABLE,
    Flag.FAST,
    Flag.VALID,
]


DEFAULT_MIDDLE_FLAGS = [
    Flag.RUNNING,
    Flag.STABLE,
    Flag.FAST,
    Flag.VALID,
]


DEFAULT_EXIT_FLAGS = [
    Flag.EXIT,
    Flag.RUNNING,
    Flag.STABLE,
    Flag.FAST,
    Flag.VALID,
]
