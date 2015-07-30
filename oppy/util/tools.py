# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

import base64
import itertools


def decodeMicrodescriptorIdentifier(microdescriptor):
    ident = microdescriptor.identifier
    short = 4-len(ident)%4
    if short:
        ident += '='*short
    return base64.b64decode(ident).rstrip('=')


def enum(**enums):
    return type('Enum', (), enums)


# TODO: fix docs
def shutdown(circuit_manager):
    '''Destroy all connections, circuits, and streams.

    Called right before a shutdown event (e.g. CTRL-C).
    '''
    circuit_manager.destroyAllCircuits()


def ctr(upper):
    """Return a generator for a rollover counter.

    :param int upper: Upper bound of counter.
    """
    return (i for _ in itertools.count() for i in range(1, upper))
