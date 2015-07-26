# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

import base64
import hashlib
import itertools


def decodeMicrodescriptorIdentifier(microdescriptor):
    ident = microdescriptor.identifier
    short = 4-len(ident)%4
    if short:
        ident += '='*short
    return base64.b64decode(ident).rstrip('=')


def signingKeyToSHA1(signing_key):
    '''Return the SHA-1 digest of *signing_key*.

    :param str signing_key: a relay's signing key
    :returns: **str** the SHA-1 digest of this signing_key
    '''
    m = hashlib.sha1()
    m.update(base64.b64decode(''.join(signing_key.split('\n')[1:4])))
    return m.digest()


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
