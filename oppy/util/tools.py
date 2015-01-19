# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

import base64
import hashlib


def signingKeyToSHA1(signing_key):
    '''Return the SHA-1 digest of *signing_key*.

    :param str signing_key: a relay's signing key
    :returns: **str** the SHA-1 digest of this signing_key
    '''
    m = hashlib.sha1()
    m.update(base64.b64decode(''.join(signing_key.split('\n')[1:4])))
    return m.digest()


# a decorator to simplify building class dispatch tables
def dispatch(d, k):
    def func(f):
        d[k] = f
    return func


def enum(**enums):
    return type('Enum', (), enums)


def shutdown():
    '''Destroy all connections, circuits, and streams.

    Called right before a shutdown event (e.g. CTRL-C).
    '''
    from oppy.shared import circuit_manager
    circuit_manager.destroyAllCircuits()
