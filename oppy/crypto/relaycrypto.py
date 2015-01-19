# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

'''
.. topic:: Details

    RelayCrypto objects make up a circuit's *crypt_path*. They are just thin
    wrappers around AES128-CTR ciphers and running SHA-1 digests, and provide
    circuit's with forward/backward ciphers and digests.

'''
from collections import namedtuple


RelayCrypto = namedtuple("RelayCrypto", ("forward_digest",
                                         "backward_digest",
                                         "forward_cipher",
                                         "backward_cipher"))
