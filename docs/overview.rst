Overview
--------

oppy is an Onion Proxy written in Python, implementing the client
functionality of the Tor protocol. Right now oppy is just a prototype, and
it does not fully implement the Tor protocol due to a number of
:ref:`simplifications <simplifications-label>`.

oppy uses Twisted for asynchronous networking, Stem for parsing and
representing network status documents and relay descriptors, and PyCrypto
and PyOpenSSL operations.

In general, oppy can be used the same way as a normal tor process. See
:ref:`usage <usage-label>` for more information.

This documentation, like the rest of oppy, is still a work in progress :)

