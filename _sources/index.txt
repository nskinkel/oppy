Welcome to oppy's documentation!
================================

oppy is an Onion Proxy (OP) written in Python, aiming to implement the OP
functionality of the Tor protocol as outlined in tor-spec. oppy does not
implement Onion Routing (OR) functionality. Any further references to "Tor" or "tor" refer to the protocol, unless otherwise noted, and do not imply
endorsement from The Tor Project organization.

oppy is `free software <https://fsf.org>`_, licensed under the "modified"
(or 3-clause) BSD license.

.. warning::

    oppy is provided in the hope it will be useful, however **oppy will NOT
    provide strong anonymity**. If you need strong anonymity, please use the
    `official Tor software <https://www.torproject.org/download/download-easy.html>`_
    from The Tor Project.

    A short, non-exhaustive list of the reasons you should not use oppy for
    anonymity purposes:

        - oppy is not well tested. It has bugs, probably lots of them, many
          probably severe.
        - oppy (probably) leaks DNS requests under some conditions.
        - oppy will leave you vulnerable to certain kinds of profiling
          attacks.
        - oppy does not safely handle cryptographic key material.

    Again, do **NOT** use oppy if you want anonymity.


Contents:
---------

.. toctree::
    :maxdepth: 1

    overview
    installation
    usage
    simplifications
    roadmap
    docs


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

