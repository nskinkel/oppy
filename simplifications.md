Simplifications and Unimplemented Functionality
===============================================

Here we aim to document the major simplifications oppy makes and OP
functionality that oppy does not yet implement. Some of the items listed here
are **required** for Tor OPs, and some just reflect the behavior tor itself has
when running as an OP.

This is a living document, subject to (possibly frequent) change. It is not
comprehensive; oppy still makes some simplifications that are not listed here.

Major user-facing simplifications
---------------------------------

    These are the major "noticeable" things that are simplified/not implented.
    These may also appear below in their appropriate section.

    - circuits and streams don't know how to recover from RelayEnd cells sent
      because of reasons other than CONNECTION_DONE. If we get a RelayEnd
      due to, say, reason EXIT_POLICY, oppy will just not be able to handle
      this request. oppy doesn't know how to try this request on a different
      circuit yet.
    - circuit build timeouts are not calculated. this means that sometimes
      circuits are slooooow to be built or may not be built at all. this also
      means that oppy sometimes gets slower circuits than it should.
    - oppy doesn't know how to tear-down a slow/broken circuit yet. If a
      circuit is just too slow to be usable or, at some point, just stops
      responding, oppy doesn't yet know that it should tear it down and
      build a new one.
    - oppy doesn't set a timeout on network status downloads, so sometimes
      these will just hang if we choose a bad V2Dir cache.

Cells
-----

    - oppy does not implement all types of cells - only (most of) the kinds
      that an OP needs.
    - RELAY_RESOLVE(D) cells are not implemented
    - oppy does not implement the "make()" helper method for all types of
      implemented cells - only those that we currently need to build (e.g.
      for backward only cells, oppy doesn't implement the helper method)

Circuits
--------

    - oppy does not rotate circuits
    - oppy does not attempt to recover from RelayEnd cells received due to
      reasons other than CONNECTION_DONE. For instance, if oppy receives a
      RelayEnd cell with reason EXIT_POLICY, oppy doesn't know how to try
      this connection on another circuit and just closes the stream.
    - oppy does not calculate circuit build timeouts
    - oppy does not tear-down slow circuits. sometimes circuits may be really
      slow or stop working properly. oppy doesn't know how to recover from this
      yet.
    - oppy does not support the TAP handshake.
    - oppy doesn't know how to build internal circuits and/or access hidden
      services.
    - oppy doesn't know how to rebuild circuits. If oppy receives a
      RelayTruncated cell, the circuit is just immediately destroyed.
    - oppy does not cannabalize circuits.
    - oppy does not take into account bandwidth usage/history when assigning
      new streams to open circuits.
    - oppy doesn't currently mark circuits as "clean" or "dirty". circuits
      are either "PENDING" (i.e. being built and currently trying to extend),
      "OPEN" (i.e. accepting new streams and forwarding traffic), or
      "BUFFERING" (waiting for a RelaySendMeCell), and that's the only real
      state information circuits have.
    - oppy does not know how to use RELAY_RESOLVE cells and, consequently,
      does not make any *resolve* circuits
    - oppy doesn't know how to build directory circuits

Connections
-----------

    - oppy only knows how to talk Link Protocol Version 3 (although
      functionality for version 4 is mostly there, at least in cells, just not
      tested yet)
    - oppy does not use the "this_or_addresses" field in a received NetInfoCell
      to verify we've connected to the correct OR address

Crypto
------

    - oppy doesn't handle clearing/wiping private keys properly (really, crypto
      should be handled in C modules)

Path Selection
--------------

    - oppy does not take bandwidth into account when choosing paths
    - oppy always uses a default set of required flags for each node position
      in a path. these flags are probably not the correct flags to be using.
    - oppy only chooses relays that support the ntor handshake.
    - oppy does not use entry guards.
    - oppy does not mark relays as *down* if they are unreachable.

Network Status Documents
------------------------

    - oppy doesn't know how to build or use directory circuits, so all
      network status document requests are just HTTP requests to V2Dir caches
      or directory authorities
    - oppy just downloads all server descriptors at once instead of splitting
      up the downloads between multiple V2Dir caches
    - oppy does not check whether or not we have the "best" server descriptor
      before downloading new descriptors. Currently, oppy just downloads all
      server descriptors everytime it grabs a fresh consensus.
    - oppy does not schedule new consensus downloads at the correct time
      interval. currently oppy just downloads new network status documents
      every hour.

SOCKS
-----

    - oppy only supports the NO_AUTH method
    - oppy does not yet implement the tor socks extensions (e.g. for the
      RESOLVE command)
    - oppy does not implement the "HTTP-Resistance" that tor does
    - oppy does not support optimistic data

Streams
-------

    - streams do not check how many cells still need to be flushed before
      sending a RelaySendMeCell. streams just send a SendMe cell as soon as
      their window reaches the SendMe threshold.

