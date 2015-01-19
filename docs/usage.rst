.. _usage-label:

Usage
-----

oppy aims to be a fully functional Tor client and can be used just the same
way as a regular Tor client.

oppy currently supports the following command line arguments::

    -l  --log-level     python log level, defaults to INFO
    -f  --log-file      filename to write logs to, defaults to sys.stdout
    -p  --SOCKS-port    local port for SOCKS interface to listen on
    -h  --help          print these help options

To run oppy at the DEBUG log level on port 10050, from the oppy/oppy directory
run::

$ ./oppy -l debug -p 10050

Now just configure any local application to use this SOCKS port like you
would for a regular tor process.

oppy will print some information as it gathers network status documents and
starts building circuits. After the first circuit opens up, oppy will be
listening on port 10050 for incoming SOCKS 5 connections.

You can tell any application that can use a SOCKS 5 proxy to use oppy (e.g.
SSH or Firefox) - just configure that application to use SOCKS 5 on localhost 
on the port that oppy is running on.

You can also tell the Tor Browser to use oppy instead of its own Tor process.

If you're using a web browser with oppy, browse to
`Tor check <https://check.torproject.org>`_ to verify oppy is working.

.. warning::

     You will **not** get strong anonymity by running, say, vanilla Firefox
     through a tor process and using "normal" browsing habits. See
     `a list of warnings <https://www.torproject.org/download/download#warning>`_
     for some reasons why this is not sufficient for strong anonymity.

