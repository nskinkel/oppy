[![Build Status](https://travis-ci.org/nskinkel/oppy.svg?branch=master)](https://travis-ci.org/nskinkel/oppy)

[![Coverage Status](https://coveralls.io/repos/nskinkel/oppy/badge.svg?branch=master)](https://coveralls.io/r/nskinkel/oppy?branch=master)

#oppy
`oppy` is a Tor onion proxy implementation written in Python. Any further references to "Tor" or "tor"
refer to the protocol, unless otherwise noted, and do not imply endorsement
from The Tor Project organization. `oppy` is produced independently from the
Tor® anonymity software and carries no guarantee from The Tor Project about
quality, suitability or anything else.

`oppy` is [free software](https://fsf.org), distributed under the "modified"
(or 3-clause) BSD license.

To learn more about what Onion Proxies do, please see `tor-spec.txt`, the Tor
protocol specification.

For full documentation, see: [oppy-docs](https://nskinkel.github.com/oppy)


###Warning
`oppy` is provided in the hope it will be useful, however **oppy will NOT
provide strong anonymity**. `oppy` is just a prototype: it's not very well
tested yet, and it makes a number of simplifications (see: simplifications.md).

If you need strong anonymity, please use the
[official Tor software](https://www.torproject.org/download/download-easy.html)
from The Tor Project.

`oppy` is, at the moment, mainly meant for developers and hackers to play
with.


###Installation
`oppy` needs a few packages to run (see REQUIREMENTS), including a new version
of `pynacl` not yet present in pypi. So first clone the `pynacl` repo and
follow the installation instructions:

```
$ git clone https://github.com/pyca/pynacl
```

Then install the following additional packages (these are all available in
pypi):

```
twisted >= 14.0
stem
ipaddress
hkdf
pycrypto
pyopenssl
```

Now you're ready to clone this repository:

```
$ git clone https://github.com/nskinkel/oppy
```

Finally, `cd` into the `oppy` directory, add it to your $PYTHONPATH, and you're
all set!

```
$ export PYTHONPATH=$PYTHONPATH:$(pwd)
```

###Usage
`oppy` aims to be a fully functional Tor client and can be used just the
same way as a regular Tor client.

`oppy` supports the following arguments:

```
-l  --log-level     python log level, defauls to INFO
-f  --log-file      filename to write logs to, defaults to sys.stdout
-p  --SOCKS-port    local port for oppy's SOCKS interface to listen on (defaults to 10050)
-h  --help          print these options
```

To run oppy at the DEBUG log level on port 10050, from the oppy/oppy directory
run:

```
$ ./oppy -l debug -p 10050
```

`oppy` will print some information as it gathers network status documents and
starts building circuits. After the first circuit opens up, `oppy` will be
listening on port 10050 for incoming SOCKS 5 connections.

You can tell any application that can use a SOCKS 5 proxy to use `oppy` (e.g.
SSH or Firefox) - just configure that application to use SOCKS 5 on localhost
on the port that `oppy` is running on.

You can also tell the Tor Browser to use `oppy` instead of its own Tor process.

If you're using a web browser with `oppy`, browse to
[Tor check](https://check.torproject.org) to verify `oppy` is working.

####Warning:
You will **not** get strong anonymity by running, say, vanilla Firefox through
a tor process and using "normal" browsing habits. See [a list of warnings](https://www.torproject.org/download/download#warning) for some reasons why this
is not sufficient for strong anonymity.

###Bugs and Simplifications Made
A few of the major "noticeable" simplifications that directly impact regular
usage include:

- oppy doesn't know how to recover from RelayEnd cells sent because of
  reasons like EXIT_POLICY. In these cases oppy just closes the stream, so
  this can sometimes look, to the user, like oppy is just not working.
- oppy doesn't currently calculate circuit build timeouts or try to
  rebuild slow circuits (or circuits which become unresponsive). Again,
  this can look to the user like oppy has stopped working (e.g. web 
  pages may stop loading if a stream gets assigned to a slow/unresponsive
  circuit).
- oppy doesn't yet put a timeout on downloading server descriptors,
  so sometimes this will hang if oppy chooses a bad V2Dir cache.

For a more complete list of the simplifications oppy makes, see:
simplifications.md.
