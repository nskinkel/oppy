Installation
------------

First, clone the git repo::

    git clone https://github.com/nskinkel/oppy

oppy needs pynacl >= 0.3.0 to support the c.crypto_scalarmult() function.
The version in pypi is old and does not support this function yet, so clone
pynacl and follow the installation instructions in the repo::

    git clone https://github.com/pyca/pynacl

Then make sure you have the following packages installed (these can all be
installed using pip)::

    twisted >= 14.0
    ipaddress
    stem
    hkdf
    pycrypto
    pyopenssl

Finally, cd into the oppy directory and add oppy to your $PYTHONPATH::

    export PYTHONPATH=$PYTHONPATH:$(pwd)

oppy should be working now! From the oppy/oppy directory, run::

    ./oppy

To see the command line arguments, run::

    ./oppy -h

or see :ref:`usage <usage-label>`.

Coming soon: a *setup.py* file and better installation process!

