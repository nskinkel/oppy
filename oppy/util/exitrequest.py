# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

import ipaddress
import struct


class ExitRequest(object):
    '''Represent a connection request.'''

    __slots__ = ('port', 'addr', 'host', 'is_ipv4', 'is_ipv6', 'is_host')

    def __init__(self, port, addr=None, host=None):
        '''
        :param str port: port to connect to
        :param str addr: IP address to connect to
        :param str host: hostname to connect to
        '''
        # either address or host must be set, but not both
        assert bool(addr) ^ bool(host)

        self.port = struct.unpack("!H", port)[0]
        self.addr = addr
        self.host = host
        self.is_ipv4 = False
        self.is_ipv6 = False
        self.is_host = False

        if addr:
            addr = ipaddress.ip_address(addr)
            if isinstance(addr, ipaddress.IPv4Address):
                self.is_ipv4 = True
            else:
                self.is_ipv6 = True
            self.addr = bytes(addr.exploded)
        else:
            self.is_host = True

    def __str__(self):
        # this is the format that a request should appear in in a RelayBegin
        # cell. overriding __str__ here allows us to just stick this
        # directly in a RelayBegin cell with str(request)
        if self.is_ipv4:
            ret = "{}:{}".format(self.addr, self.port)
        elif self.is_ipv6:
            ret = "[{}]:{}".format(self.addr, self.port)
        else:
            ret = "{}:{}".format(self.host, self.port)
        ret += "\x00"
        return ret
