# Copyright 2014, 2015, Nik Kinkel and David Johnston
# See LICENSE for licensing information

import ipaddress
import struct

import oppy.cell.definitions as DEF

from oppy.cell.exceptions import BadLinkSpecifier, BadPayloadData
from oppy.util.tools import decodeMicrodescriptorIdentifier


class LinkSpecifier(object):
    '''.. note:: tor-spec, Section 5.1.2'''

    def __init__(self, path_node, legacy=False):
        '''
        :param bool legacy: if **True**, make a legacy link specifier.
            make an IPv4 or IPv6 link specifier otherwise according to
            the relay's public IP address.
        '''
        if legacy is True:
            self.lstype = DEF.LSTYPE_LEGACY
            self.lslen = DEF.LSLEN_LEGACY
            self.lspec = decodeMicrodescriptorIdentifier(
                                                    path_node.microdescriptor)
        else:
            address = path_node.router_status_entry.address
            addr = ipaddress.ip_address(unicode(address))
            port = path_node.router_status_entry.or_port
            if isinstance(addr, ipaddress.IPv4Address):
                self.lstype = DEF.LSTYPE_IPv4
                self.lslen = DEF.LSLEN_IPv4
            else:
                self.lstype = DEF.LSTYPE_IPv6
                self.lslen = DEF.LSLEN_IPv6

            self.lspec = addr.packed + struct.pack('!H', port)

        if len(self.lspec) != self.lslen:
            raise BadLinkSpecifier()

    def getBytes(self):
        '''Build and construct the raw byte string represented by this
        link specifier.

        :returns: **str** raw byte string this link specifier represents
        '''
        ret = struct.pack('!B', self.lstype)
        ret += struct.pack('!B', self.lslen)
        ret += self.lspec
        return ret

    def __len__(self):
        # lstype and lslen fields are one byte each
        return 1 + 1 + self.lslen


TLV_ADDR_TYPE_LEN   = 1
TLV_ADDR_LEN_LEN    = 1


TLV_ERROR_TRANSIENT     = 0xF0
TLV_ERROR_NONTRANSIENT  = 0xF1


# XXX what about TTL?
class TLVTriple(object):
    '''.. note:: tor-spec, Section 6.4
    
    .. todo:: Handle the hostname type properly. TLVTriple's currently
        don't know how to deal with a hostname type. Additionally, they
        don't know how to handle a TTL or the various errors that can
        occur.
    '''
    
    def __init__(self, addr):
        '''
        :param str addr: IP address for this TLVTriple
        '''
        addr = ipaddress.ip_address(unicode(addr))
        if isinstance(addr, ipaddress.IPv4Address):
            self.addr_type = DEF.IPv4_ADDR_TYPE
            self.addr_len  = DEF.IPv4_ADDR_LEN
        elif isinstance(addr, ipaddress.IPv6Address):
            self.addr_type = DEF.IPv6_ADDR_TYPE
            self.addr_len  = DEF.IPv6_ADDR_LEN
        else:
            msg = 'TLVTriple can only handle IPv4 and IPv6 type/length/value '
            msg += 'triples for now.'
            raise ValueError(msg)

        self.value = addr.packed

    # XXX addr_len is currently ignored because we can only currently handle
    #     IPv4 and IPv6 TLV's and not hostnames. When RELAY_RESOLVE/D cells
    #     are implemented, this should be changed to handle hostnames of
    #     different lengths
    @staticmethod
    def parse(data, offset):
        '''Parse and extract TLVTriple fields from a byte string.

        :param str data: byte string to parse
        :param int offset: offset in str data where we should start
            reading
        :returns: :class:`~oppy.cell.util.TLVTriple`
        '''
        addr_type = struct.unpack('!B', data[offset:offset +
                                             TLV_ADDR_TYPE_LEN])[0]
        offset += TLV_ADDR_TYPE_LEN

        # use addr_len for hostname types
        addr_len  = struct.unpack('!B', data[offset:offset +
                                             TLV_ADDR_LEN_LEN])[0]
        offset += TLV_ADDR_LEN_LEN

        if addr_type == DEF.IPv4_ADDR_TYPE:
            value = data[offset:offset + DEF.IPv4_ADDR_LEN]
            offset += DEF.IPv4_ADDR_LEN
            value = ipaddress.ip_address(value).exploded
        elif addr_type == DEF.IPv6_ADDR_TYPE:
            value = data[offset:offset + DEF.IPv6_ADDR_LEN]
            offset += DEF.IPv6_ADDR_LEN
            value = ipaddress.ip_address(value).exploded
        else:
            msg = "TLVTriple can't parse type {0} yet.".format(addr_type)
            raise ValueError(msg)

        return TLVTriple(value)

    # XXX handle hostname types and errors properly
    def getBytes(self):
        '''Construct and return the raw byte string this TLVTriple
        represents.

        :returns: **str** raw byte string this TLVTriple represents.
        '''
        ret = struct.pack('!B', self.addr_type)
        ret += struct.pack('!B', self.addr_len)
        ret += self.value
        return ret

    def __len__(self):
        return TLV_ADDR_TYPE_LEN + TLV_ADDR_LEN_LEN + len(self.value)

    def __repr__(self):
        fmt = "TLVTriple(addr={})"
        return fmt.format(repr(ipaddress.ip_address(self.value).exploded))

    def __eq__(self, other):
        if type(other) is type(self):
            return self.__dict__ == other.__dict__
        return False

CERT_TYPE_LEN = 1
CERT_LEN_LEN = 2
SUPPORTED_CERT_TYPES = (1, 2, 3,)


class CertsCellPayloadItem(object):
    
    __slots__ = ('cert_type', 'cert_len', 'cert')

    def __init__(self, cert_type, cert_len, cert):
        self.cert_type = cert_type
        self.cert_len = cert_len
        self.cert = cert

    def getBytes(self):
        ret = struct.pack('!B', self.cert_type)
        ret += struct.pack('!H', self.cert_len)
        ret += self.cert
        return ret

    @staticmethod
    def parse(data, offset):
        cert_type = struct.unpack('!B',
                                  data[offset: offset + CERT_TYPE_LEN])[0]
        offset += CERT_TYPE_LEN
        if cert_type not in SUPPORTED_CERT_TYPES:
            msg = "Got cert type {}, but oppy only supports cert types {}."
            raise BadPayloadData(msg.format(cert_type, SUPPORTED_CERT_TYPES))

        cert_len = struct.unpack('!H', data[offset: offset + CERT_LEN_LEN])[0]
        offset += CERT_LEN_LEN

        cert = data[offset: offset + cert_len]

        return CertsCellPayloadItem(cert_type, cert_len, cert)

    def __repr__(self):
        fmt = "CertsCellPayloadItem(cert_type={}, cert_len={}, cert={})"
        return fmt.format(repr(self.cert_type), repr(self.cert_len),
                          repr(self.cert))

    def __len__(self):
        return 1 + 2 + len(self.cert)

    def __eq__(self, other):
        if type(other) is type(self):
            equal = True
            equal &= (self.cert_type == other.cert_type)
            equal &= (self.cert_len == other.cert_len)
            equal &= (self.cert == other.cert)
            return equal
        return False
