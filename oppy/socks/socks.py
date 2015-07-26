# Copyright 2014, 2015, Nik Kinkel and David Johnston
# See LICENSE for licensing information

'''
.. topic:: Details

    OppySOCKSProtocol instances handle the initial SOCKS 5 handshake with
    client applications, passing the remote resource request to a stream,
    and then forwarding data back and forth between a circuit and a local
    application.

    An OppySOCKSProtocol instance is assigned to each incoming request on
    the SOCKS port, and upon successful handshake negotiaton a stream is
    created for the client application's request.

    Once the client has made a successful request, this object goes into the
    forwarding state in which it:

        - forwards all subsequent data from the client to the remote resource
          (through a circuit)
        - sends all data written to this object's recv() method to the
          client application

    Throughout this process, this object communicates with the client
    application via transport, as usual for Twisted Protocol objects.

'''
import logging
import struct

from twisted.internet.protocol import Protocol, ServerFactory

from oppy.stream.stream import Stream
from oppy.util.exitrequest import ExitRequest
from oppy.util.tools import enum


# Major TODO's:
#   - catch possible exceptions raised from ExitRequest construction
#   - make sure ExitRequest catches invalid ports etc.

class MalformedSOCKSHandshake(Exception):
    pass


class MalformedSOCKSRequest(Exception):
    pass


class NoSupportedMethods(Exception):
    pass


class UnsupportedAddressType(Exception):
    pass


class UnsupportedCommand(Exception):
    pass


class UnsupportedVersion(Exception):
    pass


VER = "\x05"
RSV = "\x00"


# supported authentication methods
NO_AUTH_REQUIRED        = "\x00"
NO_ACCEPTABLE_METHODS   = "\xFF"


# SOCKS commands
CONNECT = "\x01"
BIND    = "\x02"
UDP     = "\x03"


# SOCKS replies
SUCCEEDED                   = "\x00"
SOCKS_FAILURE               = "\x01"
NETWORK_FAILURE             = "\x02"
NETWORK_UNREACHABLE         = "\x03"
HOST_UNREACHABLE            = "\x04"
CONNECTION_REFUSED          = "\x05"
TTL_EXPIRED                 = "\x06"
COMMAND_NOT_SUPPORTED       = "\x07"
ADDRESS_TYPE_NOT_SUPPORTED  = "\x08"


# SOCKS address types
IPv4        = "\x01"
DOMAIN_NAME = "\x03"
IPv6        = "\x04"


# used for parsing incoming SOCKS data
VER_LEN = 1
NMETHODS_LEN = 1
CMD_LEN = 1
RSV_LEN = 1
ADDR_TYPE_LEN = 1
IPv4_LEN = 4
IPv6_LEN = 16
PORT_LEN = 2
REQUEST_HEADER_LEN = VER_LEN+CMD_LEN+RSV_LEN+ADDR_TYPE_LEN


State = enum(
    HANDSHAKE=0,
    REQUEST=1,
    FORWARDING=2,
)


class OppySOCKSProtocol(Protocol):
    '''Do SOCKS 5 handshake and forward local traffic to streams.'''

    def __init__(self, circuit_manager):
        self._circuit_manager = circuit_manager
        self.state = State.HANDSHAKE
        self.request = None
        # An `oppy.stream.stream` object over which the SOCKS client's data
        # will be forwarded. This will be set by the time that state has
        # become forwarding
        self.stream = None

    def dataReceived(self, data):
        '''Either handle an incoming SOCKS handshake, make a new stream
        request, or forward application data on to a stream.

        Called when data is received from a local application.

        :param str data: data that was received
        '''
        if self.state == State.HANDSHAKE:
            self._handleHandshake(data)
        elif self.state == State.REQUEST:
            self._handleRequest(data)
        else:
            self.stream.send(data)

    def recv(self, data):
        '''Write received *data* to local client application.

        :param str data: data to write
        '''
        self.transport.write(data)

    def closeFromStream(self):
        '''Lose this transports local connection.

        Called by the attached stream when we want to signal to a local
        application that this connection has closed.
        '''
        self.transport.loseConnection()

    def _handleHandshake(self, data):
        '''Check for supported versions and methods in the SOCKS 5 handshake.

        If we get a good version and a method we can support, send back
        a SUCCESS response to the client and advance to a state expecting
        a connection request.

        .. warning:: oppy only supports the NO_AUTH method.

        :param str data: handshake data
        '''

        try:
            methods = _parseHandshake(data)
        except (MalformedSOCKSHandshake,
                NoSupportedMethods,
                UnsupportedVersion) as e:
            logging.error(e)
            # TODO: do we need to write a response?
            self.transport.loseConnection()
            return

        if NO_AUTH_REQUIRED not in methods:
            logging.error("SOCKS client does not support NO_AUTH method.")
            self.transport.write(VER + NO_ACCEPTABLE_METHODS)
            self.transport.loseConnection()
            return

        # for now, always use NO_AUTH method
        self.transport.write(VER + NO_AUTH_REQUIRED)
        self.state = State.REQUEST

    def _handleRequest(self, data):
        '''Process an incoming connection request and assign the request
        to an oppy.stream.stream.Stream.

        Send a SUCCESS reply to the client and advance to the FORWARDING
        state if we get a good request.

        :param str data: incoming request data to process
        '''
        try:
            addr_type = _parseSOCKSRequestHeader(data)
        except (MalformedSOCKSRequest,
                UnsupportedCommand,
                UnsupportedVersion) as e:
            logging.error(e)
            if isinstance(e, UnsupportedVersion):
                self._sendReply(SOCKS_FAILURE)
            elif isinstance(e, UnsupportedCommand):
                self._sendReply(COMMAND_NOT_SUPPORTED)
            else:
                self._sendReply(SOCKS_FAILURE)
            self.transport.loseConnection()
            return

        data = data[REQUEST_HEADER_LEN:]

        try:
            self.request = _parseRequest(data, addr_type)
        except (MalformedSOCKSRequest, UnsupportedAddressType) as e:
            logging.error(e)
            if isinstance(e, MalformedSOCKSRequest):
                self._sendReply(SOCKS_FAILURE)
            else:
                self._sendReply(ADDRESS_TYPE_NOT_SUPPORTED)
            self.transport.loseConnection()
            return

        self.stream = Stream(self._circuit_manager, self.request, self)
        self.state = State.FORWARDING
        self._sendReply(SUCCEEDED)

    def _sendReply(self, REP):
        '''Send a valid SOCKS 5 reply to a local client.

        .. note:: We currently always use 127.0.0.1 for the address
        and 0 for the port.

        :param str REP: reply to send
        '''
        # 127.0.0.1
        ADDR = "\x7f\x00\x00\x01"
        # port 0 for localhost
        PORT = "\x00\x00"
        self.transport.write(VER + REP + RSV + IPv4 + ADDR + PORT)

    def connectionLost(self, reason):
        '''If we have been assigned a good stream, just log that we've
        lost the connection.

        :param reason reason: reason this connection was lost
        '''
        # sometimes, if stream creation is attempted before circuit
        # manager exists, a SOCKS object will get a stream that has no
        # stream id. in this case just skip logging and closing that
        # stream and let it die
        if self.stream is not None and hasattr(self.stream, 'stream_id'):
            msg = "SOCKS on stream id {} is done with its local connection."
            logging.debug(msg.format(self.stream.stream_id))
            self.stream.closeFromSOCKS()

    def connectionMade(self):
        '''Log that SOCKS has made a local connection and wait for an
        incoming handshake request.
        '''
        logging.debug("SOCKS made a local connection.")


def _parseHandshake(data):
    
    if len(data) < VER_LEN+NMETHODS_LEN:
        msg = "Not enough data for a valid SOCKS handshake."
        raise MalformedSOCKSHandshake(msg)

    pos = 0
    version = data[:VER_LEN]
    pos += VER_LEN
    nmethods = data[pos:pos+NMETHODS_LEN]
    pos += NMETHODS_LEN

    if version != VER:
        msg = "Unsupported SOCKS version: {}".format(ord(version))
        raise UnsupportedVersion(msg)

    if nmethods == "\x00":
        msg = "No supported SOCKS methods in received handshake."
        raise NoSupportedMethods(msg)

    _nmethods = struct.unpack("!B", nmethods)[0]

    if len(data) < VER_LEN+NMETHODS_LEN+_nmethods:
        msg = "Not enough data for a valid SOCKS handshake."
        raise MalformedSOCKSHandshake(msg)

    methods = data[pos:pos+_nmethods]

    return methods


def _parseSOCKSRequestHeader(data):

    if len(data) < VER_LEN+CMD_LEN+RSV_LEN+ADDR_TYPE_LEN:
        msg = "Not enough data for a valid SOCKS request."
        raise MalformedSOCKSRequest(msg)

    pos = 0
    ver = data[:VER_LEN]
    pos += VER_LEN
    cmd = data[pos:pos+CMD_LEN]
    pos += CMD_LEN
    rsv = data[pos:pos+RSV_LEN]
    pos += RSV_LEN
    addr_type = data[pos:pos+ADDR_TYPE_LEN]
    pos += ADDR_TYPE_LEN

    if ver != VER:
        raise UnsupportedVersion("Unsupported version: {}".format(ord(ver)))

    if cmd != CONNECT:
        raise UnsupportedCommand("Unsupported command: {}".format(ord(cmd)))

    if rsv != RSV:
        raise MalformedSOCKSRequest("Reserved byte was non-zero.")

    return addr_type


def _parseRequest(data, addr_type):
    if addr_type == IPv4:
        request = _parseIPv4Request(data)
    elif addr_type == DOMAIN_NAME:
        request = _parseHostRequest(data)
    elif addr_type == IPv6:
        request = _parseIPv6Request(data)
    else:
        msg = ("OppySOCKSProtocol received a request with unsupported "
               "address type: {}".format(ord(addr_type)))
        raise UnsupportedAddressType(msg)

    return request


def _parseIPv4Request(data):
    if len(data) < IPv4_LEN+PORT_LEN:
        msg = "Not enough data for a valid IPv4 request."
        raise MalformedSOCKSRequest(msg)

    addr = data[:IPv4_LEN]
    port = data[IPv4_LEN:IPv4_LEN+PORT_LEN]
    return ExitRequest(port, addr=addr)


def _parseHostRequest(data):
    try:
        length = struct.unpack("!B", data[0])[0]
        if len(data) < 1+length+PORT_LEN:
            raise IndexError
    except (struct.error, IndexError):
        msg = "Not enough data for a valid Domain Name request."
        raise MalformedSOCKSRequest(msg)

    # hostname length is 1 byte
    pos = 1
    host = data[pos:pos+length]
    pos += length
    port = data[pos:pos+PORT_LEN]
    return ExitRequest(port, host=host)


def _parseIPv6Request(data):
    if len(data) < IPv6_LEN+PORT_LEN:
        msg = "Not enough data for a valid IPv6 request."
        raise MalformedSOCKSRequest(msg)
    addr = data[:IPv6_LEN]
    port = data[IPv6_LEN:IPv6_LEN+PORT_LEN]
    return ExitRequest(port, addr=addr)


class OppySOCKSProtocolFactory(ServerFactory):
    '''Serve *OppySOCKSProtocol* instances.'''

    def __init__(self, circuit_manager):
        self.circuit_manager = circuit_manager

    def buildProtocol(self, addr):
        return OppySOCKSProtocol(self.circuit_manager)
