# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

# TODO: fix docs (a lot!)
'''
.. topic:: PathConstraints

    PathConstraints represent constraints on a path through the Tor network.
    They are constructed by passing a dict of {'keyword': 'value'} as an
    argument for each node. A list of filters is built for each node. Then,
    using the satisfy() method, a PathConstraints object can select only
    the RelayDescriptors that satisfy the proper constraints.

    Path constraint objects can be used as follows (suppose *relays* is a
    list of RelayDescriptors):

    >>> p = PathConstraints(entry={'ntor': True, 'flags': ['Fast', 'Guard']},
    >>>                     middle={'ntor': True, 'flags': ['Stable']},
    >>>                     exit={'ntor': True, 'flags': ['Exit'],
    >>>                           'exit_to_port': 443})
    >>> entry_candidates = p.satisfy(node='entry', relays)

    *entry_candidates* would now be a list of all relays that satisfy the
    entry node constraints.

'''
import random

from collections import namedtuple

import ipaddress

from twisted.internet import defer

import stem
from stem.descriptor.server_descriptor import DEFAULT_IPV6_EXIT_POLICY

from oppy.path.exceptions import UnknownPathConstraint
from oppy.util.tools import dispatch


Path = namedtuple("Path", ("entry",
                           "middle",
                           "exit",))


class PathConstraints(object):
    '''Represent a set of path constraints.'''

    keywords = set([
        'flags',
        'ntor',
        'exit_IPv6',
        'exit_to_IP',
        'exit_to_port',
        'exit_to_IP_and_port',
        'fingerprint',
    ])

    _build_table = {}

    def __init__(self, entry, middle, exit):
        '''
        :param dict entry: dict of 'keyword: value' arguments to build
            filters for the entry node
        :param dict middle: dict of 'keyword: value' arguments to build
            filters for the middle node
        :param dict exit: dict of 'keyword: value' arguments to build
            filters for the exit node
        '''
        self.entry_filters = self._buildFilterList(entry)
        self.middle_filters = self._buildFilterList(middle)
        self.exit_filters = self._buildFilterList(exit)
        self.is_IPv6_exit = 'exit_IPv6' in exit and exit['exit_IPv6'] is True

    def _buildFilterList(self, args):
        '''
        :param dict args: dict of 'keyword: value' args to build relay
            filters
        :returns: **list, function** a list of filtering functions
        '''
        filter_list = []
        for key in args:
            if key not in PathConstraints.keywords:
                msg = "Unrecognized path constraint: '{}'.".format(key)
                raise UnknownPathConstraint(msg)
            build = PathConstraints._build_table[key].__get__(self, type(self))
            filter_list.append(build(args[key]))
        return filter_list

    def satisfy(self, relays, node, family_fprints=None, subnets=None):
        '''Return the subset of *relays* that satisfies the path constraints
        for chosen *node*.

        :param list relays:
            a list (of stem.descriptor.server_descriptor.RelayDescriptor) of
            relays to filter
        :param str node: the node for which we're filtering ('entry', 'middle',
            or 'exit'). determines which filters to use
        :param set family_fprints: a set (of str) of fingerprints in use
            by "family members" of relays on the current path. do not
            choose any relays with a fingerprint in family_fprints
        :param set subnets: set (of ipaddress.ip_network) of the current
            /16's in use for the path in question. do not choose any relays
            that share the same /16 as a relay that's already been chosen.
        :returns: **list, stem.descriptor.server_descriptor.RelayDescriptor**
            all RelayDescriptors from *relays* that satisfy the path
            constraints for the chosen node position
        '''
        filters = None
        if node == 'entry':
            filters = self.entry_filters
        elif node == 'middle':
            filters = self.middle_filters
        elif node == 'exit':
            filters = self.exit_filters
        else:
            msg = "Unrecognized node type: '{}'.".format(node)
            raise UnknownPathConstraint(msg)

        f = lambda x: all([f(x) for f in filters])
        node_list = filter(f, relays)

        if family_fprints is not None:
            f = lambda r: r.fingerprint not in family_fprints
            node_list = filter(f, node_list)
        if subnets is not None:
            f = lambda r: ipaddress.ip_address(r.address) not in subnets
            node_list = filter(f, node_list)

        return node_list

    @dispatch(_build_table, 'flags')
    def _buildFlagsFilter(self, flags):
        '''Build and return a 'flags' filtering function.

        The returned function takes a RelayDescriptor as an argument and
        returns **True** if every flag in *flags* is contained in the
        RelayDescriptors 'flags' field, and **False** otherwise.

        :param **list, str** flags: flags to check
        :returns: **function**
        '''
        for flag in flags[:]:
            if flag not in stem.Flag:
                msg = "Unrecognized flag: '{}'.".format(flag)
                raise UnknownPathConstraint(msg)
            # convert to unicode to work with RouterStatusEntry.flags arg
            flag = unicode(flag)
        flags = set(flags)
        return lambda r: flags.issubset(r.flags)

    @dispatch(_build_table, 'ntor')
    def _buildNTorFilter(self, value):
        '''Build and return an 'ntor' filtering function.

        The returned function takes a RelayDescriptor as an argument and
        returns whether or not the relay's 'ntor_onion_key' field's presence
        matches the desired value.

        That is, if *value* is True and the relay has an *ntor_onion_key*
        field, then return **True**, etc.

        :param bool value: desired truth value of statement (for some relay):
            'this relay's ntor onion key field is not None'
        :returns: **function**
        '''
        return lambda r: (r.ntor_onion_key is not None) == value

    @dispatch(_build_table, 'exit_IPv6')
    def _buildExitIPv6Filter(self, value):
        '''Build and return an exit IPv6 filter.
        :param bool value: desired truth value of statement
        :returns: **function**
        '''
        POLICY = DEFAULT_IPV6_EXIT_POLICY
        return lambda r: (r.exit_policy_v6 != POLICY) == value

    @dispatch(_build_table, 'exit_to_IP')
    def _buildExitToIPFilter(self, IP):
        '''Build and return an exit policy filter.

        Build a function that takes a RelayDescriptor as an argument and
        returns **True** if that relay's exit policy allows exits to IP.

        :param str IP: desired IP to exit to
        :returns: **function**
        '''
        return lambda r: r.exit_policy.can_exit_to(address=IP, strict=True)

    @dispatch(_build_table, 'exit_to_port')
    def _buildExitToPortFilter(self, port):
        '''Build and return a function that checks if a relay allows exits
        to a certain port.

        :param int port: port to check
        :return: **function**
        '''
        return lambda r: r.exit_policy.can_exit_to(port=port, strict=True)

    @dispatch(_build_table, 'exit_to_IP_and_port')
    def _buildExitToIPAndPortFilter(self, arg):
        '''Build and return a function that takes an IP and port in form
        '127.0.0.1:443' format and checks if an relay allows exits to both
        the desired IP and port.

        :param str arg: IP and port, delimited by ':'
        :returns: **function**
        '''
        arg = arg.split(':')
        addr = arg[0]
        port = int(arg[1])
        return lambda r: r.exit_policy.can_exit_to(address=addr, port=port)

    @dispatch(_build_table, 'fingerprint')
    def _buildFingerprintFilter(self, fingerprint):
        '''Build and return a function that takes a RelayDescriptor as an
        argument and returns **True** if that relay's fingerprint matches
        the value *fingerprint*.

        :param str fingerprint: fingerprint to match
        :returns: **function**
        '''
        return lambda r: r.fingerprint == fingerprint


# TODO: fix docs
@defer.inlineCallbacks
def getPath(constraints):
    '''
    Filter the current set of RelayDescriptors and randomly choose an
    entry, middle, and exit node that satisfy the desired path constraints.

    We currently just use the absolutely bare minimum path constraints,
    namely:

        - no two relays in the same family
        - no two relays in the same /16
        - each relay has the required default flags

    .. note: oppy currently only knows how to do an NTor handshake, so
        we only choose RelayDescriptors that have an ntor_onion_key.

    :param oppy.path.path.PathConstraints constraints: path constraints
        to satisfy
    :returns: **twisted.internet.defer.Deferred** that fires with an
        oppy.path.Path
    '''

    path = []
    entry = yield getEntry(constraints, path)
    path.append(entry)
    middle = yield getMiddle(constraints, path)
    path.append(middle)
    exit = yield getExit(constraints, path)
    defer.returnValue(Path(entry, middle, exit))


# TODO: add docs
# TODO: exception handling
@defer.inlineCallbacks
def getEntry(constraints, path):
    family_fprints = _getFamilyFingerprints(path)
    subnets = _getSubnets(path)
    from oppy.shared import net_status
    relays = yield net_status.getDescriptors()
    relays = relays.values()
    entry_list = constraints.satisfy(relays, node='entry',
                                     family_fprints=family_fprints,
                                     subnets=subnets)
    entry = random.choice(entry_list)
    defer.returnValue(entry)


# TODO: add docs
# TODO: exception handling
@defer.inlineCallbacks
def getMiddle(constraints, path):
    family_fprints = _getFamilyFingerprints(path)
    subnets = _getSubnets(path)
    from oppy.shared import net_status
    relays = yield net_status.getDescriptors()
    relays = relays.values()

    middle_list = constraints.satisfy(relays, node='middle',
                                      family_fprints=family_fprints,
                                      subnets=subnets)
    middle = random.choice(middle_list)
    defer.returnValue(middle)


# TODO: add docs
# TODO: exception handling
@defer.inlineCallbacks
def getExit(constraints, path):
    family_fprints = _getFamilyFingerprints(path)
    subnets = _getSubnets(path)
    from oppy.shared import net_status
    relays = yield net_status.getDescriptors()
    relays = relays.values()
    exit_list = constraints.satisfy(relays, node='exit',
                                    family_fprints=family_fprints,
                                    subnets=subnets)
    exit = random.choice(exit_list)
    defer.returnValue(exit)


def _getFamilyFingerprints(path):
    family_fprints = set()
    for node in path:
        family_fprints |= set([i.strip(u'$') for i in node.family])
    return family_fprints


def _getSubnets(path):
    subnets = set()
    for node in path:
        subnets.add(ipaddress.ip_network(node.address + u'/16', strict=False))
    return subnets
