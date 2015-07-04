# NOTE:
#   This code is very loosely based on pathsim.py from the torps project
#   but is neither reviewed nor endorsed by the torps authors. Torps is a
#   relatively straightforward Python port of tor's path selection algorithm.
#   The original torps code and licensing information can be found at:
#   https://github.com/torps/torps
#
#   oppy makes the following high-level modifications to Tor's path selection
#   algorithm:
#       - we only choose relays that support the ntor handshake. oppy doesn't
#         know how to do the TAP handshake, and hopefuly TAP will be gone soon
#         anyway.
#       - If there are any pending connections, Tor uses them to make a list of
#         the "best" exit node candidates (i.e. the nodes that can support the
#         most pending connections) and chooses a weighted node from this list.
#         oppy doesn't do this (yet), and just chooses a weighted exit from
#         a list of all usable exits without considering pending requests.

import random

from collections import namedtuple

from twisted.internet import defer

from stem import Flag
from stem.exit_policy import ExitPolicy

from oppy.path import util as path_util
from oppy.path.exceptions import (
    NoUsableGuardsException,
    PathSelectionFailedException,
)


# NOTE: make sure to mention in docs that path never changes the guards
#       we just raise an exception here and let something at a higher level
#       update the guard list


DEFAULT_BWWEIGHTSCALE = 10000


Path = namedtuple("Path", ("entry", "middle", "exit"))


# TODO: docs
# TODO: update to support arbitrary path lengths
# TODO: verify consensus is valid re: current time (should always be True)
@defer.inlineCallbacks
def getPath(netstatus, guard_manager, exit_request=None, fast=True,
            stable=True, internal=False):
    # Raises:
    #   - NoUsableGuardsException (i.e. we need to find a new guard)
    #   - PathSelectionFailedException
    consensus = yield netstatus.getConsensus()
    descriptors = yield netstatus.getDescriptors()
    guards = yield guard_manager.getUsableGuards()
    cons_rel_stats = consensus.routers
    cons_bw_weights = consensus.bandwidth_weights
    ip = exit_request.addr if exit_request else None
    port = exit_request.port if exit_request else None
    cons_bwweightscale = DEFAULT_BWWEIGHTSCALE

    try:
        exit_fprint = selectExitNode(cons_bw_weights, cons_bwweightscale,
                                     cons_rel_stats, descriptors, fast, stable,
                                     internal, ip, port)

        guard_fprint = selectGuardNode(cons_bw_weights, cons_bwweightscale,
                                       cons_rel_stats, descriptors, guards,
                                       fast, stable, exit_fprint)

        middle_fprint = selectMiddleNode(cons_bw_weights, cons_bwweightscale,
                                         cons_rel_stats, descriptors, fast,
                                         stable, exit_fprint, guard_fprint)

        exit_node = descriptors[exit_fprint]
        middle_node = descriptors[middle_fprint]
        guard_node = descriptors[guard_fprint]
        defer.returnValue(Path(guard_node, middle_node, exit_node))
    except ValueError as e:
        raise PathSelectionFailedException("Unable to select a valid path. "
                                           "Reason: {}".format(e))


def selectExitNode(bw_weights, bwweightscale, cons_rel_stats, descriptors,
                   fast, stable, internal, ip, port):
    exits = filterExits(cons_rel_stats, descriptors, fast, stable, internal,
                        ip, port)
    
    if len(exits) == 0:
        raise ValueError("No usable exit nodes for requested path.")

    if len(exits) == 1:
        return exits[0]

    weight_pos = 'm' if internal is True else 'e'
    weights = path_util.getPositionWeights(exits, cons_rel_stats, weight_pos,
                                           bw_weights, bwweightscale)
    weighted_exits = path_util.getWeightedNodes(exits, weights)      

    return path_util.selectWeightedNode(weighted_exits)


def selectGuardNode(cons_bw_weights, cons_bwweightscale, cons_rel_stats,
                    descriptors, guards, fast, stable, exit_node):
    try:
        guard_candidates = [g for g in guards
                            if guardFilter(g, cons_rel_stats, descriptors,
                                            fast, stable, exit_node)]
        return random.choice(guard_candidates)
    except IndexError:
        raise NoUsableGuardsException("No usable guard nodes for requested "
                                      "path.")


def selectMiddleNode(bw_weights, bwweightscale, cons_rel_stats, descriptors,
                       fast, stable, exit_node, guard_node):
    middles = filterMiddles(cons_rel_stats, descriptors, fast, stable,
                            exit_node, guard_node)

    if len(middles) == 0:
        raise ValueError("No usable middle nodes for requested path.")

    if len(middles) == 1:
        return middles[0]

    weights = path_util.getPositionWeights(middles, cons_rel_stats, 'm',
                                           bw_weights, bwweightscale)
    weighted_middles = path_util.getWeightedNodes(middles, weights)    
    return path_util.selectWeightedNode(weighted_middles)


def filterExits(cons_rel_stats, descriptors, fast, stable, internal, ip, port):
    exits = []
    for fprint in cons_rel_stats:
        if exitFilter(fprint, cons_rel_stats, descriptors, fast, stable,
                      internal, ip, port):
            exits.append(fprint)
    return exits


def filterMiddles(cons_rel_stats, descriptors, fast, stable, exit_node,
                  guard_node):
    middles = []
    for fprint in cons_rel_stats:
        if (middleFilter(fprint, cons_rel_stats, descriptors, exit_node,
                         guard_node, fast, stable)):
            middles.append(fprint)
    return middles


def exitFilter(exit, cons_rel_stats, descriptors, fast, stable, internal, ip,
               port):
    try:
        rel_stat = cons_rel_stats[exit]
        desc = descriptors[exit]
    except KeyError:
        return False

    if (desc.ntor_onion_key is None) or (desc.hibernating is True):
        return False

    if Flag.BADEXIT in rel_stat.flags:
        return False
    if Flag.RUNNING not in rel_stat.flags:
        return False
    if Flag.VALID not in rel_stat.flags:
        return False
    if (fast is True) and (Flag.FAST not in rel_stat.flags):
        return False
    if (stable is True) and (Flag.STABLE not in rel_stat.flags):
        return False

    # we don't care about the exit policy if exit is for an internal circuit
    if internal is True:
        return True
    elif ip is not None:
        return desc.exit_policy.can_exit_to(ip, port)
    elif port is not None:
        return path_util.canExitToPort(desc, port)
    else:
        return (not path_util.policyIsRejectStar(desc.exit_policy))

def guardFilter(guard, cons_rel_stats, descriptors, fast, stable, exit):
    try:
        rel_stat = cons_rel_stats[guard]
        _ = descriptors[guard]
    except KeyError:
        return False

    if (fast is True) and (Flag.FAST not in rel_stat.flags):
        return False
    if (stable is True) and (Flag.STABLE not in rel_stat.flags):
        return False
    if path_util.nodeUsableWithOther(exit, guard, descriptors) is False:
        return False

    return True

def middleFilter(node, cons_rel_stats, descriptors, exit, guard, fast=False,
                 stable=False):
    try:
        rel_stat = cons_rel_stats[node]
        desc = descriptors[node]
    except KeyError:
        return False

    if (desc.ntor_onion_key is None) or (desc.hibernating is True):
        return False

    # Note that we intentionally allow non-Valid routers for middle
    # as per path-spec.txt default config    
    if Flag.RUNNING not in rel_stat.flags:
        return False
    if (fast is True) and (Flag.FAST not in rel_stat.flags):
        return False
    if (stable is True) and (Flag.STABLE not in rel_stat.flags):
        return False
    if path_util.nodeUsableWithOther(exit, node, descriptors) is False:
        return False
    if path_util.nodeUsableWithOther(guard, node, descriptors) is False:
        return False

    return True
