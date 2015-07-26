# NOTE:
#   This code is based on pathsim.py from the torps project
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

from oppy.path import util as path_util
from oppy.path.exceptions import (
    NoUsableGuardsException,
    PathSelectionFailedException,
)


# NOTE: make sure to mention in docs that path never changes the guards
#       we just raise an exception here and let something at a higher level
#       update the guard list

# Major TODO's:
#   - figure out what happened to 'hibernating' field in microdescriptors?
#   - handle IPv6 exit requests properly (do we already do this?)


DEFAULT_BWWEIGHTSCALE = 10000


PathNode = namedtuple("PathNode", ("microdescriptor", "router_status_entry"))
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
    consensus = yield netstatus.getMicroconsensus()
    descriptors = yield netstatus.getMicrodescriptorsForCircuit()
    guards = yield guard_manager.getUsableGuards()
    cons_rel_stats = consensus.routers
    cons_bw_weights = consensus.bandwidth_weights
    port = exit_request.port if exit_request else None
    cons_bwweightscale = DEFAULT_BWWEIGHTSCALE

    try:
        exit_fprint = selectExitNode(cons_bw_weights, cons_bwweightscale,
                                     cons_rel_stats, descriptors, fast, stable,
                                     internal, port)
        exit_status_entry = consensus.routers[exit_fprint]
        exit_desc = descriptors[exit_status_entry.digest]

        guard_fprint = selectGuardNode(cons_rel_stats, descriptors, guards,
                                       fast, stable, exit_desc,
                                       exit_status_entry)
        guard_status_entry = consensus.routers[guard_fprint]
        guard_desc = descriptors[guard_status_entry.digest]

        middle_fprint = selectMiddleNode(cons_bw_weights, cons_bwweightscale,
                                         cons_rel_stats, descriptors, fast,
                                         stable, exit_desc, exit_status_entry,
                                         guard_desc, guard_status_entry)
        middle_status_entry = consensus.routers[middle_fprint]
        middle_desc = descriptors[middle_status_entry.digest]

        path = Path(PathNode(guard_desc, guard_status_entry),
                    PathNode(middle_desc, middle_status_entry),
                    PathNode(exit_desc, exit_status_entry))
        defer.returnValue(path)
    except ValueError as e:
        raise PathSelectionFailedException("Unable to select a valid path. "
                                           "Reason: {}".format(e))


def selectExitNode(bw_weights, bwweightscale, cons_rel_stats, descriptors,
                   fast, stable, internal, port):
    exits = filterExits(cons_rel_stats, descriptors, fast, stable, internal,
                        port)

    if len(exits) == 0:
        raise ValueError("No usable exit nodes for requested path.")

    if len(exits) == 1:
        return exits[0]

    weight_pos = 'm' if internal is True else 'e'
    weights = path_util.getPositionWeights(exits, cons_rel_stats, weight_pos,
                                           bw_weights, bwweightscale)
    weighted_exits = path_util.getWeightedNodes(exits, weights)

    return path_util.selectWeightedNode(weighted_exits)


def selectGuardNode(cons_rel_stats, descriptors, guards, fast, stable,
                    exit_desc, exit_status_entry):
    try:
        guard_candidates = [g for g in guards
                            if guardFilter(g, cons_rel_stats, descriptors,
                                           fast, stable, exit_desc,
                                           exit_status_entry)]
        return random.choice(guard_candidates)
    except IndexError:
        raise NoUsableGuardsException("No usable guard nodes for requested "
                                      "path.")


def selectMiddleNode(bw_weights, bwweightscale, cons_rel_stats, descriptors,
                     fast, stable, exit_desc, exit_status_entry, guard_desc,
                     guard_status_entry):
    middles = filterMiddles(cons_rel_stats, descriptors, fast, stable,
                            exit_desc, exit_status_entry, guard_desc,
                            guard_status_entry)

    if len(middles) == 0:
        raise ValueError("No usable middle nodes for requested path.")

    if len(middles) == 1:
        return middles[0]

    weights = path_util.getPositionWeights(middles, cons_rel_stats, 'm',
                                           bw_weights, bwweightscale)
    weighted_middles = path_util.getWeightedNodes(middles, weights)
    return path_util.selectWeightedNode(weighted_middles)


def filterExits(cons_rel_stats, descriptors, fast, stable, internal, port):
    exits = []
    for fprint in cons_rel_stats:
        if exitFilter(fprint, cons_rel_stats, descriptors, fast, stable,
                      internal, port):
            exits.append(fprint)
    return exits


def filterMiddles(cons_rel_stats, descriptors, fast, stable, exit_desc,
                  exit_status_entry, guard_desc, guard_status_entry):
    middles = []
    for fprint in cons_rel_stats:
        if (middleFilter(fprint, cons_rel_stats, descriptors, exit_desc,
                         exit_status_entry, guard_desc, guard_status_entry,
                         fast, stable)):
            middles.append(fprint)
    return middles


def exitFilter(exit_fprint, cons_rel_stats, descriptors, fast, stable,
               internal, port):
    try:
        rel_stat = cons_rel_stats[exit_fprint]
        desc = descriptors[rel_stat.digest]
    except KeyError:
        return False

    if desc.ntor_onion_key is None:
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
    elif port is not None:
        return desc.exit_policy.can_exit_to(port=port)
    else:
        return desc.exit_policy.is_exiting_allowed

def guardFilter(guard, cons_rel_stats, descriptors, fast, stable, exit_desc,
                exit_status_entry):
    try:
        rel_stat = cons_rel_stats[guard]
        guard_desc = descriptors[rel_stat.digest]
    except KeyError:
        return False

    if (fast is True) and (Flag.FAST not in rel_stat.flags):
        return False
    if (stable is True) and (Flag.STABLE not in rel_stat.flags):
        return False

    return path_util.nodeUsableWithOther(guard_desc, rel_stat,
                                         exit_desc, exit_status_entry)

def middleFilter(node, cons_rel_stats, descriptors, exit_desc,
                 exit_status_entry, guard_desc, guard_status_entry,
                 fast=False, stable=False):
    try:
        rel_stat = cons_rel_stats[node]
        node_desc = descriptors[rel_stat.digest]
    except KeyError:
        return False

    if node_desc.ntor_onion_key is None:
        return False
    # Note that we intentionally allow non-Valid routers for middle
    # as per path-spec.txt default config
    if Flag.RUNNING not in rel_stat.flags:
        return False
    if (fast is True) and (Flag.FAST not in rel_stat.flags):
        return False
    if (stable is True) and (Flag.STABLE not in rel_stat.flags):
        return False
    if path_util.nodeUsableWithOther(exit_desc, exit_status_entry, node_desc,
        rel_stat) is False:
        return False

    return path_util.nodeUsableWithOther(guard_desc, guard_status_entry,
                                         node_desc, rel_stat)
