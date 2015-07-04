# NOTE:
#   Most of these functions are based off pathsim.py from the torps project,
#   but this code is neither reviewed nor endorsed by the torps authors.
#   Torps is a relatively straightforward Python port of tor's path selection
#   algorithm. The original torps code and licensing information can be
#   found at: https://github.com/torps/torps
import random

from stem import Flag

# TODO: docs
# TODO: mention in docs the assumptions made here
#       (i.e. primarily that node fprints are guaranteed to be in descriptors)

def nodeUsableWithOther(node1, node2, descriptors):
    # return True if test_node is usable in a circuit with node
    # check:
    #   - nodes are not equal
    #   - nodes are not in same family
    #   - nodes are not in same /16 subnet
    if node1 == node2:
        return False
    if inSameFamily(node1, node2, descriptors):
        return False
    if inSame16Subnet(node1, node2, descriptors):
        return False

    return True


def selectWeightedNode(weighted_nodes):
    """Takes (node,cum_weight) pairs where non-negative cum_weight increases,
    ending at 1. Use cum_weights as cumulative probablity to select a node."""
    r = random.random()
    begin = 0
    end = len(weighted_nodes)-1
    mid = int((end+begin)/2)
    while True:
        if (r <= weighted_nodes[mid][1]):
            if (mid == begin):
                return weighted_nodes[mid][0]
            else:
                end = mid
                mid = int((end+begin)/2)
        else:
            if (mid == end):
                raise ValueError('Weights must sum to 1.')
            else:
                begin = mid+1
                mid = int((end+begin)/2)


def getWeightedNodes(nodes, weights):
    """Takes list of nodes (rel_stats) and weights (as a dict) and outputs
    a list of (node, cum_weight) pairs, where cum_weight is the cumulative
    probability of the nodes weighted by weights.
    """
    # compute total weight
    total_weight = sum([float(weights[n]) for n in nodes])
    if (total_weight == 0):
        raise ValueError('Error: Node list has total weight zero.')

    # create cumulative weights
    weighted_nodes = []
    cum_weight = 0
    for node in nodes:
        cum_weight += weights[node] / total_weight
        weighted_nodes.append((node, cum_weight))

    return weighted_nodes


def getPositionWeights(nodes, cons_rel_stats, position, bw_weights,
                       bwweightscale):
    """Computes the consensus "bandwidth" weighted by position weights."""
    weights = {}
    bwweightscale = float(bwweightscale)
    for node in nodes:
        r = cons_rel_stats[node]
        bw = float(r.bandwidth)
        weight = float(getBwweight(r.flags, position, bw_weights))
        weight_scaled = weight / bwweightscale
        weights[node] = bw * weight_scaled
    return weights 


def getBwweight(flags, position, bw_weights):
    """Returns weight to apply to relay's bandwidth for given position.
        flags: list of Flag values for relay from a consensus
        position: position for which to find selection weight,
             one of 'g' for guard, 'm' for middle, and 'e' for exit
        bw_weights: bandwidth_weights from NetworkStatusDocumentV3 consensus
    """
    if (position == 'g'):
        if (Flag.GUARD in flags) and (Flag.EXIT in flags):
            return bw_weights['Wgd']
        elif (Flag.GUARD in flags):
            return bw_weights['Wgg']
        elif (Flag.EXIT not in flags):
            return bw_weights['Wgm']
        else:
            raise ValueError('Wge weight does not exist.')
    elif (position == 'm'):
        if (Flag.GUARD in flags) and (Flag.EXIT in flags):
            return bw_weights['Wmd']
        elif (Flag.GUARD in flags):
            return bw_weights['Wmg']
        elif (Flag.EXIT in flags):
            return bw_weights['Wme']
        else:
            return bw_weights['Wmm']
    elif (position == 'e'):
        if (Flag.GUARD in flags) and (Flag.EXIT in flags):
            return bw_weights['Wed']
        elif (Flag.GUARD in flags):
            return bw_weights['Weg']
        elif (Flag.EXIT in flags):
            return bw_weights['Wee']
        else:
            return bw_weights['Wem']    
    else:
        raise ValueError('get_weight does not support position {0}.'.format(
            position))


def mightExitToPort(descriptor, port):
    """Returns if will exit to port for *some* ip.
    Is conservative - never returns a false negative."""
    for rule in descriptor.exit_policy:
        if rule.min_port <= port <= rule.max_port:
            if rule.is_accept:
                return True
            else:
                if rule.is_address_wildcard():
                    return False
                if rule.get_masked_bits() == 0:
                    return False
    # default accept if no rule matches
    return True


def canExitToPort(descriptor, port):
    """Derived from compare_unknown_tor_addr_to_addr_policy() in policies.c.
    That function returns ACCEPT, PROBABLY_ACCEPT, REJECT, and PROBABLY_REJECT.
    We ignore the PROBABLY status, as is done by Tor in the uses of
    compare_unknown_tor_addr_to_addr_policy() that we care about."""
    for rule in descriptor.exit_policy:
        if rule.min_port <= port <= rule.max_port:
            if rule.is_address_wildcard() or rule.get_masked_bits() == 0:
                return rule.is_accept
    # default accept if no rule matches
    return True
    

def policyIsRejectStar(exit_policy):
    """Replicates Tor function of same name in policies.c."""
    for rule in exit_policy:
        if rule.is_accept:
            return False
        elif rule.min_port in (0, 1) and rule.max_port == 65535:
            return True
        elif rule.is_port_wildcard():
            if rule.is_address_wildcard() or rule.get_masked_bits() == 0:
                return True

    return True
    

def inSameFamily(node1, node2, descriptors):
    """Takes list of descriptors and two node fingerprints,
    checks if nodes list each other as in the same family."""
    desc1 = descriptors[node1]
    desc2 = descriptors[node2]
    fprint1 = desc1.fingerprint
    fprint2 = desc2.fingerprint

    family1 = set([i.strip(u'$') for i in desc1.family])
    family2 = set([i.strip(u'$') for i in desc2.family])

    # True only if both nodes list each other
    return ((fprint1 in family2) and (fprint2 in family1))

    
# XXX: what do we do for IPv6?
def inSame16Subnet(node1, node2, descriptors):
    address1 = descriptors[node1].address
    address2 = descriptors[node2].address

    return (address1.split('.')[:2] == address2.split('.')[:2])
