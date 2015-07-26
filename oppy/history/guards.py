'''
5. Guard nodes

  We use Guard nodes (also called "helper nodes" in the literature) to
  prevent certain profiling attacks.  Here's the risk: if we choose entry and
  exit nodes at random, and an attacker controls C out of N relays
  (ignoring bandwidth), then the
  attacker will control the entry and exit node of any given circuit with
  probability (C/N)^2.  But as we make many different circuits over time,
  then the probability that the attacker will see a sample of about (C/N)^2
  of our traffic goes to 1.  Since statistical sampling works, the attacker
  can be sure of learning a profile of our behavior.

  If, on the other hand, we picked an entry node and held it fixed, we would
  have probability C/N of choosing a bad entry and being profiled, and
  probability (N-C)/N of choosing a good entry and not being profiled.

  When guard nodes are enabled, Tor maintains an ordered list of entry nodes
  as our chosen guards, and stores this list persistently to disk.  If a Guard
  node becomes unusable, rather than replacing it, Tor adds new guards to the
  end of the list.  When choosing the first hop of a circuit, Tor
  chooses at
  random from among the first NumEntryGuards (default 3) usable guards on the
  list.  If there are not at least 2 usable guards on the list, Tor adds
  routers until there are, or until there are no more usable routers to add.

  A guard is unusable if any of the following hold:
    - it is not marked as a Guard by the networkstatuses,
    - it is not marked Valid (and the user hasn't set AllowInvalid entry)
    - it is not marked Running
    - Tor couldn't reach it the last time it tried to connect

  A guard is unusable for a particular circuit if any of the rules for path
  selection in 2.2 are not met.  In particular, if the circuit is "fast"
  and the guard is not Fast, or if the circuit is "stable" and the guard is
  not Stable, or if the guard has already been chosen as the exit node in
  that circuit, Tor can't use it as a guard node for that circuit.

  If the guard is excluded because of its status in the networkstatuses for
  over 30 days, Tor removes it from the list entirely, preserving order.

  If Tor fails to connect to an otherwise usable guard, it retries
  periodically: every hour for six hours, every 4 hours for 3 days, every
  18 hours for a week, and every 36 hours thereafter.  Additionally, Tor
  retries unreachable guards the first time it adds a new guard to the list,
  since it is possible that the old guards were only marked as unreachable
  because the network was unreachable or down.

  Tor does not add a guard persistently to the list until the first time we
  have connected to it successfully.
'''
import random

from twisted.internet import defer

from stem import Flag


class GuardManager(object):

    def __init__(self, netstatus):
        self._netstatus = netstatus

    # this is a stub. just pick some random guards.
    @defer.inlineCallbacks
    def getUsableGuards(self):
        microconsensus = yield self._netstatus.getMicroconsensus()

        guards = [n for n in microconsensus.routers.values()
                  if (Flag.GUARD in n.flags and\
                      Flag.RUNNING in n.flags and\
                      Flag.FAST in n.flags and\
                      Flag.STABLE in n.flags)]
        random.shuffle(guards)
        defer.returnValue([g.fingerprint for g in guards[:20]])
