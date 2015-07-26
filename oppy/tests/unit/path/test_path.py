import mock

from stem import Flag

from twisted.internet import defer
from twisted.trial import unittest

from oppy.path import path
from oppy.path import util as path_util
from oppy.path.exceptions import NoUsableGuardsException


class PathTest(unittest.TestCase):

    @mock.patch('oppy.path.path.selectExitNode', return_value='exit_fprint')
    @mock.patch('oppy.path.path.selectGuardNode', return_value='guard_fprint')
    @mock.patch('oppy.path.path.selectMiddleNode', return_value='middle_fprint')
    def test_getPath(self, mock_sm, mock_sg, mock_se):
        mock_ns = mock.Mock()
        mock_gm = mock.Mock()

        mock_exit_rs = mock.Mock()
        mock_exit_rs.digest = 'exit digest'
        mock_middle_rs = mock.Mock()
        mock_middle_rs.digest = 'middle digest'
        mock_guard_rs = mock.Mock()
        mock_guard_rs.digest = 'guard digest'


        mock_consensus = mock.Mock()
        mock_consensus.routers = {'exit_fprint': mock_exit_rs,
                                  'middle_fprint': mock_middle_rs,
                                  'guard_fprint': mock_guard_rs}

        mock_consensus.bandwidth_weights = 'bandwidth weights'
        mock_exit_request = mock.Mock()
        mock_exit_request.port = 'port'

        mock_descriptors = {'exit digest': 'exit_fprint',
                            'middle digest': 'middle_fprint',
                            'guard digest': 'guard_fprint'}

        mock_ns.getMicroconsensus = mock.Mock()
        mock_ns.getMicroconsensus.return_value = defer.succeed(mock_consensus)
        mock_ns.getMicrodescriptorsForCircuit = mock.Mock()
        mock_ns.getMicrodescriptorsForCircuit.return_value = \
            defer.succeed(mock_descriptors)
        mock_gm.getUsableGuards = mock.Mock()
        mock_gm.getUsableGuards.return_value = defer.succeed('guards')

        mock_fast = True
        mock_stable = True
        mock_internal = False

        mock_bwweightscale = path.DEFAULT_BWWEIGHTSCALE
        
        ret = path.getPath(mock_ns, mock_gm, mock_exit_request, mock_fast,
                           mock_stable, mock_internal)

        mock_se.assert_called_once_with(mock_consensus.bandwidth_weights,
                                        mock_bwweightscale,
                                        mock_consensus.routers,
                                        mock_descriptors,
                                        mock_fast,
                                        mock_stable,
                                        mock_internal,
                                        mock_exit_request.port)

        mock_sg.assert_called_once_with(mock_consensus.routers,
                                        mock_descriptors,
                                        'guards',
                                        mock_fast,
                                        mock_stable,
                                        'exit_fprint',
                                        mock_exit_rs)
        
        mock_sm.assert_called_once_with(mock_consensus.bandwidth_weights,
                                        mock_bwweightscale,
                                        mock_consensus.routers,
                                        mock_descriptors,
                                        mock_fast,
                                        mock_stable,
                                        'exit_fprint',
                                        mock_exit_rs,
                                        'guard_fprint',
                                        mock_guard_rs)

        self.assertEqual(self.successResultOf(ret),
            path.Path(path.PathNode('guard_fprint', mock_guard_rs),
                      path.PathNode('middle_fprint', mock_middle_rs),
                      path.PathNode('exit_fprint', mock_exit_rs)))

    @mock.patch('oppy.path.path.selectExitNode', side_effect=ValueError())
    def test_getPath_exception(self, mock_se):
        mock_ns = mock.Mock()
        mock_gm = mock.Mock()

        mock_exit_rs = mock.Mock()
        mock_exit_rs.digest = 'exit digest'
        mock_middle_rs = mock.Mock()
        mock_middle_rs.digest = 'middle digest'
        mock_guard_rs = mock.Mock()
        mock_guard_rs.digest = 'guard digest'


        mock_consensus = mock.Mock()
        mock_consensus.routers = {'exit_fprint': mock_exit_rs,
                                  'middle_fprint': mock_middle_rs,
                                  'guard_fprint': mock_guard_rs}

        mock_consensus.bandwidth_weights = 'bandwidth weights'
        mock_exit_request = mock.Mock()
        mock_exit_request.port = 'port'

        mock_descriptors = {'exit digest': 'exit_fprint',
                            'middle digest': 'middle_fprint',
                            'guard digest': 'guard_fprint'}

        mock_ns.getMicroconsensus = mock.Mock()
        mock_ns.getMicroconsensus.return_value = defer.succeed(mock_consensus)
        mock_ns.getMicrodescriptorsForCircuit = mock.Mock()
        mock_ns.getMicrodescriptorsForCircuit.return_value = \
            defer.succeed(mock_descriptors)
        mock_gm.getUsableGuards = mock.Mock()
        mock_gm.getUsableGuards.return_value = defer.succeed('guards')

        mock_fast = True
        mock_stable = True
        mock_internal = False

        mock_bwweightscale = path.DEFAULT_BWWEIGHTSCALE

        self.assertEqual(
            self.failureResultOf(
                path.getPath(mock_ns,
                             mock_gm,
                             mock_exit_request,
                             mock_fast,
                             mock_stable,
                             mock_internal))\
                                .trap(path.PathSelectionFailedException),
            path.PathSelectionFailedException)

    @mock.patch('oppy.path.util.getPositionWeights', return_value='weights')
    @mock.patch('oppy.path.util.getWeightedNodes', return_value='nodes')
    @mock.patch('oppy.path.util.selectWeightedNode', return_value='blah')
    @mock.patch('oppy.path.path.filterExits', return_value=['exit1', 'exit2'])
    def test_selectExitNode(self, mock_fe, mock_swn, mock_gwn, mock_gpw):
        bw_weights = 'bw_weights'
        bwweightscale = 'bwweightscale'
        cons_rel_stats = 'cons_rel_stats'
        descriptors = 'descriptors'
        fast = 'fast'
        stable = 'stable'
        internal = 'internal'
        port = 'port'

        _ = path.selectExitNode(
            bw_weights,
            bwweightscale,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port)

        mock_fe.assert_called_once_with(
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port)

        mock_gpw.assert_called_once_with(
            ['exit1', 'exit2'],
            cons_rel_stats,
            'e',
            bw_weights,
            bwweightscale)

        mock_gwn.assert_called_once_with(['exit1', 'exit2'], 'weights')

        mock_swn.assert_called_once_with('nodes')
        
    @mock.patch('oppy.path.util.getPositionWeights', return_value='weights')
    @mock.patch('oppy.path.util.getWeightedNodes', return_value='nodes')
    @mock.patch('oppy.path.util.selectWeightedNode', return_value='blah')
    @mock.patch('oppy.path.path.filterExits', return_value=['exit1', 'exit2'])
    def test_selectExitNode_internal(self, mock_fe, mock_swn, mock_gwn, mock_gpw):
        bw_weights = 'bw_weights'
        bwweightscale = 'bwweightscale'
        cons_rel_stats = 'cons_rel_stats'
        descriptors = 'descriptors'
        fast = 'fast'
        stable = 'stable'
        internal = True
        port = 'port'

        _ = path.selectExitNode(
            bw_weights,
            bwweightscale,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port)

        mock_fe.assert_called_once_with(
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port)

        mock_gpw.assert_called_once_with(
            ['exit1', 'exit2'],
            cons_rel_stats,
            'm',
            bw_weights,
            bwweightscale)

    @mock.patch('oppy.path.path.filterExits', return_value=[])
    def test_selectExitNode_no_exits(self, mock_fe):
        bw_weights = 'bw_weights'
        bwweightscale = 'bwweightscale'
        cons_rel_stats = 'cons_rel_stats'
        descriptors = 'descriptors'
        fast = 'fast'
        stable = 'stable'
        internal = 'internal'
        port = 'port'

        self.assertRaises(ValueError,
                          path.selectExitNode,
                          bw_weights,
                          bwweightscale,
                          cons_rel_stats,
                          descriptors,
                          fast,
                          stable,
                          internal,
                          port)

    @mock.patch('oppy.path.util.getPositionWeights', return_value='weights')
    @mock.patch('oppy.path.util.getWeightedNodes', return_value='nodes')
    @mock.patch('oppy.path.util.selectWeightedNode', return_value='blah')
    @mock.patch('oppy.path.path.filterExits', return_value=['exit1'])
    def test_selectExitNode_one_exit(self, mock_fe, mock_swn, mock_gwn, mock_gpw):
        bw_weights = 'bw_weights'
        bwweightscale = 'bwweightscale'
        cons_rel_stats = 'cons_rel_stats'
        descriptors = 'descriptors'
        fast = 'fast'
        stable = 'stable'
        internal = 'internal'
        port = 'port'

        ret = path.selectExitNode(
            bw_weights,
            bwweightscale,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port)

        self.assertEqual(ret, 'exit1')

        mock_fe.assert_called_once_with(
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port)

        self.assertEqual(mock_gpw.call_count, 0)
        self.assertEqual(mock_gwn.call_count, 0)
        self.assertEqual(mock_swn.call_count, 0)

    @mock.patch('random.choice')
    @mock.patch('oppy.path.path.guardFilter', return_value=True)
    def test_selectGuardNode(self, mock_gf, mock_rc):
        cons_rel_stats = 'cons_rel_stats'
        descriptors = 'descriptors'
        guards = ['guard']
        fast = 'fast'
        stable = 'stable'
        exit_desc = 'exit_desc'
        exit_status_entry = 'exit_status_entry'

        _ = path.selectGuardNode(
            cons_rel_stats,
            descriptors,
            guards,
            fast,
            stable,
            exit_desc,
            exit_status_entry)

        mock_gf.assert_called_once_with(
            'guard',
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            exit_desc,
            exit_status_entry)

        mock_rc.assert_called_once_with(['guard'])

    def test_selectGuardNode_no_guards(self):
        cons_rel_stats = 'cons_rel_stats'
        descriptors = 'descriptors'
        guards = []
        fast = 'fast'
        stable = 'stable'
        exit_desc = 'exit_desc'
        exit_status_entry = 'exit_status_entry'

        self.assertRaises(NoUsableGuardsException,
                          path.selectGuardNode,
                          cons_rel_stats,
                          descriptors,
                          guards,
                          fast,
                          stable,
                          exit_desc,
                          exit_status_entry)


    @mock.patch('oppy.path.util.getPositionWeights', return_value='weights')
    @mock.patch('oppy.path.util.getWeightedNodes', return_value='nodes')
    @mock.patch('oppy.path.util.selectWeightedNode')
    @mock.patch('oppy.path.path.filterMiddles', return_value=['middle1', 'middle2'])
    def test_selectMiddleNode(self, mock_fm, mock_swn, mock_gwn, mock_gpw):
        bw_weights = 'bw_weights'
        bwweightscale = 'bwweightscale'
        cons_rel_stats = 'cons_rel_stats'
        descriptors = 'descriptors'
        fast = 'fast'
        stable = 'stable'
        exit_desc = 'exit_desc'
        exit_status_entry = 'exit_status_entry'
        guard_desc = 'guard_desc'
        guard_status_entry = 'guard_status_entry'

        _ = path.selectMiddleNode(
            bw_weights,
            bwweightscale,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry)

        mock_fm.assert_called_once_with(
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry)

        mock_gpw.assert_called_once_with(
            ['middle1', 'middle2'],
            cons_rel_stats,
            'm',
            bw_weights,
            bwweightscale)

        mock_gwn.assert_called_once_with(['middle1', 'middle2'], 'weights')

        mock_swn.assert_called_once_with('nodes')

    @mock.patch('oppy.path.util.getPositionWeights', return_value='weights')
    @mock.patch('oppy.path.util.getWeightedNodes', return_value='nodes')
    @mock.patch('oppy.path.util.selectWeightedNode')
    @mock.patch('oppy.path.path.filterMiddles', return_value=[])
    def test_selectMiddleNode_no_nodes(self, mock_fm, mock_swn, mock_gwn, mock_gpw):
        bw_weights = 'bw_weights'
        bwweightscale = 'bwweightscale'
        cons_rel_stats = 'cons_rel_stats'
        descriptors = 'descriptors'
        fast = 'fast'
        stable = 'stable'
        exit_desc = 'exit_desc'
        exit_status_entry = 'exit_status_entry'
        guard_desc = 'guard_desc'
        guard_status_entry = 'guard_status_entry'

        self.assertRaises(ValueError,
                          path.selectMiddleNode,
                          bw_weights,
                          bwweightscale,
                          cons_rel_stats,
                          descriptors,
                          fast,
                          stable,
                          exit_desc,
                          exit_status_entry,
                          guard_desc,
                          guard_status_entry)

    @mock.patch('oppy.path.util.getPositionWeights', return_value='weights')
    @mock.patch('oppy.path.util.getWeightedNodes', return_value='nodes')
    @mock.patch('oppy.path.util.selectWeightedNode', return_value='blah')
    @mock.patch('oppy.path.path.filterMiddles', return_value=['middle'])
    def test_selectMiddleNode_one_node(self, mock_fm, mock_swn, mock_gwn, mock_gpw):
        bw_weights = 'bw_weights'
        bwweightscale = 'bwweightscale'
        cons_rel_stats = 'cons_rel_stats'
        descriptors = 'descriptors'
        fast = 'fast'
        stable = 'stable'
        exit_desc = 'exit_desc'
        exit_status_entry = 'exit_status_entry'
        guard_desc = 'guard_desc'
        guard_status_entry = 'guard_status_entry'

        ret = path.selectMiddleNode(
            bw_weights,
            bwweightscale,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry)

        self.assertEqual(ret, 'middle')

        mock_fm.assert_called_once_with(
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry)

        self.assertEqual(mock_gpw.call_count, 0)
        self.assertEqual(mock_gwn.call_count, 0)
        self.assertEqual(mock_swn.call_count, 0)

    @mock.patch('oppy.path.path.exitFilter', return_value=True)
    def test_filterExits(self, mock_ef):
        cons_rel_stats = ['test']
        descriptors = 'descriptors'
        fast = 'fast'
        stable = 'stable'
        internal = 'internal'
        port = 'port'

        ret = path.filterExits(
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port)

        self.assertEqual(ret, ['test'])

        mock_ef.assert_called_once_with(
            'test',
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port)

    @mock.patch('oppy.path.path.middleFilter', return_value=True)
    def test_filterMiddles(self, mock_mf):
        cons_rel_stats = ['test']
        descriptors = 'descriptors'
        fast = 'fast'
        stable = 'stable'
        exit_desc = 'exit_desc'
        exit_status_entry = 'exit_status_entry'
        guard_desc = 'guard_desc'
        guard_status_entry = 'guard_status_entry'

        ret = path.filterMiddles(
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry)

        self.assertEqual(ret, ['test'])

        mock_mf.assert_called_once_with(
            'test',
            cons_rel_stats,
            descriptors,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry,
            fast,
            stable)

    def test_exitFilter_no_consensus_entry(self):
        exit_fprint = 'exit_fprint'
        cons_rel_stats = {}
        descriptors = {'exit_fprint': 'exit_desc'}
        fast = True
        stable = True
        internal = False
        port = 0

        self.assertFalse(path.exitFilter(
            exit_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port))

    def test_exitFilter_no_descriptor(self):
        exit_fprint = 'exit_fprint'
        rel_stat = mock.Mock()
        rel_stat.digest = 'exit_digest'
        cons_rel_stats = {'exit_fprint': rel_stat}
        descriptors = {}
        fast = True
        stable = True
        internal = False
        port = 0

        self.assertFalse(path.exitFilter(
            exit_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port))

    def test_exitFilter_no_ntor_key(self):
        exit_fprint = 'exit_fprint'
        rel_stat = mock.Mock()
        rel_stat.digest = 'exit_digest'
        desc = mock.Mock()
        desc.ntor_onion_key = None
        cons_rel_stats = {'exit_fprint': rel_stat}
        descriptors = {'exit_digest': desc}
        fast = True
        stable = True
        internal = False
        port = 0

        self.assertFalse(path.exitFilter(
            exit_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port))

    def test_exitFilter_badexit_flag(self):
        exit_fprint = 'exit_fprint'
        rel_stat = mock.Mock()
        rel_stat.flags = (Flag.BADEXIT)
        rel_stat.digest = 'exit_digest'
        desc = mock.Mock()
        desc.ntor_onion_key = 'ntor-key'
        cons_rel_stats = {'exit_fprint': rel_stat}
        descriptors = {'exit_digest': desc}
        fast = True
        stable = True
        internal = False
        port = 0

        self.assertFalse(path.exitFilter(
            exit_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port))

    def test_exitFilter_not_running(self):
        exit_fprint = 'exit_fprint'
        rel_stat = mock.Mock()
        rel_stat.flags = ()
        rel_stat.digest = 'exit_digest'
        desc = mock.Mock()
        desc.ntor_onion_key = 'ntor-key'
        cons_rel_stats = {'exit_fprint': rel_stat}
        descriptors = {'exit_digest': desc}
        fast = True
        stable = True
        internal = False
        port = 0

        self.assertFalse(path.exitFilter(
            exit_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port))

    def test_exitFilter_not_valid(self):
        exit_fprint = 'exit_fprint'
        rel_stat = mock.Mock()
        rel_stat.flags = (Flag.RUNNING)
        rel_stat.digest = 'exit_digest'
        desc = mock.Mock()
        desc.ntor_onion_key = 'ntor-key'
        cons_rel_stats = {'exit_fprint': rel_stat}
        descriptors = {'exit_digest': desc}
        fast = True
        stable = True
        internal = False
        port = 0

        self.assertFalse(path.exitFilter(
            exit_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port))

    def test_exitFilter_not_fast_want_fast(self):
        exit_fprint = 'exit_fprint'
        rel_stat = mock.Mock()
        rel_stat.flags = (Flag.RUNNING, Flag.VALID)
        rel_stat.digest = 'exit_digest'
        desc = mock.Mock()
        desc.ntor_onion_key = 'ntor-key'
        cons_rel_stats = {'exit_fprint': rel_stat}
        descriptors = {'exit_digest': desc}
        fast = True
        stable = True
        internal = False
        port = 0

        self.assertFalse(path.exitFilter(
            exit_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port))

    def test_exitFilter_not_stable_want_stable(self):
        exit_fprint = 'exit_fprint'
        rel_stat = mock.Mock()
        rel_stat.flags = (Flag.RUNNING, Flag.VALID, Flag.FAST)
        rel_stat.digest = 'exit_digest'
        desc = mock.Mock()
        desc.ntor_onion_key = 'ntor-key'
        cons_rel_stats = {'exit_fprint': rel_stat}
        descriptors = {'exit_digest': desc}
        fast = True
        stable = True
        internal = False
        port = 0

        self.assertFalse(path.exitFilter(
            exit_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port))

    def test_exitFilter_internal(self):
        exit_fprint = 'exit_fprint'
        rel_stat = mock.Mock()
        rel_stat.flags = (Flag.RUNNING, Flag.VALID, Flag.STABLE, Flag.FAST)
        rel_stat.digest = 'exit_digest'
        desc = mock.Mock()
        desc.ntor_onion_key = 'ntor-key'
        desc.exit_policy = mock.Mock()
        desc.exit_policy.can_exit_to = mock.Mock()
        desc.exit_policy.can_exit_to.return_value = False
        desc.exit_policy.is_exiting_allowed = False
        cons_rel_stats = {'exit_fprint': rel_stat}
        descriptors = {'exit_digest': desc}
        fast = True
        stable = True
        internal = True
        port = 0

        self.assertTrue(path.exitFilter(
            exit_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port))

    def test_exitFilter_have_port(self):
        exit_fprint = 'exit_fprint'
        rel_stat = mock.Mock()
        rel_stat.flags = (Flag.RUNNING, Flag.VALID, Flag.STABLE, Flag.FAST)
        rel_stat.digest = 'exit_digest'
        desc = mock.Mock()
        desc.ntor_onion_key = 'ntor-key'
        desc.exit_policy = mock.Mock()
        desc.exit_policy.can_exit_to = mock.Mock()
        desc.exit_policy.can_exit_to.return_value = 'test retval'
        desc.exit_policy.is_exiting_allowed = False
        cons_rel_stats = {'exit_fprint': rel_stat}
        descriptors = {'exit_digest': desc}
        fast = True
        stable = True
        internal = False
        port = 0

        self.assertEqual(path.exitFilter(
            exit_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port),
            'test retval')

    def test_exitFilter_no_port(self):
        exit_fprint = 'exit_fprint'
        rel_stat = mock.Mock()
        rel_stat.flags = (Flag.RUNNING, Flag.VALID, Flag.STABLE, Flag.FAST)
        rel_stat.digest = 'exit_digest'
        desc = mock.Mock()
        desc.ntor_onion_key = 'ntor-key'
        desc.exit_policy = mock.Mock()
        desc.exit_policy.can_exit_to = mock.Mock()
        desc.exit_policy.can_exit_to.return_value = False
        desc.exit_policy.is_exiting_allowed = 'test retval'
        cons_rel_stats = {'exit_fprint': rel_stat}
        descriptors = {'exit_digest': desc}
        fast = True
        stable = True
        internal = False
        port = None

        self.assertEqual(path.exitFilter(
            exit_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            internal,
            port),
            'test retval')

    def test_guardFilter_no_consensus_entry(self):
        guard_fprint = 'guard_fprint'
        cons_rel_stats = {}
        descriptors = {'guard_fprint': 'guard_desc'}
        fast = True
        stable = True
        exit_desc = 'exit desc'
        exit_status_entry = 'exit se'

        self.assertFalse(path.guardFilter(
            guard_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            exit_desc,
            exit_status_entry))

    def test_guardFilter_no_descriptor(self):
        guard_fprint = 'guard fprint'
        rel_stat = mock.Mock()
        rel_stat.digest = 'guard digest'
        cons_rel_stats = {'guard fprint': rel_stat}
        descriptors = {}
        fast = True
        stable = True
        exit_desc = 'exit desc'
        exit_status_entry = 'exit se'

        self.assertFalse(path.guardFilter(
            guard_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            exit_desc,
            exit_status_entry))

    def test_guardFilter_want_fast_no_fast(self):
        guard_fprint = 'guard fprint'
        rel_stat = mock.Mock()
        rel_stat.digest = 'guard digest'
        rel_stat.flags = ()
        cons_rel_stats = {'guard fprint': rel_stat}
        descriptors = {'guard digest': 'guard desc'}
        fast = True
        stable = True
        exit_desc = 'exit desc'
        exit_status_entry = 'exit se'

        self.assertFalse(path.guardFilter(
            guard_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            exit_desc,
            exit_status_entry))

    def test_guardFilter_want_stable_no_stable(self):
        guard_fprint = 'guard fprint'
        rel_stat = mock.Mock()
        rel_stat.digest = 'guard digest'
        rel_stat.flags = (Flag.FAST)
        cons_rel_stats = {'guard fprint': rel_stat}
        descriptors = {'guard digest': 'guard desc'}
        fast = True
        stable = True
        exit_desc = 'exit desc'
        exit_status_entry = 'exit se'

        self.assertFalse(path.guardFilter(
            guard_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            exit_desc,
            exit_status_entry))

    @mock.patch('oppy.path.util.nodeUsableWithOther', return_value='test val')
    def test_guardFilter(self, mock_nuwo):
        guard_fprint = 'guard fprint'
        rel_stat = mock.Mock()
        rel_stat.digest = 'guard digest'
        rel_stat.flags = (Flag.FAST, Flag.STABLE)
        cons_rel_stats = {'guard fprint': rel_stat}
        descriptors = {'guard digest': 'guard desc'}
        fast = True
        stable = True
        exit_desc = 'exit desc'
        exit_status_entry = 'exit se'

        self.assertEqual(path.guardFilter(
            guard_fprint,
            cons_rel_stats,
            descriptors,
            fast,
            stable,
            exit_desc,
            exit_status_entry), 'test val')

    def test_middleFilter_no_consensus_entry(self):
        middle_fprint = 'middle fprint'
        cons_rel_stats = {}
        descriptors = {'middle fprint': 'middle desc'}
        fast = True
        stable = True
        exit_desc = 'exit desc'
        exit_status_entry = 'exit se'
        guard_desc = 'guard desc'
        guard_status_entry = 'guard se'

        self.assertFalse(path.middleFilter(
            middle_fprint,
            cons_rel_stats,
            descriptors,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry,
            fast,
            stable))

    def test_middleFilter_no_descriptor(self):
        middle_fprint = 'middle fprint'
        rel_stat = mock.Mock()
        rel_stat.digest = 'middle digest'
        cons_rel_stats = {'middle fprint': rel_stat}
        descriptors = {}
        fast = True
        stable = True
        exit_desc = 'exit desc'
        exit_status_entry = 'exit se'
        guard_desc = 'guard desc'
        guard_status_entry = 'guard se'

        self.assertFalse(path.middleFilter(
            middle_fprint,
            cons_rel_stats,
            descriptors,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry,
            fast,
            stable))

    def test_middleFilter_no_ntor_key(self):
        middle_fprint = 'middle fprint'
        rel_stat = mock.Mock()
        rel_stat.digest = 'middle digest'
        cons_rel_stats = {'middle fprint': rel_stat}
        desc = mock.Mock()
        desc.ntor_onion_key = None
        descriptors = {'middle digest': desc}
        fast = True
        stable = True
        exit_desc = 'exit desc'
        exit_status_entry = 'exit se'
        guard_desc = 'guard desc'
        guard_status_entry = 'guard se'

        self.assertFalse(path.middleFilter(
            middle_fprint,
            cons_rel_stats,
            descriptors,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry,
            fast,
            stable))

    def test_middleFilter_not_running(self):
        middle_fprint = 'middle fprint'
        rel_stat = mock.Mock()
        rel_stat.flags = ()
        rel_stat.digest = 'middle digest'
        cons_rel_stats = {'middle fprint': rel_stat}
        desc = mock.Mock()
        desc.ntor_onion_key = 'ntor-onion-key'
        descriptors = {'middle digest': desc}
        fast = True
        stable = True
        exit_desc = 'exit desc'
        exit_status_entry = 'exit se'
        guard_desc = 'guard desc'
        guard_status_entry = 'guard se'

        self.assertFalse(path.middleFilter(
            middle_fprint,
            cons_rel_stats,
            descriptors,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry,
            fast,
            stable))

    def test_middleFilter_want_fast_no_fast(self):
        middle_fprint = 'middle fprint'
        rel_stat = mock.Mock()
        rel_stat.flags = (Flag.RUNNING)
        rel_stat.digest = 'middle digest'
        cons_rel_stats = {'middle fprint': rel_stat}
        desc = mock.Mock()
        desc.ntor_onion_key = 'ntor-onion-key'
        descriptors = {'middle digest': desc}
        fast = True
        stable = True
        exit_desc = 'exit desc'
        exit_status_entry = 'exit se'
        guard_desc = 'guard desc'
        guard_status_entry = 'guard se'

        self.assertFalse(path.middleFilter(
            middle_fprint,
            cons_rel_stats,
            descriptors,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry,
            fast,
            stable))

    def test_middleFilter_want_stable_no_stable(self):
        middle_fprint = 'middle fprint'
        rel_stat = mock.Mock()
        rel_stat.flags = (Flag.RUNNING, Flag.FAST)
        rel_stat.digest = 'middle digest'
        cons_rel_stats = {'middle fprint': rel_stat}
        desc = mock.Mock()
        desc.ntor_onion_key = 'ntor-onion-key'
        descriptors = {'middle digest': desc}
        fast = True
        stable = True
        exit_desc = 'exit desc'
        exit_status_entry = 'exit se'
        guard_desc = 'guard desc'
        guard_status_entry = 'guard se'

        self.assertFalse(path.middleFilter(
            middle_fprint,
            cons_rel_stats,
            descriptors,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry,
            fast,
            stable))

    @mock.patch('oppy.path.util.nodeUsableWithOther', return_value=False)
    def test_middleFilter_not_usable_with_exit(self, mock_nuwo):
        middle_fprint = 'middle fprint'
        rel_stat = mock.Mock()
        rel_stat.flags = (Flag.RUNNING, Flag.FAST, Flag.STABLE)
        rel_stat.digest = 'middle digest'
        cons_rel_stats = {'middle fprint': rel_stat}
        desc = mock.Mock()
        desc.ntor_onion_key = 'ntor-onion-key'
        descriptors = {'middle digest': desc}
        fast = True
        stable = True
        exit_desc = 'exit desc'
        exit_status_entry = 'exit se'
        guard_desc = 'guard desc'
        guard_status_entry = 'guard se'

        self.assertFalse(path.middleFilter(
            middle_fprint,
            cons_rel_stats,
            descriptors,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry,
            fast,
            stable))

    @mock.patch('oppy.path.util.nodeUsableWithOther', return_value='test val')
    def test_middleFilter(self, mock_nuwo):
        middle_fprint = 'middle fprint'
        rel_stat = mock.Mock()
        rel_stat.flags = (Flag.RUNNING, Flag.FAST, Flag.STABLE)
        rel_stat.digest = 'middle digest'
        cons_rel_stats = {'middle fprint': rel_stat}
        desc = mock.Mock()
        desc.ntor_onion_key = 'ntor-onion-key'
        descriptors = {'middle digest': desc}
        fast = True
        stable = True
        exit_desc = 'exit desc'
        exit_status_entry = 'exit se'
        guard_desc = 'guard desc'
        guard_status_entry = 'guard se'

        self.assertEqual(path.middleFilter(
            middle_fprint,
            cons_rel_stats,
            descriptors,
            exit_desc,
            exit_status_entry,
            guard_desc,
            guard_status_entry,
            fast,
            stable), 'test val')
