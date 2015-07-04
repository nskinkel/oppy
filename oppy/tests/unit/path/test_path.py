import mock

from twisted.internet import defer
from twisted.trial import unittest

from stem import Flag

import oppy.path.path as path


DEFAULT_FAST = True
DEFAULT_STABLE = True
DEFAULT_INTERNAL = False
DEFAULT_IP = None
DEFAULT_PORT = None


class PathTest(unittest.TestCase):

    @mock.patch('oppy.netstatus.netstatus.NetStatus', autospec=True)
    @mock.patch('oppy.history.guards.GuardManager', autospec=True)
    def setUp(self, gm, ns):
        self.gm = gm
        self.ns = ns

        self.mock_bw_weights = mock.Mock()
        self.mock_bwweightscale = mock.Mock()
        self.mock_routers = mock.Mock()
        self.mock_consensus = mock.Mock()
        self.mock_descriptors = mock.MagicMock()
        self.mock_guards = mock.Mock()
        self.mock_consensus.routers = self.mock_routers
        self.mock_consensus.bandwidth_weights = self.mock_bw_weights

        self.ns.getConsensus.return_value = defer.succeed(self.mock_consensus)
        self.ns.getDescriptors.return_value = defer.succeed(
                                                        self.mock_descriptors)
        self.gm.getUsableGuards.return_value = defer.succeed(self.mock_guards)

    def test_path_obj_construction(self):
        from oppy.path.path import Path

        mock_entry = mock.Mock()
        mock_middle = mock.Mock()
        mock_exit = mock.Mock()

        p = Path(mock_entry, mock_middle, mock_exit)

        self.assertEqual(p.entry, mock_entry)
        self.assertEqual(p.middle, mock_middle)
        self.assertEqual(p.exit, mock_exit)

    @mock.patch('oppy.path.path.selectExitNode')
    @mock.patch('oppy.path.path.selectGuardNode')
    @mock.patch('oppy.path.path.selectMiddleNode')
    def test_getPath_defaults(self, mock_select_middle, mock_select_guard,
                              mock_select_exit):
        mock_exit = mock.Mock()
        mock_middle = mock.Mock()
        mock_guard = mock.Mock()

        self.mock_descriptors[mock_exit].return_value = mock_exit
        self.mock_descriptors[mock_middle].return_value = mock_middle
        self.mock_descriptors[mock_guard].return_value = mock_guard

        mock_select_exit.return_value = mock_exit
        mock_select_middle.return_value = mock_middle
        mock_select_guard.return_value = mock_guard

        ret = path.getPath(self.ns, self.gm)

        self.assertEqual(mock_select_exit.call_count, 1)
        self.assertEqual(mock_select_exit.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE,
                                    DEFAULT_INTERNAL, DEFAULT_IP,
                                    DEFAULT_PORT)])

        self.assertEqual(mock_select_guard.call_count, 1)
        self.assertEqual(mock_select_guard.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    self.mock_guards, DEFAULT_FAST,
                                    DEFAULT_STABLE, mock_exit)])

        self.assertEqual(mock_select_middle.call_count, 1)
        self.assertEqual(mock_select_middle.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE,
                                    mock_exit, mock_guard)])

        self.assertEqual(self.successResultOf(ret),
                         path.Path(
                            self.mock_descriptors[mock_guard],
                            self.mock_descriptors[mock_middle],
                            self.mock_descriptors[mock_exit]))

    @mock.patch('oppy.path.path.selectExitNode')
    @mock.patch('oppy.path.path.selectGuardNode')
    @mock.patch('oppy.path.path.selectMiddleNode')
    def test_getPath_exit_request_host_port(self, mock_select_middle,
                                            mock_select_guard,
                                            mock_select_exit):
        mock_exit_request = mock.Mock()
        mock_exit_request.addr = None
        mock_exit_request.host = 'test.org'
        mock_exit_request.port = 0

        mock_exit = mock.Mock()
        mock_middle = mock.Mock()
        mock_guard = mock.Mock()

        self.mock_descriptors[mock_exit].return_value = mock_exit
        self.mock_descriptors[mock_middle].return_value = mock_middle
        self.mock_descriptors[mock_guard].return_value = mock_guard

        mock_select_exit.return_value = mock_exit
        mock_select_middle.return_value = mock_middle
        mock_select_guard.return_value = mock_guard

        ret = path.getPath(self.ns, self.gm, exit_request=mock_exit_request)

        self.assertEqual(mock_select_exit.call_count, 1)
        self.assertEqual(mock_select_exit.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE,
                                    DEFAULT_INTERNAL, None,
                                    0)])

    @mock.patch('oppy.path.path.selectExitNode')
    @mock.patch('oppy.path.path.selectGuardNode')
    @mock.patch('oppy.path.path.selectMiddleNode')
    def test_getPath_exit_request_addr_port(self, mock_select_middle,
                                            mock_select_guard,
                                            mock_select_exit):
        mock_exit_request = mock.Mock()
        mock_exit_request.addr = '127.0.0.1'
        mock_exit_request.host = None
        mock_exit_request.port = 0

        mock_exit = mock.Mock()
        mock_middle = mock.Mock()
        mock_guard = mock.Mock()

        self.mock_descriptors[mock_exit].return_value = mock_exit
        self.mock_descriptors[mock_middle].return_value = mock_middle
        self.mock_descriptors[mock_guard].return_value = mock_guard

        mock_select_exit.return_value = mock_exit
        mock_select_middle.return_value = mock_middle
        mock_select_guard.return_value = mock_guard

        ret = path.getPath(self.ns, self.gm, exit_request=mock_exit_request)

        self.assertEqual(mock_select_exit.call_count, 1)
        self.assertEqual(mock_select_exit.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE,
                                    DEFAULT_INTERNAL, '127.0.0.1',
                                    0)])

    @mock.patch('oppy.path.path.selectExitNode')
    @mock.patch('oppy.path.path.selectGuardNode')
    @mock.patch('oppy.path.path.selectMiddleNode')
    def test_getPath_no_fast_yes_stable(self, mock_select_middle,
                                        mock_select_guard, mock_select_exit):
        mock_exit = mock.Mock()
        mock_middle = mock.Mock()
        mock_guard = mock.Mock()

        self.mock_descriptors[mock_exit].return_value = mock_exit
        self.mock_descriptors[mock_middle].return_value = mock_middle
        self.mock_descriptors[mock_guard].return_value = mock_guard

        mock_select_exit.return_value = mock_exit
        mock_select_middle.return_value = mock_middle
        mock_select_guard.return_value = mock_guard

        ret = path.getPath(self.ns, self.gm, fast=False)

        self.assertEqual(mock_select_exit.call_count, 1)
        self.assertEqual(mock_select_exit.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    False, DEFAULT_STABLE,
                                    DEFAULT_INTERNAL, DEFAULT_IP,
                                    DEFAULT_PORT)])

        self.assertEqual(mock_select_guard.call_count, 1)
        self.assertEqual(mock_select_guard.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    self.mock_guards, False,
                                    DEFAULT_STABLE, mock_exit)])

        self.assertEqual(mock_select_middle.call_count, 1)
        self.assertEqual(mock_select_middle.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    False, DEFAULT_STABLE,
                                    mock_exit, mock_guard)])

        self.assertEqual(self.successResultOf(ret),
                         path.Path(
                            self.mock_descriptors[mock_guard],
                            self.mock_descriptors[mock_middle],
                            self.mock_descriptors[mock_exit]))

    @mock.patch('oppy.path.path.selectExitNode')
    @mock.patch('oppy.path.path.selectGuardNode')
    @mock.patch('oppy.path.path.selectMiddleNode')
    def test_getPath_yes_fast_no_stable(self, mock_select_middle,
                                        mock_select_guard, mock_select_exit):
        DEFAULT_FAST = True
        DEFAULT_STABLE = True
        DEFAULT_INTERNAL = False
        DEFAULT_IP = None
        DEFAULT_PORT = None

        mock_exit = mock.Mock()
        mock_middle = mock.Mock()
        mock_guard = mock.Mock()

        self.mock_descriptors[mock_exit].return_value = mock_exit
        self.mock_descriptors[mock_middle].return_value = mock_middle
        self.mock_descriptors[mock_guard].return_value = mock_guard

        mock_select_exit.return_value = mock_exit
        mock_select_middle.return_value = mock_middle
        mock_select_guard.return_value = mock_guard

        ret = path.getPath(self.ns, self.gm, fast=True, stable=False)

        self.assertEqual(mock_select_exit.call_count, 1)
        self.assertEqual(mock_select_exit.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    True, False,
                                    DEFAULT_INTERNAL, DEFAULT_IP,
                                    DEFAULT_PORT)])

        self.assertEqual(mock_select_guard.call_count, 1)
        self.assertEqual(mock_select_guard.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    self.mock_guards, True,
                                    False, mock_exit)])

        self.assertEqual(mock_select_middle.call_count, 1)
        self.assertEqual(mock_select_middle.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    True, False,
                                    mock_exit, mock_guard)])

        self.assertEqual(self.successResultOf(ret),
                         path.Path(
                            self.mock_descriptors[mock_guard],
                            self.mock_descriptors[mock_middle],
                            self.mock_descriptors[mock_exit]))

    # this test is equivalent to just calling getPath with default args
    def test_getPath_no_fast_no_stable(self):
        pass

    @mock.patch('oppy.path.path.selectExitNode')
    @mock.patch('oppy.path.path.selectGuardNode')
    @mock.patch('oppy.path.path.selectMiddleNode')
    def test_getPath_internal_yes(self, mock_select_middle, mock_select_guard,
                                  mock_select_exit):
        mock_exit = mock.Mock()
        mock_middle = mock.Mock()
        mock_guard = mock.Mock()

        self.mock_descriptors[mock_exit].return_value = mock_exit
        self.mock_descriptors[mock_middle].return_value = mock_middle
        self.mock_descriptors[mock_guard].return_value = mock_guard

        mock_select_exit.return_value = mock_exit
        mock_select_middle.return_value = mock_middle
        mock_select_guard.return_value = mock_guard

        ret = path.getPath(self.ns, self.gm, internal=True)

        self.assertEqual(mock_select_exit.call_count, 1)
        self.assertEqual(mock_select_exit.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE,
                                    True, DEFAULT_IP,
                                    DEFAULT_PORT)])

    @mock.patch('oppy.path.path.selectExitNode')
    @mock.patch('oppy.path.path.selectGuardNode')
    @mock.patch('oppy.path.path.selectMiddleNode')
    def test_getPath_no_usable_guards(self, mock_select_middle,
                                      mock_select_guard, mock_select_exit):
        from oppy.path.exceptions import NoUsableGuardsException

        mock_exit = mock.Mock()
        mock_middle = mock.Mock()
        mock_guard = mock.Mock()

        mock_select_guard.side_effect = NoUsableGuardsException()

        self.mock_descriptors[mock_exit].return_value = mock_exit
        self.mock_descriptors[mock_middle].return_value = mock_middle
        self.mock_descriptors[mock_guard].return_value = mock_guard

        mock_select_exit.return_value = mock_exit
        mock_select_middle.return_value = mock_middle
        mock_select_guard.return_value = mock_guard


        ret = path.getPath(self.ns, self.gm)

        self.assertEqual(self.failureResultOf(ret).trap(NoUsableGuardsException),
                         NoUsableGuardsException)

        self.assertEqual(mock_select_exit.call_count, 1)
        self.assertEqual(mock_select_exit.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE,
                                    DEFAULT_INTERNAL, DEFAULT_IP,
                                    DEFAULT_PORT)])

        self.assertEqual(mock_select_guard.call_count, 1)
        self.assertEqual(mock_select_guard.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    self.mock_guards, DEFAULT_FAST,
                                    DEFAULT_STABLE, mock_exit)])

        self.assertEqual(mock_select_middle.call_count, 0)

    @mock.patch('oppy.path.path.selectExitNode')
    @mock.patch('oppy.path.path.selectGuardNode')
    @mock.patch('oppy.path.path.selectMiddleNode')
    def test_getPath_selection_failure(self, mock_select_middle,
                                       mock_select_guard, mock_select_exit):
        from oppy.path.exceptions import PathSelectionFailedException

        mock_exit = mock.Mock()
        mock_middle = mock.Mock()
        mock_guard = mock.Mock()

        mock_select_exit.side_effect = ValueError()

        self.mock_descriptors[mock_exit].return_value = mock_exit
        self.mock_descriptors[mock_middle].return_value = mock_middle
        self.mock_descriptors[mock_guard].return_value = mock_guard

        mock_select_exit.return_value = mock_exit
        mock_select_middle.return_value = mock_middle
        mock_select_guard.return_value = mock_guard


        ret = path.getPath(self.ns, self.gm)

        self.assertEqual(self.failureResultOf(ret).trap(PathSelectionFailedException),
                         PathSelectionFailedException)

        self.assertEqual(mock_select_exit.call_count, 1)
        self.assertEqual(mock_select_exit.call_args_list,
                         [mock.call(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE,
                                    DEFAULT_INTERNAL, DEFAULT_IP,
                                    DEFAULT_PORT)])

        self.assertEqual(mock_select_guard.call_count, 0)
        self.assertEqual(mock_select_middle.call_count, 0)

    @mock.patch('oppy.path.path.filterExits')
    @mock.patch('oppy.path.util.getPositionWeights')
    @mock.patch('oppy.path.util.getWeightedNodes')
    @mock.patch('oppy.path.util.selectWeightedNode')
    def test_selectExitNode_middle_weight(self, mock_selectWeightedNode,
                                          mock_getWeightedNodes,
                                          mock_getPositionWeights,
                                          mock_filterExits):

        mock_filterExits.return_value = ['t1', 't2']
        mock_getPositionWeights.return_value = 'posweights'
        mock_getWeightedNodes.return_value = 'weighted exits'
        mock_selectWeightedNode.return_value = 'retval'

        # request an internal exit to use middle node weight
        ret = path.selectExitNode(self.mock_bw_weights,
                                  path.DEFAULT_BWWEIGHTSCALE,
                                  self.mock_routers, self.mock_descriptors,
                                  DEFAULT_FAST, DEFAULT_STABLE,
                                  True, DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(mock_filterExits.call_count, 1)
        self.assertEqual(mock_filterExits.call_args_list,
                         [mock.call(self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE,
                                    True, DEFAULT_IP,
                                    DEFAULT_PORT)])

        self.assertEqual(mock_getPositionWeights.call_count, 1)
        self.assertEqual(mock_getPositionWeights.call_args_list,
                         [mock.call(['t1', 't2'], self.mock_routers, 'm',
                                    self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE)])

        self.assertEqual(mock_getWeightedNodes.call_count, 1)
        self.assertEqual(mock_getWeightedNodes.call_args_list,
                         [mock.call(['t1', 't2'], 'posweights')])

        mock_selectWeightedNode.assert_called_once_with('weighted exits')

        self.assertEqual(ret, 'retval')

    @mock.patch('oppy.path.path.filterExits')
    @mock.patch('oppy.path.util.getPositionWeights')
    @mock.patch('oppy.path.util.getWeightedNodes')
    @mock.patch('oppy.path.util.selectWeightedNode')
    def test_selectExitNode_exit_weight(self, mock_selectWeightedNode,
                                        mock_getWeightedNodes,
                                        mock_getPositionWeights,
                                        mock_filterExits):
        mock_filterExits.return_value = ['t1', 't2']
        mock_getPositionWeights.return_value = 'posweights'
        mock_getWeightedNodes.return_value = 'weighted exits'
        mock_selectWeightedNode.return_value = 'retval'

        # request an external exit to use exit node weight
        ret = path.selectExitNode(self.mock_bw_weights,
                                  path.DEFAULT_BWWEIGHTSCALE,
                                  self.mock_routers, self.mock_descriptors,
                                  DEFAULT_FAST, DEFAULT_STABLE,
                                  False, DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(mock_filterExits.call_count, 1)
        self.assertEqual(mock_filterExits.call_args_list,
                         [mock.call(self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE,
                                    False, DEFAULT_IP,
                                    DEFAULT_PORT)])

        self.assertEqual(mock_getPositionWeights.call_count, 1)
        self.assertEqual(mock_getPositionWeights.call_args_list,
                         [mock.call(['t1', 't2'], self.mock_routers, 'e',
                                    self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE)])

        self.assertEqual(mock_getWeightedNodes.call_count, 1)
        self.assertEqual(mock_getWeightedNodes.call_args_list,
                         [mock.call(['t1', 't2'], 'posweights')])

        mock_selectWeightedNode.assert_called_once_with('weighted exits')

        self.assertEqual(ret, 'retval')

    @mock.patch('oppy.path.path.filterExits')
    @mock.patch('oppy.path.util.getPositionWeights')
    @mock.patch('oppy.path.util.getWeightedNodes')
    @mock.patch('oppy.path.util.selectWeightedNode')
    def test_selectExitNode_one_usable_nodes(self, mock_selectWeightedNode,
                                            mock_getWeightedNodes,
                                            mock_getPositionWeights,
                                            mock_filterExits):
        mock_filterExits.return_value = ['t1']

        ret = path.selectExitNode(self.mock_bw_weights,
                                  path.DEFAULT_BWWEIGHTSCALE,
                                  self.mock_routers, self.mock_descriptors,
                                  DEFAULT_FAST, DEFAULT_STABLE,
                                  DEFAULT_INTERNAL, DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(mock_filterExits.call_count, 1)
        self.assertEqual(mock_filterExits.call_args_list,
                         [mock.call(self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE,
                                    DEFAULT_INTERNAL, DEFAULT_IP,
                                    DEFAULT_PORT)])

        self.assertEqual(mock_getPositionWeights.call_count, 0)
        self.assertEqual(mock_getWeightedNodes.call_count, 0)
        self.assertEqual(mock_selectWeightedNode.call_count, 0)
        self.assertEqual(ret, 't1')

    @mock.patch('oppy.path.path.filterExits')
    @mock.patch('oppy.path.util.getPositionWeights')
    @mock.patch('oppy.path.util.getWeightedNodes')
    @mock.patch('oppy.path.util.selectWeightedNode')
    def test_selectExitNode_no_usable_nodes(self, mock_selectWeightedNode,
                                             mock_getWeightedNodes,
                                             mock_getPositionWeights,
                                             mock_filterExits):
        mock_filterExits.return_value = []

        self.assertRaises(ValueError,
                          path.selectExitNode,
                          self.mock_bw_weights,
                          path.DEFAULT_BWWEIGHTSCALE,
                          self.mock_routers, self.mock_descriptors,
                          DEFAULT_FAST, DEFAULT_STABLE,
                          DEFAULT_INTERNAL, DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(mock_filterExits.call_count, 1)
        self.assertEqual(mock_filterExits.call_args_list,
                         [mock.call(self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE,
                                    DEFAULT_INTERNAL, DEFAULT_IP,
                                    DEFAULT_PORT)])

        self.assertEqual(mock_getPositionWeights.call_count, 0)
        self.assertEqual(mock_getWeightedNodes.call_count, 0)
        self.assertEqual(mock_selectWeightedNode.call_count, 0)

    @mock.patch('oppy.path.path.guardFilter')
    def test_selectGuardNode(self, mock_guardFilter):
        mock_guardFilter.return_value = True

        mock_exit = mock.Mock()

        ret = path.selectGuardNode(self.mock_bw_weights,
                                   path.DEFAULT_BWWEIGHTSCALE,
                                   self.mock_routers,
                                   self.mock_descriptors,
                                   ['retval'],
                                   DEFAULT_FAST, DEFAULT_STABLE,
                                   mock_exit)
        
        self.assertEqual(mock_guardFilter.call_count, 1)
        self.assertEqual(mock_guardFilter.call_args_list,
                         [mock.call('retval', self.mock_routers,
                                    self.mock_descriptors, DEFAULT_FAST,
                                    DEFAULT_STABLE, mock_exit)])

        self.assertEqual(ret, 'retval')

    @mock.patch('oppy.path.path.guardFilter')
    def test_selectGuardNode_no_usable_node(self, mock_guardFilter):
        from oppy.path.exceptions import NoUsableGuardsException
        mock_guardFilter.return_value = False

        mock_exit = mock.Mock()

        self.assertRaises(NoUsableGuardsException,
                          path.selectGuardNode,
                          self.mock_bw_weights,
                          path.DEFAULT_BWWEIGHTSCALE,
                          self.mock_routers,
                          self.mock_descriptors,
                          ['retval'],
                          DEFAULT_FAST, DEFAULT_STABLE,
                          mock_exit)
        
        self.assertEqual(mock_guardFilter.call_count, 1)
        self.assertEqual(mock_guardFilter.call_args_list,
                         [mock.call('retval', self.mock_routers,
                                    self.mock_descriptors, DEFAULT_FAST,
                                    DEFAULT_STABLE, mock_exit)])

    @mock.patch('oppy.path.path.filterMiddles')
    @mock.patch('oppy.path.util.getPositionWeights')
    @mock.patch('oppy.path.util.getWeightedNodes')
    @mock.patch('oppy.path.util.selectWeightedNode')
    def test_selectMiddleNodes(self, mock_selectWeightedNode,
                               mock_getWeightedNodes, mock_getPositionWeights,
                               mock_filterMiddles):
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()

        mock_filterMiddles.return_value = ['ret1', 'ret2']
        mock_getPositionWeights.return_value = 'pos weights'
        mock_getWeightedNodes.return_value = 'weighted nodes'
        mock_selectWeightedNode.return_value = 'retval'

        ret = path.selectMiddleNode(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers,
                                    self.mock_descriptors, DEFAULT_FAST,
                                    DEFAULT_STABLE, mock_exit, mock_guard)

        self.assertEqual(mock_filterMiddles.call_count, 1)
        self.assertEqual(mock_filterMiddles.call_args_list,
                         [mock.call(self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE, mock_exit,
                                    mock_guard)])

        self.assertEqual(mock_getPositionWeights.call_count, 1)
        self.assertEqual(mock_getPositionWeights.call_args_list,
                         [mock.call(['ret1', 'ret2'], self.mock_routers, 'm',
                                    self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE)])

        self.assertEqual(mock_getWeightedNodes.call_count, 1)
        self.assertEqual(mock_getWeightedNodes.call_args_list,
                         [mock.call(['ret1', 'ret2'], 'pos weights')])

        mock_selectWeightedNode.assert_called_once_with('weighted nodes')

        self.assertEqual(ret, 'retval')

    @mock.patch('oppy.path.path.filterMiddles')
    @mock.patch('oppy.path.util.getPositionWeights')
    @mock.patch('oppy.path.util.getWeightedNodes')
    @mock.patch('oppy.path.util.selectWeightedNode')
    def test_selectMiddleNode_no_usable_node(self, mock_selectWeightedNode,
                                             mock_getWeightedNodes,
                                             mock_getPositionWeights,
                                             mock_filterMiddles):
        mock_filterMiddles.return_value = []

        mock_exit = mock.Mock()
        mock_guard = mock.Mock()

        self.assertRaises(ValueError,
                          path.selectMiddleNode,
                          self.mock_bw_weights,
                          path.DEFAULT_BWWEIGHTSCALE,
                          self.mock_routers,
                          self.mock_descriptors, DEFAULT_FAST,
                          DEFAULT_STABLE, mock_exit, mock_guard)

        self.assertEqual(mock_filterMiddles.call_count, 1)
        self.assertEqual(mock_filterMiddles.call_args_list,
                         [mock.call(self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE, mock_exit,
                                    mock_guard)])

        self.assertEqual(mock_getPositionWeights.call_count, 0)
        self.assertEqual(mock_getWeightedNodes.call_count, 0)
        self.assertEqual(mock_selectWeightedNode.call_count, 0)

    @mock.patch('oppy.path.path.filterMiddles')
    @mock.patch('oppy.path.util.getPositionWeights')
    @mock.patch('oppy.path.util.getWeightedNodes')
    @mock.patch('oppy.path.util.selectWeightedNode')
    def test_selectMiddleNode_one_usable_node(self, mock_selectWeightedNode,
                                              mock_getWeightedNodes,
                                              mock_getPositionWeights,
                                              mock_filterMiddles):
        mock_filterMiddles.return_value = ['retval']

        mock_exit = mock.Mock()
        mock_guard = mock.Mock()

        ret = path.selectMiddleNode(self.mock_bw_weights,
                                    path.DEFAULT_BWWEIGHTSCALE,
                                    self.mock_routers,
                                    self.mock_descriptors, DEFAULT_FAST,
                                    DEFAULT_STABLE, mock_exit, mock_guard)

        self.assertEqual(mock_filterMiddles.call_count, 1)
        self.assertEqual(mock_filterMiddles.call_args_list,
                         [mock.call(self.mock_routers, self.mock_descriptors,
                                    DEFAULT_FAST, DEFAULT_STABLE, mock_exit,
                                    mock_guard)])

        self.assertEqual(mock_getPositionWeights.call_count, 0)
        self.assertEqual(mock_getWeightedNodes.call_count, 0)
        self.assertEqual(mock_selectWeightedNode.call_count, 0)

        self.assertEqual(ret, 'retval')

    @mock.patch('oppy.path.path.exitFilter')
    def test_filterExits_yes(self, mock_exitFilter):
        mock_consensus_keyvals = ['v1', 'v2']

        mock_exitFilter.return_value = True

        ret = path.filterExits(mock_consensus_keyvals, self.mock_descriptors,
                               DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                               DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(mock_exitFilter.call_count, 2)
        self.assertEqual(mock_exitFilter.call_args_list,
                         [
                            mock.call('v1', mock_consensus_keyvals,
                                      self.mock_descriptors, DEFAULT_FAST,
                                      DEFAULT_STABLE, DEFAULT_INTERNAL,
                                      DEFAULT_IP, DEFAULT_PORT),
                            mock.call('v2', mock_consensus_keyvals,
                                      self.mock_descriptors, DEFAULT_FAST,
                                      DEFAULT_STABLE, DEFAULT_INTERNAL,
                                      DEFAULT_IP, DEFAULT_PORT),
                         ]
        )
        self.assertEqual(ret, ['v1', 'v2'])

    @mock.patch('oppy.path.path.exitFilter')
    def test_filterExits_no(self, mock_exitFilter):
        mock_consensus_keyvals = ['v1', 'v2']

        mock_exitFilter.return_value = False

        ret = path.filterExits(mock_consensus_keyvals, self.mock_descriptors,
                               DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                               DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(mock_exitFilter.call_count, 2)
        self.assertEqual(mock_exitFilter.call_args_list,
                         [
                            mock.call('v1', mock_consensus_keyvals,
                                      self.mock_descriptors, DEFAULT_FAST,
                                      DEFAULT_STABLE, DEFAULT_INTERNAL,
                                      DEFAULT_IP, DEFAULT_PORT),
                            mock.call('v2', mock_consensus_keyvals,
                                      self.mock_descriptors, DEFAULT_FAST,
                                      DEFAULT_STABLE, DEFAULT_INTERNAL,
                                      DEFAULT_IP, DEFAULT_PORT),
                         ]
        )
        self.assertEqual(ret, [])

    @mock.patch('oppy.path.path.middleFilter')
    def test_filterMiddles_yes(self, mock_middleFilter):
        mock_consensus_keyvals = ['v1', 'v2']

        mock_exit = mock.Mock()
        mock_guard = mock.Mock()

        mock_middleFilter.return_value = True

        ret = path.filterMiddles(mock_consensus_keyvals,
                                 self.mock_descriptors,
                                 DEFAULT_FAST, DEFAULT_STABLE,
                                 mock_exit, mock_guard)

        self.assertEqual(mock_middleFilter.call_count, 2)
        self.assertEqual(mock_middleFilter.call_args_list,
                         [
                            mock.call('v1', mock_consensus_keyvals,
                                      self.mock_descriptors, mock_exit,
                                      mock_guard, DEFAULT_FAST,
                                      DEFAULT_STABLE),
                            mock.call('v2', mock_consensus_keyvals,
                                      self.mock_descriptors, mock_exit,
                                      mock_guard, DEFAULT_FAST,
                                      DEFAULT_STABLE)
                         ]
        )
        self.assertEqual(ret, ['v1', 'v2'])

    @mock.patch('oppy.path.path.middleFilter')
    def test_filterMiddles_no(self, mock_middleFilter):
        mock_consensus_keyvals = ['v1', 'v2']

        mock_exit = mock.Mock()
        mock_guard = mock.Mock()

        mock_middleFilter.return_value = False

        ret = path.filterMiddles(mock_consensus_keyvals,
                                 self.mock_descriptors,
                                 DEFAULT_FAST, DEFAULT_STABLE,
                                 mock_exit, mock_guard)

        self.assertEqual(mock_middleFilter.call_count, 2)
        self.assertEqual(mock_middleFilter.call_args_list,
                         [
                            mock.call('v1', mock_consensus_keyvals,
                                      self.mock_descriptors, mock_exit,
                                      mock_guard, DEFAULT_FAST,
                                      DEFAULT_STABLE),
                            mock.call('v2', mock_consensus_keyvals,
                                      self.mock_descriptors, mock_exit,
                                      mock_guard, DEFAULT_FAST,
                                      DEFAULT_STABLE)
                         ]
        )
        self.assertEqual(ret, [])

    def test_exitFilter_no_consensus_entry(self):
        mock_cons_rel_stats = {} 

        ret = path.exitFilter(mock.Mock(),
                              mock_cons_rel_stats, self.mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                              DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(ret, False)

    def test_exitFilter_no_descriptors_entry(self):
        mock_exit = mock.Mock()
        mock_cons_rel_stats = {mock_exit: mock_exit}
        mock_descriptors = {}

        ret = path.exitFilter(mock_exit,
                              mock_cons_rel_stats, mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                              DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(ret, False)

    def test_exitFilter_no_ntor_key(self):
        mock_exit = mock.Mock()
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = None
        mock_desc.hibernating = False

        mock_cons_rel_stats = {mock_exit: mock_exit}
        mock_descriptors = {mock_exit: mock_desc}

        ret = path.exitFilter(mock_exit,
                              mock_cons_rel_stats, mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                              DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(ret, False)

    def test_exitFilter_hibernating(self):
        mock_exit = mock.Mock()
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = mock.Mock()
        mock_desc.hibernating = True

        mock_cons_rel_stats = {mock_exit: mock_exit}
        mock_descriptors = {mock_exit: mock_desc}

        ret = path.exitFilter(mock_exit,
                              mock_cons_rel_stats, mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                              DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(ret, False)

    def test_exitFilter_badexit_flag(self):
        mock_exit = mock.Mock()
        mock_rs_entry = mock.Mock()
        mock_rs_entry.flags = [Flag.BADEXIT]
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = mock.Mock()
        mock_desc.hibernating = False

        mock_cons_rel_stats = {mock_exit: mock_rs_entry}
        mock_descriptors = {mock_exit: mock_desc}

        ret = path.exitFilter(mock_exit,
                              mock_cons_rel_stats, mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                              DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(ret, False)

    def test_exitFilter_no_running_flag(self):
        mock_exit = mock.Mock()
        mock_rs_entry = mock.Mock()
        mock_rs_entry.flags = []
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = mock.Mock()
        mock_desc.hibernating = False

        mock_cons_rel_stats = {mock_exit: mock_rs_entry}
        mock_descriptors = {mock_exit: mock_desc}

        ret = path.exitFilter(mock_exit,
                              mock_cons_rel_stats, mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                              DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(ret, False)

    def test_exitFilter_no_valid_flag(self):
        mock_exit = mock.Mock()
        mock_rs_entry = mock.Mock()
        mock_rs_entry.flags = [Flag.RUNNING]
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = mock.Mock()
        mock_desc.hibernating = False

        mock_cons_rel_stats = {mock_exit: mock_rs_entry}
        mock_descriptors = {mock_exit: mock_desc}

        ret = path.exitFilter(mock_exit,
                              mock_cons_rel_stats, mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                              DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(ret, False)

    def test_exitFilter_want_fast_no_flag(self):
        mock_exit = mock.Mock()
        mock_rs_entry = mock.Mock()
        mock_rs_entry.flags = [Flag.RUNNING, Flag.VALID]
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = mock.Mock()
        mock_desc.hibernating = False

        mock_cons_rel_stats = {mock_exit: mock_rs_entry}
        mock_descriptors = {mock_exit: mock_desc}

        ret = path.exitFilter(mock_exit,
                              mock_cons_rel_stats, mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                              DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(ret, False)

    def test_exitFilter_want_stable_no_flag(self):
        mock_exit = mock.Mock()
        mock_rs_entry = mock.Mock()
        mock_rs_entry.flags = [Flag.RUNNING, Flag.VALID, Flag.FAST]
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = mock.Mock()
        mock_desc.hibernating = False

        mock_cons_rel_stats = {mock_exit: mock_rs_entry}
        mock_descriptors = {mock_exit: mock_desc}

        ret = path.exitFilter(mock_exit,
                              mock_cons_rel_stats, mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                              DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(ret, False)

    @mock.patch('oppy.path.util.canExitToPort')
    @mock.patch('oppy.path.util.policyIsRejectStar')
    def test_exitFilter_internal(self, mock_policyIsRejectStar,
                                 mock_canExitToPort):
        mock_canExitToPort.return_value = False
        mock_policyIsRejectStar.return_value = True

        mock_exit = mock.Mock()
        mock_rs_entry = mock.Mock()
        mock_rs_entry.flags = [Flag.RUNNING, Flag.VALID, Flag.FAST,
                               Flag.STABLE]
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = mock.Mock()
        mock_desc.hibernating = False
        mock_desc.exit_policy = mock.Mock()
        mock_desc.exit_policy.can_exit_to = mock.Mock()
        mock_desc.exit_policy.can_exit_to.return_value = False

        mock_cons_rel_stats = {mock_exit: mock_rs_entry}
        mock_descriptors = {mock_exit: mock_desc}

        ret = path.exitFilter(mock_exit,
                              mock_cons_rel_stats, mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, True,
                              DEFAULT_IP, DEFAULT_PORT)

        self.assertEqual(ret, True)

        self.assertEqual(mock_desc.exit_policy.can_exit_to.call_count, 0)
        self.assertEqual(mock_canExitToPort.call_count, 0)
        self.assertEqual(mock_policyIsRejectStar.call_count, 0)

    @mock.patch('oppy.path.util.canExitToPort')
    @mock.patch('oppy.path.util.policyIsRejectStar')
    def test_exitFilter_have_ip(self, mock_policyIsRejectStar,
                                 mock_canExitToPort):
        mock_canExitToPort.return_value = False
        mock_policyIsRejectStar.return_value = True

        mock_exit = mock.Mock()
        mock_rs_entry = mock.Mock()
        mock_rs_entry.flags = [Flag.RUNNING, Flag.VALID, Flag.FAST,
                               Flag.STABLE]
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = mock.Mock()
        mock_desc.hibernating = False
        mock_desc.exit_policy = mock.Mock()
        mock_desc.exit_policy.can_exit_to = mock.Mock()
        mock_desc.exit_policy.can_exit_to.return_value = True

        mock_cons_rel_stats = {mock_exit: mock_rs_entry}
        mock_descriptors = {mock_exit: mock_desc}

        ret = path.exitFilter(mock_exit,
                              mock_cons_rel_stats, mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                              '127.0.0.1', DEFAULT_PORT)

        self.assertEqual(ret, True)

        self.assertEqual(mock_desc.exit_policy.can_exit_to.call_count, 1)
        self.assertEqual(mock_desc.exit_policy.can_exit_to.call_args_list,
                         [mock.call('127.0.0.1', DEFAULT_PORT)])
        self.assertEqual(mock_canExitToPort.call_count, 0)
        self.assertEqual(mock_policyIsRejectStar.call_count, 0)

    @mock.patch('oppy.path.util.canExitToPort')
    @mock.patch('oppy.path.util.policyIsRejectStar')
    def test_exitFilter_no_ip_have_port(self, mock_policyIsRejectStar,
                                        mock_canExitToPort):
        mock_canExitToPort.return_value = True
        mock_policyIsRejectStar.return_value = True

        mock_exit = mock.Mock()
        mock_rs_entry = mock.Mock()
        mock_rs_entry.flags = [Flag.RUNNING, Flag.VALID, Flag.FAST,
                               Flag.STABLE]
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = mock.Mock()
        mock_desc.hibernating = False
        mock_desc.exit_policy = mock.Mock()
        mock_desc.exit_policy.can_exit_to = mock.Mock()
        mock_desc.exit_policy.can_exit_to.return_value = False

        mock_cons_rel_stats = {mock_exit: mock_rs_entry}
        mock_descriptors = {mock_exit: mock_desc}

        ret = path.exitFilter(mock_exit,
                              mock_cons_rel_stats, mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                              None, 0)

        self.assertEqual(ret, True)

        self.assertEqual(mock_desc.exit_policy.can_exit_to.call_count, 0)
        self.assertEqual(mock_canExitToPort.call_count, 1)
        self.assertEqual(mock_canExitToPort.call_args_list,
                         [mock.call(mock_desc, 0)])
        self.assertEqual(mock_policyIsRejectStar.call_count, 0)

    @mock.patch('oppy.path.util.canExitToPort')
    @mock.patch('oppy.path.util.policyIsRejectStar')
    def test_exitFilter_no_ip_no_port_no_reject_star(self,
                                                     mock_policyIsRejectStar,
                                                     mock_canExitToPort):
        mock_canExitToPort.return_value = False
        mock_policyIsRejectStar.return_value = False

        mock_exit = mock.Mock()
        mock_rs_entry = mock.Mock()
        mock_rs_entry.flags = [Flag.RUNNING, Flag.VALID, Flag.FAST,
                               Flag.STABLE]
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = mock.Mock()
        mock_desc.hibernating = False
        mock_desc.exit_policy = mock.Mock()
        mock_desc.exit_policy.can_exit_to = mock.Mock()
        mock_desc.exit_policy.can_exit_to.return_value = False

        mock_cons_rel_stats = {mock_exit: mock_rs_entry}
        mock_descriptors = {mock_exit: mock_desc}

        ret = path.exitFilter(mock_exit,
                              mock_cons_rel_stats, mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                              None, None)

        self.assertEqual(ret, True)

        self.assertEqual(mock_desc.exit_policy.can_exit_to.call_count, 0)
        self.assertEqual(mock_canExitToPort.call_count, 0)
        self.assertEqual(mock_policyIsRejectStar.call_count, 1)
        self.assertEqual(mock_policyIsRejectStar.call_args_list,
                         [mock.call(mock_desc.exit_policy)])

    @mock.patch('oppy.path.util.canExitToPort')
    @mock.patch('oppy.path.util.policyIsRejectStar')
    def test_exitFilter_no_ip_no_port_yes_reject_star(self,
                                                     mock_policyIsRejectStar,
                                                     mock_canExitToPort):
        mock_canExitToPort.return_value = False
        mock_policyIsRejectStar.return_value = True

        mock_exit = mock.Mock()
        mock_rs_entry = mock.Mock()
        mock_rs_entry.flags = [Flag.RUNNING, Flag.VALID, Flag.FAST,
                               Flag.STABLE]
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = mock.Mock()
        mock_desc.hibernating = False
        mock_desc.exit_policy = mock.Mock()
        mock_desc.exit_policy.can_exit_to = mock.Mock()
        mock_desc.exit_policy.can_exit_to.return_value = False

        mock_cons_rel_stats = {mock_exit: mock_rs_entry}
        mock_descriptors = {mock_exit: mock_desc}

        ret = path.exitFilter(mock_exit,
                              mock_cons_rel_stats, mock_descriptors,
                              DEFAULT_FAST, DEFAULT_STABLE, DEFAULT_INTERNAL,
                              None, None)

        self.assertEqual(ret, False)

        self.assertEqual(mock_desc.exit_policy.can_exit_to.call_count, 0)
        self.assertEqual(mock_canExitToPort.call_count, 0)
        self.assertEqual(mock_policyIsRejectStar.call_count, 1)
        self.assertEqual(mock_policyIsRejectStar.call_args_list,
                         [mock.call(mock_desc.exit_policy)])

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_guardFilter_no_consensus_entry(self, mock_nodeUsable):
        mock_cons_rel_stats = {} 
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()

        ret = path.guardFilter(mock_guard,
                               mock_cons_rel_stats, self.mock_descriptors,
                               DEFAULT_FAST, DEFAULT_STABLE, mock_exit)

        self.assertEqual(ret, False)
        self.assertEqual(mock_nodeUsable.call_count, 0)

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_guardFilter_no_descriptors_entry(self, mock_nodeUsable):
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_cons_rel_stats = {mock_guard: mock_guard}
        mock_descriptors = {}

        ret = path.guardFilter(mock_guard,
                               mock_cons_rel_stats, mock_descriptors,
                               DEFAULT_FAST, DEFAULT_STABLE, mock_exit)

        self.assertEqual(ret, False)
        self.assertEqual(mock_nodeUsable.call_count, 0)

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_guardFilter_want_fast_no_flag(self, mock_nodeUsable):
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_rel_stat = mock.Mock()
        mock_rel_stat.flags = []
        mock_desc = mock.Mock()
        mock_cons_rel_stats = {mock_guard: mock_rel_stat}
        mock_descriptors = {mock_guard: mock_desc}

        ret = path.guardFilter(mock_guard,
                               mock_cons_rel_stats, mock_descriptors,
                               True, DEFAULT_STABLE, mock_exit)

        self.assertEqual(ret, False)
        self.assertEqual(mock_nodeUsable.call_count, 0)

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_guardFilter_want_stable_no_flag(self, mock_nodeUsable):
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_rel_stat = mock.Mock()
        mock_rel_stat.flags = [Flag.FAST]
        mock_desc = mock.Mock()
        mock_cons_rel_stats = {mock_guard: mock_rel_stat}
        mock_descriptors = {mock_guard: mock_desc}

        ret = path.guardFilter(mock_guard,
                               mock_cons_rel_stats, mock_descriptors,
                               True, True, mock_exit)

        self.assertEqual(ret, False)
        self.assertEqual(mock_nodeUsable.call_count, 0)

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_guardFilter_usable_with_other_yes(self, mock_nodeUsable):
        mock_nodeUsable.return_value = True

        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_rel_stat = mock.Mock()
        mock_rel_stat.flags = [Flag.FAST, Flag.STABLE]
        mock_desc = mock.Mock()
        mock_cons_rel_stats = {mock_guard: mock_rel_stat}
        mock_descriptors = {mock_guard: mock_desc}

        ret = path.guardFilter(mock_guard,
                               mock_cons_rel_stats, mock_descriptors,
                               True, True, mock_exit)

        self.assertEqual(ret, True)
        self.assertEqual(mock_nodeUsable.call_count, 1)
        self.assertEqual(mock_nodeUsable.call_args_list,
                         [mock.call(mock_exit, mock_guard,
                                    mock_descriptors)])

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_guardFilter_usable_with_other_no(self, mock_nodeUsable):
        mock_nodeUsable.return_value = False

        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_rel_stat = mock.Mock()
        mock_rel_stat.flags = [Flag.FAST, Flag.STABLE]
        mock_desc = mock.Mock()
        mock_cons_rel_stats = {mock_guard: mock_rel_stat}
        mock_descriptors = {mock_guard: mock_desc}

        ret = path.guardFilter(mock_guard,
                               mock_cons_rel_stats, mock_descriptors,
                               True, True, mock_exit)

        self.assertEqual(ret, False)
        self.assertEqual(mock_nodeUsable.call_count, 1)
        self.assertEqual(mock_nodeUsable.call_args_list,
                         [mock.call(mock_exit, mock_guard,
                                    mock_descriptors)])

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_middleFilter_no_consensus_entry(self, mock_nodeUsable):
        mock_middle = mock.Mock()
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_cons_rel_stats = {} 

        ret = path.middleFilter(mock_middle,
                                mock_cons_rel_stats, self.mock_descriptors,
                                mock_exit, mock_guard,
                                DEFAULT_FAST, DEFAULT_STABLE)

        self.assertEqual(ret, False)
        self.assertEqual(mock_nodeUsable.call_count, 0)

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_middleFilter_no_descriptors_entry(self, mock_nodeUsable):
        mock_middle = mock.Mock()
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_rel_stat = mock.Mock()
        mock_cons_rel_stats = {mock_middle: mock_rel_stat}
        mock_descriptors = {}

        ret = path.middleFilter(mock_middle,
                                mock_cons_rel_stats, mock_descriptors,
                                mock_exit, mock_guard,
                                DEFAULT_FAST, DEFAULT_STABLE)

        self.assertEqual(ret, False)
        self.assertEqual(mock_nodeUsable.call_count, 0)

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_middleFilter_no_ntor_key(self, mock_nodeUsable):
        mock_middle = mock.Mock()
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_rel_stat = mock.Mock()
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = None
        mock_desc.hibernating = False
        mock_cons_rel_stats = {mock_middle: mock_rel_stat}
        mock_descriptors = {mock_middle: mock_desc}

        ret = path.middleFilter(mock_middle,
                                mock_cons_rel_stats, mock_descriptors,
                                mock_exit, mock_guard,
                                DEFAULT_FAST, DEFAULT_STABLE)

        self.assertEqual(ret, False)
        self.assertEqual(mock_nodeUsable.call_count, 0)

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_middleFilter_hibernating(self, mock_nodeUsable):
        mock_middle = mock.Mock()
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_rel_stat = mock.Mock()
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = 'key'
        mock_desc.hibernating = True
        mock_cons_rel_stats = {mock_middle: mock_rel_stat}
        mock_descriptors = {mock_middle: mock_desc}

        ret = path.middleFilter(mock_middle,
                                mock_cons_rel_stats, mock_descriptors,
                                mock_exit, mock_guard,
                                DEFAULT_FAST, DEFAULT_STABLE)

        self.assertEqual(ret, False)
        self.assertEqual(mock_nodeUsable.call_count, 0)

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_middleFilter_not_running(self, mock_nodeUsable):
        mock_middle = mock.Mock()
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_rel_stat = mock.Mock()
        mock_rel_stat.flags = []
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = 'key'
        mock_desc.hibernating = False
        mock_cons_rel_stats = {mock_middle: mock_rel_stat}
        mock_descriptors = {mock_middle: mock_desc}

        ret = path.middleFilter(mock_middle,
                                mock_cons_rel_stats, mock_descriptors,
                                mock_exit, mock_guard,
                                DEFAULT_FAST, DEFAULT_STABLE)

        self.assertEqual(ret, False)
        self.assertEqual(mock_nodeUsable.call_count, 0)

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_middleFilter_want_fast_no_flag(self, mock_nodeUsable):
        mock_middle = mock.Mock()
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_rel_stat = mock.Mock()
        mock_rel_stat.flags = [Flag.RUNNING]
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = 'key'
        mock_desc.hibernating = False
        mock_cons_rel_stats = {mock_middle: mock_rel_stat}
        mock_descriptors = {mock_middle: mock_desc}

        ret = path.middleFilter(mock_middle,
                                mock_cons_rel_stats, mock_descriptors,
                                mock_exit, mock_guard,
                                True, DEFAULT_STABLE)

        self.assertEqual(ret, False)
        self.assertEqual(mock_nodeUsable.call_count, 0)

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_middleFilter_want_stable_no_flag(self, mock_nodeUsable):
        mock_middle = mock.Mock()
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_rel_stat = mock.Mock()
        mock_rel_stat.flags = [Flag.RUNNING, Flag.FAST]
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = 'key'
        mock_desc.hibernating = False
        mock_cons_rel_stats = {mock_middle: mock_rel_stat}
        mock_descriptors = {mock_middle: mock_desc}

        ret = path.middleFilter(mock_middle,
                                mock_cons_rel_stats, mock_descriptors,
                                mock_exit, mock_guard,
                                True, True)

        self.assertEqual(ret, False)
        self.assertEqual(mock_nodeUsable.call_count, 0)

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_middleFilter_node_usable_no(self, mock_nodeUsable):
        mock_nodeUsable.return_value = False

        mock_middle = mock.Mock()
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_rel_stat = mock.Mock()
        mock_rel_stat.flags = [Flag.RUNNING, Flag.FAST, Flag.STABLE]
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = 'key'
        mock_desc.hibernating = False
        mock_cons_rel_stats = {mock_middle: mock_rel_stat}
        mock_descriptors = {mock_middle: mock_desc}

        ret = path.middleFilter(mock_middle,
                                mock_cons_rel_stats, mock_descriptors,
                                mock_exit, mock_guard,
                                True, True)

        self.assertEqual(ret, False)
        self.assertEqual(mock_nodeUsable.call_count, 1)
        # this returns False for this test, so only the first usable node
        # check gets run
        self.assertEqual(mock_nodeUsable.call_args_list,
                         [mock.call(mock_exit, mock_middle,
                                    mock_descriptors)])

    @mock.patch('oppy.path.util.nodeUsableWithOther')
    def test_middleFilter_node_usable_yes(self, mock_nodeUsable):
        mock_nodeUsable.return_value = True

        mock_middle = mock.Mock()
        mock_exit = mock.Mock()
        mock_guard = mock.Mock()
        mock_rel_stat = mock.Mock()
        mock_rel_stat.flags = [Flag.RUNNING, Flag.FAST, Flag.STABLE]
        mock_desc = mock.Mock()
        mock_desc.ntor_onion_key = 'key'
        mock_desc.hibernating = False
        mock_cons_rel_stats = {mock_middle: mock_rel_stat}
        mock_descriptors = {mock_middle: mock_desc}

        ret = path.middleFilter(mock_middle,
                                mock_cons_rel_stats, mock_descriptors,
                                mock_exit, mock_guard,
                                True, True)

        self.assertEqual(ret, True)
        # this returns True for this test, so a nodeUsable check happens
        # for both exit and guard
        self.assertEqual(mock_nodeUsable.call_count, 2)
        self.assertEqual(mock_nodeUsable.call_args_list,
                         [
                            mock.call(mock_exit, mock_middle,
                                      mock_descriptors),
                            mock.call(mock_guard, mock_middle,
                                      mock_descriptors)])
