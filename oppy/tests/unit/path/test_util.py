import mock

from twisted.internet import defer
from twisted.trial import unittest

from stem import Flag

import oppy.path.util as path_util


class PathUtilTest(unittest.TestCase):

    def setUp(self):
        self.bw_weights = {
            'Wgd': 0,
            'Wgg': 1,
            'Wgm': 2,
            'Wmd': 3,
            'Wmg': 4,
            'Wme': 5,
            'Wmm': 6,
            'Wed': 7,
            'Weg': 8,
            'Wee': 9,
            'Wem': 10,
        }

    @mock.patch('oppy.path.util.inSameFamily')
    @mock.patch('oppy.path.util.inSame16Subnet')
    def test_NodeUsableWithOther_no_equal_nodes(self, mock_subnet,
        mock_family):

        desc1 = 'desc1'
        se1 = mock.Mock()
        se1.fingerprint = 'fprint1'
        desc2 = 'desc1'
        se2 = mock.Mock()
        se2.fingerprint = 'fprint1'

        self.assertFalse(path_util.nodeUsableWithOther(
            desc1, se1, desc2, se2))
        self.assertEqual(mock_subnet.call_count, 0)
        self.assertEqual(mock_family.call_count, 0)

    @mock.patch('oppy.path.util.inSameFamily')
    @mock.patch('oppy.path.util.inSame16Subnet')
    def test_nodeUsableWithOther_no_in_same_family(self, mock_subnet,
                                                   mock_family):
        desc1 = 'desc1'
        se1 = mock.Mock()
        se1.fingerprint = 'fprint1'
        desc2 = 'desc2'
        se2 = mock.Mock()
        se2.fingerprint = 'fprint2'

        mock_family.return_value = True
        mock_subnet.return_value = False

        self.assertFalse(path_util.nodeUsableWithOther(
            desc1, se1, desc2, se2))

        self.assertEqual(mock_family.call_count, 1)
        self.assertEqual(mock_subnet.call_count, 0)

    @mock.patch('oppy.path.util.inSameFamily')
    @mock.patch('oppy.path.util.inSame16Subnet')
    def test_nodeUsableWithOther_no_in_same_16_subnet(self, mock_subnet,
                                                      mock_family):
        desc1 = 'desc1'
        se1 = mock.Mock()
        se1.fingerprint = 'fprint1'
        desc2 = 'desc2'
        se2 = mock.Mock()
        se2.fingerprint = 'fprint2'

        mock_family.return_value = False
        mock_subnet.return_value = True

        self.assertFalse(path_util.nodeUsableWithOther(
            desc1, se1, desc2, se2))

        self.assertEqual(mock_family.call_count, 1)
        self.assertEqual(mock_subnet.call_count, 1)

    @mock.patch('oppy.path.util.inSameFamily')
    @mock.patch('oppy.path.util.inSame16Subnet')
    def test_nodeUsableWithOther_yes(self, mock_subnet, mock_family):
        desc1 = 'desc1'
        se1 = mock.Mock()
        se1.fingerprint = 'fprint1'
        desc2 = 'desc2'
        se2 = mock.Mock()
        se2.fingerprint = 'fprint2'

        mock_family.return_value = False
        mock_subnet.return_value = False

        self.assertTrue(path_util.nodeUsableWithOther(
            desc1, se1, desc2, se2))

        self.assertEqual(mock_family.call_count, 1)
        self.assertEqual(mock_subnet.call_count, 1)


    @mock.patch('random.random')
    def test_selectWeightedNode_lt_mid_equal(self, mock_random):
        mock_node_1 = mock.Mock()
        mock_node_2 = mock.Mock()
        mock_node_3 = mock.Mock()
        mock_node_4 = mock.Mock()
        mock_node_5 = mock.Mock()

        mock_weighted_nodes = [
            (mock_node_1, 0.1),
            (mock_node_2, 0.3),
            (mock_node_3, 0.57),
            (mock_node_4, 0.78),
            (mock_node_5, 1.0),
        ]

        mock_random.return_value = 0.5
        # r < 0.57, so...
        # end = 2, mid = 1
        # then r > 0.3, so...
        # begin = 2, mid = 2
        # r < 0.57
        # mid == begin, so
        # return w[2][0]
        expected = mock_weighted_nodes[2][0]
        ret = path_util.selectWeightedNode(mock_weighted_nodes)
        self.assertEqual(ret, expected)

    def test_getWeightedNodes(self):
        mock_node_1 = mock.Mock()
        mock_node_2 = mock.Mock()
        mock_node_3 = mock.Mock()

        mock_nodes = [
            mock_node_1,
            mock_node_2,
            mock_node_3,
        ]

        mock_weights = {
            mock_node_1: 1.0,
            mock_node_2: 2.0,
            mock_node_3: 3.0,
        }

        ret = path_util.getWeightedNodes(mock_nodes, mock_weights)

        expected = [
            (mock_node_1, 1.0/6.0),
            (mock_node_2, 3.0/6.0),
            (mock_node_3, 6.0/6.0),
        ]

        self.assertEqual(ret, expected)

    def test_getWeightedNodes_total_weight_zero(self):
        mock_node_1 = mock.Mock()
        mock_node_2 = mock.Mock()
        mock_node_3 = mock.Mock()

        mock_nodes = [
            mock_node_1,
            mock_node_2,
            mock_node_3,
        ]

        mock_weights = {
            mock_node_1: 0.0,
            mock_node_2: 0.0,
            mock_node_3: 0.0,
        }

        self.assertRaises(ValueError,
                          path_util.getWeightedNodes,
                          mock_nodes,
                          mock_weights)

    @mock.patch('oppy.path.util.getBwweight')
    def test_getPositionWeights(self, mock_getBwweight):
        from oppy.path.path import DEFAULT_BWWEIGHTSCALE

        mock_getBwweight.return_value = 5

        mock_flags = mock.Mock()
        mock_bwweights = mock.Mock()
        mock_node = mock.Mock()
        mock_node.bandwidth = 100
        mock_rel_stats = {mock_node: mock_node}
        mock_nodes = [mock_node]

        ret = path_util.getPositionWeights(mock_nodes, mock_rel_stats, 'g',
                                           mock_bwweights,
                                           DEFAULT_BWWEIGHTSCALE)

        expected = (5.0 / DEFAULT_BWWEIGHTSCALE) * 100

        self.assertTrue(isinstance(ret[mock_node], float))
        self.assertEqual(ret[mock_node], expected)
        self.assertTrue(mock_getBwweight.call_count, 1)
        self.assertTrue(mock_getBwweight.call_args_list,
                        [mock.call(mock_flags, 'g', mock_bwweights)])

    def test_getBwweight_g_guard_and_exit(self):
        flags = [Flag.GUARD, Flag.EXIT]

        self.assertEqual(path_util.getBwweight(flags, 'g', self.bw_weights),
                         self.bw_weights['Wgd'])

    def test_getBwweight_g_just_guard(self):
        flags = [Flag.GUARD]

        self.assertEqual(path_util.getBwweight(flags, 'g', self.bw_weights),
                         self.bw_weights['Wgg'])

    def test_getBwweight_g_no_exit(self):
        flags = []

        self.assertEqual(path_util.getBwweight(flags, 'g', self.bw_weights),
                         self.bw_weights['Wgm'])

    def test_getBwweight_g_just_exit_fail(self):
        flags = [Flag.EXIT]

        self.assertRaises(ValueError,
                          path_util.getBwweight,
                          flags,
                          'g',
                          self.bw_weights)

    def test_getBwweight_m_guard_and_exit(self):
        flags = [Flag.GUARD, Flag.EXIT]

        self.assertEqual(path_util.getBwweight(flags, 'm', self.bw_weights),
                         self.bw_weights['Wmd'])

    def test_getBwweight_m_just_guard(self):
        flags = [Flag.GUARD]

        self.assertEqual(path_util.getBwweight(flags, 'm', self.bw_weights),
                         self.bw_weights['Wmg'])

    def test_getBwweight_m_just_exit(self):
        flags = [Flag.EXIT]

        self.assertEqual(path_util.getBwweight(flags, 'm', self.bw_weights),
                         self.bw_weights['Wme'])

    def test_getBwweight_m_not_guard_or_exit(self):
        flags = []

        self.assertEqual(path_util.getBwweight(flags, 'm', self.bw_weights),
                         self.bw_weights['Wmm'])

    def test_getBwweight_e_guard_and_exit(self):
        flags = [Flag.GUARD, Flag.EXIT]

        self.assertEqual(path_util.getBwweight(flags, 'e', self.bw_weights),
                         self.bw_weights['Wed'])

    def test_getBwweight_e_just_guard(self):
        flags = [Flag.GUARD]

        self.assertEqual(path_util.getBwweight(flags, 'e', self.bw_weights),
                         self.bw_weights['Weg'])

    def test_getBwweight_e_just_exit(self):
        flags = [Flag.EXIT]

        self.assertEqual(path_util.getBwweight(flags, 'e', self.bw_weights),
                         self.bw_weights['Wee'])

    def test_getBwweight_e_not_guard_or_exit(self):
        flags = []

        self.assertEqual(path_util.getBwweight(flags, 'e', self.bw_weights),
                         self.bw_weights['Wem'])

    def test_getBwweight_unknown_position_letter(self):
        flags = []

        self.assertRaises(ValueError,
                          path_util.getBwweight,
                          flags,
                          'x',
                          self.bw_weights)

    def test_inSameFamily_yes(self):
        mock_rel_stat1 = mock.Mock()
        mock_rel_stat2 = mock.Mock()

        mock_rel_stat1.fingerprint = u'fprint1'
        mock_rel_stat2.fingerprint = u'fprint2'

        mock_desc1 = mock.Mock()
        mock_desc2 = mock.Mock()

        mock_desc1.family = [u'$hey', u'$fprint2']
        mock_desc2.family = [u'$yo', u'$fprint1']

        self.assertTrue(path_util.inSameFamily(mock_desc1, mock_rel_stat1,
                                               mock_desc2, mock_rel_stat2))

    def test_inSameFamily_no_node1_lists_node2(self):
        mock_rel_stat1 = mock.Mock()
        mock_rel_stat2 = mock.Mock()

        mock_rel_stat1.fingerprint = u'fprint1'
        mock_rel_stat2.fingerprint = u'fprint2'

        mock_desc1 = mock.Mock()
        mock_desc2 = mock.Mock()

        mock_desc1.family = [u'$hey', u'$fprint2']
        mock_desc2.family = [u'$yo']

        self.assertFalse(path_util.inSameFamily(mock_desc1, mock_rel_stat1,
                                                mock_desc2, mock_rel_stat2))

    def test_inSameFamily_no_node1_no_list(self):
        mock_rel_stat1 = mock.Mock()
        mock_rel_stat2 = mock.Mock()

        mock_rel_stat1.fingerprint = u'fprint1'
        mock_rel_stat2.fingerprint = u'fprint2'

        mock_desc1 = mock.Mock()
        mock_desc2 = mock.Mock()

        mock_desc1.family = [u'$hey']
        mock_desc2.family = [u'$yo', u'$fprint1']

        self.assertFalse(path_util.inSameFamily(mock_desc1, mock_rel_stat1,
                                                mock_desc2, mock_rel_stat2))

    def test_inSameFamily_no_common_lists(self):
        mock_rel_stat1 = mock.Mock()
        mock_rel_stat2 = mock.Mock()

        mock_rel_stat1.fingerprint = u'fprint1'
        mock_rel_stat2.fingerprint = u'fprint2'

        mock_desc1 = mock.Mock()
        mock_desc2 = mock.Mock()

        mock_desc1.family = [u'$hey']
        mock_desc2.family = [u'$yo']

        self.assertFalse(path_util.inSameFamily(mock_desc1, mock_rel_stat1,
                                                mock_desc2, mock_rel_stat2))

    def test_inSame16Subnet_yes(self):
        ip1 = mock.Mock()
        ip1.address = u'162.233.1.2'
        ip2 = mock.Mock()
        ip2.address = u'162.233.3.4'

        self.assertTrue(path_util.inSame16Subnet(ip1, ip2))

        ip1.address = u'162.233.157.234'
        ip2.address = u'162.233.99.8'

        self.assertTrue(path_util.inSame16Subnet(ip1, ip2))

        ip1.address = u'1.1.1.1'
        ip2.address = u'1.1.1.1'

        self.assertTrue(path_util.inSame16Subnet(ip1, ip2))

    def test_inSame16Subnet_no(self):
        ip1 = mock.Mock()
        ip1.address = u'162.234.1.2'
        ip2 = mock.Mock()
        ip2.address = u'162.233.1.2'

        self.assertFalse(path_util.inSame16Subnet(ip1, ip2))

        ip1.address = u'162.233.157.234'
        ip2.address = u'161.233.157.234'

        self.assertFalse(path_util.inSame16Subnet(ip1, ip2))

        ip1.address = u'1.0.1.1'
        ip2.address = u'0.1.1.1'

        self.assertFalse(path_util.inSame16Subnet(ip1, ip2))
