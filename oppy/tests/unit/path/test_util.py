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
        node1 = 'test'
        node2 = node1

        self.assertFalse(path_util.nodeUsableWithOther(node1, node2,
                                                       mock.Mock()))
        self.assertEqual(mock_subnet.call_count, 0)
        self.assertEqual(mock_family.call_count, 0)

    @mock.patch('oppy.path.util.inSameFamily')
    @mock.patch('oppy.path.util.inSame16Subnet')
    def test_nodeUsableWithOther_no_in_same_family(self, mock_subnet,
                                                   mock_family):
        mock_family.return_value = True
        mock_subnet.return_value = False

        node1 = '1'
        node2 = '2'
        descriptors = mock.Mock()

        self.assertFalse(path_util.nodeUsableWithOther(node1, node2,
                                                       descriptors))
        self.assertEqual(mock_family.call_count, 1)
        self.assertEqual(mock_family.call_args_list,
                         [mock.call(node1, node2, descriptors)])
        self.assertEqual(mock_subnet.call_count, 0)

    @mock.patch('oppy.path.util.inSameFamily')
    @mock.patch('oppy.path.util.inSame16Subnet')
    def test_nodeUsableWithOther_no_in_same_16_subnet(self, mock_subnet,
                                                      mock_family):
        mock_family.return_value = False
        mock_subnet.return_value = True

        node1 = '1'
        node2 = '2'
        descriptors = mock.Mock()

        self.assertFalse(path_util.nodeUsableWithOther(node1, node2,
                                                       descriptors))
        self.assertEqual(mock_family.call_count, 1)
        self.assertEqual(mock_family.call_args_list,
                         [mock.call(node1, node2, descriptors)])
        self.assertEqual(mock_subnet.call_count, 1)
        self.assertEqual(mock_subnet.call_args_list,
                         [mock.call(node1, node2, descriptors)])

    @mock.patch('oppy.path.util.inSameFamily')
    @mock.patch('oppy.path.util.inSame16Subnet')
    def test_nodeUsableWithOther_yes(self, mock_subnet, mock_family):
        mock_family.return_value = False
        mock_subnet.return_value = False

        node1 = '1'
        node2 = '2'
        descriptors = mock.Mock()

        self.assertTrue(path_util.nodeUsableWithOther(node1, node2,
                                                      descriptors))
        self.assertEqual(mock_family.call_count, 1)
        self.assertEqual(mock_family.call_args_list,
                         [mock.call(node1, node2, descriptors)])
        self.assertEqual(mock_subnet.call_count, 1)
        self.assertEqual(mock_subnet.call_args_list,
                         [mock.call(node1, node2, descriptors)])

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

    def test_mightExitToPort_in_accept_range(self):
        desc = mock.Mock()
        mock_rule_1 = mock.Mock()
        mock_rule_1.min_port = 1
        mock_rule_1.max_port = 10
        mock_rule_1.is_accept = True
        desc.exit_policy = [mock_rule_1]

        self.assertTrue(path_util.mightExitToPort(desc, 8))

    def test_mightExitToPort_no_in_accept_range_with_address_wildcard(self):
        desc = mock.Mock()
        mock_rule_1 = mock.Mock()
        mock_rule_1.min_port = 1
        mock_rule_1.max_port = 10
        mock_rule_1.is_accept = False
        mock_rule_1.is_address_wildcard = mock.Mock(return_value=True)
        desc.exit_policy = [mock_rule_1]

        self.assertFalse(path_util.mightExitToPort(desc, 8))

    def test_mightExitToPort_no_in_accept_range_no_addr_wildcard_0_masked_bits(self):
        desc = mock.Mock()
        mock_rule_1 = mock.Mock()
        mock_rule_1.min_port = 1
        mock_rule_1.max_port = 10
        mock_rule_1.is_accept = False
        mock_rule_1.is_address_wildcard = mock.Mock(return_value=False)
        mock_rule_1.get_masked_bits = mock.Mock(return_value=0)
        desc.exit_policy = [mock_rule_1]

        self.assertFalse(path_util.mightExitToPort(desc, 8))

    def test_mightExitToPort_in_range_default_accept_no_matches(self):
        desc = mock.Mock()
        mock_rule_1 = mock.Mock()
        mock_rule_1.min_port = 1
        mock_rule_1.max_port = 10
        mock_rule_1.is_accept = False
        mock_rule_1.is_address_wildcard = mock.Mock(return_value=False)
        mock_rule_1.get_masked_bits = mock.Mock(return_value=1)
        desc.exit_policy = [mock_rule_1]

        self.assertTrue(path_util.mightExitToPort(desc, 8))

    def test_mightExitToPort_not_in_range_default_accept_no_matches(self):
        desc = mock.Mock()
        mock_rule_1 = mock.Mock()
        mock_rule_1.min_port = 1
        mock_rule_1.max_port = 10
        mock_rule_1.is_accept = False
        mock_rule_1.is_address_wildcard = mock.Mock(return_value=False)
        mock_rule_1.get_masked_bits = mock.Mock(return_value=0)
        desc.exit_policy = [mock_rule_1]

        self.assertTrue(path_util.mightExitToPort(desc, 11))

    def test_canExitToPort_port_in_range_addr_wildcard(self):
        desc = mock.Mock()
        mock_rule_1 = mock.Mock()
        mock_rule_1.min_port = 1
        mock_rule_1.max_port = 10
        mock_rule_1.is_address_wildcard = mock.Mock(return_value=True)
        desc.exit_policy = [mock_rule_1]

        mock_rule_1.is_accept = False
        self.assertFalse(path_util.mightExitToPort(desc, 8))

        mock_rule_1.is_accept = True
        self.assertTrue(path_util.mightExitToPort(desc, 8))

    def test_canExitToPort_port_in_range_masked_bits_0(self):
        desc = mock.Mock()
        mock_rule_1 = mock.Mock()
        mock_rule_1.min_port = 1
        mock_rule_1.max_port = 10
        mock_rule_1.is_address_wildcard = mock.Mock(return_value=False)
        mock_rule_1.get_masked_bits = mock.Mock(return_value=0)
        desc.exit_policy = [mock_rule_1]

        mock_rule_1.is_accept = False
        self.assertFalse(path_util.mightExitToPort(desc, 8))

        mock_rule_1.is_accept = True
        self.assertTrue(path_util.mightExitToPort(desc, 8))

    def test_canExitToPort_in_range_default(self):
        desc = mock.Mock()
        mock_rule_1 = mock.Mock()
        mock_rule_1.min_port = 1
        mock_rule_1.max_port = 10
        mock_rule_1.is_address_wildcard = mock.Mock(return_value=False)
        mock_rule_1.get_masked_bits = mock.Mock(return_value=1)
        desc.exit_policy = [mock_rule_1]

        mock_rule_1.is_accept = True
        self.assertTrue(path_util.mightExitToPort(desc, 8))

    def test_canExitToPort_out_of_range_default(self):
        desc = mock.Mock()
        mock_rule_1 = mock.Mock()
        mock_rule_1.min_port = 1
        mock_rule_1.max_port = 10
        mock_rule_1.is_address_wildcard = mock.Mock(return_value=False)
        mock_rule_1.get_masked_bits = mock.Mock(return_value=1)
        desc.exit_policy = [mock_rule_1]

        mock_rule_1.is_accept = True
        self.assertTrue(path_util.mightExitToPort(desc, 11))

    def test_policyIsRejectStar_is_accept(self):
        mock_rule_1 = mock.Mock()
        mock_rule_1.is_accept = True
        mock_policy = [mock_rule_1]

        self.assertFalse(path_util.policyIsRejectStar(mock_policy))

    def test_policyIsRejectStar_reject_with_port_range_cover(self):
        mock_rule_1 = mock.Mock()
        mock_rule_1.is_accept = False
        mock_rule_1.min_port = 0
        mock_rule_1.max_port = 65535
        mock_policy = [mock_rule_1]

        self.assertTrue(path_util.policyIsRejectStar(mock_policy))

        mock_rule_1.min_port = 1
        self.assertTrue(path_util.policyIsRejectStar(mock_policy))

    def test_policyIsRejectStar_port_wildcard_with_addr_wildcard(self):
        mock_rule_1 = mock.Mock()
        mock_rule_1.is_accept = False
        mock_rule_1.min_port = 1024
        mock_rule_1.max_port = 8192
        mock_rule_1.is_port_wildcard = mock.Mock(return_value=True)
        mock_rule_1.is_address_wildcard = mock.Mock(return_value=True)
        mock_policy = [mock_rule_1]

        self.assertTrue(path_util.policyIsRejectStar(mock_policy))

    def test_policyIsRejectStar_port_wildcard_with_masked_bits_0(self):
        mock_rule_1 = mock.Mock()
        mock_rule_1.is_accept = False
        mock_rule_1.min_port = 1024
        mock_rule_1.max_port = 8192
        mock_rule_1.is_port_wildcard = mock.Mock(return_value=True)
        mock_rule_1.is_address_wildcard = mock.Mock(return_value=False)
        mock_rule_1.get_basked_bits = mock.Mock(return_value=0)
        mock_policy = [mock_rule_1]

        self.assertTrue(path_util.policyIsRejectStar(mock_policy))

    def test_policyIsRejectStar_rule_miss_defaults(self):
        mock_rule_1 = mock.Mock()
        mock_rule_1.is_accept = False
        mock_rule_1.min_port = 1024
        mock_rule_1.max_port = 8192
        mock_rule_1.is_port_wildcard = mock.Mock(return_value=False)
        mock_policy = [mock_rule_1]

        self.assertTrue(path_util.policyIsRejectStar(mock_policy))

    def test_inSameFamily_yes(self):
        mock_desc_1 = mock.Mock()
        mock_desc_2 = mock.Mock()

        mock_desc_1.fingerprint = u'fprint1'
        mock_desc_2.fingerprint = u'fprint2'

        mock_desc_1.family = [u'$hey', u'$fprint2']
        mock_desc_2.family = [u'$yo', u'$fprint1']

        descriptors = {mock_desc_1: mock_desc_1, mock_desc_2: mock_desc_2}

        self.assertTrue(path_util.inSameFamily(mock_desc_1, mock_desc_2,
                                               descriptors))

    def test_inSameFamily_no_node1_lists_node2(self):
        mock_desc_1 = mock.Mock()
        mock_desc_2 = mock.Mock()

        mock_desc_1.fingerprint = u'fprint1'
        mock_desc_2.fingerprint = u'fprint2'

        mock_desc_1.family = [u'$hey', u'$fprint2']
        mock_desc_2.family = [u'$yo']

        descriptors = {mock_desc_1: mock_desc_1, mock_desc_2: mock_desc_2}

        self.assertFalse(path_util.inSameFamily(mock_desc_1, mock_desc_2,
                                                descriptors))

    def test_inSameFamily_no_node1_no_list(self):
        mock_desc_1 = mock.Mock()
        mock_desc_2 = mock.Mock()

        mock_desc_1.fingerprint = u'fprint1'
        mock_desc_2.fingerprint = u'fprint2'

        mock_desc_1.family = [u'$hey']
        mock_desc_2.family = [u'$yo', u'$fprint1']

        descriptors = {mock_desc_1: mock_desc_1, mock_desc_2: mock_desc_2}

        self.assertFalse(path_util.inSameFamily(mock_desc_1, mock_desc_2,
                                                descriptors))

    def test_inSameFamily_no_common_lists(self):
        mock_desc_1 = mock.Mock()
        mock_desc_2 = mock.Mock()

        mock_desc_1.fingerprint = u'fprint1'
        mock_desc_2.fingerprint = u'fprint2'

        mock_desc_1.family = [u'$hey']
        mock_desc_2.family = [u'$yo']

        descriptors = {mock_desc_1: mock_desc_1, mock_desc_2: mock_desc_2}

        self.assertFalse(path_util.inSameFamily(mock_desc_1, mock_desc_2,
                                                descriptors))

    def test_inSame16Subnet_yes(self):
        ip1 = mock.Mock()
        ip1.address = u'162.233.1.2'
        ip2 = mock.Mock()
        ip2.address = u'162.233.3.4'
        md = {ip1: ip1, ip2: ip2}

        self.assertTrue(path_util.inSame16Subnet(ip1, ip2, md))

        ip1.address = u'162.233.157.234'
        ip2.address = u'162.233.99.8'

        self.assertTrue(path_util.inSame16Subnet(ip1, ip2, md))

        ip1.address = u'1.1.1.1'
        ip2.address = u'1.1.1.1'

        self.assertTrue(path_util.inSame16Subnet(ip1, ip2, md))

    def test_inSame16Subnet_no(self):
        ip1 = mock.Mock()
        ip1.address = u'162.234.1.2'
        ip2 = mock.Mock()
        ip2.address = u'162.233.1.2'
        md = {ip1: ip1, ip2: ip2}

        self.assertFalse(path_util.inSame16Subnet(ip1, ip2, md))

        ip1.address = u'162.233.157.234'
        ip2.address = u'161.233.157.234'

        self.assertFalse(path_util.inSame16Subnet(ip1, ip2, md))

        ip1.address = u'1.0.1.1'
        ip2.address = u'0.1.1.1'

        self.assertFalse(path_util.inSame16Subnet(ip1, ip2, md))
