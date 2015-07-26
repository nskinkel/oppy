import mock

from twisted.trial import unittest

from oppy.netstatus import netstatus


class NetstatusTest(unittest.TestCase):

    @mock.patch('oppy.netstatus.netstatus.MicroconsensusManager', autospec=True)
    @mock.patch('oppy.netstatus.netstatus.MicrodescriptorManager', autospec=True)
    def setUp(self, mock_md, mock_mc):
        self.mdm = mock_md
        self.mcm = mock_mc
        self.ns = netstatus.NetStatus()

    def test_getMicrodescriptorsForCircuit(self):
        _ = self.ns.getMicrodescriptorsForCircuit()
        self.assertEqual(self.ns._mdm.getMicrodescriptorsForCircuit.call_count, 1)

    def test_getMicroconsensus(self):
        _ = self.ns.getMicroconsensus()
        self.assertEqual(self.ns._mcm.getMicroconsensus.call_count, 1)
