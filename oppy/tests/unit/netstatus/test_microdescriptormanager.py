import mock

from base64 import b64encode

from twisted.internet import defer
from twisted.trial import unittest

import oppy.netstatus.microdescriptormanager as mdm


class MicrodescriptorManagerTest(unittest.TestCase):

    @mock.patch('oppy.netstatus.microconsensusmanager.MicroconsensusManager', autospec=True)
    def setUp(self, mcm):
        self.mcm = mcm
        self.mdm = mdm.MicrodescriptorManager(mcm, autostart=False)

    def test_getMicrodescriptorsForCircuit_have_descriptors(self):
        self.mdm._microdescriptors = 'test'
        self.mdm._enough_for_circuit = True
        ret = self.mdm.getMicrodescriptorsForCircuit()

        self.assertEqual(self.successResultOf(ret), 'test')

    @mock.patch('twisted.internet.defer.Deferred')
    def test_getMicrodescriptorsForCircuit_no_descriptors(self, mock_defer):
        mock_defer.return_value = 'test'
        self.mdm._enough_for_circuit = True
        ret = self.mdm.getMicrodescriptorsForCircuit()

        self.assertEqual(self.mdm._pending_requests_for_circuit, ['test'])

    @mock.patch('twisted.internet.defer.Deferred')
    def test_getMicrodescriptorsForCircuit_not_enough(self, mock_defer):
        mock_defer.return_value = 'test'
        self.mdm._microdescriptors = 'md'
        self.mdm._enough_for_circuit = False
        ret = self.mdm.getMicrodescriptorsForCircuit()

        self.assertEqual(self.mdm._pending_requests_for_circuit, ['test'])

    def test_servePendingRequestsForCircuit(self):
        mock_request_1 = mock.Mock()
        mock_request_1.callback = mock.Mock()
        mock_request_2 = mock.Mock()
        mock_request_2.callback = mock.Mock()

        self.mdm._pending_requests_for_circuit = [mock_request_1,
                                                  mock_request_2]
        self.mdm._microdescriptors = 'test'

        self.mdm._servePendingRequestsForCircuit()

        mock_request_1.callback.assert_called_once_with('test')
        mock_request_2.callback.assert_called_once_with('test')
        self.assertEqual(self.mdm._pending_requests_for_circuit, [])

    @mock.patch('oppy.netstatus.microconsensusmanager.getV2DirsFromConsensus', return_value='v2dirs')
    @mock.patch('oppy.netstatus.microdescriptormanager._getNeededDescriptorDigests', return_value=['needed'])
    @mock.patch('twisted.internet.defer.gatherResults')
    def test_downloadMicrodescriptors_have_blocks(self, mock_gr, mock_needed,
                                                  mock_v2):
        mock_defer = mock.Mock()
        mock_defer.addCallback = mock.Mock()
        mock_gr.return_value = mock_defer

        self.mdm._microconsensus_manager.addMicroconsensusDownloadCallback = mock.Mock()
        self.mcm.getMicroconsensus = mock.Mock()
        mock_consensus = mock.Mock()
        mock_consensus.routers = ['ms']
        self.mcm.getMicroconsensus.return_value = defer.succeed(mock_consensus)

        self.mdm._discardUnlistedMicrodescriptors = mock.Mock()
        self.mdm._checkIfReadyToBuildCircuit = mock.Mock()
        self.mdm._downloadMicrodescriptorBlock = mock.Mock()
        self.mdm._downloadMicrodescriptorBlock.return_value = 'md'

        self.mdm._downloadMicrodescriptors(initial=True)

        self.assertEqual(self.mcm.getMicroconsensus.call_count, 1)
        mock_v2.assert_called_once_with(mock_consensus)
        self.mdm._discardUnlistedMicrodescriptors.assert_called_once_with(
            mock_consensus)
        self.assertEqual(mock_needed.call_count, 1)
        self.assertEqual(mock_needed.call_args_list,
                         [mock.call(mock_consensus, None)])
        self.assertEqual(self.mdm._checkIfReadyToBuildCircuit.call_count, 1)
        self.mdm._downloadMicrodescriptorBlock.assert_called_once_with(
            ['needed'], 'v2dirs')
        mock_gr.assert_called_once_with(['md'])
        mock_defer.addCallback.assert_called_once_with(
            self.mdm._writeMicrodescriptorCacheFile)
        self.mdm._microconsensus_manager.addMicroconsensusDownloadCallback.assert_called_once_with(self.mdm._downloadMicrodescriptors)

    @mock.patch('oppy.netstatus.microconsensusmanager.getV2DirsFromConsensus', return_value='v2dirs')
    @mock.patch('oppy.netstatus.microdescriptormanager._getNeededDescriptorDigests', return_value=[])
    @mock.patch('twisted.internet.defer.gatherResults')
    def test_downloadMicrodescriptors_no_blocks(self, mock_gr, mock_needed,
                                                mock_v2):
        mock_defer = mock.Mock()
        mock_defer.addCallback = mock.Mock()
        mock_gr.return_value = mock_defer

        self.mcm.getMicroconsensus = mock.Mock()
        mock_consensus = mock.Mock()
        mock_consensus.routers = ['ms']
        self.mcm.getMicroconsensus.return_value = defer.succeed(mock_consensus)

        self.mdm._discardUnlistedMicrodescriptors = mock.Mock()
        self.mdm._checkIfReadyToBuildCircuit = mock.Mock()
        self.mdm._downloadMicrodescriptorBlock = mock.Mock()
        self.mdm._downloadMicrodescriptorBlock.return_value = 'md'

        self.mdm._downloadMicrodescriptors()

        self.assertEqual(self.mcm.getMicroconsensus.call_count, 1)
        mock_v2.assert_called_once_with(mock_consensus)
        self.mdm._discardUnlistedMicrodescriptors.assert_called_once_with(
            mock_consensus)
        self.assertEqual(mock_needed.call_count, 1)
        self.assertEqual(mock_needed.call_args_list,
                         [mock.call(mock_consensus, None)])
        self.assertEqual(self.mdm._checkIfReadyToBuildCircuit.call_count, 1)

        self.assertEqual(self.mdm._downloadMicrodescriptorBlock.call_count, 0)
        self.assertEqual(mock_gr.call_count, 0)

    @mock.patch('oppy.netstatus.microdescriptormanager._makeDescDownloadURL', return_value='test')
    @mock.patch('oppy.netstatus.microdescriptormanager.getPage', side_effect=Exception())
    def test_downloadMicrodescriptorBlock_getPage_fail(self, mock_gp, mock_durl):
        mock_block = ['test'.encode('hex')]
        mock_v2dirs = ['testdir']
        # basically just test that nothing crashes
        self.mdm._downloadMicrodescriptorBlock(mock_block, mock_v2dirs)

    @mock.patch('oppy.netstatus.microdescriptormanager._makeDescDownloadURL', return_value='test')
    @mock.patch('oppy.netstatus.microdescriptormanager.getPage', return_value=defer.succeed('test_result'))
    def test_downloadMicrodescriptorBlock(self, mock_gp, mock_durl):
        mock_block = ['test'.encode('hex')]
        mock_v2dirs = ['testdir']

        self.mdm._processMicrodescriptorBlockResult = mock.Mock()
        self.mdm._processMicrodescriptorBlockResult.return_value = []
        mock_block_result = self.mdm._processMicrodescriptorBlockResult

        self.mdm._downloadMicrodescriptorBlock(mock_block, mock_v2dirs)

        self.assertEqual(mock_durl.call_count, 1)
        self.assertEqual(mock_durl.call_args_list,
            [mock.call('testdir', set([b64encode('test').rstrip('=')]))])
        self.assertEqual(mock_gp.call_count, 1) 

        from oppy.netstatus.microdescriptormanager import TIMEOUT

        self.assertEqual(mock_gp.call_args_list,
            [mock.call('test', timeout=TIMEOUT)])

        self.assertEqual(mock_block_result.call_count, 1)
        self.assertEqual(mock_block_result.call_args_list,
            [mock.call('test_result', set([b64encode('test').rstrip('=')]))])

    @mock.patch('oppy.netstatus.microdescriptormanager._decompressAndSplitResult', return_value=['test1'])
    @mock.patch('oppy.netstatus.microdescriptormanager.b64encode', return_value='test2')
    @mock.patch('oppy.netstatus.microdescriptormanager.sha256')
    @mock.patch('stem.descriptor.microdescriptor.Microdescriptor')
    def test_processMicrodescriptorBlockResult(self, mock_md, mock_sha256,
                                               mock_b64, mock_decompSplit):
        mock_md_result = mock.Mock()
        mock_md_result.digest = 'test_digest'
        mock_md.return_value = mock_md_result
        mock_sha = mock.Mock()
        mock_sha.digest = mock.Mock()
        mock_sha.digest.return_value = 'test3'
        mock_sha256.return_value = mock_sha
        self.mdm._saveProcessedMicrodescriptors = mock.Mock()

        self.mdm._processMicrodescriptorBlockResult('r', ['test2'])

        mock_decompSplit.assert_called_once_with('r')
        mock_sha256.assert_called_once_with('test1')
        mock_b64.assert_called_once_with('test3')
        mock_md.assert_called_once_with('test1')
        self.mdm._saveProcessedMicrodescriptors.assert_called_once_with(
            {'test_digest': mock_md_result})

    @mock.patch('oppy.netstatus.microdescriptormanager._decompressAndSplitResult', side_effect=ValueError())
    def test_processMicrodescriptorBlockResult_decompress_fail(self, mock_ds):
        result = 'test result'
        request = 'test requested'

        self.assertEqual(self.mdm._processMicrodescriptorBlockResult(result, request), request)

    @mock.patch('oppy.netstatus.microdescriptormanager._decompressAndSplitResult', return_value=['test1'])
    @mock.patch('oppy.netstatus.microdescriptormanager.b64encode', return_value='test2')
    @mock.patch('oppy.netstatus.microdescriptormanager.sha256')
    @mock.patch('stem.descriptor.microdescriptor.Microdescriptor', side_effect=Exception())
    def test_processMicrodescriptorBlockResult_stem_parse_fail(self,
        mock_md, mock_sha256, mock_b64, mock_decompSplit):

        mock_md_result = mock.Mock()
        mock_md_result.digest = 'test_digest'
        mock_md.return_value = mock_md_result
        mock_sha = mock.Mock()
        mock_sha.digest = mock.Mock()
        mock_sha.digest.return_value = 'test3'
        mock_sha256.return_value = mock_sha
        self.mdm._saveProcessedMicrodescriptors = mock.Mock()

        self.mdm._processMicrodescriptorBlockResult('r', ['test2'])

        self.mdm._saveProcessedMicrodescriptors.assert_called_once_with({})

    def test_processMicrodescriptorBlockResult_not_requested(self):
        raise Exception
    @mock.patch('oppy.netstatus.microdescriptormanager._decompressAndSplitResult', return_value=['test1'])
    @mock.patch('oppy.netstatus.microdescriptormanager.b64encode', return_value='not requested')
    @mock.patch('oppy.netstatus.microdescriptormanager.sha256')
    @mock.patch('stem.descriptor.microdescriptor.Microdescriptor')
    def test_processMicrodescriptorBlockResult_not_requested(self,
        mock_md, mock_sha256, mock_b64, mock_decompSplit):

        mock_md_result = mock.Mock()
        mock_md_result.digest = 'test_digest'
        mock_md.return_value = mock_md_result
        mock_sha = mock.Mock()
        mock_sha.digest = mock.Mock()
        mock_sha.digest.return_value = 'test3'
        mock_sha256.return_value = mock_sha
        self.mdm._saveProcessedMicrodescriptors = mock.Mock()

        self.mdm._processMicrodescriptorBlockResult('r', ['test2'])

        self.mdm._saveProcessedMicrodescriptors.assert_called_once_with({})

    def test_saveProcessedMicrodescriptors_microdesc_none(self):
        self.mdm._microdescriptors = {}
        self.mdm._enough_for_circuit = False
        self.mdm._checkIfReadyToBuildCircuit = mock.Mock()

        self.mdm._saveProcessedMicrodescriptors({1: 2})

        self.assertEqual(self.mdm._microdescriptors, {1: 2})
        self.assertEqual(self.mdm._checkIfReadyToBuildCircuit.call_count, 1)

    def test_saveProcessedMicrodescriptors_have_microdesc(self):
        self.mdm._microdescriptors = {1: 2}
        self.mdm._enough_for_circuit = False
        self.mdm._checkIfReadyToBuildCircuit = mock.Mock()

        self.mdm._saveProcessedMicrodescriptors({3: 4})

        self.assertEqual(self.mdm._microdescriptors, {1: 2, 3: 4})
        self.assertEqual(self.mdm._checkIfReadyToBuildCircuit.call_count, 1)

    def test_checkIfReadyToBuildCircuit_no_microdescs(self):
        self.mdm._microdescriptors = {1: 2}
        self.mdm._enough_for_circuit = False
        self.mdm._checkIfReadyToBuildCircuit = mock.Mock()

        self.mdm._saveProcessedMicrodescriptors({})

        self.assertEqual(self.mdm._microdescriptors, {1: 2})
        self.assertEqual(self.mdm._checkIfReadyToBuildCircuit.call_count, 1)

    def test_checkIfReadyToBuildCircuit_have_enough(self):
        self.mdm._microdescriptors = {1: 2}
        self.mdm._enough_for_circuit = True
        self.mdm._checkIfReadyToBuildCircuit = mock.Mock()

        self.mdm._saveProcessedMicrodescriptors({})

        self.assertEqual(self.mdm._microdescriptors, {1: 2})
        self.assertEqual(self.mdm._checkIfReadyToBuildCircuit.call_count, 0)

    def test_checkIfReadyToBuildCircuit_got_enough(self):
        self.mdm._enough_for_circuit = False
        self.mdm._total_descriptors = 10
        self.mdm._microdescriptors = {0: 1,
                                      1: 2,
                                      2: 3,
                                      3: 4,
                                      4: 5,
                                      5: 6,
                                      6: 7,
                                      7: 8}
        self.mdm._servePendingRequestsForCircuit = mock.Mock()

        self.mdm._checkIfReadyToBuildCircuit()

        self.assertTrue(self.mdm._enough_for_circuit)
        self.assertEqual(self.mdm._servePendingRequestsForCircuit.call_count,
            1)

    def test_checkIfReadyToBuildCircuit_not_enough(self):
        self.mdm._enough_for_circuit = False
        self.mdm._total_descriptors = 10
        self.mdm._microdescriptors = {0: 1,
                                      1: 2,
                                      2: 3,
                                      3: 4,
                                      4: 5,
                                      5: 6,
                                      6: 7}
        self.mdm._servePendingRequestsForCircuit = mock.Mock()

        self.mdm._checkIfReadyToBuildCircuit()

        self.assertFalse(self.mdm._enough_for_circuit)
        self.assertEqual(self.mdm._servePendingRequestsForCircuit.call_count,
            0)

    def test_writeMicrodescriptorCacheFile_write_fail(self):
        open_name = 'oppy.netstatus.microdescriptormanager.open'
        m = mock.mock_open()
        with mock.patch(open_name, m, create=True):
            handle = m()
            handle.write.side_effect = IOError()
            self.mdm._writeMicrodescriptorCacheFile('test')

    def test_writeMicrodescriptorCacheFile_succeed(self):
        self.mdm._microdescriptors = {1: 'test'}

        open_name = 'oppy.netstatus.microdescriptormanager.open'
        m = mock.mock_open()
        with mock.patch(open_name, m, create=True):
            handle = m()
            self.mdm._writeMicrodescriptorCacheFile('test')
            self.assertEqual(m.call_args_list,
                [mock.call(), mock.call(mdm.MICRO_DESC_CACHE_FILE, 'w')])
            handle.write.assert_called_once_with('test')

    def test_discardUnlistedMicrodescriptors(self):
        self.mdm._microdescriptors = {1: 2, 3: 4}

        consensus = mock.Mock()
        router = mock.Mock()
        router.digest = 3
        consensus.routers = {3: router}

        self.mdm._discardUnlistedMicrodescriptors(consensus)
        self.assertEqual(self.mdm._microdescriptors, {3: 4})

    @mock.patch('stem.descriptor.microdescriptor.Microdescriptor')
    def test_getMicrodescriptorsFromCacheFile(self, mock_md):
        md = mock.Mock()
        md.digest = 'test'
        mock_md.return_value = md

        open_name = 'oppy.netstatus.microdescriptormanager.open'
        m = mock.mock_open(read_data='data')
        with mock.patch(open_name, m, create=True):
            ret = mdm._getMicrodescriptorsFromCacheFile()
            self.assertEqual(ret, {'test': md})

    def test_getMicrodescriptorsFromCacheFile_read_fail(self):
        open_name = 'oppy.netstatus.microdescriptormanager.open'
        m = mock.mock_open(read_data='data')
        with mock.patch(open_name, m, create=True):
            m.side_effect = IOError()
            ret = mdm._getMicrodescriptorsFromCacheFile()
            self.assertEqual(ret, None)

    @mock.patch('stem.descriptor.microdescriptor.Microdescriptor')
    def test_getMicrodescriptorsFromCacheFile_stem_parse_fail(self, mock_md):
        mock_md.side_effect = Exception

        open_name = 'oppy.netstatus.microdescriptormanager.open'
        m = mock.mock_open(read_data='data')
        with mock.patch(open_name, m, create=True):
            ret = mdm._getMicrodescriptorsFromCacheFile()
            self.assertEqual(ret, None)

    def test_decompressAndSplitResult_decomp_fail(self):
        self.assertRaises(ValueError,
                          mdm._decompressAndSplitResult,
                          'not compressed')

    @mock.patch('zlib.decompress')
    def test_decompressAndSplitResult(self, mock_d):
        mock_d.return_value = 'onion-key\ntest1\nonion-key\ntest2\n'
        ret = mdm._decompressAndSplitResult('test')
        self.assertEqual(ret,
            ['onion-key\ntest1\n', 'onion-key\ntest2\n'])

    def test_makeDescDownloadURL(self):
        test_digests = ['testdigest1', 'testdigest2']
        v2dir = mock.Mock()
        v2dir.address = '127.0.0.1'
        v2dir.dir_port = 80

        ret = mdm._makeDescDownloadURL(v2dir, test_digests)
        self.assertEqual(ret,
            'http://127.0.0.1:80/tor/micro/d/testdigest1-testdigest2.z')

    def test_getNeededDescriptorDigests_desc_have_none(self):
        mock_router = mock.Mock()
        mock_router.digest = 'digest'
        consensus = mock.Mock()
        consensus.routers = {'test': mock_router}

        ret = mdm._getNeededDescriptorDigests(consensus, None)
        self.assertEqual(ret, ['digest'])

    def test_getNeededDescriptorDigests_desc_need_none(self):
        mock_router = mock.Mock()
        mock_router.digest = 'digest'
        consensus = mock.Mock()
        consensus.routers = {'test': mock_router}

        descriptors = {'test': mock_router}

        ret = mdm._getNeededDescriptorDigests(consensus, descriptors)
        self.assertEqual(ret, [])

    def test_getNeededDescriptorDigests(self):
        mock_router = mock.Mock()
        mock_router.digest = 'digest'
        mock_router2 = mock.Mock()
        mock_router2.digest = 'needed digest'
        consensus = mock.Mock()
        consensus.routers = {'test': mock_router, 'test2': mock_router2}

        descriptors = {'test': mock_router}

        ret = mdm._getNeededDescriptorDigests(consensus, descriptors)
        self.assertEqual(ret, ['needed digest'])
