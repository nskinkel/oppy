import mock

from twisted.internet import defer
from twisted.trial import unittest

# wow this 'as' name is confusing as fuck
import oppy.netstatus.microconsensusmanager as mcm


class MicroconsensusManagerTest(unittest.TestCase):

    def setUp(self):
        self.mcm = mcm.MicroconsensusManager(autostart=False)

    def test_getMicronsensus_have_consensus(self):
        self.mcm._consensus = 'test'
        ret = self.mcm.getMicroconsensus()

        self.assertEqual(self.successResultOf(ret), 'test')

    @mock.patch('twisted.internet.defer.Deferred', autospec=True)
    def test_getMicroconsensus_no_consensus(self, mock_defer):
        mock_defer.return_value = 'test'

        ret = self.mcm.getMicroconsensus()
        self.assertEqual(self.mcm._pending_consensus_requests, ['test'])
        self.assertEqual(ret, 'test')

    def test_addMicroconsensusDownloadCallback(self):
        self.mcm.addMicroconsensusDownloadCallback('test')
        self.assertEqual(self.mcm._consensus_download_callbacks, set(['test']))

    def test_removeMicroconsensusDownloadCallback(self):
        self.mcm._consensus_download_callbacks = ['test']
        self.mcm.removeMicroconsensusDownloadCallback('test')
        self.assertEqual(self.mcm._consensus_download_callbacks, [])

    # for now, just test that this works without throwing an exception
    def test_removeMicroconsensusDownloadCallback_no_ref(self):
        self.mcm.removeMicroconsensusDownloadCallback('test')

    def test_servePendingRequests(self):
        mock_request_1 = mock.Mock()
        mock_request_1.callback = mock.Mock()
        mock_request_2 = mock.Mock()
        mock_request_2.callback = mock.Mock()

        self.mcm._pending_consensus_requests = [mock_request_1, mock_request_2]
        self.mcm._consensus = 'test'

        self.mcm._servePendingRequests()

        mock_request_1.callback.assert_called_once_with('test')
        mock_request_2.callback.assert_called_once_with('test')
        self.assertEqual(self.mcm._pending_consensus_requests, [])

    def test_serveConsensusDownloadCallbacks(self):
        mock_callback_1 = mock.Mock()
        mock_callback_2 = mock.Mock()

        self.mcm._consensus_download_callbacks = [mock_callback_1,
                                                  mock_callback_2]

        self.mcm._serveConsensusDownloadCallbacks()

        self.assertEqual(mock_callback_1.call_count, 1)
        self.assertEqual(mock_callback_2.call_count, 1)
        self.assertEqual(self.mcm._consensus_download_callbacks,
                         [mock_callback_1, mock_callback_2])

    @mock.patch('oppy.netstatus.microconsensusmanager._readV2DirsFromCacheFile', return_value='v2dirs')
    def test_scheduledConsensusUpdate_initial_download_works(self, mock_v2):

        self.mcm._downloadMicroconsensus = mock.Mock()
        self.mcm._downloadMicroconsensus.return_value = defer.succeed('test')
        self.mcm._scheduleNextConsensusDownload = mock.Mock()
        self.mcm._servePendingRequests = mock.Mock()
        self.mcm._serveConsensusDownloadCallbacks = mock.Mock()

        self.mcm._scheduledConsensusUpdate(initial=True)

        self.mcm._downloadMicroconsensus.assert_called_once_with('v2dirs')
        self.assertEqual(self.mcm._consensus, 'test')
        self.assertEqual(mock_v2.call_count, 1)
        self.assertEqual(self.mcm._scheduleNextConsensusDownload.call_count, 1)
        self.assertEqual(self.mcm._servePendingRequests.call_count, 1)
        self.assertEqual(self.mcm._serveConsensusDownloadCallbacks.call_count, 1)

    @mock.patch('oppy.netstatus.microconsensusmanager._readV2DirsFromCacheFile', return_value='v2dirs')
    @mock.patch('twisted.internet.reactor', autospec=True)
    def test_scheduledConsensusUpdate_initial_download_fails(self, mock_reactor,
                                                             mock_v2):
        self.mcm._downloadMicroconsensus = mock.Mock()
        self.mcm._downloadMicroconsensus.side_effect = \
            mcm.ConsensusDownloadFailed()
        self.mcm._scheduleNextConsensusDownload = mock.Mock()
        self.mcm._servePendingRequests = mock.Mock()
        self.mcm._serveConsensusDownloadCallbacks = mock.Mock()
        mock_reactor.callLater = mock.Mock()

        self.mcm._scheduledConsensusUpdate(initial=True)

        self.mcm._downloadMicroconsensus.assert_called_once_with('v2dirs')
        self.assertEqual(self.mcm._consensus, None)
        self.assertEqual(mock_v2.call_count, 1)
        self.assertEqual(self.mcm._scheduleNextConsensusDownload.call_count, 0)
        self.assertEqual(self.mcm._servePendingRequests.call_count, 0)
        self.assertEqual(self.mcm._serveConsensusDownloadCallbacks.call_count, 0)

        self.assertEqual(mock_reactor.callLater.call_count, 1)
        self.assertEqual(mock_reactor.callLater.call_args_list,
                         [mock.call(mcm.SLEEP,
                                    self.mcm._scheduledConsensusUpdate,
                                    True)])

    @mock.patch('oppy.netstatus.microconsensusmanager._readV2DirsFromCacheFile', return_value='v2dirs')
    def test_scheduledConsensusUpdate_no_consensus_works(self, mock_v2):
        self.mcm._downloadMicroconsensus = mock.Mock()
        self.mcm._downloadMicroconsensus.return_value = defer.succeed('test')
        self.mcm._scheduleNextConsensusDownload = mock.Mock()
        self.mcm._servePendingRequests = mock.Mock()
        self.mcm._serveConsensusDownloadCallbacks = mock.Mock()

        self.mcm._scheduledConsensusUpdate(initial=False)

        self.mcm._downloadMicroconsensus.assert_called_once_with('v2dirs')
        self.assertEqual(self.mcm._consensus, 'test')
        self.assertEqual(mock_v2.call_count, 1)
        self.assertEqual(self.mcm._scheduleNextConsensusDownload.call_count, 1)
        self.assertEqual(self.mcm._servePendingRequests.call_count, 1)
        self.assertEqual(self.mcm._serveConsensusDownloadCallbacks.call_count, 1)

    @mock.patch('oppy.netstatus.microconsensusmanager._readV2DirsFromCacheFile', return_value='v2dirs')
    @mock.patch('twisted.internet.reactor', autospec=True)
    def test_scheduledConsensusUpdate_no_consensus_fails(self, mock_reactor,
                                                         mock_v2):
        self.mcm._downloadMicroconsensus = mock.Mock()
        self.mcm._downloadMicroconsensus.side_effect = \
            mcm.ConsensusDownloadFailed()
        self.mcm._scheduleNextConsensusDownload = mock.Mock()
        self.mcm._servePendingRequests = mock.Mock()
        self.mcm._serveConsensusDownloadCallbacks = mock.Mock()
        mock_reactor.callLater = mock.Mock()

        self.mcm._scheduledConsensusUpdate(initial=False)

        self.mcm._downloadMicroconsensus.assert_called_once_with('v2dirs')
        self.assertEqual(self.mcm._consensus, None)
        self.assertEqual(mock_v2.call_count, 1)
        self.assertEqual(self.mcm._scheduleNextConsensusDownload.call_count, 0)
        self.assertEqual(self.mcm._servePendingRequests.call_count, 0)
        self.assertEqual(self.mcm._serveConsensusDownloadCallbacks.call_count, 0)

        self.assertEqual(mock_reactor.callLater.call_count, 1)
        self.assertEqual(mock_reactor.callLater.call_args_list,
                         [mock.call(mcm.SLEEP,
                                    self.mcm._scheduledConsensusUpdate,
                                    False)])

    @mock.patch('oppy.netstatus.microconsensusmanager._readV2DirsFromCacheFile', return_value=None)
    @mock.patch('oppy.netstatus.microconsensusmanager.get_authorities', return_value={'test': 'v2dirs'})
    def test_scheduledConsensusUpdate_read_fails_no_consensus_works(self,
        mock_ga, mock_v2):
        self.mcm._downloadMicroconsensus = mock.Mock()
        self.mcm._downloadMicroconsensus.return_value = defer.succeed('test')
        self.mcm._scheduleNextConsensusDownload = mock.Mock()
        self.mcm._servePendingRequests = mock.Mock()
        self.mcm._serveConsensusDownloadCallbacks = mock.Mock()

        self.mcm._scheduledConsensusUpdate(initial=False)

        self.mcm._downloadMicroconsensus.assert_called_once_with(['v2dirs'])
        self.assertEqual(self.mcm._consensus, 'test')
        self.assertEqual(mock_v2.call_count, 1)
        self.assertEqual(mock_ga.call_count, 1)
        self.assertEqual(self.mcm._scheduleNextConsensusDownload.call_count, 1)
        self.assertEqual(self.mcm._servePendingRequests.call_count, 1)
        self.assertEqual(self.mcm._serveConsensusDownloadCallbacks.call_count, 1)

    @mock.patch('oppy.netstatus.microconsensusmanager._processRawMicroconsensus')
    @mock.patch('oppy.netstatus.microconsensusmanager.getPage', side_effect=Exception())
    @mock.patch('random.shuffle')
    def test_downloadMicroconsensus_getPage_fail(self, mock_shuffle,
                                                 mock_getPage, mock_processRaw):
        mock_dir = mock.Mock()
        mock_dir.address = 'addr'
        mock_dir.dir_port = 'dir_port'

        self.assertEqual(
            self.failureResultOf(
                self.mcm._downloadMicroconsensus([mock_dir]))\
                .trap(mcm.ConsensusDownloadFailed),
            mcm.ConsensusDownloadFailed)
        
        mock_shuffle.assert_called_once_with([mock_dir])
        mock_getPage.assert_called_once_with(
            "http://addr:dir_port"+mcm.MICRO_CONSENSUS_PATH)
        self.assertEqual(mock_processRaw.call_count, 0)

    @mock.patch('oppy.netstatus.microconsensusmanager._processRawMicroconsensus', side_effect=ValueError())
    @mock.patch('oppy.netstatus.microconsensusmanager.getPage', return_value=defer.succeed('page'))
    @mock.patch('random.shuffle')
    def test_downloadMicroconsensus_process_fail(self, mock_shuffle,
                                                 mock_getPage, mock_processRaw):
        mock_dir = mock.Mock()
        mock_dir.address = 'addr'
        mock_dir.dir_port = 'dir_port'

        self.assertEqual(
            self.failureResultOf(
                self.mcm._downloadMicroconsensus([mock_dir]))\
                .trap(mcm.ConsensusDownloadFailed),
            mcm.ConsensusDownloadFailed)
        
        mock_shuffle.assert_called_once_with([mock_dir])
        mock_getPage.assert_called_once_with(
            "http://addr:dir_port"+mcm.MICRO_CONSENSUS_PATH)
        mock_processRaw.assert_called_once_with('page')

    @mock.patch('oppy.netstatus.microconsensusmanager._processRawMicroconsensus', return_value='succeed')
    @mock.patch('oppy.netstatus.microconsensusmanager.getPage', return_value=defer.succeed('page'))
    @mock.patch('random.shuffle')
    def test_downloadMicroconsensus_succeed(self, mock_shuffle,
                                            mock_getPage, mock_processRaw):
        mock_dir = mock.Mock()
        mock_dir.address = 'addr'
        mock_dir.dir_port = 'dir_port'

        self.assertEqual(
            self.successResultOf(
                self.mcm._downloadMicroconsensus([mock_dir])),
            'succeed')
        
        mock_shuffle.assert_called_once_with([mock_dir])
        mock_getPage.assert_called_once_with(
            "http://addr:dir_port"+mcm.MICRO_CONSENSUS_PATH)
        mock_processRaw.assert_called_once_with('page')

    # TODO: write a real test
    def test_scheduleNextConsensusDownload(self):
        pass

    def test_getV2DirsFromConsensus(self):
        from stem import Flag
        mock_router_1 = mock.Mock()
        mock_router_2 = mock.Mock()
        mock_router_1.flags = [Flag.V2DIR]
        mock_router_2.flags = []
        mc = mock.Mock()
        mc.routers = {'1': mock_router_1, '2': mock_router_2}

        ret = mcm.getV2DirsFromConsensus(mc)
        self.assertEqual(ret, [mock_router_1])

    @mock.patch('oppy.netstatus.microconsensusmanager.NetworkStatusDocumentV3', return_value='ret1')
    @mock.patch('oppy.netstatus.microconsensusmanager.getV2DirsFromConsensus', return_value='ret2')
    def test_readV2DirsFromCacheFile_succeed(self, mock_gv2, mock_nsdv3):
        open_name = 'oppy.netstatus.microconsensusmanager.open'
        m = mock.mock_open(read_data='data')
        with mock.patch(open_name, m, create=True):
            ret = mcm._readV2DirsFromCacheFile()
            mock_nsdv3.assert_called_once_with('data')
            mock_gv2.assert_called_once_with('ret1')
            self.assertEqual(ret, 'ret2')

    @mock.patch('oppy.netstatus.microconsensusmanager.NetworkStatusDocumentV3', side_effect=IOError())
    @mock.patch('oppy.netstatus.microconsensusmanager.getV2DirsFromConsensus', return_value='ret2')
    def test_readV2DirsFromCacheFile_fail(self, mock_gv2, mock_nsdv3):
        open_name = 'oppy.netstatus.microconsensusmanager.open'
        m = mock.mock_open(read_data='data')
        with mock.patch(open_name, m, create=True):
            ret = mcm._readV2DirsFromCacheFile()
            mock_nsdv3.assert_called_once_with('data')
            self.assertEqual(mock_gv2.call_count, 0)
            self.assertEqual(ret, None)

    def test_writeConsensusCacheFile_fail(self):
        open_name = 'oppy.netstatus.microconsensusmanager.open'
        m = mock.mock_open()
        with mock.patch(open_name, m, create=True):
            handle = m()
            handle.write.side_effect = IOError()
            mcm._writeConsensusCacheFile('raw')
            self.assertEqual(m.call_args_list[1],
                mock.call(mcm.MICRO_CONSENSUS_CACHE_FILE, 'wb'))
            handle.write.assert_called_once_with('raw')

    def test_writeConsensusCacheFile_succeed(self):
        open_name = 'oppy.netstatus.microconsensusmanager.open'
        m = mock.mock_open()
        with mock.patch(open_name, m, create=True):
            handle = m()
            mcm._writeConsensusCacheFile('raw')
            self.assertEqual(m.call_args_list[1],
                mock.call(mcm.MICRO_CONSENSUS_CACHE_FILE, 'wb'))
            handle.write.assert_called_once_with('raw')

    @mock.patch('zlib.decompress', return_value='zlib')
    @mock.patch('oppy.netstatus.microconsensusmanager.NetworkStatusDocumentV3', return_value='consensus')
    @mock.patch('oppy.netstatus.microconsensusmanager._writeConsensusCacheFile')
    def test_processRawMicroconsensus(self, mock_wc, mock_nsd, mock_zd):
        ret = mcm._processRawMicroconsensus('raw')
        mock_zd.assert_called_once_with('raw')
        mock_nsd.assert_called_once_with('zlib')
        mock_wc.assert_called_once_with('consensus')
        self.assertEqual(ret, 'consensus')
