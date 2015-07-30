import mock

from twisted.trial import unittest

from oppy.util import tools


class ToolsTest(unittest.TestCase):
    
    @mock.patch('base64.b64decode', return_value='ret')
    def test_decodeMicrodescriptorIdentifier_pad4(self, mock_b64d):
        md = mock.Mock()
        md.identifier = 'test'
        ret = tools.decodeMicrodescriptorIdentifier(md)
        self.assertEqual(ret, 'ret')
        mock_b64d.assert_called_once_with('test====')

    @mock.patch('base64.b64decode', return_value='ret')
    def test_decodeMicrodescriptorIdentifier_pad3(self, mock_b64d):
        md = mock.Mock()
        md.identifier = 't'
        ret = tools.decodeMicrodescriptorIdentifier(md)
        self.assertEqual(ret, 'ret')
        mock_b64d.assert_called_once_with('t===')

    @mock.patch('base64.b64decode', return_value='ret')
    def test_decodeMicrodescriptorIdentifier_pad2(self, mock_b64d):
        md = mock.Mock()
        md.identifier = 'te'
        ret = tools.decodeMicrodescriptorIdentifier(md)
        self.assertEqual(ret, 'ret')
        mock_b64d.assert_called_once_with('te==')

    @mock.patch('base64.b64decode', return_value='ret')
    def test_decodeMicrodescriptorIdentifier_pad1(self, mock_b64d):
        md = mock.Mock()
        md.identifier = 'tes'
        ret = tools.decodeMicrodescriptorIdentifier(md)
        self.assertEqual(ret, 'ret')
        mock_b64d.assert_called_once_with('tes=')

    def test_enum(self):
        e = tools.enum(OPEN=0, CLOSED=1)
        self.assertEqual(e.OPEN, 0)
        self.assertEqual(e.CLOSED, 1)

    def test_shutdown(self):
        mock_cm = mock.Mock()
        mock_cm.destroyAllCircuits = mock.Mock()
        tools.shutdown(mock_cm)
        self.assertEqual(mock_cm.destroyAllCircuits.call_count, 1)

    def test_ctr(self):
        c = tools.ctr(10)
        for i in range(1, 10):
            self.assertEqual(i, next(c))
        self.assertEqual(1, next(c))
