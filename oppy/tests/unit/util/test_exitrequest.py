import mock

from twisted.trial import unittest

from oppy.util import exitrequest


class ExitRequestTest(unittest.TestCase):

    def test_ExitRequest_addr_ipv4(self):
        er = exitrequest.ExitRequest('\x00\x00', addr='\x7f\x00\x00\x01')
        self.assertTrue(er.is_ipv4)
        self.assertFalse(er.is_ipv6)
        self.assertFalse(er.is_host)
        self.assertEqual(er.port, 0)
        self.assertEqual(er.addr, '127.0.0.1')
        self.assertEqual(er.host, None)

    def test_ExitRequest_addr_ipv6(self):
        er = exitrequest.ExitRequest('\x00\x00',
            addr=' \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00')
        self.assertFalse(er.is_ipv4)
        self.assertTrue(er.is_ipv6)
        self.assertFalse(er.is_host)
        self.assertEqual(er.port, 0)
        self.assertEqual(er.addr, '2001:0db8:0000:0000:0000:0000:0000:1000')
        self.assertEqual(er.host, None)

    def test_ExitRequest_host(self):
        er = exitrequest.ExitRequest('\x00\x00', host='https://example.com')
        self.assertFalse(er.is_ipv4)
        self.assertFalse(er.is_ipv6)
        self.assertTrue(er.is_host)
        self.assertEqual(er.port, 0)
        self.assertEqual(er.addr, None)
        self.assertEqual(er.host, 'https://example.com')

    def test_ExitRequest_not_addr_or_port(self):
        self.assertRaises(AssertionError,
                          exitrequest.ExitRequest,
                          '\x00\x00')

    def test_ExitRequest_both(self):
        self.assertRaises(AssertionError,
                          exitrequest.ExitRequest,
                          0,
                          addr='\x7f\x00\x00\x01',
                          host='https://example.com')

    def test_str_ipv4(self):
        er = exitrequest.ExitRequest('\x00\x00', addr='\x7f\x00\x00\x01')
        self.assertEqual(str(er), '127.0.0.1:0\x00')

    def test_str_ipv6(self):
        er = exitrequest.ExitRequest('\x00\x00',
            addr=' \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00')
        self.assertEqual(str(er),
            '[2001:0db8:0000:0000:0000:0000:0000:1000]:0\x00')

    def test_str_host(self):
        er = exitrequest.ExitRequest('\x00\x00', host='https://example.com')
        self.assertEqual(str(er), 'https://example.com:0\x00')
