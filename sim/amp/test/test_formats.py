
import struct
import uuid
import datetime
import unittest
from testhelpers import TestCase, random_octets
from scapy.packet import Packet
from .. import formats

class TestUint8Field(TestCase):
    ''' Verify UInt8Field class '''
    
    class DummyPacket(Packet):
        fields_desc = [
            formats.UInt8Field('attr', None),
        ]
    
    def testSerialize(self):
        pkt = self.DummyPacket()
        fld = pkt.get_field('attr')
        self.assertIsNone(fld.default)
        
        # Default value
        self.assertIsNone(pkt.getfieldval('attr'))
        self.assertIsNone(pkt.attr)
        data = str(pkt)
        self.assertDataEqual(data, '\0')
        
        # Particular value
        testval = 0x30
        pkt.setfieldval('attr', testval)
        self.assertEqual(pkt.getfieldval('attr'), testval)
        self.assertEqual(pkt.attr, testval)
        data = str(pkt)
        self.assertDataEqual(data, '\x30')
    
    def testDeserialize(self):
        testval = 0x30
        data = ''.join([chr(testval)])
        pkt = self.DummyPacket(data)
        self.assertEqual(len(pkt), 1)
        self.assertEqual(pkt.getfieldval('attr'), testval)

class TestOidField(TestCase):
    ''' Verify OidField class '''
    
    class DummyPacket(Packet):
        explicit = 1
        fields_desc = [
            formats.OidField('attr', default=None),
        ]
    
    def testSerialize(self):
        pkt = self.DummyPacket()
        fld = pkt.get_field('attr')
        self.assertIsNone(fld.default)
        
        # Default value
        self.assertIsNone(pkt.getfieldval('attr'))
        self.assertIsNone(pkt.attr)
        data = str(pkt)
        self.assertDataEqual(data, '')
        
        # Particular value
        testval = (1,3,6)
        pkt.setfieldval('attr', testval)
        self.assertEqual(pkt.getfieldval('attr'), testval)
        self.assertEqual(pkt.attr, testval)
        data = str(pkt)
        self.assertDataEqual(data, '\x2b\x06')
    
    def testDeserialize(self):
        testval = 0x30
        data = ''.join([chr(testval)])
        pkt = self.DummyPacket(data)
        self.assertEqual(len(pkt), 1)
        self.assertEqual(pkt.getfieldval('attr'), (1, 8))


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
