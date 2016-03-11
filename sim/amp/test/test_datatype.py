
import unittest
from scapy import packet
from .. import formats, datatype

class TestBlob(unittest.TestCase):

    def test_serialize(self):
        pkt = datatype.Blob(data='')
        print str(pkt).encode('hex')
        print pkt.show2()

class TestDataCollection(unittest.TestCase):

    def test_serialize(self):
        pkt = datatype.DataCollection()
        pkt.items = [datatype.Blob(data='hi')]
        print pkt.show2()
        pkt = packet.fuzz(pkt)
        print pkt.show2()

class TestTypedDataCollection(unittest.TestCase):

    def test_serialize(self):
        pkt = datatype.TypedDataCollection()
        #pkt.items = [datatype.Blob(data='hi')]
        print pkt.show2()
        pkt = packet.fuzz(pkt)
        print pkt.show2()

class TestMid(unittest.TestCase):

    def test_serialize(self):
        pkt = datatype.Mid(oid=(1,2,3,4), nickname=formats.RandOid(size=3))
        #print pkt.show2()
        #pkt = packet.fuzz(pkt)
        #print pkt.show2()
        data = str(pkt)
        print data.encode('hex')
        
        pkt = datatype.Mid(data)
        print pkt.show2()

class TestTimeRule(unittest.TestCase):

    def test_serialize(self):
        pkt = datatype.TimeRule()
        print pkt.show2()
        pkt = packet.fuzz(pkt)
        print pkt.show2()
        data = str(pkt)
        print data.encode('hex')
        
        pkt = datatype.Mid(data)
        print pkt.show2()

class TestTypedValue(unittest.TestCase):
    
    def test_serialize(self):
        TYPE_VAL = (
            datatype.Int(value=0),
            datatype.UInt(value=0),
            datatype.Vast(value=0),
            datatype.UVast(value=0),
            datatype.Str(value=''),
            datatype.Blob(data=''),
            datatype.Sdnv(value=0),
            datatype.Ts(value=0),
            
            datatype.MidCollection(items=[datatype.Mid()]),
            datatype.TimeRule(),
        )
        for val in TYPE_VAL:
            pkt = datatype.TypedData()/val
            pkt = packet.fuzz(pkt)
            print pkt.show()
            print str(pkt).encode('hex')
            print pkt.show2()

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
