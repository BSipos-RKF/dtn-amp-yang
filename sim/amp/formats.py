
import logging
from scapy import fields, packet, volatile
from . import sdnv

#: module-level logger
logger = logging.getLogger(__name__)

class UInt8Field(fields.Field):
    ''' Unsigned 8-bit value. '''
    def __init__(self, name, default):
        fields.Field.__init__(self, name, default, "!B")

class TypeIdField(UInt8Field):
    ''' Type ID storage. '''

class SInt32Field(fields.Field):
    ''' Signed 32-bit value. '''
    def __init__(self, name, default):
        fields.Field.__init__(self, name, default, "!i")

class UInt32Field(fields.Field):
    ''' Unsigned 32-bit value. '''
    def __init__(self, name, default):
        fields.Field.__init__(self, name, default, "!I")

class SInt64Field(fields.Field):
    ''' Signed 64-bit value. '''
    def __init__(self, name, default):
        fields.Field.__init__(self, name, default, "!q")

class UInt64Field(fields.Field):
    ''' Unsigned 64-bit value. '''
    def __init__(self, name, default):
        fields.Field.__init__(self, name, default, "!Q")

class SdnvField(fields.Field):
    ''' Represent a single independent SDNV-encoded integer.
    
    If the value/default is None the output is the zero-value SDNV.
    
    :param maxval: The maximum value allowed in this field.
        Warnings will be output if the actual value is above this limit
    '''
    def __init__(self, name, default, maxval=None):
        fields.Field.__init__(self, name, default, fmt='!s')
        if maxval is None:
            maxval = 2L**32-1
        self._maxval = maxval
    
    def i2m(self, pkt, x):
        ''' Convert internal-to-machine encoding. '''
        if x is None:
            x = 0
        return sdnv.int2sdnv(x)
    
    def m2i(self, pkt, x):
        ''' Convert machine-to-internal encoding. '''
        if x is None:
            return None, 0
        return sdnv.sdnv2int(x)[1]
    
    def addfield(self, pkt, s, val):
        ''' Append this field to a packet contents. '''
        return s+self.i2m(pkt, val)
    
    def getfield(self, pkt, s):
        ''' Extract this field from a packet contents. '''
        return sdnv.sdnv2int(s)
    
    def randval(self):
        return volatile.RandNum(0, self._maxval)

class SdnvPayloadLenField(SdnvField):
    ''' An SDNV value which represents the octet length of the payload data.
    '''
    def i2m(self, pkt, x):
        if x is None:
            x = len(pkt.payload)
        return SdnvField.i2m(self, pkt, x)

class SdnvFieldLenField(SdnvField):
    ''' An SDNV value which represents a count/length of another field.
    '''
    def __init__(self, name, default=None, count_of=None, length_of=None, adjust=None):
        SdnvField.__init__(self, name, default)
        if length_of:
            def func(pkt):
                fld,fval = pkt.getfield_and_val(length_of)
                val = fld.i2len(pkt, fval)
                return val
            self.extract = func
        elif count_of:
            def func(pkt):
                fld,fval = pkt.getfield_and_val(count_of)
                val = fld.i2count(pkt, fval)
                return val
            self.extract = func
        else:
            raise ValueError('One of length_of or count_of is required')
        
        if adjust is None:
            adjust = lambda pkt,x: x
        self.adjust = adjust
    
    def i2m(self, pkt, x):
        ''' override to extract value from packet '''
        if x is None:
            x = self.extract(pkt)
            x = self.adjust(pkt,x)
        return SdnvField.i2m(self, pkt, x)

class NoPayloadPacket(packet.Packet):
    ''' A packet which never contains payload data.
    '''
    def extract_padding(self, s):
        ''' No payload, all extra data is padding '''
        return (None, s)

class RandOid(volatile.RandField):
    def __init__(self, size=None, scale=None, prefix=None):
        if size is None:
            size = volatile.RandNumExpo(0.1)
        if scale is None:
            scale = 100
        if prefix is None:
            prefix = (1,3,6,1)
        self.size = size
        self.partlambda = 1.0/scale
        self.prefix = prefix
    
    def _fix(self):
        parts = list(self.prefix)
        for ix in range(self.size):
            parts.append(volatile.RandNumExpo(self.partlambda))
        return tuple(parts)

class OidField(fields.Field):
    ''' An OID-string field.
    The field internal value is a tuple of numeric values.
    The encoded value is ASN.1 OID encoding without type prefix.
    
    :param length_from: A lambda function to look up the OID length (in octets).
    '''
    
    @staticmethod
    def tuple2oidenc(oid):
        ''' Convert from a tuple-of-numeric to OID value encoding.
        '''
        if len(oid) < 2:
            return ''
        # Encode OID elements, then convert each element to data
        parts = (oid[0] * 40 + oid[1],) + oid[2:]
        return ''.join([sdnv.int2sdnv(part) for part in parts])
    
    @staticmethod
    def oidenc2tuple(data):
        if len(data) < 1:
            return tuple()
        # Extract as many elements as exist in data
        oid = []
        
        initdata = ord(data[0])
        oid.append(initdata / 40)
        oid.append(initdata % 40)
        data = data[1:]
        
        while len(data) > 0:
            (data, val) = sdnv.sdnv2int(data)
            oid.append(val)
        
        return tuple(oid)
    
    def __init__(self, name, default=None, length_from=None, **kwargs):
        self.length_from = length_from
        fields.Field.__init__(self, name, default, **kwargs)
    
    def h2i(self, pkt, x):
        ''' Convert human-to-internal encoding. '''
        if x is None:
            return None
        if len(x) < 3:
            raise ValueError('OID must have at least 3 elements')
        return tuple(x)
    
    def i2m(self, pkt, x):
        ''' Convert internal-to-machine encoding. '''
        if x is None:
            return ''
        return self.tuple2oidenc(x)
    
    def m2i(self, pkt, x):
        ''' Convert machine-to-internal encoding. '''
        if x is None:
            return None, 0
        return self.oidenc2tuple(x)
    
    def i2len(self, pkt, x):
        ''' Encoded data length. '''
        if x is None:
            return 0
        partlen = [sdnv.sdnvlen(val) for val in x]
        return sum(partlen)
    
    def addfield(self, pkt, s, val):
        ''' Append this field to a packet contents. '''
        #l = self.length_from(pkt)
        return s+self.i2m(pkt, val)
    
    def getfield(self, pkt, s):
        ''' Extract this field from a packet contents. '''
        if self.length_from:
            l = self.length_from(pkt)
        else:
            l = len(s)
        return (s[l:], self.oidenc2tuple(s[:l]))
    
    def randval(self):
        #l = self.length_from(None)
        return RandOid()
