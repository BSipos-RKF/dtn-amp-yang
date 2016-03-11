import logging
from scapy import fields, packet
from . import formats

#: module-level logger
logger = logging.getLogger(__name__)

class AbstractData(formats.NoPayloadPacket):
    ''' Base class for all AMP data type encoding.
    '''

class TypedData(packet.Packet):
    ''' A container with a type ID value indicating encoding type.
    The payload of TypedData is always an :py:class:`AbstractData` derived
    type.
    '''
    fields_desc = [
        formats.TypeIdField('type_id', None),
    ]

class Byte(AbstractData):
    ''' Unsigned 8-bit integer. '''
    fields_desc = [
        formats.UInt8Field('value', default=None)
    ]

class Int(AbstractData):
    ''' Signed 32-bit integer. '''
    fields_desc = [
        fields.Field('value', default=None, fmt='!i')
    ]

class UInt(AbstractData):
    ''' Unsigned 32-bit integer. '''
    fields_desc = [
        fields.Field('value', default=None, fmt='!I')
    ]

class Vast(AbstractData):
    ''' Signed 64-bit integer. '''
    fields_desc = [
        fields.Field('value', default=None, fmt='!q')
    ]

class UVast(AbstractData):
    ''' Unsigned 64-bit integer. '''
    fields_desc = [
        fields.Field('value', default=None, fmt='!Q')
    ]

class Float32(AbstractData):
    ''' 32-bit floating point. '''
    fields_desc = [
        fields.Field('value', default=None, fmt='!f')
    ]

class Float64(AbstractData):
    ''' 64-bit floating point. '''
    fields_desc = [
        fields.Field('value', default=None, fmt='!d')
    ]

class Str(AbstractData):
    ''' Null-terminated UTF-8 string. '''
    fields_desc = [
        fields.StrNullField('value', default='')
    ]

class Sdnv(AbstractData):
    ''' Self-delimited numeric value. '''
    fields_desc = [
        formats.SdnvField('value', default=None)
    ]

class Ts(Sdnv):
    ''' Integer timestamp value. '''

class Blob(AbstractData):
    ''' An arbitrary data string.
    '''
    fields_desc = [
        formats.SdnvFieldLenField('length', default=None, length_of='data'),
        fields.StrLenField('data', default='',
                           length_from=lambda pkt: pkt.length)
    ]

class DataCollection(AbstractData):
    ''' Ordered list of Blobs.
    '''
    fields_desc = [
        formats.SdnvFieldLenField('count', default=None, count_of='items'),
        fields.PacketListField('items', default=[],
                               count_from=lambda pkt: pkt.count,
                               cls=Blob)
    ]

class TypedDataCollection(AbstractData):
    ''' Ordered list of types and Blobs.
    '''
    fields_desc = [
        formats.SdnvFieldLenField('count', default=None, count_of='items'),
#        fields.FieldListField('types', default=None,
#            count_from=lambda pkt: pkt.count,
#           field=formats.TypeIdField('id', default=[])
#       ),
#        fields.PacketListField('items', default=[],
#            count_from=lambda pkt: pkt.count,
#            cls=Blob
#        )
        fields.PacketListField('items', default=[],
                               count_from=lambda pkt: pkt.count,
                               cls=TypedData)
    ]

class PresenceFlag(fields.BitEnumField):
    ''' A flag which corresponds with an other ConditionalField presence.
    '''
    PRES_FLAG = {
        0: 'ABSENT',
        1: 'PRESENT',
    }
    
    def __init__(self, name, presence_of):
        fields.BitEnumField.__init__(self, name, default=None, size=1, enum=self.PRES_FLAG)
        if not callable(presence_of):
            name = str(presence_of)
            presence_of = lambda pkt: getattr(pkt, name) is not None
        self.pres_of = presence_of
    
    def i2m(self, pkt, x):
        if x is None:
            pres = bool(self.pres_of(pkt))
            x = (0, 1)[pres]
        
        return fields.EnumField.i2m(self, pkt, x)

class Mid(AbstractData):
    ''' An arbitrary wrapped OID value.
    '''
    OID_TYPE = {
        0: 'OID_FULL',
        1: 'OID_FULL_PARAM',
        2: 'OID_COMP',
        3: 'OID_COMP_PARAM',
    }
    
    fields_desc = [
        #fields.BitEnumField('oid_type', default=None, size=2, enum=OID_TYPE),
        PresenceFlag('nick_pres', presence_of='nickname'),
        PresenceFlag('param_pres', presence_of='parameters'),
        PresenceFlag('tag_pres', presence_of='tag'),
        PresenceFlag('issuer_pres', presence_of='issuer'),
        fields.BitField('pad', default=0, size=4),
        
        fields.ConditionalField(
            formats.SdnvField('issuer', default=None),
            lambda pkt: pkt.issuer_pres == 1
        ),
        fields.ConditionalField(
            formats.SdnvField('nickname', default=None),
            lambda pkt: pkt.nick_pres == 1
        ),
        formats.SdnvFieldLenField('oid_len', default=None, length_of='oid'),
        formats.OidField('oid', default=None, length_from=lambda pkt: pkt.oid_len),
        fields.ConditionalField(
            fields.StrField('parameters', default=None),
            lambda pkt: pkt.param_pres == 1
        ),
        fields.ConditionalField(
            formats.SdnvField('tag', default=None),
            lambda pkt: pkt.tag_pres == 1
        ),
    ]

class MidCollection(AbstractData):
    ''' Ordered list of MID values.
    '''
    fields_desc = [
        formats.SdnvFieldLenField('count', default=None, count_of='items'),
        fields.PacketListField('items', default=[],
            count_from=lambda pkt: pkt.count,
            cls=Mid
        ),
    ]

class TimeRule(AbstractData):
    ''' Time-based reporting rule.
    '''
    fields_desc = [
        formats.SdnvField('start', default=None),
        formats.SdnvField('period', default=None),
        formats.SdnvField('count', default=None),
        # default value is packet data string
        fields.PacketField('action', default='', cls=MidCollection),
    ]

packet.bind_layers(TypedData, Byte, type_id=0)
packet.bind_layers(TypedData, Int, type_id=1)
packet.bind_layers(TypedData, UInt, type_id=2)
packet.bind_layers(TypedData, Vast, type_id=3)
packet.bind_layers(TypedData, UVast, type_id=4)
packet.bind_layers(TypedData, Float32, type_id=5)
packet.bind_layers(TypedData, Float64, type_id=6)
packet.bind_layers(TypedData, Str, type_id=7)
packet.bind_layers(TypedData, Blob, type_id=8)
packet.bind_layers(TypedData, Sdnv, type_id=9)
packet.bind_layers(TypedData, Ts, type_id=10)

packet.bind_layers(TypedData, Mid, type_id=12)
packet.bind_layers(TypedData, MidCollection, type_id=13)
packet.bind_layers(TypedData, TypedDataCollection, type_id=18)
packet.bind_layers(TypedData, TimeRule, type_id=16)
