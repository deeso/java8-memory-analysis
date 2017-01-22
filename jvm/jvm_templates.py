import struct
from jvm_overlays import KLASS_TYPE, INSTANCE_KLASS_TYPE, ARRAY_KLASS_TYPE, \
                OBJ_ARRAY_KLASS_TYPE, TYPE_ARRAY_KLASS_TYPE, ARRAY_T_TYPE

from jvm_overlays import get_bits32, get_bits64, get_named_array32, \
                         get_named_array64, get_field_types, name_fields,\
                         get_named_types_dict, get_field_sizes32, \
                         get_field_sizes64, get_size32, get_size64
from jvm_base import BaseOverlay

#from jvm_klass import Klass
#from jvm_meta import Method

ARRAY_MAP = {
    "jushort":None,
    "int":None,
    "u2":None,
    "u1":None,
    "Klass*":None,#Klass,
    "Method*":None,#Method,
}


class U2(BaseOverlay):
    _name ="prim_short"
    bits32 = 'H'
    bits64 = 'H'
    named32 = []
    named64 = []
    size32 = 2
    size64 = 2
    types = ['u2']
    _overlay = []

    def __init__(self):
        pass

    def update_fields(self, force_update=False):
        pass

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        data_unpack = struct.unpack(fmt, _bytes)
        return data_unpack[0]

class U1(BaseOverlay):
    _name ="prim_byte"
    bits32 = 'B'
    bits64 = 'B'
    named32 = []
    named64 = []
    size32 = 1
    size64 = 1
    types = ['u1']
    _overlay = []

    def __init__(self):
        pass

    def update_fields(self, force_update=False):
        pass

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        return ord(_bytes[0])

class U4(BaseOverlay):
    _name ="prim_int"
    bits32 = 'I'
    bits64 = 'I'
    named32 = []
    named64 = []
    size32 = 4
    size64 = 4
    types = ['u4']
    _overlay = []

    def __init__(self):
        pass

    def update_fields(self, force_update=False):
        pass

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        data_unpack = struct.unpack(fmt, _bytes)
        return data_unpack[0]

class U8(BaseOverlay):
    _name ="prim_longlong"
    bits32 = 'Q'
    bits64 = 'Q'
    named32 = []
    named64 = []
    size32 = 8
    size64 = 8
    types = ['u8']
    _overlay = []

    def __init__(self):
        pass

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        data_unpack = struct.unpack(fmt, _bytes)
        return data_unpack[0]

class ArrayT(BaseOverlay):
    bits32 = get_bits32(ARRAY_T_TYPE)
    bits64 = get_bits64(ARRAY_T_TYPE)
    named32 = get_named_array32(ARRAY_T_TYPE)
    named64 = get_named_array64(ARRAY_T_TYPE)
    size32 = get_size32(ARRAY_T_TYPE)
    size64 = get_size64(ARRAY_T_TYPE)
    types = get_field_types(ARRAY_T_TYPE)
    _overlay = ARRAY_T_TYPE

    def __init__(self, **kargs):
        #list.__init__(self)
        for k,v in kargs.items():
            setattr(self, k, v)

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)
        
    def parse_class_fields(self):
        setattr(self, 'updated', True)

    @classmethod
    def get_array (cls, addr, jvm_analysis, cls_str):
        sz = ArrayT.size32 if jvm_analysis.is_32bit else \
             ArrayT.size64
        nbytes = jvm_analysis.read(addr, sz)
        if nbytes is None:
            print ("nbytes is none @ 0x%08x"%addr)
            return None
        return ArrayT.from_bytes(addr, nbytes, jvm_analysis, cls_str)

    @classmethod
    def from_bytes (cls, addr, _bytes, jvm_analysis, cls_str):
        sz = ArrayT.size32 if jvm_analysis.is_32bit else ArrayT.size64
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        cls_name = cls_str.split("<")[1].split(">")[0]
        mcls = ARRAY_MAP.get(cls_name.strip('*'), None)
        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False,'elem':[], "T":cls_name,
                 'value_ptr':False, 'cls':mcls,}
        data_unpack = struct.unpack(fmt, _bytes)

        name_fields(data_unpack, nfields, fields=kargs)

        _length = kargs['length']
        _elem = kargs['elem']
        pos = 0
        incr = 0
        value_ptr = False
        if cls_name[-1] == '*':
            kargs['value_ptr'] = True
            incr = 4 if jvm_analysis.is_32bit else 8
            value_ptr = True
        else:
            incr = mcls.size32 if jvm_analysis.is_32bit else mcls.size64

        if not mcls is None and _length > 0 and _length < 65535:
            waddr = addr+4
            sz = mcls.size32 if jvm_analysis.is_32bit else mcls.size64
            #print ("Staring at 0x%08x reading %d %s %d"%(waddr, _length, cls._name, sz))
            while pos < _length:
                stb_addr = pos*incr+waddr
                if value_ptr:
                    stb_addr = jvm_analysis.deref32(stb_addr) if jvm_analysis.is_32bit else\
                               jvm_analysis.deref64(stb_addr)
                nbytes = jvm_analysis.read(stb_addr, sz)
                e = None
                if not nbytes is None:
                    e = mcls.from_jva(stb_addr, jvm_analysis)
                #print e
                _elem.append(e)
                pos += 1
        if _length > 65535:
            print ("Something is wrong at 0x%08x wants to read %d for %s %d"%(addr, _length, mcls._name, sz))

        d = ArrayT(**kargs)
        #if jvm_analysis:
        #    jvm_analysis.add_internal_object(addr, d)
        return d



ARRAY_MAP["jushort"] = U2
ARRAY_MAP["int"] = U4
ARRAY_MAP["u2"] = U2
ARRAY_MAP["u1"] = U1
