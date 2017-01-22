import struct

from jvm_overlays import CHAR_OOP_TYPE, BYTE_OOP_TYPE, INT_OOP_TYPE,\
            LONG_OOP_TYPE, SHORT_OOP_TYPE, BOOL_OOP_TYPE, DOUBLE_OOP_TYPE,\
            FLOAT_OOP_TYPE

from jvm_overlays import get_bits32, get_bits64, get_named_array32, \
                         get_named_array64, get_field_types, get_size32,\
                         get_size64
from jvm_base import BaseOverlay


class IntKlass:
    _name = "Integer"
    def __str__(self):
        return self._name

class ByteOop(BaseOverlay):
    _name = "ByteOop"
    _overlay = BYTE_OOP_TYPE
    bits32 = get_bits32(BYTE_OOP_TYPE)
    bits64 = get_bits64(BYTE_OOP_TYPE)
    named32 = get_named_array32(BYTE_OOP_TYPE)
    named64 = get_named_array64(BYTE_OOP_TYPE)
    size32 = get_size32(BYTE_OOP_TYPE)
    size64 = get_size64(BYTE_OOP_TYPE)
    types = get_field_types(BYTE_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value', None)

    def python_value(self, bread_crumbs={}, **kargs):
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':False,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        #if not v is None:
        #    v = bytes(v)
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field(self, field_name, klass_name=None):
        return self.get_oop_field_value(field_name)

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis,
                  "ooptype":cls._name, "klasstype":""}
        fmt = cls.bits32
        data_unpack, = struct.unpack(fmt, _bytes)
        kargs['value'] = data_unpack
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class CharOop(BaseOverlay):
    _name = "CharOop"
    _overlay = CHAR_OOP_TYPE
    bits32 = get_bits32(CHAR_OOP_TYPE)
    bits64 = get_bits64(CHAR_OOP_TYPE)
    named32 = get_named_array32(CHAR_OOP_TYPE)
    named64 = get_named_array64(CHAR_OOP_TYPE)
    size32 = get_size32(CHAR_OOP_TYPE)
    size64 = get_size64(CHAR_OOP_TYPE)
    types = get_field_types(CHAR_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':False,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        jva = jvm_analysis
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis,
                  "ooptype":cls._name, "klasstype":""}
        fmt = cls.bits32
        data_unpack = struct.unpack(fmt, _bytes)
        kargs['value'] = "".join(data_unpack)
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class DoubleOop(BaseOverlay):
    _name = "DoubleOop"
    _overlay = DOUBLE_OOP_TYPE
    bits32 = get_bits32(DOUBLE_OOP_TYPE)
    bits64 = get_bits64(DOUBLE_OOP_TYPE)
    named32 = get_named_array32(DOUBLE_OOP_TYPE)
    named64 = get_named_array64(DOUBLE_OOP_TYPE)
    size32 = get_size32(DOUBLE_OOP_TYPE)
    size64 = get_size64(DOUBLE_OOP_TYPE)
    types = get_field_types(DOUBLE_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':False,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field(self, field_name, klass_name=None):
        return self.get_oop_field_value(field_name)

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis,
                    "ooptype":cls._name, "klasstype":""}
        fmt = cls.bits32
        data_unpack, = struct.unpack(fmt, _bytes)
        kargs['value'] = data_unpack
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class FloatOop(BaseOverlay):
    _name = "FloatOop"
    _overlay = FLOAT_OOP_TYPE
    bits32 = get_bits32(FLOAT_OOP_TYPE)
    bits64 = get_bits64(FLOAT_OOP_TYPE)
    named32 = get_named_array32(FLOAT_OOP_TYPE)
    named64 = get_named_array64(FLOAT_OOP_TYPE)
    size32 = get_size32(FLOAT_OOP_TYPE)
    size64 = get_size64(FLOAT_OOP_TYPE)
    types = get_field_types(FLOAT_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':False,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field(self, field_name, klass_name=None):
        return self.get_oop_field_value(field_name)

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        jva = jvm_analysis
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis, "ooptype":cls._name,
                  "klasstype":""}
        fmt = cls.bits32
        data_unpack, = struct.unpack(fmt, _bytes)
        kargs['value'] = data_unpack
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class IntOop(BaseOverlay):
    _name = "IntOop"
    _overlay = INT_OOP_TYPE
    bits32 = get_bits32(INT_OOP_TYPE)
    bits64 = get_bits64(INT_OOP_TYPE)
    named32 = get_named_array32(INT_OOP_TYPE)
    named64 = get_named_array64(INT_OOP_TYPE)
    size32 = get_size32(INT_OOP_TYPE)
    size64 = get_size64(INT_OOP_TYPE)
    types = get_field_types(INT_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':False,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field(self, field_name, klass_name=None):
        return self.get_oop_field_value(field_name)

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis,
                    "ooptype":cls._name, "klasstype":""}
        fmt = cls.bits32
        data_unpack, = struct.unpack(fmt, _bytes)
        kargs['value'] = data_unpack
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class LongOop(BaseOverlay):
    _name = "LongOop"
    _overlay = LONG_OOP_TYPE
    bits32 = get_bits32(LONG_OOP_TYPE)
    bits64 = get_bits64(LONG_OOP_TYPE)
    named32 = get_named_array32(LONG_OOP_TYPE)
    named64 = get_named_array64(LONG_OOP_TYPE)
    size32 = get_size32(LONG_OOP_TYPE)
    size64 = get_size64(LONG_OOP_TYPE)
    types = get_field_types(LONG_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':False,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field(self, field_name, klass_name=None):
        return self.get_oop_field_value(field_name)

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis, "ooptype":cls._name,
                  "klasstype":""}
        fmt = cls.bits32
        data_unpack, = struct.unpack(fmt, _bytes)
        kargs['value'] = data_unpack
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class ShortOop(BaseOverlay):
    _name = "ShortOop"
    _overlay = SHORT_OOP_TYPE
    bits32 = get_bits32(SHORT_OOP_TYPE)
    bits64 = get_bits64(SHORT_OOP_TYPE)
    named32 = get_named_array32(SHORT_OOP_TYPE)
    named64 = get_named_array64(SHORT_OOP_TYPE)
    size32 = get_size32(SHORT_OOP_TYPE)
    size64 = get_size64(SHORT_OOP_TYPE)
    types = get_field_types(SHORT_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':False,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field(self, field_name, klass_name=None):
        return self.get_oop_field_value(field_name)

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis, "ooptype":cls._name,
                  "klasstype":""}
        fmt = cls.bits32
        data_unpack, = struct.unpack(fmt, _bytes)
        kargs['value'] = data_unpack
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class BoolOop(BaseOverlay):
    _name = "BoolOop"
    _overlay = BOOL_OOP_TYPE
    bits32 = get_bits32(BOOL_OOP_TYPE)
    bits64 = get_bits64(BOOL_OOP_TYPE)
    named32 = get_named_array32(BOOL_OOP_TYPE)
    named64 = get_named_array64(BOOL_OOP_TYPE)
    size32 = get_size32(BOOL_OOP_TYPE)
    size64 = get_size64(BOOL_OOP_TYPE)
    types = get_field_types(BOOL_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        v = self.raw_value()
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':False,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        v = v > 0 if v else False
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field(self, field_name, klass_name=None):
        return self.get_oop_field_value(field_name)

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis, "ooptype":cls._name,
                  "klasstype":""}
        fmt = cls.bits32
        data_unpack, = struct.unpack(fmt, _bytes)
        kargs['value'] = data_unpack
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d


class ByteArrayOop(BaseOverlay):
    _name = "ByteArrayOop"
    _overlay = BYTE_OOP_TYPE
    bits32 = get_bits32(BYTE_OOP_TYPE)
    bits64 = get_bits64(BYTE_OOP_TYPE)
    named32 = get_named_array32(BYTE_OOP_TYPE)
    named64 = get_named_array64(BYTE_OOP_TYPE)
    size32 = get_size32(BYTE_OOP_TYPE)
    size64 = get_size64(BYTE_OOP_TYPE)
    types = get_field_types(BYTE_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        v = self.raw_value()
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':True,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        #if not v is None:
        #    v = bytes(v)
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field(self, field_name, klass_name=None):
        return self.get_oop_field_value(field_name)

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis, "ooptype":cls._name,
                  "klasstype":""}
        fmt = cls.bits32
        data_unpack = struct.unpack(fmt, _bytes)
        kargs['value'] = "".join(data_unpack)
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class CharArrayOop(BaseOverlay):
    _name = "CharArrayOop"
    _overlay = CHAR_OOP_TYPE
    bits32 = get_bits32(CHAR_OOP_TYPE)
    bits64 = get_bits64(CHAR_OOP_TYPE)
    named32 = get_named_array32(CHAR_OOP_TYPE)
    named64 = get_named_array64(CHAR_OOP_TYPE)
    size32 = get_size32(CHAR_OOP_TYPE)
    size64 = get_size64(CHAR_OOP_TYPE)
    types = get_field_types(CHAR_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        v = self.raw_value()
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':True,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field(self, field_name, klass_name=None):
        return self.get_oop_field_value(field_name)

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis, "ooptype":cls._name,
                  "klasstype":""}
        fmt = cls.bits32
        data_unpack = struct.unpack(fmt, _bytes)
        kargs['value'] = "".join(data_unpack)
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class DoubleArrayOop(BaseOverlay):
    _name = "DoubleArrayOop"
    _overlay = DOUBLE_OOP_TYPE
    bits32 = get_bits32(DOUBLE_OOP_TYPE)
    bits64 = get_bits64(DOUBLE_OOP_TYPE)
    named32 = get_named_array32(DOUBLE_OOP_TYPE)
    named64 = get_named_array64(DOUBLE_OOP_TYPE)
    size32 = get_size32(DOUBLE_OOP_TYPE)
    size64 = get_size64(DOUBLE_OOP_TYPE)
    types = get_field_types(DOUBLE_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        v = self.raw_value()
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':True,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field(self, field_name, klass_name=None):
        return self.get_oop_field_value(field_name)

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis, "ooptype":cls._name,
                  "klasstype":""}
        fmt = cls.bits32
        data_unpack = struct.unpack(fmt, _bytes)
        kargs['value'] = "".join(data_unpack)
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class FloatArrayOop(BaseOverlay):
    _name = "FloatArrayOop"
    _overlay = FLOAT_OOP_TYPE
    bits32 = get_bits32(FLOAT_OOP_TYPE)
    bits64 = get_bits64(FLOAT_OOP_TYPE)
    named32 = get_named_array32(FLOAT_OOP_TYPE)
    named64 = get_named_array64(FLOAT_OOP_TYPE)
    size32 = get_size32(FLOAT_OOP_TYPE)
    size64 = get_size64(FLOAT_OOP_TYPE)
    types = get_field_types(FLOAT_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':True,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis, "ooptype":cls._name,
                  "klasstype":""}
        fmt = cls.bits32
        data_unpack = struct.unpack(fmt, _bytes)
        kargs['value'] = "".join(data_unpack)
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class IntArrayOop(BaseOverlay):
    _name = "IntArrayOop"
    _overlay = INT_OOP_TYPE
    bits32 = get_bits32(INT_OOP_TYPE)
    bits64 = get_bits64(INT_OOP_TYPE)
    named32 = get_named_array32(INT_OOP_TYPE)
    named64 = get_named_array64(INT_OOP_TYPE)
    size32 = get_size32(INT_OOP_TYPE)
    size64 = get_size64(INT_OOP_TYPE)
    types = get_field_types(INT_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':True,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis, "ooptype":cls._name,
                  "klasstype":""}
        fmt = cls.bits32
        data_unpack = struct.unpack(fmt, _bytes)
        kargs['value'] = "".join(data_unpack)
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class LongArrayOop(BaseOverlay):
    _name = "LongArrayOop"
    _overlay = LONG_OOP_TYPE
    bits32 = get_bits32(LONG_OOP_TYPE)
    bits64 = get_bits64(LONG_OOP_TYPE)
    named32 = get_named_array32(LONG_OOP_TYPE)
    named64 = get_named_array64(LONG_OOP_TYPE)
    size32 = get_size32(LONG_OOP_TYPE)
    size64 = get_size64(LONG_OOP_TYPE)
    types = get_field_types(LONG_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':True,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis, "ooptype":cls._name,
                  "klasstype":""}
        fmt = cls.bits32
        data_unpack = struct.unpack(fmt, _bytes)
        kargs['value'] = "".join(data_unpack)
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class ShortArrayOop(BaseOverlay):
    _name = "ShortArrayOop"
    _overlay = SHORT_OOP_TYPE
    bits32 = get_bits32(SHORT_OOP_TYPE)
    bits64 = get_bits64(SHORT_OOP_TYPE)
    named32 = get_named_array32(SHORT_OOP_TYPE)
    named64 = get_named_array64(SHORT_OOP_TYPE)
    size32 = get_size32(SHORT_OOP_TYPE)
    size64 = get_size64(SHORT_OOP_TYPE)
    types = get_field_types(SHORT_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':True,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        jva = jvm_analysis
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis, "ooptype":cls._name,
                  "klasstype":""}
        fmt = cls.bits32
        data_unpack = struct.unpack(fmt, _bytes)
        kargs['value'] = "".join(data_unpack)
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d

class BoolArrayOop(BaseOverlay):
    _name = "BoolArrayOop"
    _overlay = BOOL_OOP_TYPE
    bits32 = get_bits32(BOOL_OOP_TYPE)
    bits64 = get_bits64(BOOL_OOP_TYPE)
    named32 = get_named_array32(BOOL_OOP_TYPE)
    named64 = get_named_array64(BOOL_OOP_TYPE)
    size32 = get_size32(BOOL_OOP_TYPE)
    size64 = get_size64(BOOL_OOP_TYPE)
    types = get_field_types(BOOL_OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_klass_prim(self):
        return True

    def __str__(self):
        #a = "0x%08x "%getattr(self, 'addr', '')
        #a = a + getattr(self, '_name', '')
        #a = a + " value: "+ str(getattr(self, 'value', ''))
        return str(getattr(self, 'value', ''))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def raw_value(self):
        return getattr(self, 'value')

    def python_value(self, bread_crumbs={}, **kargs):
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':True,
                                       'is_prim':True, 'value':{},
                                       'addr':self.addr}
        v = self.raw_value()
        bread_crumbs[self.addr]['value'] = v
        return v

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        kargs = { "addr":addr, "updated":False, 'jvm_analysis':jvm_analysis, "ooptype":cls._name,
                  "klasstype":""}
        fmt = cls.bits32
        data_unpack = struct.unpack(fmt, _bytes)
        kargs['value'] = "".join(data_unpack)
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        return d
