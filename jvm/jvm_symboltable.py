import struct
import numpy as np
import string

from jvm_overlays import SYMBOL_TABLE_BUCKET_TYPE, SYMBOL_TABLE_TYPE,\
                         SYMBOL_TABLE_ENTRY_TYPE, SYMBOL_TYPE

from jvm_overlays import get_bits32, get_bits64, get_named_array32, \
                         get_named_array64, get_field_types, name_fields, \
                         get_size32, get_size64

from jvm_base import BaseOverlay

END_IT_SIZE = 20000
MAX_NUM_SYMBOLS = 65536
class Symbol(BaseOverlay):
    _name = "Symbol"
    _overlay = SYMBOL_TYPE
    bits32 = get_bits32(SYMBOL_TYPE)
    bits64 = get_bits64(SYMBOL_TYPE)
    named32 = get_named_array32(SYMBOL_TYPE)
    named64 = get_named_array64(SYMBOL_TYPE)
    size32 = get_size32(SYMBOL_TYPE)
    size64 = get_size64(SYMBOL_TYPE)
    types = get_field_types(SYMBOL_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def is_symbol(self):
        return True

    def __str__(self):
        v = getattr(self, 'jbyte', 'Unknown Name')
        if v.find("Unknown") == 0:
            return v
        elif all(k in string.printable for k in v):
            return v
        return repr(v)


    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self):
        setattr(self, 'updated', True)

    def raw_value(self):
        return str(getattr(self, 'jbyte'))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        if jvm_analysis and jvm_analysis.has_internal_object(addr):
            sym = jvm_analysis.lookup_internal_symbol_only(addr)
            if sym and sym._name != "Symbol":
                raise BaseException("Symbol is not a symbol @ 0x%08x")
            elif sym:
                return sym
        #print ("In symbol 0x%08x type(bytes)=%s fmt=%s"%(addr, str(type(bytes)), fmt))
        if bytes is None:
            return None
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        data_unpack = struct.unpack(fmt, _bytes)
        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False}
        if jvm_analysis.is_32bit:
            name_fields(data_unpack, Symbol.named32, fields=kargs)
        else:
            name_fields(data_unpack, Symbol.named64, fields=kargs)


        kargs['jbyte'] = None
        _length = kargs['length']
        if _length > 300 :
            print ("Warning: really long symbol length (%d) at 0x%08x"%(_length, addr))
            #return None
        if _length > 1500:
            print ("WARNING: Symbol extremely long length (%d) at 0x%08x"%(_length, addr))
        if _length >= END_IT_SIZE:
            print ("WARNING: Symbol extremely long length (%d) at 0x%08x"%(_length, addr))
            raise Exception("WARNING: Symbol extremely long length (%d) at 0x%08x"%(_length, addr))
            #return None
        # there is a dummy byte in there for the "jbyte"
        if jvm_analysis.is_32bit:
            kargs['jbyte'] = jvm_analysis.read(addr+Symbol.size32-1, _length)
        else:
            kargs['jbyte'] = jvm_analysis.read(addr+Symbol.size64-1, _length)
        d = Symbol(**kargs)
        if jvm_analysis:
            jvm_analysis.insert_symbol(addr, d)
        return d

class SymbolTableEntry(BaseOverlay):
    _name = "HashTableEntry<Symbol*>"
    _overlay = SYMBOL_TABLE_ENTRY_TYPE
    bits32 = get_bits32(SYMBOL_TABLE_ENTRY_TYPE)
    bits64 = get_bits64(SYMBOL_TABLE_ENTRY_TYPE)
    named32 = get_named_array32(SYMBOL_TABLE_ENTRY_TYPE)
    named64 = get_named_array64(SYMBOL_TABLE_ENTRY_TYPE)
    size32 = get_size32(SYMBOL_TABLE_ENTRY_TYPE)
    size64 = get_size64(SYMBOL_TABLE_ENTRY_TYPE)
    types = get_field_types(SYMBOL_TABLE_ENTRY_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__ (self):
        literal = getattr(self, 'literal', -1)
        hash_ = getattr(self, 'hash', -1)
        Symbol_value = getattr(self, 'Symbol_value', None)
        return (" _hash = 0x%08x Symbol@0x%08x->%s "%(hash_, \
            literal, str(Symbol_value)))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self):
        setattr(self, 'updated', True)

    def has_next(self):
        return getattr(self, 'has_next')

    def get_next(self):
        return getattr(self, 'next_value', None)

    def get_value(self):
        return getattr(self, 'Symbol_value', None)

    def get_values(self):
        res = []
        entry = getattr(self, 'Symbol_value', None)
        if self.has_next:
            next_ = self.get_next()
            if next_:
                res = next_.get_values()
        if entry:
            return res.append(entry)
        return res

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        #if jvm_analysis and jvm_analysis.has_internal_object(addr):
        #    return jvm_analysis.get_internal_object(addr)
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        data_unpack = struct.unpack(fmt, _bytes)
        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False}
        name_fields(data_unpack, nfields, fields=kargs)
        _next = kargs['next']
        kargs['has_next'] = _next != 0 and \
                            jvm_analysis.is_valid_addr(_next) and\
                            jvm_analysis.read_addr(_next) != 0

        kargs['next_value'] = None
        if kargs['has_next']:
            kargs['next_value'] = SymbolTableEntry.from_jva(cls.make_ptr(_next),
                                  jvm_analysis)

        kargs['Symbol_value'] = None
        _literal = kargs['literal']
        if jvm_analysis.is_valid_addr(_literal):
            kargs['Symbol_value'] = Symbol.from_jva(_literal, jvm_analysis)
        d = SymbolTableEntry(**kargs)
        if jvm_analysis:
            jvm_analysis.add_internal_object(addr, d)
        return d

class SymbolTableBucket(BaseOverlay):
    _name = "SymbolTableBucket"
    _overlay = SYMBOL_TABLE_BUCKET_TYPE
    bits32 = get_bits32(SYMBOL_TABLE_BUCKET_TYPE)
    bits64 = get_bits64(SYMBOL_TABLE_BUCKET_TYPE)
    named32 = get_named_array32(SYMBOL_TABLE_BUCKET_TYPE)
    named64 = get_named_array64(SYMBOL_TABLE_BUCKET_TYPE)
    size32 = get_size32(SYMBOL_TABLE_BUCKET_TYPE)
    size64 = get_size64(SYMBOL_TABLE_BUCKET_TYPE)
    types = get_field_types(SYMBOL_TABLE_BUCKET_TYPE)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self):
        setattr(self, 'updated', True)

    def has_entry (self):
        return not getattr(self, 'entry_is_null', True)

    def get_entry_addr (self):
        literal = getattr(self, 'literal', -1)
        if self.has_entry():
            return literal
        return 0

    def get_entry_value (self):
        if self.has_entry():
            entry_value = getattr(self, 'entry_value', None)
            return entry_value.get_value()
        return None

    def get_entry_values (self):
        res = []
        if self.has_entry():
            entry_value = getattr(self, 'entry_value', None)
            while entry_value:
                if entry_value:
                    res.append(entry_value.get_value())
                    entry_value = entry_value.next_value
        return res

    def __str__(self):
        entry_value = getattr(self, 'entry_value', None)
        entry = getattr(self, 'entry', -1)
        entry_str = "NONE" if self.has_entry() else str(entry_value)
        return "%s 0x%08x %s"%(self._name, entry, entry_str)

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        if jvm_analysis and jvm_analysis.has_internal_object(addr):
            return jvm_analysis.get_internal_object(addr)

        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        data_unpack = struct.unpack(fmt, _bytes)
        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False}
        name_fields(data_unpack, nfields, fields=kargs)

        _entry = kargs["entry"]
        kargs["entry_value"] = None
        kargs["entry_is_null"] = _entry == 0
        kargs['entry_values'] = []
        if not kargs["entry_is_null"]:
            kargs['entry_value'] = SymbolTableEntry.from_jva(_entry, jvm_analysis)

        d = SymbolTableBucket(**kargs)
        if jvm_analysis:
            jvm_analysis.add_internal_object(addr, d)
        return d

class SymbolTable(BaseOverlay):
    _name = "SymbolTable"
    _overlay = SYMBOL_TABLE_TYPE
    bits32 = get_bits32(SYMBOL_TABLE_TYPE)
    bits64 = get_bits64(SYMBOL_TABLE_TYPE)
    named32 = get_named_array32(SYMBOL_TABLE_TYPE)
    named64 = get_named_array64(SYMBOL_TABLE_TYPE)
    size32 = get_size32(SYMBOL_TABLE_TYPE)
    size64 = get_size64(SYMBOL_TABLE_TYPE)
    types = get_field_types(SYMBOL_TABLE_TYPE)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__ (self):
        addr = getattr(self, 'addr', None)
        return ("SymbolTable@0x%08x"%addr)

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self):
        setattr(self, 'updated', True)

    def get_bucket_values(self):
        bucket_values = getattr(self, 'bucket_values', [])
        res = []

        if bucket_values is None:
            return res
        for stb in bucket_values:
            if stb and stb.has_entry():
                v = stb.get_entry_values()
                if v:
                     res += v
        return res

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):

        if jvm_analysis and jvm_analysis.has_internal_object(addr):
            return jvm_analysis.get_internal_object(addr)

        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        data_unpack = struct.unpack(fmt, _bytes)
        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False}
        name_fields(data_unpack, nfields, fields=kargs)

        kargs['bucket_values'] = None

        if jvm_analysis:
            symbol_table_buckets = []
            pos = 0
            incr = jvm_analysis.word_sz
            _table_size = kargs['table_size']
            _buckets = kargs['buckets']
            while pos < _table_size:
                stb_addr = pos*incr+_buckets
                symbol_table_bucket = SymbolTableBucket.from_jva(stb_addr, jvm_analysis)
                symbol_table_buckets.append(symbol_table_bucket)
                pos += 1
            kargs['bucket_values'] = symbol_table_buckets

        d = SymbolTable(**kargs)
        if jvm_analysis:
            jvm_analysis.add_internal_object(addr, d)
        return d

    @classmethod
    def find_best_match(cls, sym_tables, jva):
        best_match = {}
        candidates = {}
        symt_avgs = [(i, np.mean([len(str(j)) for j in i.get_bucket_values()])) for i in sym_tables if len(i.get_bucket_values()) > 0]
        for symt, avg in symt_avgs:
            if symt is None or len(symt.get_bucket_values()) == 0 or\
                    len(symt.get_bucket_values()) > MAX_NUM_SYMBOLS:
                continue
            a = symt.addr
            bvalues = symt.get_bucket_values()
            syms = [str(i) for i in bvalues]
            max_sym_len = np.max([len(i) for i in syms])
            if max_sym_len < 65537 and avg < 100:
                return symt
        return None


