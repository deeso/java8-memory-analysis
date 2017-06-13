import struct

from jvm_flags import AccessFlags, CPCacheEntryFlags
from jvm_overlays import CONSTANT_POOL_META_TYPE, CP_CACHE_META_TYPE,\
               METHOD_META_TYPE, CONST_METHOD_META_TYPE, METHOD_DATA_META_TYPE,\
               CP_CACHE_ENTRY_META_TYPE, METHOD_COUNTERS_META_TYPE
from jvm_overlays import get_bits32, get_bits64, get_named_array32, \
                         get_named_array64, get_field_types, name_fields,\
                         get_klass, get_size32, get_size64, get_meta,\
                         get_oaklassoop

from jvm_base import BaseOverlay
from jvm_templates import ArrayT, ARRAY_MAP


class MethodCounters(BaseOverlay):
    _name = "MethodCounters"
    _overlay = METHOD_COUNTERS_META_TYPE
    bits32 = get_bits32(METHOD_COUNTERS_META_TYPE)
    bits64 = get_bits64(METHOD_COUNTERS_META_TYPE)
    named32 = get_named_array32(METHOD_COUNTERS_META_TYPE)
    named64 = get_named_array64(METHOD_COUNTERS_META_TYPE)
    size32 = get_size32(METHOD_COUNTERS_META_TYPE)
    size64 = get_size64(METHOD_COUNTERS_META_TYPE)
    types = get_field_types(METHOD_COUNTERS_META_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def update_fields(self, force_update=False):
        jva = getattr(self, "jvm_analysis")

        meta = None
        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)

        invocation_counter = getattr(self, "_invocation_counter__counter", None)
        ic_state = invocation_counter & 0b0011
        ic_carry = (invocation_counter & 0b0100) >> 2
        ic_count = (invocation_counter & 0xFFFFFFF8) >> 3
        setattr(self, 'ic_state', ic_state)
        setattr(self, 'ic_carry', ic_carry)
        setattr(self, 'ic_count', ic_count)
        invocation_counter = getattr(self, "_back_edge_counter__counter", None)
        ic_state = invocation_counter & 0b0011
        ic_carry = (invocation_counter & 0b0100) >> 2
        ic_count = (invocation_counter & 0xFFFFFFF8) >> 3
        setattr(self, 'bec_state', ic_state)
        setattr(self, 'bec_carry', ic_carry)
        setattr(self, 'bec_count', ic_count)

class ConstMethod(BaseOverlay):
    _name = "ConstMethod"
    _overlay = CONST_METHOD_META_TYPE
    bits32 = get_bits32(CONST_METHOD_META_TYPE)
    bits64 = get_bits64(CONST_METHOD_META_TYPE)
    named32 = get_named_array32(CONST_METHOD_META_TYPE)
    named64 = get_named_array64(CONST_METHOD_META_TYPE)
    size32 = get_size32(CONST_METHOD_META_TYPE)
    size64 = get_size64(CONST_METHOD_META_TYPE)
    types = get_field_types(CONST_METHOD_META_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__(self):
        name_value = getattr(self, "name_value", None)
        if name_value:
            return str(name_value)
        return "ConstMethod class @ 0x%08x"%(getattr(self, "addr", -1))

    def update_fields(self, force_update=False):

        jva = getattr(self, "jvm_analysis")
        meta = None
        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)

        addr = getattr(self, "constants", None)
        if addr and addr > 0:
            meta = get_meta(jva, addr, ConstantPool)
            setattr(self, 'constants_value', meta)
            meta.update_fields()

        addr = getattr(self, 'stackmap_data', None)
        if addr and addr > 0:
            arry_val = ArrayT.get_array(addr, jva, 'Array<u1>*')
            setattr(self, 'stackmap_data_value', arry_val)

    def get_all_info(self):
        name_idx = getattr(self, 'name_index')
        sig_idx = getattr(self, 'signature_index')
        idnum = getattr(self, 'method_idnum')
        max_stack = getattr(self, 'max_stack')
        max_locals = getattr(self, 'max_locals')
        acc = getattr(self, 'flags')
        return acc, name_idx, sig_idx, idnum, max_stack, max_locals

    def get_idnum(self):
        return getattr(self, 'method_idnum')

    def get_code_sz(self):
        return getattr(self, 'code_size')

    def get_constant_pool(self):
        return getattr(self, 'constants_value', None)

    def signature(self):
        idx = getattr(self, 'signature_index', None)
        cp = self.get_constant_pool()
        return cp.entrys[idx] if idx < len(cp.entrys) else\
               None

    def name(self):
        idx = getattr(self, 'name_index', None)
        cp = self.get_constant_pool()
        return cp.entrys[idx] if idx < len(cp.entrys) else\
               None

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        data_unpack = struct.unpack(fmt, _bytes)
        kargs = {"addr":addr,'jvm_analysis':jvm_analysis,
                 'updated':False,"metatype":'ConstMethod',
                 'ooptype':'', 'klasstype':'', 'is_32bit':jvm_analysis.is_32bit}
        name_fields(data_unpack, nfields, fields=kargs)
        kargs['unpacked_values'] = data_unpack
        d = ConstMethod(**kargs)
        if jvm_analysis:
            jvm_analysis.add_meta(d)
        #d.update_fields()
        return d

class MethodData(BaseOverlay):
    _name = "MethodData"
    _overlay = METHOD_DATA_META_TYPE
    bits32 = get_bits32(METHOD_DATA_META_TYPE)
    bits64 = get_bits64(METHOD_DATA_META_TYPE)
    named32 = get_named_array32(METHOD_DATA_META_TYPE)
    named64 = get_named_array64(METHOD_DATA_META_TYPE)
    size32 = get_size32(METHOD_DATA_META_TYPE)
    size64 = get_size64(METHOD_DATA_META_TYPE)
    types = get_field_types(METHOD_DATA_META_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__(self):
        name_value = getattr(self, "name_value", None)
        if name_value:
            return str(name_value)
        return "MethodData class @ 0x%08x"%(getattr(self, "addr", -1))

    def update_fields(self, force_update=False):
        jva = getattr(self, "jvm_analysis")

        meta = None
        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)

        addr = getattr(self, "method", None)
        if addr and addr > 0:
            meta = get_meta(jva, addr, Method)
            setattr(self, 'method_value', meta)

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        data_unpack = struct.unpack(fmt, _bytes)
        kargs = {"addr":addr,'jvm_analysis':jvm_analysis,
                 'updated':False,"metatype":'MethodData',
                 'ooptype':'', 'klasstype':''}
        name_fields(data_unpack, nfields, fields=kargs)
        kargs['unpacked_values'] = data_unpack
        d = MethodData(**kargs)
        if jvm_analysis:
            jvm_analysis.add_meta(d)
        #d.update_fields()
        return d

class Method(BaseOverlay):
    _name = "Method"
    _overlay = METHOD_META_TYPE
    bits32 = get_bits32(METHOD_META_TYPE)
    bits64 = get_bits64(METHOD_META_TYPE)
    named32 = get_named_array32(METHOD_META_TYPE)
    named64 = get_named_array64(METHOD_META_TYPE)
    size32 = get_size32(METHOD_META_TYPE)
    size64 = get_size64(METHOD_META_TYPE)
    types = get_field_types(METHOD_META_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__(self):
        name_value = getattr(self, "name_value", None)
        if name_value:
            return str(name_value)
        return "Method class @ 0x%08x"%(getattr(self, "addr", -1))

    def update_fields(self, force_update=False):
        jva = self.get_jva()

        meta = None
        if getattr(self, "updated", False) and not force_update:
            return
        setattr(self, "updated", True)
        self.get_const_method()
        addr = getattr(self, "method_data", None)
        if addr and addr > 0:
            meta = get_meta(jva, addr, MethodData)
            setattr(self, 'method_data_value', meta)
            if meta:
                meta.update_fields()
        addr = getattr(self, "method_counters", None)
        if addr and addr > 0:
            meta = get_meta(jva, addr, MethodCounters)
            setattr(self, 'method_counters_value', meta)
            if meta:
                meta.update_fields()
        # addr = getattr(self, "method_counters", None)
        # if addr and addr > 0:
        #     meta = get_meta(jva, addr, MethodData)
        #     setattr(self, 'method_counters', meta)
        prototype = self.method_prototype()
        setattr(self, 'prototype', prototype)

    def read_code(self):
        cm_value = self.get_const_method()
        code_sz = cm_value.get_code_sz()
        # Method + ConstMethod
        offset = cm_value.get_addr()+cm_value.size_aligned()
        jva = self.get_jva()
        code = jva.read(offset, code_sz)
        setattr(self, 'bci', code)
        setattr(self, 'bci_addr', offset)
        setattr(self, 'bci_size', code_sz)

    def update_name (self):
        jva = self.get_jva()
        cm_value = self.get_const_method()
        if cm_value is None:
            return
        setattr(self, 'flags', getattr(cm_value, 'flags'))
        setattr(self, 'signature_value', cm_value.signature())
        setattr(self, 'name_value', cm_value.name())

    def get_const_method(self):
        cm_value = getattr(self, 'const_method_value', None)
        if cm_value is None:
            jva = self.get_jva()
            addr = getattr(self, "const_method", None)
            if addr and addr > 0:
                meta = get_meta(jva, addr, ConstMethod)
                setattr(self, 'const_method_value', meta)
                if meta:
                    meta.update_fields()
                    self.get_constant_pool()
                    self.get_klass_holder()
                    self.read_code()
        cm_value = getattr(self, 'const_method_value', None)
        return cm_value

    def get_constant_pool(self):
        cp_value = getattr(self, "contant_pool_value", None)
        if not cp_value is None:
            return cp_value
        cm_value = self.get_const_method()
        if cm_value is None:
            return None
        cp_value = cm_value.get_constant_pool()
        setattr(self, "contant_pool_value", cp_value)
        return cp_value

    def get_klass_holder(self):
        class_holder = getattr(self, "klass_holder_value", None)
        if not class_holder is None:
            return class_holder
        cp_value = self.get_constant_pool()
        if cp_value:
            class_holder = cp_value.get_pool_holder()
            setattr(self, "klass_holder_value", class_holder)
        return class_holder

    def get_idnum(self):
        method_idnum = getattr(self, "method_idnum", None)
        if not method_idnum is None:
            return method_idnum
        cm_value = self.get_const_method()
        method_idnum = cm_value.get_idnum()
        setattr(self, "method_idnum", method_idnum)
        return method_idnum

    def name(self):
        name_value = getattr(self, 'name_value', None)
        if name_value is None:
            self.update_name()
        name_value = getattr(self, 'name_value', None)
        if name_value is None:
            raise BaseException("Unable to resolve method name")
        return str(name_value)

    def signature(self):
        mname = ""
        try:
            mname = self.name()
        except:
            mname = "UNKNOWN @ 0x%08x"%self.addr

        if mname.find("UNKNOWN @") == 0:
            return ""
        elif mname == "<init>" or mname == "<clinit>":
            return ""
        name_value = getattr(self, 'signature_value', None)
        if name_value is None:
            self.update_name()
        name_value = getattr(self, 'signature_value', None)
        if name_value is None:
            raise BaseException("Unable to resolve method signature for: %s"%str(self))
        return str(name_value)

    def rvalue(self):
        return self.unmangle_return_value(self.signature())

    def parameters(self):
        return self.unmangle_arguments(self.signature())

    def unmangle(self):
        try:
             return self.rvalue(), self.name(), self.parameters()
        except:
             return "UNKNOWN_RVALUE", "UNKNOWN_NAME_0x%08x"%self.addr, ["UNKNOWN_PARAMS",]

    def access_strings(self, idx=0):
        # idx is ignored
        flags = getattr(self, 'flags')
        return AccessFlags.get_method_access_strings(flags)

    def method_prototype(self, idx=0):
        # idx is ignored
        rvalue, name, parameters = self.unmangle()
        access = " ".join(self.access_strings())
        addr = getattr(self, 'addr')
        return ("%s %s %s(%s);// @0x%08x"%(access, rvalue, name,
                ",".join(parameters), addr)).strip()

    @classmethod
    def unmangle_arguments(cls, string):
        if string == "<init>" or string == "<clinit>":
            return []
        results = []
        if string.find("(") > -1 and string.find(")") > string.find("("):
            string = string.split("(")[1].split(")")[0]
        elif string.find("(") > -1 or string.find(")") > -1:
            raise BaseException("Bad method parameter string")

        pos = 0
        end = len(string)
        while pos < end:
            used,t = cls.unmangle_type(string[pos:])
            pos += used
            results.append(t)
        return results

    @classmethod
    def unmangle_return_value(cls, string):
        if string == "<init>" or string == "<clinit>":
            return "V"
        if string.find("(") > -1 and string.find(")") > string.find("("):
            string = string.split(")")[1].strip()
        elif string.find("(") > -1 or string.find(")") > -1:
            raise BaseException("Bad signature string")
        return cls.unmangle_type(string)[1]

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        data_unpack = struct.unpack(fmt, _bytes)
        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False,"metatype":'Method',
                 'ooptype':'', 'klasstype':''}
        name_fields(data_unpack, nfields, fields=kargs)
        kargs['unpacked_values'] = data_unpack
        d = Method(**kargs)
        #d.update_fields()
        if jvm_analysis:
            jvm_analysis.add_meta(d)
        #d.update_fields()
        return d

class ConstantPool(BaseOverlay):
    _name = "ConstantPool"
    _overlay = CONSTANT_POOL_META_TYPE
    bits32 = get_bits32(CONSTANT_POOL_META_TYPE)
    bits64 = get_bits64(CONSTANT_POOL_META_TYPE)
    named32 = get_named_array32(CONSTANT_POOL_META_TYPE)
    named64 = get_named_array64(CONSTANT_POOL_META_TYPE)
    size32 = get_size32(CONSTANT_POOL_META_TYPE)
    size64 = get_size64(CONSTANT_POOL_META_TYPE)
    types = get_field_types(CONSTANT_POOL_META_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__(self):
        name_value = getattr(self, "name_value", None)
        if name_value:
            return str(name_value)
        return "ConstantPool class @ 0x%08x"%(getattr(self, "addr", -1))

    def update_cache(self):
        addr = getattr(self, 'cache')
        jva = self.get_jva()
        if addr:
            meta = get_meta(jva, addr, CPCache)
            setattr(self, 'cache_value', meta)
        else:
            setattr(self, 'cache_value', None)
        cache_value = getattr(self, 'cache_value', None)
        if cache_value:
            cache_value.update_fields()
            cache_value.update_entrys()
            return True
        return False

    def update_resolved_references (self):
        jva = self.get_jva()
        name = "resolved_references"
        addr = getattr(self, name, None)
        if addr:
            naddr = jva.deref32(addr) if jva.is_32bit else\
                    jva.deref64(addr)
            oop = get_oaklassoop(jva, naddr)
            if oop:
                oop.update_fields()
            setattr(self, name+'_value', oop)

    def phase2_update_fields(self):
        self.update_cache()
        #self.update_resolved_references()
        return

    def update_fields(self, force_update=False):
        jva = getattr(self, "jvm_analysis")

        if self.is_updated(force_update):
            return
        #print ("Updating %s force_update=%s updated=%s"%(str(self), force_update, self.updated))
        setattr(self, "updated", True)
        name = "tags"
        addr = getattr(self, name, None)
        if addr:
            t = ArrayT.get_array(addr, jva, "Array<u1>")
            setattr(self, name+'_value', t)
            setattr(self, 'cp_count', t.length)
        name = "operands"
        addr = getattr(self, name, None)
        if addr:
            t = ArrayT.get_array(addr, jva, "Array<u2>")
            setattr(self, name+'_value', t)
        name = "reference_map"
        addr = getattr(self, name, None)
        if addr:
            t = ArrayT.get_array(addr, jva, "Array<u2>")
            setattr(self, name+'_value', t)
        name = "pool_holder"
        addr = getattr(self, name, None)
        klass = None
        if addr:
            klass = get_klass(jva, addr)
            setattr(self, name+'_value', klass)

        if klass:
            #print ("updating cp entrys for %s"%str(klass))
            self.extract_cp_entrys()

    def extract_cp_entrys(self):
        jva = getattr(self, 'jvm_analysis')
        cp_cnt = getattr(self, 'cp_count')
        base = getattr(self, 'addr')

        if cp_cnt == 0:
            print ("Error: Constant pool length is 0, did you update fields 1st?")
            return
        entrys = []
        entrys_addrs = []
        setattr(self, 'entrys', entrys)
        setattr(self, 'entrys_addrs', entrys_addrs)
        base += self.size32 if jva.is_32bit else\
             self.size64
        # slots fall after the main constant pool structure
        incr = jva.word_sz

        for e in xrange(0, cp_cnt):
            found_item = False
            off = base + incr*e
            val = jva.read_addr(off)
            entrys_addrs.append(val)
            if jva.is_valid_addr(val):
                if jva.lookup_internal_symbol_only(val):
                    sym = jva.lookup_internal_symbol_only(val)
                    entrys.append(sym)
                    found_item = True
                #elif jva.lookup_known_oop(val):
                #    oop = jva.lookup_known_oop_only(val)
                #    found_item = True
                #    entrys.append(oop)

            if not found_item:
                entrys.append(None)
        return entrys

    def get_entry (self, idx=0):
        entrys = getattr(self, 'entrys', None)
        if entrys is None:
            raise BaseException("Could not retrieve the CP entrys")
        elif idx < len(entrys):
            return entrys[idx]
        return None
            #raise BaseException("Could not retrieve entry, too many")


    def get_pool_holder(self):
        return getattr(self, 'pool_holder_value', None)

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        #print hex(addr), len(bytes), Klass.bits32, Klass.size32
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        if bytes is None:
            return None
        if jvm_analysis.has_internal_object(addr):
            return jvm_analysis.get_internal_object(addr)


        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False,"metatype":'ConstantPool',
                 'ooptype':'', 'klasstype':'', 'cp_count':0, 'entrys':[]}
        data_unpack = struct.unpack(fmt, _bytes)
        name_fields(data_unpack, nfields, fields=kargs)

        kargs['unpacked_values'] = data_unpack
        #if paddr:
        #    kargs['pool_holder_value'] = get_klass(jvm_analysis, addr)
        d = ConstantPool(**kargs)
        if jvm_analysis:
            jvm_analysis.add_meta(d)
        d.update_fields()
        #setattr(d, "updated", False)
        return d

class CPCacheEntry(BaseOverlay):
    _name = "CPCacheEntry"
    _overlay = CP_CACHE_ENTRY_META_TYPE
    bits32 = get_bits32(CP_CACHE_ENTRY_META_TYPE)
    bits64 = get_bits64(CP_CACHE_ENTRY_META_TYPE)
    named32 = get_named_array32(CP_CACHE_ENTRY_META_TYPE)
    named64 = get_named_array64(CP_CACHE_ENTRY_META_TYPE)
    size32 = get_size32(CP_CACHE_ENTRY_META_TYPE)
    size64 = get_size64(CP_CACHE_ENTRY_META_TYPE)
    types = get_field_types(CP_CACHE_ENTRY_META_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__(self):
        name_value = getattr(self, "name_value", None)
        if name_value:
            return str(name_value)
        return "CPCacheEntry class @ 0x%08x"%(getattr(self, "addr", -1))

    def update_fields(self, force_update=False):
        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)
        val = getattr(self, 'flags')
        jva = self.get_jva()
        flags_info = CPCacheEntryFlags.get_flag_information(val, {})
        setattr(self, 'flags_info', flags_info)
        indices = getattr(self, 'indices')
        cp_index = indices & 0xff
        b1 = (indices >> 16) & 0xff
        b2 = (indices >> 24) & 0xff
        f1_value = None
        f1 = getattr(self, 'f1')
        f2 = getattr(self, 'f2')
        f1_info = None
        f2_info = None
        f2_value = None
        ref_klass = None
        psize = 0
        #print ("before updating cache entry info")
        if flags_info['entry_type'] == 'field':
            f1_value = jva.lookup_known_klass(f1)
            ref_klass = f1_value
            if f1_value:
                f2_info = f1_value.get_field_info_by_offset(f2)
            setattr(self, 'get_code', b1)
            setattr(self, 'put_code', b2)
        else:
            psize = cp_index
            cp_index = 0
            is_virtual = flags_info['is_interface_vcall'] or \
                         flags_info['is_vfinal']
            if flags_info['is_interface_vcall']:
                f1_value = jva.lookup_known_klass(f1)
            else:
                #f1_value = jva.lookup_known_method(f1)
                f1_value = jva.get_method_only(f1)


            setattr(self, 'invoke_code_f1', b1)
            setattr(self, 'invoke_code_f2', b2)
            if f1_value and str(type(f1_value)).find("Klass") > -1:
                ref_klass = f1_value.get_klass_holder()
                if ref_klass and not flags_info['is_vfinal']:
                    f2_value = ref_klass.get_method_by_idx(f2)
                    f2_info = ref_klass.get_method_info_by_idx(f2)
                elif ref_klass:
                    f2_value = jva.lookup_known_meta(f2)
                    f2_info = ref_klass.get_method_info_by_idx(f2)
                elif ref_klass:
                    f2_value = jva.lookup_known_meta(f2)
                    f2_info = ref_klass.get_method_info_by_idx(f2)
            elif f1_value is None:
                f2_value = jva.lookup_known_meta(f2)



        setattr(self, 'f2_info', f2_info)
        setattr(self, 'f1_info', f1_info)
        setattr(self, 'f2_value', f2_value)
        setattr(self, 'f1_value', f1_value)
        setattr(self, 'b1', b1)
        setattr(self, 'b2', b2)
        setattr(self, 'cp_index', cp_index)
        setattr(self, 'psize', psize)
        setattr(self, 'ref_klass', ref_klass)
        if ref_klass:
            cp = ref_klass.get_constant_pool()
            setattr(self, 'cp_entry_value', cp.get_entry(cp_index))
        #print ("done updating cache entry")


class CPCache(BaseOverlay):
    _name = "ConstantPoolCache"
    _overlay = CP_CACHE_META_TYPE
    bits32 = get_bits32(CP_CACHE_META_TYPE)
    bits64 = get_bits64(CP_CACHE_META_TYPE)
    named32 = get_named_array32(CP_CACHE_META_TYPE)
    named64 = get_named_array64(CP_CACHE_META_TYPE)
    size32 = get_size32(CP_CACHE_META_TYPE)
    size64 = get_size64(CP_CACHE_META_TYPE)
    types = get_field_types(CP_CACHE_META_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__(self):
        name_value = getattr(self, "name_value", None)
        if name_value:
            return str(name_value)
        return "CPCache class @ 0x%08x"%(getattr(self, "addr", -1))

    def read_cp_entry_at_idx(self, idx):
        addr = self.get_entry_offset(idx)
        entry = CPCacheEntry.from_jva(addr, self.get_jva())
        #print ("Created CPEntry address = 0x%08x"%entry.addr)
        return entry

    def get_length(self):
        return getattr(self, 'length')

    def update_entrys(self):
        #print ("Updating cache entrys")
        pos = 0
        for e in getattr(self, "cp_cache_entrys"):
            #print ("Updating cache entry: %d"%pos)
            if e:
                e.update_fields()
            pos += 1

    def update_fields(self, force_update=False):
        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)
        cp_cache_entrys = getattr(self, "cp_cache_entrys" )
        idx = 0
        end = self.get_length()
        while idx < end:
            #print ("Updating cache entry: %d out of %d"%(idx, end))
            cp_entry = self.read_cp_entry_at_idx(idx)
            cp_cache_entrys[idx] = cp_entry
            #print ("Done updating cache entry: %d out of %d"%(idx, end))
            #cp_entry.update_fields()
            idx += 1

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        #print hex(addr), len(bytes), Klass.bits32, Klass.size32
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64

        if _bytes is None:
            return None
        if jvm_analysis.has_internal_object(addr):
            return jvm_analysis.get_internal_object(addr)

        kargs = {"addr":addr,'jvm_analysis':jvm_analysis,
                 'updated':False,"metatype":'ConstantPoolCache',
                 'ooptype':'', 'klasstype':'',
                 'is_32bit':jvm_analysis.is_32bit}
        data_unpack = struct.unpack(fmt, _bytes)
        name_fields(data_unpack, nfields, fields=kargs)

        # if is_32bit and jva:
        #     resolve_syms(ConstantPool.types, ConstantPool.named32, jva, kargs)
        # elif jva:
        #     resolve_syms(ConstantPool.types, ConstantPool.named64, jva, kargs)
        #
        kargs["cp_cache_entrys"] = [None for i in xrange(0, kargs['length'])]
        kargs['unpacked_values'] = data_unpack
        d = CPCache(**kargs)
        if jvm_analysis:
            jvm_analysis.add_meta(d)
        #d.update_fields()
        #d.update_klasses(jvm_analysis)
        return d

    def get_entry_offset(self, idx=0):
        jva = self.get_jva()
        cp_cache_entry_sz = CPCacheEntry.header_size32() if jva.is_32bit else\
                            CPCacheEntry.header_size64()
        if idx < getattr(self, "length", 0):
            return self.get_addr() + self.header_size() +\
                   idx * cp_cache_entry_sz
        raise BaseException("Index exceeds cache length")

    def get_entry(self, idx=0):
        entrys = getattr(self, "cp_cache_entrys")
        if idx < len(entrys):
            return entrys[idx]
        raise BaseException("Entry is not in the cp_cache_entrys")


ARRAY_MAP['Method'] = Method
#ARRAY_MAP['Method*'] = Method
