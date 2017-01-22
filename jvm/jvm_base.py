import struct, copy
from jvm_flags import AccessFlags
from jvm_overlays import get_bits32, get_bits64, get_named_array32, \
                         get_named_array64, get_field_types, name_fields,\
                         get_size32, get_size64, print_overlay_offsets32,\
                         print_overlay_offsets64

from datetime import datetime

def time_str():
    return str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))
PRIMITIVES_LIST = [
    'C', 'B', 'D', 'F', 'I', 'J', 'S', 'Z',
    'char', 'byte', 'double', 'float', 'int', 'long', 'short', 'bool',
'[B', '[C', '[D', '[F', '[I', '[J', '[S', '[Z', ]

JAVA_LANG_PRIMITIVES_LIST = ['java/lang/Byte',
    'java/lang/Character', 'java/lang/Double', 'java/lang/Float',
    'java/lang/Integer', 'java/lang/Long', 'java/lang/Short',
    'java/lang/Boolean',
]
JAVA_LANG_PRIMITIVES = set(JAVA_LANG_PRIMITIVES_LIST)

TYPES = {"V":'void', "J":'long', 'Z':'boolean', 'I':"integer",
         "C":'char', "B":'byte', 'F':'float', 'D':"double",
         "S":'short'}

PRIM_KLASS_NAME_MAPPING = {
'BoolOop':'bool',
'BoolArrayOop':'[bool',
'ByteOop':'byte',
'ByteArrayOop':'[byte',
'DoubleOop':'double',
'DoubleArrayOop':'[double',
'FloatOop':'float',
'FloatArrayOop':'[float',
'IntOop':'int',
'IntArrayOop':'[int',
'CharOop':'char',
'CharArrayOop':'[char',
'IntOop':'int',
'IntArrayOop':'[int',
'LongOop':'long',
'LongArrayOop':'[long',
'ShortOop':'short',
'ShortArrayOop':'[short',
}

PRIMITIVES = set(PRIMITIVES_LIST)

class BaseOverlay(object):
    is_win = False
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)
        jva = getattr(self, 'jvm_analysis')
        setattr(self, 'word_sz', jva.word_sz)
        setattr(self, 'is_32bit', jva.is_32bit)
        setattr(self, 'field_cnt', 0)
        setattr(self, 'oop_fields_updated', False)
        setattr(self, 'field_info_by_offset', {})
        setattr(self, 'all_field_infos', {})
        setattr(self, 'all_field_infos_visited', False)

    def __getstate__(self):
        #jva = getattr(self, 'jvm_analysis', None)
        #setattr(self, 'jvm_analysis', None)
        #print ("Pickling: %s"%str(self))
        #odict = self.__dict__.copy()#copy.deepcopy(self.__dict__)
        #print ("Done with the copy: %s"%str(self))
        #setattr(self, 'jvm_analysis', jva)
        return self.__dict__

    def set_jvm_analysis(self, jva):
        setattr(self, 'jvm_analysis', jva)

    def __setstate__(self, _dict):
        self.__dict__.update(_dict)

    def is_updated(self, force_update=False):
        if getattr(self, 'updated', False) or force_update:
            return True
        return False

    def get_addr(self):
        return getattr(self, 'addr')

    def dump_class_prototypes(self):
        klass = self.get_klass()
        methods = []
        method_info = getattr(klass, 'method_info', {})
        for mi in method_info.values():
            methods.append(mi.get('prototype', ''))
        fields = []
        field_info = getattr(klass, 'field_info', {})
        for fi in field_info.values():
            fields.append(fi.get('prototype', ''))

        fields = "// Fields\n%s\n"%"\n".join(fields)
        methods = "// Fields\n%s\n"%"\n".join(methods)

        fmt = "%s{\n%s\n%s\n}"
        klass_prototype = "// @0x%08x\n%s"%(getattr(self, 'addr'), getattr(klass, 'prototype'))
        # methods
        # fields
        # TODO inner classes
        # TODO anonymous classes
        return fmt%(klass_prototype, fields, methods )

    def add_method_value(self, name, idnum, method_klass):
        klass = self.get_klass()
        if not self.is_instance():
            return False
        method_values = getattr(klass, 'method_values')
        method_values[idnum] = method_klass
        method_values_by_name = getattr(klass, 'method_values_by_name')
        if not name in method_values_by_name:
            method_values_by_name[name] = set()
        method_values_by_name[name].add(method_klass)
        return True

    def get_methods (self):
        methods = []
        klass = self.get_klass()
        if klass is None:
            return names
        method_values = getattr(klass, 'method_values')
        for method in method_values.values():
            methods.append(method)
        return methods

    def get_method_names (self):
        names = []
        klass = self.get_klass()
        if klass is None:
            return names
        method_values = getattr(klass, 'method_values')
        for method in method_values.values():
            names.append(method.name())
        return names

    def get_method_by_name (self, name):
        methods = []
        klass = self.get_klass()
        if klass is None:
            return methods
        method_values_by_name = getattr(klass, 'method_values_by_name')
        if name in method_values_by_name:
            methods = list(method_values_by_name[name])
        return methods

    def get_method_by_idx (self, idx):
        method = None
        klass = self.get_klass()
        if klass is None:
            return method
        method_values = getattr(klass, 'method_values')
        if idx in method_values:
            method = method_values[idx]
        return method

    @classmethod
    def align_pad(cls, addr, align=8):
        return (align - (addr % align)) % align

    #TODO highly inappropriate to do the whole classmethod vs. instance method here
    # trying to account for windows
    @classmethod
    def header_size32(cls):
        sz = cls.size32
        if cls._name.find("Klass") > -1:
            sz = cls.size32 - (BaseOverlay.is_win * 4)
        return sz + cls.align_pad(sz)

    @classmethod
    def header_size64(cls):
        sz = cls.size64
        return sz + cls.align_pad(sz)

    def header_size(self):
        sz = self.size()
        return sz + self.align_pad(sz)

    def cpcache_entry_offset(self, idx=0):
        #if getattr(self, "_name", "") != "ConstantPoolCache":
        #    raise BaseException("Object not a ConstantPoolCache")
        if getattr(self, "_name", "") != "ConstantPoolCache":
            raise BaseException("Object not a ConstantPoolCache")
        #cp_cache = getattr(self, "cache_value", None)
        #if cp_cache is None:
        #    raise BaseException("Object not a ConstantPoolCache")
        #num_cp_cache_entrys = getattr(cp_cache, "length", 0)
        return self.get_entry_offset(idx=idx)


    def jvtable_size(self):
        klass = self.get_klass()
        word_sz = getattr(klass, "word_sz")
        sz = klass.jvtable_len()*word_sz
        return sz + self.align_pad(sz)

    def jvtable_end(self):
        klass = self.get_klass()
        return klass.jvtable_offset() +\
               klass.jvtable_size()

    def jitable_end(self):
        klass = self.get_klass()
        return klass.jitable_offset() +\
               klass.jitable_size()

    def jitable_len(self):
        klass = self.get_klass()
        return getattr(klass, 'itable_len')

    def jvtable_len(self):
        klass = self.get_klass()
        return getattr(klass, 'vtable_len')

    def jitable_size(self):
        klass = self.get_klass()
        word_sz = getattr(klass, "word_sz")
        sz = klass.jitable_len()*word_sz
        return sz + self.align_pad(sz)

    def jvtable_offset(self):
        klass = self.get_klass()
        return klass.header_size() + klass.get_addr()

    def jitable_offset(self):
        klass = self.get_klass()
        return klass.jvtable_end() + klass.get_addr()

    def joop_maps_offset(self):
        klass = self.get_klass()
        return klass.jitable_end()

    def set_constant_pool (self):
        raise NotImplementedError

    def get_method_info_by_idx(self, idx):
        klass = self.get_klass()
        info = getattr(klass, 'method_info', {})
        if idx in info:
            return info[idx]
        print ("Error could not find %d in method info in %s"%(idx, str(klass)))
        return None

    def get_field_info_by_offset(self, offset):
        klass = self.get_klass()
        info = klass.get_field_info()
        res = None
        if info:
            for i in info.values():
                if i['offset'] == offset:
                    res = i
                    break
        if not res:
            print ("Error could not field offset 0x%04x in field info"%offset)
        return res

    def get_field_info_by_idx(self, idx):
        klass = self.get_klass()
        info = getattr(klass, 'field_info', {})
        if idx in info:
            return info[idx]
        print ("Error could not find %d in field info in %s"%(idx, str(klass)))
        return None

    def is_java_klass(self):
        klass = None
        if _name.lower().find("oop") > -1:
            klass = getattr(self, 'klass_value', None)
        return not klass is None

    def get_klass(self):
        klass = None
        _name = getattr(self, '_name', '').lower()
        if _name.lower().find("oop") > -1:
            klass = getattr(self, 'klass_value', None)
        elif _name.find('klass') > -1:
            klass = self
        return klass

    def klass_name(self):
        klass = self.get_klass()
        check_oop_klass = False if klass else self._name.lower().find('oop') > -1

        if klass is None and not check_oop_klass:
            return "Unknown"

        if check_oop_klass:
            name = self._name
            if name in PRIM_KLASS_NAME_MAPPING:
                return PRIM_KLASS_NAME_MAPPING[name]
            return "Unknown"

        name = getattr(klass, 'name_value', None)
        if name:
            return str(name)
        return "Unknown"

    def update_java_mirror(self):
        klass = self.get_klass()
        jva = self.get_jva()

        if klass is None:
            raise BaseException (str(self)+" does not have a mirror to update")
        addr = getattr(klass, 'java_mirror')
        oop = None #getattr(klass, "java_mirror_value", None)
        if not oop is None:
            return oop

        setattr(klass, "java_mirror_value", oop)
        #print ("[%s] Looking for %s klass @ 0x%08x"%(time_str(), klass, addr))
        try:
            #print ("In %s performing oop lookup"%str(klass))
            oop = jva.lookup_known_oop(addr)
        except:
            print ("Failed to update the mirror_class @ 0x%08x for %s"%(addr, str(klass)))
            import traceback
            traceback.print_exc()
            raise
        setattr(klass, "java_mirror_value", oop)
        if oop:
            #print ("[%s] Updated %s klass oop fields"%(time_str(), klass))
            #oop.update_fields()
            pass
        return oop

    def print_dump(self):
        print self.get_dump()

    def update_fields(self, force_update=False):
        print ("Error: %s does not implement this method"%getattr(self, '_name'))
        raise NotImplementedError

    def parse_class_fields (self, force_update=False):
        print ("Error: %s does not implement this method"%getattr(self, '_name'))
        raise NotImplementedError

    def raw_value (self):
        if self.is_prim() and self.is_oop() and not self.is_array_oop():
            return self.value
        print ("Error: %s does not implement this method"%getattr(self, '_name'))
        raise NotImplementedError

    def agg_size(self):
        print ("Error: %s does not implement this method"%getattr(self, '_name'))
        raise NotImplementedError

    def size_aligned(self):
        sz = self.size()
        return sz + self.align_pad(sz)

    def size(self):
        is_32bit = getattr(self, "is_32bit")
        if is_32bit:
            return getattr(self, 'size32')
        else:
            return getattr(self, 'size64')

    def is_array_oop(self):
        return False

    def is_oop(self):
        return False

    def is_instance_array(self):
        return False

    def is_symbol(self):
        return False

    def is_prim(self):
        return self.is_klass_prim()

    def is_instance(self):
        return False

    def update_fields_nop (self):
        setattr(self, "updated", True)

    def is_java_lang_prim(self):
        kname = self.klass_name()
        if kname:
            return kname.strip('[').strip(';') in JAVA_LANG_PRIMITIVES
        return False

    def is_klass_prim(self):
        kname = self.klass_name()
        if kname:
            return kname.strip('[') in PRIMITIVES
        return False

    @classmethod
    def from_jva(cls, addr, jvm_analysis):
        sz = cls.size32 if jvm_analysis.is_32bit else\
             cls.size64
        if addr == 0 or not jvm_analysis.is_valid_addr(addr):
            return None
        nbytes = jvm_analysis.read(addr, sz)
        if nbytes is None:
            #print ("Error: failed to read %d bytes @ 0x%08x"%(sz, addr))
            return None
        elif len(nbytes) != sz:
            #print ("Error: failed to read %d bytes @ 0x%08x"%(sz, addr))
            return None
        return cls.from_bytes (addr, nbytes, jvm_analysis)

    @classmethod
    def reset_overlay(cls, TYPE):
        cls._overlay = TYPE
        cls.bits32 = get_bits32(TYPE)
        cls.bits64 = get_bits64(TYPE)
        cls.named32 = get_named_array32(TYPE)
        cls.named64 = get_named_array64(TYPE)
        cls.size32 = get_size32(TYPE)
        cls.size64 = get_size64(TYPE)
        cls.types = get_field_types(TYPE)

    def get_dump(self):
        unpacked_values = getattr(self, 'unpacked_values', None)
        addr = getattr(self, 'addr', None)
        overlay = getattr(self, '_overlay', None)
        jva = getattr(self, 'jvm_analysis', None)
        if jva and unpacked_values and jva.is_32bit:
            return print_overlay_offsets32(overlay,
                                 unpacked_values, addr)
        elif jva and unpacked_values and not jva.is_32bit:
            return print_overlay_offsets64(overlay,
                                 unpacked_values, addr)
    def get_jva(self):
        return getattr(self, 'jvm_analysis')

    def is_win(self):
        return self.get_jva().is_win

    def get_access_flags(self):
        klass = self.get_klass()
        flags = getattr(self, "access_flags")
        return AccessFlags.get_class_access_strings(flags)

    def update_class_prototype(self):
        klass = self.get_klass()
        if klass.klass_name().find("[") == 0:
            t = self.unmangle_type(self.klass_name())
        else:
            t = klass.klass_name().replace("/", ".")
        acc = self.get_access_flags()
        p = "%s %s"%(" ".join(acc), t)
        setattr(klass, "access_flag_strings", acc)
        setattr(klass, "prototype", p.strip())
        setattr(klass, "type_string", p)

    def populate_class_method_info (self):
        method_info = {}
        setattr(self, 'method_info', method_info)
        jva = self.get_jva()
        klass = self.get_klass()
        vtable_loc = klass.jvtable_offset()
        vtable_len = klass.jvtable_len()
        pos = 0
        while pos < vtable_len:
            maddr = jva.read_addr(vtable_loc)
            method = jva.get_method(maddr)
            if method is None:
                pos += 1
                vtable_loc += jva.word_sz
                continue

            cm_value = method.get_const_method()
            acc, name, sig, idnum,\
            max_stack, max_locals = cm_value.get_all_info()

            data = {'access':acc, 'name_idx':name, 'sig_idx':sig,
                    'idnum':idnum, 'max_stack':max_stack,
                    'max_locals':max_locals,'prototype':''}
            rvalue, name, parameters = method.unmangle()
            data['name'] = name
            data['parameters'] = parameters
            data['rvalue'] = rvalue
            data['signature'] = method.signature()
            data['prototype'] = method.method_prototype()
            method_info[idnum] = data
            pos += 1
            vtable_loc += jva.word_sz

    def get_field_prototypes (self):
        field_info = self.get_field_info()
        if field_info is None:
            return None
        names = [i['prototype'] for i in field_info.values()]
        return names

    def get_field_names (self):
        field_info = self.get_field_info()
        if field_info is None:
            return None
        names = [i['name'] for i in field_info.values()]
        return names

    def get_constant_pool(self):
        klass = self.get_klass()
        cp = None
        if klass:
            cp = getattr(self, 'constants_value', None)
            if cp is None:
                cp = klass.set_constant_pool()
        return cp

    def get_field_name_types (self):
        names = self.get_field_names()
        types = self.get_field_types()
        return zip(types, names)


    def get_field_types(self):
        field_info = self.get_field_info()
        if field_info is None:
            return None
        names = [i['signature'] for i in field_info.values()]
        return names

    def get_field_by_offset(self, offset):
        klass = self.get_klass()
        if klass is None:
            return klass
        field_info = klass.get_field_info()
        if field_info is None:
            return None
        fi_by_offset = getattr(klass, 'field_info', None)
        if fi_by_offset:
            return fi_by_offset.get(offset, None)
        return None


    def get_all_field_infos(self, bread_cumbs=set()):
        if getattr(self, "all_field_infos_visited", False):
            return getattr(self, 'all_field_infos')
        self.update_all_field_infos()
        all_field_infos = getattr(self, 'all_field_infos')
        return all_field_infos

    def get_ordered_klass_dependencies(self):
        klass = self.get_klass()
        deps = []
        if klass is None:
            print "Attempting to get the klass of: %s:"%str(self)
            return []

        if getattr(klass, 'ordered_klass_dependencies', None):
            return getattr(klass, 'ordered_klass_dependencies')

        if getattr(klass, 'primary_supers_0_value', None):
            s = getattr(klass, 'primary_supers_0_value')
            deps.append(str(s))
        if getattr(klass, 'primary_supers_1_value', None):
            s = getattr(klass, 'primary_supers_1_value')
            deps.append(str(s))
        if getattr(klass, 'primary_supers_2_value', None):
            s = getattr(klass, 'primary_supers_2_value')
            deps.append(str(s))
        if getattr(klass, 'primary_supers_3_value', None):
            s = getattr(klass, 'primary_supers_3_value')
            deps.append(str(s))
        if getattr(klass, 'primary_supers_4_value', None):
            s = getattr(klass, 'primary_supers_4_value')
            deps.append(str(s))
        if getattr(klass, 'primary_supers_5_value', None):
            s = getattr(klass, 'primary_supers_5_value')
            deps.append(str(s))
        if getattr(klass, 'primary_supers_6_value', None):
            s = getattr(klass, 'primary_supers_6_value')
            deps.append(str(s))
        if getattr(klass, 'primary_supers_7_value', None):
            s = getattr(klass, 'primary_supers_7_value')
            deps.append(str(s))
        setattr(klass, 'ordered_klass_dependencies', deps)
        return deps

    def set_klass_dependencies(self, bread_cumbs=set()):
        klass = self.get_klass()
        bread_cumbs.add(str(klass))
        dependencies = getattr(self, 'klass_dependencies', {})
        if getattr(klass, 'primary_supers_0_value', None):
            s = getattr(klass, 'primary_supers_0_value')
            dependencies[str(s)] = set()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_1_value', None):
            s = getattr(klass, 'primary_supers_1_value')
            dependencies[str(s)] = set()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_2_value', None):
            s = getattr(klass, 'primary_supers_2_value')
            dependencies[str(s)] = set()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_3_value', None):
            s = getattr(klass, 'primary_supers_3_value')
            dependencies[str(s)] = set()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_4_value', None):
            s = getattr(klass, 'primary_supers_4_value')
            dependencies[str(s)] = set()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_5_value', None):
            s = getattr(klass, 'primary_supers_5_value')
            dependencies[str(s)] = set()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_6_value', None):
            s = getattr(klass, 'primary_supers_6_value')
            dependencies[str(s)] = set()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_7_value', None):
            s = getattr(klass, 'primary_supers_7_value')
            dependencies[str(s)] = set()
            bread_cumbs.add(str(s))
        setattr(self, 'klass_dependencies', dependencies)
        return True
    #def discover_klass_dependence_phase_2(self, bread_cumbs=set()):
    #    klass = self.get_klass()
    #    bread_cumbs.add(str(klass))
    #    direct_supers = getattr(self, 'dependencies', {})
    #    direct_supers = getattr(self, 'dependencies', {})
    #    if getattr(klass, 'primary_supers_0_value', None):
    #        s = getattr(klass, 'primary_supers_0_value')
    #        inheritances[str(s)] = set()
    #        bread_cumbs.add(str(s))
    #    if not extends_klass and\
    #        getattr(klass, 'primary_supers_1_value', None):
    #        s = getattr(klass, 'primary_supers_1_value')
    #        inheritances[str(s)] = set()
    #        bread_cumbs.add(str(s))
    #    if not extends_klass and\
    #        getattr(klass, 'primary_supers_2_value', None):
    #        s = getattr(klass, 'primary_supers_2_value')
    #        inheritances[str(s)] = set()
    #        bread_cumbs.add(str(s))
    #    if not extends_klass and\
    #        getattr(klass, 'primary_supers_3_value', None):
    #        s = getattr(klass, 'primary_supers_3_value')
    #        inheritances[str(s)] = set()
    #        bread_cumbs.add(str(s))
    #    if not extends_klass and\
    #        getattr(klass, 'primary_supers_4_value', None):
    #        s = getattr(klass, 'primary_supers_4_value')
    #        inheritances[str(s)] = set()
    #        bread_cumbs.add(str(s))
    #    if not extends_klass and\
    #        getattr(klass, 'primary_supers_5_value', None):
    #        s = getattr(klass, 'primary_supers_5_value')
    #        inheritances[str(s)] = set()
    #        bread_cumbs.add(str(s))
    #    if not extends_klass and\
    #        getattr(klass, 'primary_supers_6_value', None):
    #        s = getattr(klass, 'primary_supers_6_value')
    #        inheritances[str(s)] = set()
    #        bread_cumbs.add(str(s))
    #    if not extends_klass and\
    #        getattr(klass, 'primary_supers_7_value', None):
    #        s = getattr(klass, 'primary_supers_7_value')
    #        inheritances[str(s)] = set()
    #        bread_cumbs.add(str(s))
    #    setattr(self, 'dependencies', inheritances)
    #    return True


    def extends_klass(self, kname, bread_cumbs=set()):
       klass = self.get_klass()
       extends_klass = str(klass) == kname
       bread_cumbs.add(str(klass))
       if not extends_klass and\
           getattr(klass, 'primary_supers_0_value', None):
           s = getattr(klass, 'primary_supers_0_value')
           extends_klass = str(s) == kname or\
                           s.extends_klass(kname)
           bread_cumbs.add(str(s))
       if not extends_klass and\
           getattr(klass, 'primary_supers_1_value', None):
           s = getattr(klass, 'primary_supers_1_value')
           extends_klass = str(s) == kname or\
                           s.extends_klass(kname)
           bread_cumbs.add(str(s))
       if not extends_klass and\
           getattr(klass, 'primary_supers_2_value', None):
           s = getattr(klass, 'primary_supers_2_value')
           extends_klass = str(s) == kname or\
                           s.extends_klass(kname)
           bread_cumbs.add(str(s))
       if not extends_klass and\
           getattr(klass, 'primary_supers_3_value', None):
           s = getattr(klass, 'primary_supers_3_value')
           extends_klass = str(s) == kname or\
                           s.extends_klass(kname)
           bread_cumbs.add(str(s))
       if not extends_klass and\
           getattr(klass, 'primary_supers_4_value', None):
           s = getattr(klass, 'primary_supers_4_value')
           extends_klass = str(s) == kname or\
                           s.extends_klass(kname)
           bread_cumbs.add(str(s))
       if not extends_klass and\
           getattr(klass, 'primary_supers_5_value', None):
           s = getattr(klass, 'primary_supers_5_value')
           extends_klass = str(s) == kname or\
                           s.extends_klass(kname)
           bread_cumbs.add(str(s))
       if not extends_klass and\
           getattr(klass, 'primary_supers_6_value', None):
           s = getattr(klass, 'primary_supers_6_value')
           extends_klass = str(s) == kname or\
                           s.extends_klass(kname)
           bread_cumbs.add(str(s))
       if not extends_klass and\
           getattr(klass, 'primary_supers_7_value', None):
           s = getattr(klass, 'primary_supers_7_value')
           extends_klass = str(s) == kname or\
                           s.extends_klass(kname)
           bread_cumbs.add(str(s))
       return extends_klass



    def update_all_field_infos(self, bread_cumbs=set()):
        if getattr(self, "all_field_infos_visited", False):
            return True
        setattr(self, 'all_field_infos_visited', True)
        field_infos = getattr(self, 'all_field_infos', {})
        if len(field_infos) == 0:
            setattr(self, 'all_field_infos', field_infos)
        klass = self.get_klass()
        bread_cumbs.add(str(klass))
        field_infos[str(klass)] = klass.get_field_info()
        if getattr(klass, 'primary_supers_0_value', None):
            s = getattr(klass, 'primary_supers_0_value')
            s.update_all_field_infos(bread_cumbs)
            field_infos[str(s)] = s.get_field_info()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_1_value', None):
            s = getattr(klass, 'primary_supers_1_value')
            s.update_all_field_infos(bread_cumbs)
            field_infos[str(s)] = s.get_field_info()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_2_value', None):
            s = getattr(klass, 'primary_supers_2_value')
            s.update_all_field_infos(bread_cumbs)
            field_infos[str(s)] = s.get_field_info()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_3_value', None):
            s = getattr(klass, 'primary_supers_3_value')
            s.update_all_field_infos(bread_cumbs)
            field_infos[str(s)] = s.get_field_info()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_4_value', None):
            s = getattr(klass, 'primary_supers_4_value')
            s.update_all_field_infos(bread_cumbs)
            field_infos[str(s)] = s.get_field_info()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_5_value', None):
            s = getattr(klass, 'primary_supers_5_value')
            s.update_all_field_infos(bread_cumbs)
            field_infos[str(s)] = s.get_field_info()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_6_value', None):
            s = getattr(klass, 'primary_supers_6_value')
            s.update_all_field_infos(bread_cumbs)
            field_infos[str(s)] = s.get_field_info()
            bread_cumbs.add(str(s))
        if getattr(klass, 'primary_supers_7_value', None):
            s = getattr(klass, 'primary_supers_7_value')
            s.update_all_field_infos(bread_cumbs)
            field_infos[str(s)] = s.get_field_info()
            bread_cumbs.add(str(s))
        return field_infos


    def get_field_info(self):
        klass = self.get_klass()
        if klass is None:
            return klass
        field_info = getattr(klass, 'field_info', None)
        if field_info is None:
            klass.update_fields()
        return getattr(klass, 'field_info', None)


    def populate_class_field_info (self):
        klass = self.get_klass()
        if klass is None:
            return klass
        klass_name = self.klass_name()
        if klass_name is None:
            em = ("Error BUG: not a valid instance klass @ 0x%08x"%self.get_addr())
            raise BaseException (em)
            #print ("Error BUG: unable to populate fields, not a valid instance klass")
            #return None

        #print ("Populating field info for %s"%str(self))
        cp = getattr(klass, 'constants_value', None)
        fields = getattr(klass, 'fields_value')
        if cp is None:
            cp = self.set_constant_pool()

        if cp is None or fields is None:
            return
        field_oop_vals = []
        field_info = getattr(klass, 'field_info', {})
        field_info_by_offset = getattr(klass, 'field_info_by_offset', {})
        field_meta = fields.elem
        cp_entrys = cp.entrys
        pos = 0
        fld = 0
        end = len(field_meta)
        setattr(klass, 'field_info', field_info)
        setattr(klass, 'field_cnt', 0)


        while pos < end-1:
            setattr(klass, 'field_cnt', fld)
            acc, name, sig, ival, low_tag, high_tag = \
                  field_meta[pos:pos+6]
            #print ("Updating field #%d of %si: access = 0x%02x"%(fld, str(klass), acc))
            if AccessFlags.is_field_generic(acc):
                #print ("Encountered a generic flag, decrementing end to %d"%(end-1))
                end -=1
            data = {'access':acc, 'name_idx':name, 'sig_idx':sig,
                    'initial_value':ival, 'high_tag':high_tag,
                    'low_tag':low_tag, 'tag':(high_tag << 8)+low_tag, 'offset':0,
                    'type':0, 'contention_group':0, 'prototype':''}
            #high_low = struct.pack("B", high_off) + struct.pack("B", low_off)
            tag = data['tag']
            if tag & 0x03 == 0x01:
                data['offset'] = (tag&0xFFFE) >> 2
            elif tag & 0x03 == 0x02:
                data['offset'] = -1
                data['type'] = (tag&0x00FE) >> 2
                print ("Plain field with type")
            elif tag & 0x03 == 0x03:
                data['type'] = (tag&0x00FE) >> 2
                data['contention_group'] = (tag&0xFF00) >> 8
                data['offset'] = -1
                print ("Contended field with type and contention group")
            else:
                offset = 0

            n = cp_entrys[name] if name < len(cp_entrys) else\
                ''
            s = cp_entrys[sig] if sig < len(cp_entrys) else \
                ''
            v = cp_entrys[ival] if sig < len(cp_entrys) else \
                None
            #print n, s, v
            data['name'] = n.raw_value() if n else ''
            data['signature'] = s.raw_value() if s else ''
            data['val'] = str(v.raw_value()) if v else "UNK"
            t = self.unmangle_type(data['signature'])[1]
            n = self.unmangle_type(data['name'])[1]
            pfmt = "%s %s %s; //@0x%08x"
            af = " ".join(AccessFlags.get_field_access_strings(acc))
            offset = self.get_addr() + data['offset']
            data['prototype'] = (pfmt%(af, t, data['name'], offset)).strip()
            data['is_static'] = data['prototype'].find(' static ') > -1
            #data['sig'] = cp_entrys[sig] if sig < len(cp_entrys) else\
            #               ''
            field_info[fld] = data
            offset = data['offset']
            if not offset in field_info_by_offset and\
               offset != 0 and offset != -1:
               field_info_by_offset[offset] = data
            pos += 6
            fld+= 1

    @classmethod
    def from_bytes(cls, addr, nbytes, jvm_analysis):
        if jvm_analysis.has_internal_object(addr):
            return jvm_analysis.get_internal_object(addr)
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        data_unpack = struct.unpack(fmt, nbytes)
        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False}
        name_fields(data_unpack, nfields, fields=kargs)
        kargs['unpacked_values'] = data_unpack
        d = cls(**kargs)
        jvm_analysis.add_internal_object(addr, d)
        return d

    @classmethod
    def unmangle_type(cls, string):
        c = "" if len(string) == 0 else string[0]
        if c in TYPES:
            return 1, TYPES[c]
        if c == "[":
            used, t = cls.unmangle_type(string[1:])
            return used+1, t+"[]"
        elif c == "L" and string.find(";") > -1:
            t = string[1:].split(";")[0]
            t = t.replace('/', '.')
            return 2+len(t), t
        return "UNKNOWN"

    def method_prototype(self, idx=0):
        raise BaseException("Not implemented")

    def field_prototype(self, idx=0):
        raise BaseException("Not implemented")

    @classmethod
    def make_ptr(cls, val):
        if val & 0x01:
            return val-1
        return val

    @classmethod
    def is_python_native(cls, val):
        return isinstance(val, str) or\
               isinstance(val, int) or\
               isinstance(val, float) or\
               isinstance(val, long) or\
               isinstance(val, bytes)
