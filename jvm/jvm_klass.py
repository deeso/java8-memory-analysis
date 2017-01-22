import struct

from jvm_overlays import KLASS_TYPE, INSTANCE_KLASS_TYPE, ARRAY_KLASS_TYPE, \
                OBJ_ARRAY_KLASS_TYPE, TYPE_ARRAY_KLASS_TYPE,\
                KLASS_TYPE_WIN, INSTANCE_KLASS_TYPE_WIN, ARRAY_KLASS_TYPE_WIN, \
                OBJ_ARRAY_KLASS_TYPE_WIN, TYPE_ARRAY_KLASS_TYPE_WIN

from jvm_overlays import get_bits32, get_bits64, get_named_array32, \
                         get_named_array64, get_field_types, name_fields,\
                         get_klass, get_sym, get_meta, resolve_syms,\
                         resolve_syms, get_size32, get_size64,\
                         get_named_types_tup_list

from jvm_templates import ArrayT, ARRAY_MAP
from jvm_meta import ConstantPool
from jvm_base import BaseOverlay

BASIC_TYPE_INFO = {
  'T_BOOLEAN': 4, 'T_CHAR': 5, 'T_FLOAT': 6, 'T_DOUBLE': 7, 'T_BYTE': 8,
  'T_SHORT': 9, 'T_INT':10, 'T_LONG':11, 'T_OBJECT':12, 'T_ARRAY':13,
  'T_VOID':14, 'T_ADDRESS':15, 'T_NARROWOOP':16, 'T_CONFLICT':17,
  'T_ILLEGAL':99,
  4:"T_BOOLEAN", 5:"T_CHAR", 6:"T_FLOAT", 7:"T_DOUBLE", 8:"T_BYTE",
  9:"T_SHORT", 10:"T_INT", 11:"T_LONG", 12:"T_OBJECT", 13:"T_ARRAY",
  14:"T_VOID", 15:"T_ADDRESS", 16:"T_NARROWOOP", 17:"T_CONFLICT",
  99:"T_ILLEGAL",
}
INLINE_PRIMITIVES_KLASSES = [ 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z',]

PRIMITIVES_KLASSES = [ 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z',
#    '[B', '[C', '[D', '[F', '[I', '[J', '[S', '[Z',
#    'java/lang/Byte',
#    'java/lang/Character',
#    'java/lang/Double',
#    'java/lang/Float',
#    'java/lang/Integer',
#    'java/lang/Long',
#    'java/lang/Short',
#    'java/lang/Boolean',
]

PRIMITIVES_KLASSES_SET = set(PRIMITIVES_KLASSES)


#FIELD_ACCESS = 0
#FIELD_NAME = 0
#FIELD_SIG = 0
#FIELD_INITIAL_VAL = 0
#FIELD_LOW_OFF = 0
#FIELD_HIGH_OFF = 0

def get_klass_info(addr, jvm_analysis):
    # check the klass and extract key info to determine
    # how the oop should dispatch the remainder of its
    # parsing at the given address
    res = {'name':'', 'is_meta':False, 'is_instance':False,
           'is_array':False, 'is_oop_array':False,
           'basic_type':None, 'basic_type_sz':0, 'is_prim':False,
           'prim_value':None, 'is_klass':False,
    }
    fmt = Klass.bits32 if jvm_analysis.is_32bit else Klass.bits64
    nfields = Klass.named32 if jvm_analysis.is_32bit else Klass.named64
    sz = Klass.size32 if jvm_analysis.is_32bit else\
         Klass.size64
    nbytes = jvm_analysis.read(addr, sz)
    kargs = {}
    if nbytes is None:
        return res
    data_unpack = struct.unpack(fmt, nbytes)
    name_fields(data_unpack, nfields, fields=kargs)
    raw_bytes = nbytes[4:8] if jvm_analysis.is_32bit else nbytes[8:0xC]
    esz, ebt, hsz, tag  = struct.unpack("4B",raw_bytes)
    layout, = struct.unpack("<I",raw_bytes)
    res['tag'] = tag
    res['esz'] = esz
    res['ebt'] = ebt
    res['hsz'] = hsz
    res['layout'] = layout
    if layout == 0:
        res['is_instance'] = False
        res['is_array'] = False
        res['is_meta'] = True
        res['is_klass'] = True
    elif kargs.get('name', 0) > 0 and jvm_analysis:
        sym = jvm_analysis.lookup_internal_symbol_only(kargs['name'])
        res['name'] = str(sym)
        res['is_instance'] = True
        res['is_klass'] = True
        #res['is_array'] = True if res['name'].find('[') == 0 else False

    res['is_prim'] = res['name'].strip('[') in PRIMITIVES_KLASSES_SET
    if res['is_prim']:
        res['prim_value'] = res['name'].strip('[')

    if (tag & 0x80) > 0 or (tag & 0xC0) > 0:
        res['basic_type'] = ebt
        res['basic_type_sz'] = esz**2
        res['is_oop_array'] = (tag & 0x80) == 0x80
        res['is_array'] = True
        res['is_klass'] = True
        res['is_type_array'] = (tag & 0xC0) == 0xc0


    return res

class Klass(BaseOverlay):
    _name = "Klass"
    _overlay = KLASS_TYPE
    bits32 = get_bits32(KLASS_TYPE)
    bits64 = get_bits64(KLASS_TYPE)
    named32 = get_named_array32(KLASS_TYPE)
    named64 = get_named_array64(KLASS_TYPE)
    size32 = get_size32(KLASS_TYPE)
    size64 = get_size64(KLASS_TYPE)
    types = get_field_types(KLASS_TYPE)

    @classmethod
    def set_win_type(cls):
        cls.reset_overlay(KLASS_TYPE_WIN)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def set_fields_value(self, typ='Array<u2>*'):
        jva = getattr(self, "jvm_analysis")
        addr = getattr(self, "fields")
        if addr:
            ary = ArrayT.get_array(addr, jva, typ)
            setattr(self, 'fields_value', ary)
            self.populate_class_field_info()

    def __str__(self):
        name_value = getattr(self, "name_value", None)
        if name_value:
            return str(name_value)
        return "Unknown class @ 0x%08x"%(getattr(self, "addr", -1))

    def update_fields(self, force_update=False):
        # do this after reading in all the classes to prevent
        # circular dependencies
        jva = getattr(self, "jvm_analysis")
        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)
        name = getattr(self, "_name")
        addr = getattr(self, "addr")
        name_value = getattr(self, 'name_value', None)
        self.set_fields_value()
        overlay = getattr(self, '_overlay')
        #getattr(self, "jvm_analysis").log ("Updating the fields for %s: 0x%08x  %s"%(name, addr, str(name_value)))
        named_typs = get_named_types_tup_list(overlay)
        for name, typ in named_typs:
            if typ.find("Klass") == 0:
                # attempt to resolve the type
                addr = getattr(self, name, None)
                klass = None
                if addr:
                    klass = get_klass(jva, addr)
                    if klass:
                        klass.update_fields()
                        #getattr(self, "jvm_analysis").log ("Resolved klass field: %s  0x%08x %s"%(name, addr, str(klass.name_value)))
                setattr(self, name+'_value', klass)
            elif typ.find("Symbol*") == 0:
                # attempt to resolve the type
                addr = getattr(self, name, None)
                setattr(self, name+'_value', get_sym(jva, addr))
            elif typ.find("Array") == 0:
                addr = getattr(self, name, None)
                if addr:
                    ary = ArrayT.get_array(addr, jva, typ)
                    setattr(self, name+'_value', ary)
                    if ary and typ.find("Klass") > -1:
                        for a in ary.elem:
                            if a:
                                a.update_fields(force_update=force_update)
        self.update_class_prototype()
        self.populate_class_field_info()
        self.set_klass_dependencies()


    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        #getattr(self, "jvm_analysis").log (hex(addr), len(bytes), Klass.bits32, Klass.size32)
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        jva = jvm_analysis
        # doing this as a sanity check all Klasses and Oops happen on 8 byte boundary
        if addr % 8 != 0:
            jvm_analysis.log ("Attempting to read a klass off of an 8-byte value @ 0x%08x"%(addr))
            return None

        if _bytes is None:
            return None
        if jvm_analysis.has_klass(addr):
            return jvm_analysis.lookup_known_klass(addr)
        klass_info = get_klass_info (addr, jvm_analysis)
        #jvm_analysis.log (klass_info)
        if klass_info['is_array']:
            if klass_info['is_oop_array']:
                return ObjArrayKlass.from_jva(addr, jva)
            else:
                return TypeArrayKlass.from_jva(addr, jva)
        elif klass_info['is_instance']:
            return KlassInstance.from_jva(addr, jva)

        kargs = {"addr":addr, "jvm_analysis":jvm_analysis, 'updated':False,
                 "ooptype":'klassOop', 'metatype':'',
                 'klasstype':'Klass', 'is_32bit':jvm_analysis.is_32bit}
        data_unpack = struct.unpack(fmt, _bytes)
        name_fields(data_unpack, nfields, fields=kargs)

        if jvm_analysis.is_32bit:
            resolve_syms(Klass.types, Klass.named32, jvm_analysis, kargs)
        elif jva:
            resolve_syms(Klass.types, Klass.named64, jvm_analysis, kargs)

        tag  = klass_info['tag']
        esz  = klass_info['esz']
        ebt  = klass_info['ebt']
        hsz  = klass_info['hsz']
        kargs['method_values'] = {}
        kargs['method_values_by_name'] = {}
        kargs['tag'] = tag
        kargs['element_sz'] = esz**2
        kargs['header_sz'] = hsz
        kargs['element_type'] = ebt
        kargs['element_type_str'] = BASIC_TYPE_INFO[ebt] \
                                    if ebt in BASIC_TYPE_INFO else\
                                    "Unknown"
        kargs['subklass_value'] = None
        kargs['java_mirror_value'] = None
        kargs['secondary_supers_value'] = None
        kargs['super_value'] = None
        kargs['next_sibling_value'] = None
        kargs['secondary_super_cache_value'] = None
        # debugging
        kargs['unpacked_values'] = data_unpack
        d = Klass(**kargs)
        #jvm_analysis.log ("Identified %s @ 0x%08x"%(str(d.name), addr))

        if jvm_analysis:
            jvm_analysis.add_klass(d, check_vtable=True)
        #d.update_klasses(jvm_analysis)
        return d

class KlassInstance(BaseOverlay):
    _name = "KlassInstance"
    _overlay = INSTANCE_KLASS_TYPE
    bits32 = get_bits32(INSTANCE_KLASS_TYPE)
    bits64 = get_bits64(INSTANCE_KLASS_TYPE)
    named32 = get_named_array32(INSTANCE_KLASS_TYPE)
    named64 = get_named_array64(INSTANCE_KLASS_TYPE)
    size32 = get_size32(INSTANCE_KLASS_TYPE)
    size64 = get_size64(INSTANCE_KLASS_TYPE)
    types = get_field_types(INSTANCE_KLASS_TYPE)

    @classmethod
    def set_win_type(cls):
        cls.reset_overlay(INSTANCE_KLASS_TYPE_WIN)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__(self):
        name_value = getattr(self, "name_value", None)
        if name_value:
            return str(name_value)
        return "Unknown class @ 0x%08x"%(getattr(self, "addr", -1))

    def update_methods(self):
        self.set_constant_pool()
        jva = getattr(self, "jvm_analysis")
        methods_value = []
        addr = getattr(self, 'methods')
        ary = ArrayT.get_array(addr, jva, 'Array<Method*>')
        if ary:
            for i in ary.elem:
                methods_value.append(i)
        setattr(self, 'methods_value', methods_value)

    def set_fields_value(self, typ='Array<u2>*'):
        jva = getattr(self, "jvm_analysis")
        addr = getattr(self, "fields")
        if addr:
            ary = ArrayT.get_array(addr, jva, typ)
            setattr(self, 'fields_value', ary)
            self.populate_class_field_info()


    def update_fields(self, force_update=False):
        # do this after reading in all the classes to prevent
        # circular dependencies
        jva = getattr(self, "jvm_analysis")
        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)
        self.set_constant_pool()
        name = getattr(self, "_name")
        addr = getattr(self, "addr")
        name_value = getattr(self, 'name_value', None)
        overlay = getattr(self, '_overlay')
        #getattr(self, "jvm_analysis").log ("Updating the fields for %s: 0x%08x  %s"%(name, addr, str(name_value)))

        named_typs = get_named_types_tup_list(overlay)
        #getattr(self, "jvm_analysis").log ("Updating fields fpr %s"%(self.name_value))
        for name, typ in named_typs:
            #getattr(self, "jvm_analysis").log ("Attempting to update field: %s of type: %s"%(name, typ))
            if typ.find("Klass") == 0:
                # attempt to resolve the type
                addr = getattr(self, name, None)
                klass = None
                if addr:
                    try:
                        klass = get_klass(jva, addr)
                    except:
                        em = "Failed to update %s %s in %s @ 0x%08x"%(typ, name, str(self), addr)
                        getattr(self, "jvm_analysis").log (em)
                    if klass:
                        #getattr(self, "jvm_analysis").log ("Updating klass: %s @0x%08x"%(str(klass), klass.addr))
                        klass.update_fields()
                    setattr(self, name+'_value', klass)
            elif typ.find("Symbol*") == 0:
                # attempt to resolve the type
                addr = getattr(self, name, None)
                if addr:
                    setattr(self, name+'_value', get_sym(jva, addr))
            elif typ.find("Array") == 0:
                addr = getattr(self, name, None)
                if addr:
                    ary = ArrayT.get_array(addr, jva, typ)
                    setattr(self, name+'_value', ary)
                    if ary and typ.find("Klass") > -1:
                        for a in ary.elem:
                            if a:
                                a.update_fields(force_update=force_update)
        self.set_fields_value()
        self.update_class_prototype()
        self.populate_class_method_info()

    def is_instance(self):
        return True

    def set_constant_pool(self):
        #getattr(self, "jvm_analysis").log ("Updating CP for %s"%str(self))
        klass_name = getattr(self, 'name_value', None)
        if klass_name is None:
            addr = getattr(self, 'addr')
            getattr(self, "jvm_analysis").log ("Error BUG: not a valid instance klass @ 0x%08x"%addr)
            raise BaseException ("Not a valid instance class")
            #return None

        addr = getattr(self, "constants", None)
        jva = getattr(self, "jvm_analysis", None)
        cp = getattr(self, "constants_value", None)
        if addr and cp is None:
            cp = get_meta(jva, addr, ConstantPool)
            if cp:
                cp.update_fields()
                #kname = str(cp.pool_holder_value)
                #getattr(self, "jvm_analysis").log ("Resolved constant pool (0x%08x) field for: %s"%(addr, kname)) setattr(self, 'constants_value', cp)
            setattr(self, 'constants_value', cp)
        else:
            setattr(self, 'constants_value', None)
        return cp

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        #getattr(self, "jvm_analysis").log (hex(addr), len(bytes), fmt)
        jva = jvm_analysis
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64

        if jvm_analysis and jvm_analysis.has_klass(addr):
            return jvm_analysis.lookup_known_klass(addr)

        # doing this as a sanity check all Klasses and Oops happen on 8 byte boundary
        if addr % 8 != 0:
            jvm_analysis.log ("Attempting to read a klass off of an 8-byte value @ 0x%08x"%(addr))
            return None
        kargs = {"addr":addr, "jvm_analysis":jvm_analysis,
                'updated':False,'ooptype':'instanceKlassOop',
                 'metatype':'', 'klasstype':'instanceKlass','field_info':{},
                 'is_32bit':jvm_analysis.is_32bit }
        data_unpack = struct.unpack(fmt, _bytes)
        if kargs.get('name', 0) > 0 and jvm_analysis:
            sym = jvm_analysis.lookup_internal_symbol_only(kargs['name'])
            if sym:
                pass#getattr(self, "jvm_analysis").log ("Processing InstanceKlass: %s at 0x%08x"%(str(sym), addr) )
            else:
                return None

        name_fields(data_unpack, nfields, fields=kargs)
        if jvm_analysis.is_32bit:
            resolve_syms(KlassInstance.types, KlassInstance.named32, jvm_analysis, kargs)
        elif jva:
            resolve_syms(KlassInstance.types, KlassInstance.named64, jvm_analysis, kargs)

        raw_bytes = _bytes[4:8] if jvm_analysis.is_32bit else _bytes[8:0xC]
        esz, ebt, hsz, tag  = struct.unpack("4B",raw_bytes)
        kargs['method_values'] = {}
        kargs['method_values_by_name'] = {}
        kargs['tag'] = tag
        kargs['element_sz'] = esz**2
        kargs['header_sz'] = hsz
        kargs['element_type'] = ebt
        kargs['element_type_str'] = BASIC_TYPE_INFO[ebt] \
                                    if ebt in BASIC_TYPE_INFO else\
                                    "Unknown"
        kargs['unpacked_values'] = data_unpack
        d = KlassInstance(**kargs)
        # dont update constant pool yet
        # still not accounting for all the other meta klasses
        #d.set_constant_pool()
        if jvm_analysis:
            jvm_analysis.add_klass(d, check_vtable=True)
        #d.update_klasses(jvm_analysis)
        return d


class ObjArrayKlass(BaseOverlay):
    _name = "ObjArrayKlass"
    _overlay = OBJ_ARRAY_KLASS_TYPE
    bits32 = get_bits32(OBJ_ARRAY_KLASS_TYPE)
    bits64 = get_bits64(OBJ_ARRAY_KLASS_TYPE)
    named32 = get_named_array32(OBJ_ARRAY_KLASS_TYPE)
    named64 = get_named_array64(OBJ_ARRAY_KLASS_TYPE)
    size32 = get_size32(OBJ_ARRAY_KLASS_TYPE)
    size64 = get_size64(OBJ_ARRAY_KLASS_TYPE)
    types = get_field_types(OBJ_ARRAY_KLASS_TYPE)

    @classmethod
    def set_win_type(cls):
        cls.reset_overlay(OBJ_ARRAY_KLASS_TYPE_WIN)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__(self):
        name_value = getattr(self, "name_value", None)
        if name_value:
            return str(name_value)
        return "Unknown class @ 0x%08x"%(getattr(self, "addr", -1))

    def is_instance_array(self):
        return True

    def update_fields(self, force_update=False):
        # do this after reading in all the classes to prevent
        # circular dependencies
        jva = getattr(self, "jvm_analysis")

        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)
        #getattr(self, "jvm_analysis").log ("Updating %s force_update=%s"%(str(self), force_update))
        name = getattr(self, "_name")
        addr = getattr(self, "addr")
        name_value = getattr(self, 'name_value', None)
        overlay = getattr(self, '_overlay')
        #getattr(self, "jvm_analysis").log ("Updating the fields for %s: 0x%08x  %s"%(name, addr, str(name_value)))
        named_typs = get_named_types_tup_list(overlay)
        for name, typ in named_typs:
            if typ.find("Klass*") == 0:
                # attempt to resolve the type
                addr = getattr(self, name, None)
                if addr:
                    klass = get_klass(jva, addr)
                    if klass:
                        pass#getattr(self, "jvm_analysis").log ("Resolved klass field: %s  0x%08x %s"%(name, addr, str(klass.name_value)))
                    setattr(self, name+'_value', klass)
            elif typ.find("Symbol*") == 0:
                # attempt to resolve the type
                addr = getattr(self, name, None)
                if addr:
                    setattr(self, name+'_value', get_sym(jva, addr))
            elif typ.find("Array") == 0:
                addr = getattr(self, name, None)
                if addr:
                    ary = ArrayT.get_array(addr, jva, typ)
                    setattr(self, name+'_value', ary)
                    if ary and typ.find("Klass") > -1:
                        for a in ary.elem:
                            if a:
                                a.update_fields(force_update=force_update)

    #def set_constant_pool (self):
    #     addr = getattr(self, "constants", None)
    #     jva = getattr(self, "jvm_analysis", None)
    #     cp = None
    #     if addr:
    #         cp = get_meta(jva, addr, ConstantPool)
    #         if cp:
    #             cp.update_fields()
    #             #kname = str(cp.pool_holder_value)
    #             #getattr(self, "jvm_analysis").log ("Resolved constant pool (0x%08x) field for: %s"%(addr, kname))
    #         setattr(self, 'constants_value', cp)
    #     return cp

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        #getattr(self, "jvm_analysis").log (hex(addr), len(bytes), fmt)
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        sz = cls.size32 if jvm_analysis.is_32bit else cls.size64
        jva = jvm_analysis
        if jvm_analysis and jvm_analysis.has_klass(addr):
            return jvm_analysis.lookup_known_klass(addr)

        if _bytes is None or len(_bytes) != sz:
            #getattr(self, "jvm_analysis").log("Bytes size do not match required needed at addr 0x%08x"%addr)
            return None

        kargs = {"addr":addr, "jvm_analysis":jvm_analysis,
                'updated':False,"ooptype":'objArrayKlassOop',
                'metatype':'', 'klasstype':'objArrayKlass',
                'is_32bit':jvm_analysis.is_32bit}
        data_unpack = struct.unpack(fmt, _bytes)
        name_fields(data_unpack, nfields, fields=kargs)

        # instance klasses have a symbol name (_name > 0) and its a symbol
        # Not sure if I want to handle this yet with the ArrayKlass
        if kargs.get('name', 0) > 0 and jvm_analysis:
            sym = jvm_analysis.lookup_internal_symbol_only(kargs['name'])
            if sym:
                pass#getattr(self, "jvm_analysis").log ("Processing ObjArrayKlass: %s at 0x%08x"%(str(sym), addr))
            else:
                return None

        if jvm_analysis.is_32bit:
            resolve_syms(cls.types, cls.named32, jvm_analysis, kargs)
        elif jva:
            resolve_syms(cls.types, cls.named64, jvm_analysis, kargs)
        #_layout helper bytes
        raw_bytes = _bytes[4:8] if jvm_analysis.is_32bit else _bytes[8:0xC]
        esz, ebt, hsz, tag  = struct.unpack("4B",raw_bytes)
        kargs['header_sz'] = hsz
        kargs['element_sz'] = esz**2
        kargs['tag'] = tag
        kargs['element_type'] = ebt
        kargs['element_type_str'] = BASIC_TYPE_INFO[ebt] \
                                    if ebt in BASIC_TYPE_INFO else\
                                    "Unknown"


        #num_elements = 2 ** (_layout_helper &0x000000FF)
        #kargs['num_elements'] = num_elements
        kargs['element_are_oop'] = tag & 0x80 == 0x80

        kargs['next_sibling_value'] = None
        kargs['secondary_supers_value'] = None
        kargs['java_mirror_value'] = None
        kargs['super_value'] = None
        kargs['subklass_value'] = None
        kargs['next_sibling_value'] = None
        kargs['secondary_super_cache_value'] = None
        kargs['higher_dimension_value'] = None
        kargs['lower_dimension_value'] = None
        kargs['component_mirror_value'] = None
        kargs['element_klass_value'] = None
        kargs['bottom_klass_value'] = None

        kargs['unpacked_values'] = data_unpack
        d = ObjArrayKlass(**kargs)
        if jvm_analysis:
            jvm_analysis.add_klass(d, check_vtable=True)
        #d.update_klasses(jvm_analysis)
        return d

class TypeArrayKlass(BaseOverlay):
    _name = "TypeArrayKlass"
    _overlay = TYPE_ARRAY_KLASS_TYPE
    bits32 = get_bits32(TYPE_ARRAY_KLASS_TYPE)
    bits64 = get_bits64(TYPE_ARRAY_KLASS_TYPE)
    named32 = get_named_array32(TYPE_ARRAY_KLASS_TYPE)
    named64 = get_named_array64(TYPE_ARRAY_KLASS_TYPE)
    size32 = get_size32(TYPE_ARRAY_KLASS_TYPE)
    size64 = get_size64(TYPE_ARRAY_KLASS_TYPE)
    types = get_field_types(TYPE_ARRAY_KLASS_TYPE)

    @classmethod
    def set_win_type(cls):
        cls.reset_overlay(TYPE_ARRAY_KLASS_TYPE_WIN)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__(self):
        name_value = getattr(self, "name_value", None)
        if name_value:
            return str(name_value)
        return "Unknown class @ 0x%08x"%(getattr(self, "addr", -1))

    def is_updated(self, force_update=False):
        if getattr(self, "updated", False) and not force_update:
            return True
        return False

    def update_fields(self, force_update=False):
        # do this after reading in all the classes to prevent
        # circular dependencies
        jva = getattr(self, "jvm_analysis")

        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)
        name = getattr(self, "_name")
        addr = getattr(self, "addr")
        overlay = getattr(self, '_overlay')
        #getattr(self, "jvm_analysis").log ("Updating the fields for %s: 0x%08x  %s"%(name, addr, str(name_value)))
        named_typs = get_named_types_tup_list(overlay)
        for name, typ in named_typs:
            if typ.find("Klass*") == 0:
                # attempt to resolve the type
                addr = getattr(self, name, None)
                if addr:
                    klass = get_klass(jva, addr)
                    if klass:
                        pass#getattr(self, "jvm_analysis").log ("Resolved klass field: %s  0x%08x %s"%(name, addr, str(klass.name_value)))
                    setattr(self, name+'_value', klass)
            elif typ.find("Symbol*") == 0:
                # attempt to resolve the type
                addr = getattr(self, name, None)
                if addr:
                    setattr(self, name+'_value', get_sym(jva, addr))
            elif typ.find("Array") == 0:
                addr = getattr(self, name, None)
                if addr:
                    ary = ArrayT.get_array(addr, jva, typ)
                    setattr(self, name+'_value', ary)
                    if ary and typ.find("Klass") > -1:
                        for a in ary.elem:
                            if a:
                                a.update_fields(force_update=force_update)

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        #getattr(self, "jvm_analysis").log (hex(addr), len(bytes), fmt)
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        jva = jvm_analysis
        if jvm_analysis and jvm_analysis.has_klass(addr):
            return jvm_analysis.lookup_known_klass(addr)

        kargs = {"addr":addr, "jvm_analysis":jvm_analysis,
                 'updated':False,"ooptype":'typeArrayKlassOop',
                'metatype':'', 'klasstype':'typeArrayKlass',
                'is_32bit':jvm_analysis.is_32bit}
        data_unpack = struct.unpack(fmt, _bytes)
        name_fields(data_unpack, nfields, fields=kargs)
        #if kargs.get('name', 0) > 0 and jvm_analysis:
        #    sym = jvm_analysis.lookup_internal_symbol_only(kargs['name'])
        #    if sym:
        #        pass#getattr(self, "jvm_analysis").log ("Processing ArrayKlass: %s at 0x%08x"%(str(sym), addr))
        #    else:
        #        return None


        if jvm_analysis.is_32bit:
            resolve_syms(TypeArrayKlass.types, TypeArrayKlass.named32, jvm_analysis, kargs)
        elif jva:
            resolve_syms(TypeArrayKlass.types, TypeArrayKlass.named64, jvm_analysis, kargs)

        raw_bytes = _bytes[4:8] if jvm_analysis.is_32bit else _bytes[8:0xC]
        esz, ebt, hsz, tag  = struct.unpack("4B",raw_bytes)
        kargs['tag'] = tag
        kargs['element_sz'] = esz**2
        kargs['tag'] = tag
        kargs['header_sz'] = hsz
        kargs['element_type'] = ebt
        kargs['element_type_str'] = BASIC_TYPE_INFO[ebt] \
                                    if ebt in BASIC_TYPE_INFO else\
                                    "Unknown"

        kargs['next_sibling_value'] = None
        kargs['secondary_supers_value'] = None
        kargs['java_mirror_value'] = None
        kargs['super_value'] = None
        kargs['subklass_value'] = None
        kargs['next_sibling_value'] = None
        kargs['secondary_super_cache_value'] = None
        kargs['higher_dimension_value'] = None
        kargs['lower_dimension_value'] = None
        kargs['component_mirror_value'] = None

        kargs['unpacked_values'] = data_unpack
        d = TypeArrayKlass(**kargs)
        if jvm_analysis:
            jvm_analysis.add_klass(d, check_vtable=True)
        #d.update_klasses(jvm_analysis)
        return d

class ArrayKlass (BaseOverlay):
    _name = "ArrayKlass"
    _overlay = ARRAY_KLASS_TYPE
    bits32 = get_bits32(ARRAY_KLASS_TYPE)
    bits64 = get_bits64(ARRAY_KLASS_TYPE)
    named32 = get_named_array32(ARRAY_KLASS_TYPE)
    named64 = get_named_array64(ARRAY_KLASS_TYPE)
    size32 = get_size32(ARRAY_KLASS_TYPE)
    size64 = get_size64(ARRAY_KLASS_TYPE)
    types = get_field_types(ARRAY_KLASS_TYPE)

    @classmethod
    def set_win_type(cls):
        cls.reset_overlay(ARRAY_KLASS_TYPE_WIN)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__(self):
        name_value = getattr(self, "name_value", None)
        if name_value:
            return str(name_value)
        return "Unknown class @ 0x%08x"%(getattr(self, "addr", -1))

    def update_fields(self, force_update=False):
        # do this after reading in all the classes to prevent
        # circular dependencies
        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)
        jva = getattr(self, "jvm_analysis")

        name = getattr(self, "_name")
        addr = getattr(self, "addr")
        overlay = getattr(self, '_overlay')
        #getattr(self, "jvm_analysis").log ("Updating the fields for %s: 0x%08x  %s"%(name, addr, str(name_value)))
        named_typs = get_named_types_tup_list(overlay)
        for name, typ in named_typs:
            if typ.find("Klass*") == 0:
                # attempt to resolve the type
                addr = getattr(self, name, None)
                if addr:
                    klass = get_klass(jva, addr)
                    if klass:
                        pass#getattr(self, "jvm_analysis").log ("Resolved klass field: %s  0x%08x %s"%(name, addr, str(klass.name_value)))
                    setattr(self, name+'_value', klass)
            elif typ.find("Symbol*") == 0:
                # attempt to resolve the type
                addr = getattr(self, name, None)
                if addr:
                    setattr(self, name+'_value', get_sym(jva, addr))
            elif typ.find("Array") == 0:
                addr = getattr(self, name, None)
                if addr:
                    ary = ArrayT.get_array(addr, jva, typ)
                    setattr(self, name+'_value', ary)
                    if ary and typ.find("Klass") > -1:
                        for a in ary.elem:
                            if a:
                                a.update_fields(force_update=force_update)

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        #getattr(self, "jvm_analysis").log (hex(addr), len(bytes), fmt)
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        jva = jvm_analysis
        if jvm_analysis and jvm_analysis.has_klass(addr):
            return jvm_analysis.lookup_known_klass(addr)

        kargs = {"addr":addr, "jvm_analysis":jvm_analysis,
                'updated':False,"ooptype":'typeArrayKlassOop',
                'metatype':'', 'klasstype':'typeArrayKlass',
                'is_32bit':jvm_analysis.is_32bit}
        data_unpack = struct.unpack(fmt, _bytes)
        name_fields(data_unpack, nfields, fields=kargs)
        if kargs.get('name', 0) > 0 and jvm_analysis:
            sym = jvm_analysis.lookup_internal_symbol_only(kargs['name'])
            if sym:
                pass#getattr(self, "jvm_analysis").log ("Processing ArrayKlass: %s at 0x%08x"%(str(sym), addr))
            else:
                return None


        if jvm_analysis.is_32bit:
            resolve_syms(ArrayKlass.types, ArrayKlass.named32, jvm_analysis, kargs)
        elif jva:
            resolve_syms(ArrayKlass.types, ArrayKlass.named64, jvm_analysis, kargs)

        raw_bytes = _bytes[4:8] if jvm_analysis.is_32bit else _bytes[8:0xC]
        esz, ebt, hsz, tag  = struct.unpack("4B",raw_bytes)
        kargs['tag'] = tag
        kargs['element_sz'] = esz**2
        kargs['header_sz'] = hsz
        kargs['element_type'] = ebt
        kargs['element_type_str'] = BASIC_TYPE_INFO[ebt] \
                                    if ebt in BASIC_TYPE_INFO else\
                                    "Unknown"

        kargs['next_sibling_value'] = None
        kargs['secondary_supers_value'] = None
        kargs['java_mirror_value'] = None
        kargs['super_value'] = None
        kargs['subklass_value'] = None
        kargs['next_sibling_value'] = None
        kargs['secondary_super_cache_value'] = None
        kargs['higher_dimension_value'] = None
        kargs['lower_dimension_value'] = None
        kargs['component_mirror_value'] = None
        kargs['unpacked_values'] = data_unpack

        d = ArrayKlass(**kargs)
        if jvm_analysis:
            jvm_analysis.add_klass(d, check_vtable=True)
        #d.update_klasses(jvm_analysis)
        return d


ARRAY_MAP['Klass'] = Klass
ARRAY_MAP['KlassInstance'] = KlassInstance
