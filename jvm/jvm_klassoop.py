import struct
from jvm_klass import Klass, ArrayKlass, KlassInstance, get_klass_info

from jvm_overlays import OOP_TYPE, OOP_TYPE, ARRAY_OOP_TYPE, \
                OBJ_ARRAY_OOP_TYPE, TYPE_ARRAY_OOP_TYPE, OOP_TYPE, \
                CHAR_OOP_TYPE, BYTE_OOP_TYPE, INT_OOP_TYPE, LONG_OOP_TYPE,\
                SHORT_OOP_TYPE, BOOL_OOP_TYPE, DOUBLE_OOP_TYPE, FLOAT_OOP_TYPE

from jvm_overlays import get_bits32, get_bits64, get_named_array32, \
                         get_named_array64, get_field_types, name_fields,\
                         get_named_types_dict, get_klass, get_sym, \
                         resolve_syms, resolve_syms, get_size32, get_size64
from jvm_base import BaseOverlay

from jvm_prim import ByteOop, CharOop, DoubleOop, FloatOop, IntOop, LongOop,\
                     ShortOop, BoolOop, ByteArrayOop, CharArrayOop,\
                     DoubleArrayOop, FloatArrayOop, IntArrayOop, LongArrayOop,\
                     ShortArrayOop, BoolArrayOop

from jvm_flags import AccessFlags

from datetime import datetime

def time_str():
    return str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))

# #  klassOop object layout:
# #    [header     ]
# #    [klass_field]
# #    [KLASS      ]
#
def translate_value_field_to_python(oop):
    field = oop.get_oop_field_value('value')
    if oop.is_python_native(field):
        return field
    return field.raw_value()

JAVA_PRIMITIVE = {
    'java/lang/Byte':translate_value_field_to_python,
    'java/lang/Character':translate_value_field_to_python,
    'java/lang/Double':translate_value_field_to_python,
    'java/lang/Float':translate_value_field_to_python,
    'java/lang/Integer':translate_value_field_to_python,
    'java/lang/Long':translate_value_field_to_python,
    'java/lang/Short':translate_value_field_to_python,
    'java/lang/Boolean':translate_value_field_to_python,
    'java/lang/String':translate_value_field_to_python,
}
PRIMITIVES_OOPS = {
    'B':ByteOop,
    'C':CharOop,
    'D':DoubleOop,
    'F':FloatOop,
    'I':IntOop,
    'J':LongOop,
    'S':ShortOop,
    'Z':BoolOop,
    #'[B':ByteOop,
    #'[C':CharOop,
    #'[D':DoubleOop,
    #'[F':FloatOop,
    #'[I':IntOop,
    #'[J':LongOop,
    #'[S':ShortOop,
    #'[Z':BoolOop,
    #'java/lang/Byte':ByteOop,
    #'java/lang/Character':CharOop,
    #'java/lang/Double':DoubleOop,
    #'java/lang/Float':FloatOop,
    #'java/lang/Integer':IntOop,
    #'java/lang/Long':LongOop,
    #'java/lang/Short':ShortOop,
    #'java/lang/Boolean':BoolOop,
    # '[C':CharArrayOop,
    # '[B':ByteArrayOop,
    # '[D':DoubleArrayOop,
    # '[F':FloatArrayOop,
    # '[I':IntArrayOop,
    # '[J':LongArrayOop,
    # '[S':ShortArrayOop,
    # '[Z':BoolArrayOop,
}


class Oop(BaseOverlay):
    _name = "Oop"
    _overlay = OOP_TYPE
    bits32 = get_bits32(OOP_TYPE)
    bits64 = get_bits64(OOP_TYPE)
    named32 = get_named_array32(OOP_TYPE)
    named64 = get_named_array64(OOP_TYPE)
    size32 = get_size32(OOP_TYPE)
    size64 = get_size64(OOP_TYPE)
    types = get_field_types(OOP_TYPE)
    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)
        self.bread_crumbs={}

    def is_oop(self):
         return True

    def get_oop_field_value(self, field_name, klass_name=None):
        klass_name = klass_name if klass_name \
                                else str(getattr(self, 'klass_value', None))
        fld = self.get_oop_field(field_name, klass_name=klass_name)
        if fld is None:
            return 'null'
        if fld.is_prim() and not hasattr(fld, 'value'):
            setattr(fld, 'updated', False)
            fld.update_fields()
            return fld.get_oop_field_value('value')
        if fld.is_prim():
            return fld.get_oop_field_value('value')
        elif fld and (fld.is_oop() or fld.is_array_oop()):
            rv = fld.raw_value()
            if type(rv) == list and len(rv) > 0\
               and 'value' in rv[0]:
               return rv[0]['value']
            elif type(rv) == list and len(rv) > 0:
               return rv[0]
            return rv
        return fld

    def get_oop_field(self, field_name, klass_name=None):
        oop_fields = getattr(self, 'oop_field_values_by_name', None)
        klass_name = klass_name if klass_name \
                                else str(getattr(self, 'klass_value', None))
        if oop_fields is None:
            self.update_fields()
        oop_fields = getattr(self, 'oop_field_values_by_name', None)
        if klass_name and oop_fields and\
            klass_name in oop_fields and\
            field_name in oop_fields[klass_name]:
            fld = oop_fields[klass_name][field_name]
            #if fld and (fld.is_prim() or fld.is_oop() or fld.is_array_oop()):
            #    return fld
            return fld
        return None

    def python_value(self, klass_name=None, field_name=None, bread_crumbs = {}, lookup={}, set_bread_crumbs=False):
        klass_fld_values = getattr(self, 'oop_field_values_by_name', None)
        if klass_fld_values is None:
            self.update_fields()
            klass_fld_values = getattr(self, 'oop_field_values_by_name', None)
        res = {}
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':self.is_array_oop(),'is_prim':self.is_prim(), 'value':{}, 'addr':self.addr}
            if set_bread_crumbs:
                setattr(self, 'bread_crumbs',bread_crumbs)
        elif self.addr in bread_crumbs and\
                klass_name is None:
            return bread_crumbs[self.addr]['value']

        if klass_name and field_name and\
            klass_name in klass_fld_values and\
            field_name in klass_fld_values[klass_name]:
            res_key = "%s:%s"%(klass_name, field_name)
            v = None
            oop = klass_fld_values[klass_name][field_name]
            if oop is None:
                res[res_key] = v
                return res

            v = lookup[oop.addr] if oop.addr in lookup else None
            if not oop.addr in lookup:
                lookup[oop.addr] = bread_crumbs[oop.addr]
                v = oop.python_value(bread_crumbs=bread_crumbs, lookup=lookup, set_bread_crumbs=set_bread_crumbs)
                if not oop.is_prim() and not oop.is_array_oop():
                    bread_crumbs[oop.addr]['value'].update(v)
                    print "updating value: %s len="%(res_key, len(v))
                else:
                    bread_crumbs[oop.addr]['value'] = v
                    print "updating value: %s len="%(res_key, len(v))

            res[res_key] = bread_crumbs[oop.addr] if oop else None
            return res

        if klass_name and\
            klass_name in klass_fld_values:
            klass_field_values = klass_fld_values[klass_name]
            for field, oop in klass_field_values.items():
                res_key = "%s:%s"%(klass_name, field)
                v = None
                if oop is None:
                    res[res_key] = v
                    continue
                v = lookup[oop.addr] if oop.addr in lookup else None
                if not oop.addr in lookup:
                    if oop.addr in bread_crumbs:
                        lookup[oop.addr] = bread_crumbs[oop.addr]
                    v = oop.python_value(bread_crumbs=bread_crumbs, lookup=lookup, set_bread_crumbs=set_bread_crumbs)
                    lookup[oop.addr] = bread_crumbs[oop.addr]

                    if not oop.is_prim() and not oop.is_array_oop() and not self.is_python_native(v):
                        try:
                            bread_crumbs[oop.addr]['value'].update(v)
                        except:
                            print ("Attempted to update a dictionary with value: %s type: %s"%(res_key, type(v)))
                            bread_crumbs[oop.addr]['value'] = v
                    else:
                        bread_crumbs[oop.addr]['value'] = v
                    if not oop.is_prim() and not oop.is_array_oop() and self.is_python_native(v):
                        print "[XXXX] OOP is not primitive, but the Python Value is native: %s"%res_key

                res[res_key] = bread_crumbs[oop.addr] if oop else None
            return res

        #if self.addr in bread_crumbs:
        #    return bread_crumbs[self.addr]['value']
        #lookup = getattr(self, 'oop_python_values', {}) if len(lookup) == 0 else lookup
        klasses = self.get_ordered_klass_dependencies()
        #print "Resolving python values for:%s (%s)"%(self.get_klass(), klasses)
        for klass_name in klasses:
            result = self.python_value(klass_name=klass_name, bread_crumbs=bread_crumbs, lookup=lookup, set_bread_crumbs=set_bread_crumbs)
            res.update(result)
        setattr(self, 'oop_python_values', bread_crumbs)
        bread_crumbs[self.addr]['value'] = res
        return res

    def raw_value (self, return_dict=False, klass_name=None):
        klass_name = klass_name if klass_name \
                                else str(getattr(self, 'klass_value', None))
        oop_fields = getattr(self, 'oop_field_values_by_name', None)
        if oop_fields is None:
            self.update_fields()
        elif hasattr(self, 'raw_value_cache'):
            if not return_dict and\
               not isinstance(getattr(self, 'raw_value_cache'), dict):
               return getattr(self, 'raw_value_cache')
            else:
               delattr(self, 'raw_value_cache')
        if getattr(self, 'resolving_raw_value', False):
            return None
        setattr(self, 'resolving_raw_value', False)
        klass = self.get_klass()
        #print "called raw_value", kname
        if klass_name and klass_name in JAVA_PRIMITIVE and not return_dict:
            xlate_field = JAVA_PRIMITIVE[klass_name]
            val = xlate_field(self)
            delattr(self, 'resolving_raw_value')
            setattr(self, 'raw_value_cache', val)
            return val

        if self.is_prim() and not hasattr(self, 'value'):
            setattr(self, 'updated', False)
            self.update_fields()
        setattr(self, 'oop_fields_updated', True)
        if self.is_prim() and not klass_name in JAVA_PRIMITIVE:
            delattr(self, 'resolving_raw_value')
            setattr(self, 'raw_value_cache', getattr(self, 'value'))
            return getattr(self, 'value')

        #print "wtf way left when should be right", kname
        if klass is None:
            BaseException("Invalid OOP")

        raise Exception("%s has no actual raw value"%(klass_name))
        #return self.addr

    def __str__(self):
        addr = getattr(self, 'addr', '')
        name = getattr(self, '_name', '')
        klass_name = "Unknown"
        klass_addr = 0x0
        klass = getattr(self, 'klass_value', None)
        if klass:
            klass_name = str(klass.name_value)
            klass_addr = klass.addr

        fmt = "%s @ 0x%08x of %s @ 0x%08x"
        a = fmt%(name,addr, klass_name, klass_addr)
        return a

    def agg_size(self):
        self.update_fields()
        sz = self.size()
        jva = getattr(self, 'jvm_analysis', None)
        klass = getattr(self, 'klass_value', None)
        if klass:
            fld_sz_str = 'oop_nonstatic_field_size'
            field_sz = getattr(self, fld_sz_str, None)
            if field_sz is None:
                try:
                    klass.update_fields()
                    field_sz = getattr(self, fld_sz_str, None)
                except:
                    print("Caught exception while trying to update fields")
                    print("\t offending klass:%s"%str(klass))
                    field_sz = 0
            sz += field_sz
        return sz

    def update_fields(self, force_update=False):
        if getattr(self, 'update_flds_in_progress', False):
            return
        setattr(self, 'update_flds_in_progress', True)
        try:
            if getattr(self, "updated", False) and not force_update:
                return
            setattr(self, "updated", True)
            klass = self.get_klass()
            if klass:
                klass.update_fields()
            self.parse_class_fields()
        except:
            pass
        finally:
            delattr(self, 'update_flds_in_progress')

    def parse_class_fields(self, force=True):
        if getattr(self, 'parse_flds_in_progress', False):
            return
        if not force and getattr(self, 'parse_flds_completed', False):
            return
        setattr(self, 'parse_flds_in_progress', True)
        try:
            jva = getattr(self, "jvm_analysis")
            klass = self.get_klass()

            if klass is None or type(klass) != KlassInstance or \
                klass.klass_name().find("Unknown") == 0:
                return
            field_cnt = getattr(klass, 'field_cnt', 0)
            mirror_oop = getattr(klass, 'java_mirror_value', None)
            if mirror_oop is None:
                jm_addr = getattr(klass, 'java_mirror')
                mirror_oop = jva.lookup_known_oop(jm_addr)
                #mirror_oop.update_fields()

            setattr(self, 'oop_field_size', field_cnt)
            setattr(self, 'oop_nonstatic_field_size', klass.nonstatic_field_size)
            #oop_fields = getattr(self, 'oop_field_values_by_name')
            #if oop_fields is None:
            #    oop_fields = {}
            #    setattr(self, 'oop_field_values', oop_fields)
            oop_fields_by_name = getattr(self, 'oop_field_values_by_name', {})
            if oop_fields_by_name is None:
                oop_fields_by_name = {}
                setattr(self, 'oop_field_values_by_name', oop_fields_by_name)
            oop_fields_by_offset = getattr(self, 'oop_field_values_by_offset', {})
            if oop_fields_by_offset is None:
                oop_fields_by_offset = {}
                setattr(self, 'oop_field_values_by_offset', oop_fields_by_offset)
            oop_baddr = getattr(self, 'addr')

            #field_info[kname] = {}
            mirror_baddr = 0
            if mirror_oop:
                mirror_baddr = getattr(mirror_oop, 'addr')
            idx = 0
            all_field_info = klass.get_all_field_infos()
            #print "Oop addr 0x%08x Updating fields for klass: %s @ 0x%08x"%(self.addr, str(klass), klass.addr)
            #print field_info
            idx = 0
            field_info = {}
            my_kname = str(self.get_klass())
            for kname, finfo in all_field_info.items():
                is_me = my_kname == kname
                oop_fields_by_name[kname] = {}
                #oop_fields[kname] = {}
                for idx, info in finfo.items():
                    naddr = oop_baddr + info['offset']

                    acc = info['access']
                    is_prim = info['signature'] in PRIMITIVES_OOPS
                    is_static = not mirror_oop is None and AccessFlags.is_field_static(acc)
                    if is_static:
                        naddr = mirror_baddr + info['offset']
                    # This is important, primitive values are raw
                    #print ("[%s] Processing 0x%08x %s oop field"%(time_str(), naddr, info['name']))
                    oop_addr = jva.read_addr(naddr)
                    oop = None
                    if is_prim:
                        oop_addr = naddr
                        PrimOop = PRIMITIVES_OOPS[info['signature']]
                        oop = PrimOop.from_jva(naddr, jva)
                    else:
                        oop = jva.lookup_known_oop(oop_addr)
                    if not is_static:
                        oop_fields_by_offset[info['offset']] = oop
                    oop_fields_by_name[kname][info['name']] = oop
                    #oop_fields[kname][idx] = oop
                    #oop_fields_by_name[kname] = info
                    #oop_fields[kname] = info
                    if is_me:
                        #oop_fields_by_name[info['name']] = oop
                        #oop_fields[idx] = oop
                        pass

                    if oop:
                        jva.add_oop(oop)
                        oop.update_fields()
                        #print oop
                        #oop.parse_class_fields()
                    idx += 1
            setattr(self, 'parse_flds_completed', True)
        except:
            import traceback
            traceback.print_exc()
        finally:
            delattr(self, 'parse_flds_in_progress')

    @classmethod
    def get_metadata(cls, addr, _bytes, jvm_analysis):
        jva = jvm_analysis
        if (addr % 8) != 0:
            return None

        fmt = cls.bits32 if jva.is_32bit else cls.bits64
        data_unpack = struct.unpack(fmt, _bytes)
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        kargs = { "addr":addr, "jvm_analysis":jvm_analysis, "ooptype":"Oop",
                  "updated":False, "klasstype":"",
                  "klass_value":None}
        name_fields(data_unpack, nfields, fields=kargs)
        return kargs['metadata']


    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        jva = jvm_analysis
        if (addr % 8) != 0:
            return None
        if jvm_analysis and jvm_analysis.has_oop(addr):
            oop = jvm_analysis.lookup_known_oop_only(addr)
            if oop and oop._name.find("Oop") == -1:
                #print "Error, not oop ", oop, " ", type(oop)
                raise BaseException("Oop is not a symbol @ 0x%08x"%(addr))
            elif oop:
                return oop
        #print ("In symbol 0x%08x type(bytes)=%s fmt=%s"%(addr, str(type(bytes)), fmt))
        if bytes is None:
            return None

        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        data_unpack = struct.unpack(fmt, _bytes)
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        kargs = { "addr":addr, "jvm_analysis":jvm_analysis, "ooptype":"Oop",
                  "updated":False, "klasstype":"",
                  "klass_value":None, 'is_32bit':jvm_analysis.is_32bit}
        name_fields(data_unpack, nfields, fields=kargs)

        klass_info = get_klass_info(kargs['metadata'], jva)
        if klass_info['is_oop_array']:
           return ObjArrayKlassOop.from_jva(addr, jva)
        elif klass_info['is_prim']:
           PrimOop = PRIMITIVES_OOPS[klass_info['prim_value']]
           return PrimOop.from_jva(addr, jva)
        elif len(klass_info['name']) == 0 or\
           not jva.is_valid_heap_addr(kargs['metadata']):
           return None

        kargs['unpacked_values'] = data_unpack

        kargs['oop_nonstatic_field_size'] = None
        kargs['oop_static_field_size'] = None
	kargs['oop_field_values_by_name'] = None
        kargs['oop_field_values_by_offset'] = None
        kargs['oop_static_field_values'] = None

        #oop_value_cls = Oop
        #is_prim = False
        #print "Looking at %s and its in PRIMITIVES_OOPS %d"%(klass_name, klass_name in PRIMITIVES_OOPS)
        #if klass_name.strip('[') in PRIMITIVES_OOPS:
        #    oop_value_cls = PRIMITIVES_OOPS[klass_name]
        #    #setattr(self, 'oop_values', oop_value_cls.new_array(base, length))
        #    incr = oop_value_cls.size32
        #    is_prim = True

        d = Oop(**kargs)
        if jvm_analysis and d:
            jvm_analysis.add_oop(d)
        elif d is None:
            #print ("Failed to create an Oop @ 0x%08x"%(addr))
            return None
        if not 'metadata' in kargs:
            pass#print kargs

        naddr = kargs['metadata']
        kargs['klass'] = kargs['metadata']
        klass = None
        if klass_info['is_array']:
            klass = ArrayKlass.from_jva(naddr, jva)
            #print ("Found %s (%s)  @ 0x%08x"%(str(klass), klass.klasstype, naddr))
        elif klass_info['is_instance']:
            klass = KlassInstance.from_jva(naddr, jva)
            #print ("Found %s (%s)  @ 0x%08x"%(str(klass), klass.klasstype, naddr))
        else:
            #??
            klass = Klass.from_jva(naddr, jva)
            if klass:
                pass#print ("Found %s (%s)  @ 0x%08x"%(str(klass), klass.klasstype, naddr))

        if klass is None:
            #print ("Error: Failed to parse the OOP: 0x%08x %s"%(addr, d))
            return None
        elif str(klass).lower().find("unknown") == 0:
            return None
        elif klass and klass_info['is_instance']:
            d.parse_class_fields()

        setattr(d, 'klass_value', klass)
        if klass_info['is_prim']:
            prim_cls = PRIMITIVES_OOPS[klass_info['prim_value']]
            prim_oop = prim_cls.from_jva(addr+2*jva.word_sz, jva)
            #setattr(d, 'is_prim', True)
            setattr(d, 'value', getattr(prim_oop, 'value', None))
            setattr(d, 'ooptype', getattr(prim_oop, '_name', None))
        elif klass:
            setattr(d, 'klasstype', klass._name)
            # may fail if the its an instanceKlassKlass
            setattr(d, 'ooptype', klass._name.replace("Klass", 'Oop'))
            klass.update_fields()
        else:
            setattr(d, 'klasstype', "ERROR")
            setattr(d, 'ooptype', "ERROR")
            return None

        # oops should not trigger any issue with circular references
        # when updating the class
        return d





class ObjArrayKlassOop(BaseOverlay):
    _name = "ObjArrayKlassOop"
    _overlay = OBJ_ARRAY_OOP_TYPE
    bits32 = get_bits32(OBJ_ARRAY_OOP_TYPE)
    bits64 = get_bits64(OBJ_ARRAY_OOP_TYPE)
    named32 = get_named_array32(OBJ_ARRAY_OOP_TYPE)
    named64 = get_named_array64(OBJ_ARRAY_OOP_TYPE)
    size32 = get_size32(OBJ_ARRAY_OOP_TYPE)
    size64 = get_size64(OBJ_ARRAY_OOP_TYPE)
    types = get_field_types(OBJ_ARRAY_OOP_TYPE)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)
        self.bread_crumbs={}

    def is_array_oop(self):
        return True

    def get_oop_field_value(self, field_name, klass_name=None):
        if field_name == 'value':
            return self.raw_value()
        raise Exception("%s has no field '%s'"%(self._name, field_name))

    def python_value(self, bread_crumbs={}, lookup={}, set_bread_crumbs=False, **kargs):
        oop_values = getattr(self, "oop_values", None)
        res = []
        name_value = getattr(self, "klass_value", None)
        prim = str(name_value).strip('[')
        if not self.addr in bread_crumbs:
            bread_crumbs[self.addr] = {'is_array':True,'is_prim':(prim in PRIMITIVES_OOPS), 'value':res, 'addr':self.addr}
            if set_bread_crumbs:
                setattr(self, 'bread_crumbs', bread_crumbs)
        bread_crumbs[self.addr]['value'] = res
        # handle character arrays separately (easy button) no list of chars
        if str(name_value) == '[C':
            v = ""
            for oop in oop_values:
                if oop:
                    v = oop.python_value(bread_crumbs=bread_crumbs, **kargs)
                    bread_crumbs[oop.addr]['value'] = v
                    lookup[oop.addr] = bread_crumbs[oop.addr]

            if len(oop_values) > 0:
                v= "".join([i.raw_value().replace('\x00', '') for i in oop_values if i])
            bread_crumbs[self.addr]['value'] = v
            lookup[self.addr] = bread_crumbs[self.addr]
            return v
        # handle all other types of arrays batta bing
        for oop in oop_values:
            if oop is None:
                res.append(None)
                continue
            v = None
            if oop:
                v = oop.python_value(bread_crumbs=bread_crumbs, lookup=lookup, set_bread_crumbs=set_bread_crumbs, **kargs)

            if oop and not oop.is_prim() and not oop.is_array_oop():
                bread_crumbs[oop.addr]['value'].update(v)
            elif oop:
                bread_crumbs[oop.addr]['value'] = v
            res.append(bread_crumbs[oop.addr])
        return res

    def raw_value(self, return_dict=False, klass_name=None):
        oop_values = getattr(self, "oop_values", None)
        name_value = getattr(self, "klass_value", None)
        prim = str(name_value).strip('[')
        # TODO not sure if I want to do this in the long term
        if name_value and prim in PRIMITIVES_OOPS:
            if prim == 'C':
                v= "".join([i.raw_value().replace('\x00', '') for i in oop_values])
                #print len(oop_values), len(v)
                #print "returning raw [C value", v
                return v

        if oop_values is None:
            return []

        all_prims = []
        for k in oop_values:
            kname = str(getattr(k, 'klass_value', None))
            if k and (k.is_prim() or kname in JAVA_PRIMITIVE):
                all_prims.append(1)
            else:
                all_prims.append(0)
        if sum(all_prims) == len(oop_values):
            return [i.raw_value() if i else None  for i in oop_values]
        vals = []
        for k in oop_values:
            try:
                v = k.raw_value() if k else None
                vals.append(v)
            except:
                vals.append(None)
        return vals

    def agg_size(self):
        sz = self.size()
        length = getattr(self, 'length', 0)
        esz = 2**getattr(self, 'esz',0 )
        return sz+(esz*length)

    def __str__(self):
        addr = getattr(self, 'addr', '')
        name = getattr(self, '_name', '')
        klass_name = "Unknown"
        klass_addr = 0x0
        klass = self.get_klass()
        if klass:
            klass_name = str(klass.name_value)
            klass_addr = klass.addr

        values = self.raw_value()
        length = getattr(self, 'length', 0)
        fmt = '%s @ 0x%08x of %s[%d] @ 0x%08x'
        a = fmt%(name, addr, klass_name, length, klass_addr)
        prim = str(klass_name).strip('[')
        #if klass_name and prim in PRIMITIVES_OOPS:
        #    if prim == 'C':
        #        # aggregate strings
        #        p = ''.join([i.replace('\x00', '') for i in values])
        #        a = a + ": "+ p
        #    elif prim == 'B':
        #        # aggregate strings
        #        p = ', '.join(["0x%02x"%i for i in values])
        #        a = a +": ["+ p +']'
        #    elif prim == 'S':
        #        # aggregate strings
        #        p = ', '.join(["0x%04x"%i for i in values])
        #        a = a +": ["+ p +']'
        #    elif prim == 'I':
        #        # aggregate strings
        #        p = ', '.join(["0x%08x"%i for i in values])
        #        a = a +": ["+ p +']'
        #    elif prim == 'J':
        #        # aggregate strings
        #        p = ', '.join(["0x%08x"%i for i in values])
        #        a = a +": ["+ p +']'
        #    elif prim == 'Z':
        #        # aggregate strings
        #        b = [i for i in values]
        #        p = " ".join(['T' if i else 'F' for i in b])
        #        a = a +": ["+ p +']'
        #    elif prim == 'D':
        #        # aggregate strings
        #        p = ', '.join([str(i) for i in values])
        #        a = a +": ["+ p +']'
        #    elif prim == 'F':
        #        # aggregate strings
        #        p = ', '.join([str(i) for i in values])
        #        a = a +": ["+ p +']'
        #elif klass_name and len(values) > 0:
        #    pass
        #    #for obj in values:
        #    #    for fld, value in obj.items():
        #    #        # build string here
        #
        if len(a) == 0:
            a = str(klass_name) + " @ 0x%08x"%getattr(self, 'addr')
        return a

    def update_fields(self, force_update=False):
        if getattr(self, "updated", False) and not force_update:
            return
        setattr(self, "updated", True)
        # read in all the oops that are after
        # header
        jva = getattr(self, 'jvm_analysis')

        sz = self.size32 if jva.is_32bit else\
             self.size64
        addr = getattr(self, 'addr', 0)
        base = addr + sz
        if sz == base:
            return # Nothing to do this is abad

        klass = self.get_klass()
        if klass is None or self.klass_name() == "Unknown":
            setattr(self, "updated", True)
            return
        klass.update_fields()
        incr = getattr(klass, "element_sz", 0)
        oop_addrs = getattr(self, 'oop_addrs', None)
        oop_vals = getattr(self, 'oop_values', None)
        length = getattr(self, 'length', 0)
        klass_name = str(getattr(klass, 'name_value', ''))

        oop_value_cls = Oop
        is_prim = False
        #print "Looking at %s and its in PRIMITIVES_OOPS %d"%(klass_name, klass_name in PRIMITIVES_OOPS)
        if klass_name.strip('[') in PRIMITIVES_OOPS:
            oop_value_cls = PRIMITIVES_OOPS[klass_name.strip("[")]
            #setattr(self, 'oop_values', oop_value_cls.new_array(base, length))
            incr = oop_value_cls.size32
            is_prim = True

        pos = 0
        # moment of truth
        if incr <= 0 or oop_addrs is None or oop_vals is None or length == 0:
            # not ready to parse or this object is incorrectly interped
            setattr(self, "updated", False)
            return
        #print "********************************* updating the obj array"
        if len(oop_vals) > 0:
            oop_vals = []
            oop_addrs = []
            setattr(self, 'oop_values', oop_vals)
            setattr(self, 'oop_addrs', oop_addrs)

        while pos < length:
            o_addr = base+pos*incr
            #print "reading address of 0x%08x"%(o_addr)
            naddr = o_addr
            if not is_prim:
                naddr = jva.read_dword(o_addr) if jva.is_32bit else\
                        jva.read_qword(o_addr)
            oop_addrs.append(o_addr)
            if naddr is None or naddr == 0:
                oop_vals.append(None)
            else:
                oop = oop_value_cls.from_jva(naddr, jva)
                if oop:
                    oop.update_fields(force_update)
                else:
                    fmt = "ERROR: ObjArrayObj(0x%08x)[%d] @0x%08x Failed to parse OOP @0x%08x"
                    #print (fmt%(addr, pos, o_addr, naddr))
                oop_vals.append(oop)
            pos+=1

    def parse_class_fields(self, force_update=False):
        pass

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        if (addr % 8) != 0:
            return None
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        jva = jvm_analysis

        if bytes is None:
            return None

        if jva and jva.has_oop(addr):
            return jva.lookup_known_oop_only(addr)

        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False,"ooptype":'ObjArrayKlassOop',
                 'metatype':'', 'klasstype':'ObjArrayKlass', "oop_values":[],
                 'oop_addrs':[], 'klass_value':None}
        data_unpack = struct.unpack(fmt, _bytes)
        name_fields(data_unpack, nfields, fields=kargs)
        klass_info = get_klass_info(kargs['metadata'], jva)
	#kargs['is_prim'] = klass_info['is_prim']
        kargs['ebt'] = klass_info['ebt']
        kargs['esz'] = klass_info['esz']
        if not klass_info['is_oop_array']:
            #print("Error: Attempting to parse a"+\
            #      "OOP Array @ 0x%08x"%addr +\
            #      "but its not an array")
            return Oop.from_jva(addr, jva)
        kargs['unpacked_values'] = data_unpack

        naddr = kargs['metadata']
        kargs['klass'] = kargs['metadata']
        #kargs['klass_value'] = ObjArrayKlass.from_jva(naddr, jva)
        kargs['klass_value'] = Klass.from_jva(naddr, jva)
        kval = kargs['klass_value']
        kargs['klasstype'] = getattr(kval, '_name', '')
        d = ObjArrayKlassOop(**kargs)
        jvm_analysis.add_oop(d)
        return d

class TypeArrayKlassOop(BaseOverlay):
    _name = "TypeArrayKlassOop"
    _overlay = TYPE_ARRAY_OOP_TYPE
    bits32 = get_bits32(TYPE_ARRAY_OOP_TYPE)
    bits64 = get_bits64(TYPE_ARRAY_OOP_TYPE)
    named32 = get_named_array32(TYPE_ARRAY_OOP_TYPE)
    named64 = get_named_array64(TYPE_ARRAY_OOP_TYPE)
    size32 = get_size32(TYPE_ARRAY_OOP_TYPE)
    size64 = get_size64(TYPE_ARRAY_OOP_TYPE)
    types = get_field_types(TYPE_ARRAY_OOP_TYPE)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__(self):
        name_value = getattr(self, "name_value", None)
        if name_value:
            return str(name_value)
        return "Unknown class @ 0x%08x"%(getattr(self, "addr", -1))

    def update_fields(self, force_update=False):
        if getattr(self, "updated", False) and not force_update:
            return
        setattr(self, "updated", True)
        # read in all the oops that are after
        # header
        jva = getattr(self, "jvm_analysis")
        sz = self.size32 if jva.is_32bit else\
             self.size64

        base = getattr(self, 'addr', 0) + sz
        if sz == base:
            return # Nothing to do this is abad

        klass = getattr(self, 'klass_value', None)
        if klass is None:
            setattr(self, "updated", False)
            return
        incr = getattr(klass, "element_sz", 0)
        setattr(self, 'oop_addrs', [])
        setattr(self, 'oop_values', [])
        oop_addrs = getattr(self, 'oop_addrs')
        oop_vals = getattr(self, 'oop_values')
        length = getattr(self, 'length', 0)
        pos = 0

        # moment of truth
        if incr <= 0 or oop_addrs is None or oop_vals is None or length == 0:
            # not ready to parse or this object is incorrectly interped
            setattr(self, "updated", False)
            return
        #print "********************************* updating the obj array"
        while pos < length:
            o_addr = base+pos*incr
            #print "reading address of 0x%08x"%(o_addr)
            naddr = jva.deref32(o_addr) if jva.is_32bit else\
                    jva.deref64(o_addr)
            oop_addrs.append(o_addr)
            if naddr == 0:
                oop_vals.append(None)
            else:
                oop = jva.lookup_known_oop (naddr)
                if oop:
                    jva.add_oop(oop)
                    oop.update_fields()
                oop_vals.append(oop)
            pos+=1



    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        if (addr % 8) != 0:
            return None
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        jva = jvm_analysis

        if bytes is None:
            return None

        if jva and jva.has_oop(addr):
            return jva.lookup_known_oop_only(addr)

        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False,"ooptype":'TypeArrayKlassOop',
                 'metatype':'', 'klasstype':'', "oop_values":[],
                 'oop_addrs':[], 'klass_value':None}
        data_unpack = struct.unpack(fmt, _bytes)
        name_fields(data_unpack, nfields, fields=kargs)

        naddr = kargs['metadata']
        kargs['klass'] = kargs['metadata']
        #kargs['klass_value'] = TypeArrayKlass.from_jva(naddr, jva)
        kargs['klass_value'] = Klass.from_jva(naddr, jva)
        kval = kargs['klass_value']
        kargs['klasstype'] = getattr(kval, '_name', '')
        kargs['unpacked_values'] = data_unpack
        d = TypeArrayKlassOop(**kargs)
        jvm_analysis.add_oop(d)
        return d


class ArrayKlassOop(BaseOverlay):
    _name = "ArrayKlassOop"
    _overlay = ARRAY_OOP_TYPE
    bits32 = get_bits32(ARRAY_OOP_TYPE)
    bits64 = get_bits64(ARRAY_OOP_TYPE)
    named32 = get_named_array32(ARRAY_OOP_TYPE)
    named64 = get_named_array64(ARRAY_OOP_TYPE)
    size32 = get_size32(ARRAY_OOP_TYPE)
    size64 = get_size64(ARRAY_OOP_TYPE)
    types = get_field_types(ARRAY_OOP_TYPE)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__(self):
        name_value = getattr(self, "name_value", None)
        if name_value:
            return str(name_value)
        return "Unknown class @ 0x%08x"%(getattr(self, "addr", -1))

    def update_fields(self, force_update=False):
        if getattr(self, "updated", False) and not force_update:
            return
        setattr(self, "updated", True)
        # read in all the oops that are after
        # header
        jva = jvm_analysis
        sz = self.size32 if jvm_analysis.is_32bit else\
             self.size64

        base = getattr(self, 'addr', 0) + sz
        if sz == base:
            return # Nothing to do this is abad

        klass = getattr(self, 'klass_value', None)
        if klass is None:
            setattr(self, "updated", False)
            return
        incr = getattr(klass, "element_sz", 0)
        oop_addrs = getattr(self, 'oop_addrs', None)
        oop_vals = getattr(self, 'oop_values', None)
        length = getattr(self, 'length', 0)
        pos = 0

        # moment of truth
        if incr <= 0 or oop_addrs is None or oop_vals is None or length == 0:
            # not ready to parse or this object is incorrectly interped
            setattr(self, "updated", False)
            return
        #print "********************************* updating the obj array"
        while pos < length:
            o_addr = base+pos*incr
            #print "reading address of 0x%08x"%(o_addr)
            naddr = jva.deref32(o_addr) if jvm_analysis.is_32bit else\
                    jva.deref64(o_addr)
            oop_addrs.append(o_addr)
            if naddr == 0:
                oop_vals.append(None)
            else:
                oop = jva.lookup_known_oop(naddr)
                if oop:
                    jva.add_oop(oop)
                    oop.update_fields()
                oop_vals.append(oop)
            pos+=1



    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        if (addr % 8) != 0:
            return None
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        jva = jvm_analysis

        if bytes is None:
            return None

        if jva and jva.has_oop(addr):
            return jva.lookup_known_oop_only(addr)

        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False,"ooptype":'TypeArrayKlassOop',
                 'metatype':'', 'klasstype':'', "oop_values":[],
                 'oop_addrs':[]}
        data_unpack = struct.unpack(fmt, _bytes)
        name_fields(data_unpack, nfields, fields=kargs)
        kargs['unpacked_values'] = data_unpack

        naddr = kargs['metadata']
        kargs['klass'] = kargs['metadata']
        #kargs['klass_value'] = TypeArrayKlass.from_jva(naddr, jva)
        kargs['klass_value'] = Klass.from_jva(naddr, jva)
        kval = kargs['klass_value']
        kargs['klasstype'] = getattr(kval, '_name', '')
        d = ArrayKlassOop(**kargs)
        jvm_analysis.add_oop(d)
        return d
