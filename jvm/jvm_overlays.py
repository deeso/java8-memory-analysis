import re, struct

import binascii
lendian_s2d = lambda sbytes: struct.unpack("<I", binascii.unhexlify(sbytes))[0]
lendian_s2x = lambda sbytes: hex(struct.unpack("<I", binascii.unhexlify(sbytes))[0])


BITS32 = 0
BITS64 = 1
TYPES = 2
NAMES = 3

get_oop = lambda jva, addr: None if jva is None \
                             else jva.get_oop(addr)
get_klass = lambda jva, addr: None if jva is None \
                             else jva.get_klass(addr)
get_meta = lambda jva, addr, cls: None if jva is None \
                             else jva.get_meta(addr, cls)
get_sym = lambda jva, addr: None if jva is None \
                        else jva.lookup_internal_symbol(addr)
get_aklassoop = lambda jva, addr: None if jva is None \
                             else jva.get_aklassoop(addr)
get_oaklassoop = lambda jva, addr: None if jva is None \
                             else jva.get_oaklassoop(addr)
get_aobjoop = lambda jva, addr: None if jva is None \
                             else jva.get_aobjoop(addr)
get_atypeoop = lambda jva, addr: None if jva is None \
                             else jva.get_atypeoop(addr)

get_cpoop = lambda jva, addr: None if jva is None \
                             else jva.get_constantPoolOop(addr)

def resolve_syms (types, names, jva, fields):
    pos = 0
    types = types
    end = len(types)
    while pos < end:
        typ = types[pos]
        name = names[pos]
        if name in fields and typ.find("Symbol*") == 0:
            sym = get_sym(jva, fields[name])
            #print typ, name, "0x%08x"%fields[name], str(sym)
            name_value = name + '_value'
            fields[name_value] = sym
        pos += 1
    return fields

def name_fields(unpacked, names, fields={}):
    pos = 0
    end = len(unpacked) if len(unpacked) < names \
                        else len(names)
    while pos < end:
        name = names[pos]
        fields[name] = unpacked[pos]
        pos += 1
    return fields

def print_overlay_offsets32(TYPE, values, base_off = 0):
    pos = 0
    fmt = "%s %s %s = %s"
    d = []
    types = get_field_types(TYPE)
    names = get_named_array32(TYPE)
    sizes = get_field_sizes32(TYPE)
    while pos < len(names):
        name = names[pos]
        sz = struct.calcsize(sizes[pos])
        value =  ("0x%0"+"%dx"%(sz*2)) % values[pos]
        offset = hex(base_off)
        type_ = types[pos]
        d.append((fmt%(offset, type_, name, value)))
        pos += 1
        base_off += struct.calcsize(sizes[pos-1])
    #print "\n".join(d)
    return "\n".join(d)

def print_overlay_offsets64(TYPE, values, base_off = 0):
    pos = 0
    fmt = "%s %s = %s @ %s"
    types = get_field_types(TYPE)
    names = get_named_array64(TYPE)
    sizes = get_field_sizes64(TYPE)
    d = []
    while pos < len(TYPE):
        name = names[pos]
        value =  hex(values[pos])
        offset = hex(base_off)
        type_ = types[pos]
        d.append((fmt%(offset, type_, name, value)))
        pos += 1
        base_off += struct.calcsize(sizes[pos-1])
    print "\n".join(d)
    return "\n".join(d)

def get_named_types_tup_list(TYPE):
    field_types = get_field_types(TYPE)
    field_names = get_named_array32(TYPE)
    res = []
    for pos in xrange(0, len(field_names)):
        res.append((field_names[pos], field_types[pos]))
    return res

def get_named_types_dict(TYPE):
    field_types = get_field_types(TYPE)
    field_names = get_named_array32(TYPE)
    res = {}
    for pos in xrange(0, len(field_names)):
        res[field_names[pos]] = field_types[pos]
    return res

def contains_digits(d):
    _digits = re.compile(r'\d')
    return bool(_digits.search(d))

def get_bits32(TYPE):
    bits32 = [i[BITS32] for i in TYPE]
    return "".join(bits32)

def get_bits64(TYPE):
    bits64 = [i[BITS64] for i in TYPE]
    return "".join(bits64)

def get_field_sizes64(TYPE):
    types= []
    for t in TYPE:
        num = 1
        f = t[BITS64]
        if contains_digits(t[BITS64]):
            # print t
            digits = [i for i in t[BITS64] if i.isdigit()]
            f = "".join(t[BITS64][len(digits):])
            # print num
            num = int("".join(digits))
        if num == 1:
            types.append(f)
        else:
            types += [f for i in xrange(0, num)]
    return types

def get_field_sizes32(TYPE):
    types= []
    for t in TYPE:
        num = 1
        f = t[BITS32]
        if contains_digits(t[BITS32]):
            # print t
            digits = [i for i in t[BITS32] if i.isdigit()]
            f = "".join(t[BITS32][len(digits):])
            # print num
            num = int("".join(digits))
        if num == 1:
            types.append(f)
        else:
            types += [f for i in xrange(0, num)]
    return types

def get_field_types(TYPE):
    types= []
    for t in TYPE:
        num = 1
        if contains_digits(t[BITS32]):
            # print t
            digits = [i for i in t[BITS32] if i.isdigit()]
            # print num
            num = int("".join(digits))
        if num == 1:
            types.append(t[TYPES])
        else:
            types += [(t[TYPES]) for i in xrange(0, num)]
    return types

def get_size64(TYPE):
    size64 = struct.calcsize(get_bits64(TYPE))
    return size64

def get_size32(TYPE):
    size32 = struct.calcsize(get_bits32(TYPE))
    return size32

def get_named_array32(TYPE):
    names = []
    for t in TYPE:
        num = 1
        if contains_digits(t[BITS32]):
            # print t
            digits = [i for i in t[BITS32] if i.isdigit()]
            # print num
            num = int("".join(digits))
        if num == 1:
            names.append(t[NAMES])
        else:
            names += [(t[NAMES]+"_%d")%i for i in xrange(0, num)]
    return names

def get_named_array64(TYPE):
    names = []
    for t in TYPE:
        num = 1
        if contains_digits(t[BITS64]):
            # print t
            digits = [i for i in t[BITS64] if i.isdigit()]
            # print num
            num = int("".join(digits))
        if num == 1:
            names.append(t[NAMES])
        else:
            names += [(t[NAMES]+"_%d")%i for i in xrange(0, num)]
    return names


CHAR_OOP_TYPE = [
    ['2c', '2c', 'jchar', 'data']
]
BYTE_OOP_TYPE = [['B', 'B', 'jbyte', 'data']]
DOUBLE_OOP_TYPE = [['d', 'd', 'jdouble', 'data']]
FLOAT_OOP_TYPE = [['f', 'f', 'jfloat', 'data']]
INT_OOP_TYPE = [['I', 'I', 'jint', 'data']]
LONG_OOP_TYPE = [['Q', 'Q', 'jlong', 'data']]
SHORT_OOP_TYPE = [['H', 'H', 'jshort', 'data']]
BOOL_OOP_TYPE = [['B', 'B', 'jbool', 'data']]

OOP_TYPE32 = [
    ['I', 'Q', 'markOop', 'mark'],
    ['I', 'Q', 'Klass*', 'metadata'],
]

OOP_TYPE64 = [
    ['I', 'Q', 'markOop', 'mark'],
    ['I', 'Q', 'Klass*', 'metadata'],
]

OOP_TYPE = OOP_TYPE32

MARK_OOP_TYPE = OOP_TYPE + []
KLASS_OOP_TYPE = OOP_TYPE + []
INSTANCE_KLASS_OOP_TYPE = OOP_TYPE + []
ARRAY_OOP_TYPE = [
    ['I', 'Q', 'markOop', 'mark'],
    ['I', 'Q', 'Klass*', 'metadata'],
    ['I', 'I', 'int', 'length'],
]

TYPE_ARRAY_OOP_TYPE = ARRAY_OOP_TYPE
OBJ_ARRAY_OOP_TYPE = ARRAY_OOP_TYPE


# Metadata classes
# //      class MetaspaceObj
# class   Method;
# //      class CHeapObj
# class   CompiledICHolder;
COMPILED_IC_HOLDER_TYPE =  [
    ['I', 'Q', 'void*', 'vtable'],
    ['I', 'I', 'int', 'live_count'],
    ['I', 'I', 'int', 'live_count_not_claimed_count'],
    ['I', 'Q', 'Method*', 'holder_method'],
    ['I', 'Q', 'Klass*', 'holder_klass'],
    ['I', 'Q', 'CompiledICHolder*', 'next'],
]

COMPILED_IC_HOLDER_META_TYPE =  [
    ['I', 'Q', 'void*', 'vtable'],
    ['I', 'Q', 'methodOop', 'holder_method'],
    ['I', 'Q', 'klassOop', 'holder_klass'],
]

METHOD_DATA_META_TYPE = [
    ['I', 'Q', 'void*', 'vtable'],
    ['I', 'Q', 'Method*', 'method'],
    ['I', 'I', 'int', 'size'],
    ['I', 'I', 'int', 'hint_di'],
    ['I', 'I', 'int', 'nof_decompiles'],
    ['I', 'I', 'int', 'nof_overflow_recompiles'],
    ['I', 'I', 'int', 'nof_overflow_traps'],
    ['17B', '17B', 'union u1', 'trap_hist'],
    ['I', 'I', 'intx', 'eflags'],
    ['I', 'I', 'intx', 'arg_local'],
    ['I', 'I', 'intx', 'arg_stack'],
    ['I', 'I', 'intx', 'arg_returned'],
    ['I', 'I', 'int', 'creation_mileage'],
    ['I', 'I', 'InvocationCounter', 'invocation_counter'],
    ['I', 'I', 'InvocationCounter', 'backedge_counter'],
    ['I', 'I', 'int', 'invocation_counter_start'],
    ['I', 'I', 'int', 'backedge_counter_start'],
    ['H', 'H', 'short', 'num_loops'],
    ['H', 'H', 'short', 'num_blocks'],
    ['B', 'B', 'u1', 'highest_comp_level'],
    ['B', 'B', 'u1', 'highest_osr_comp_level'],
    ['B', 'B', 'bool', 'would_profile'],
    ['I', 'I', 'int', 'data_size'],
    ['I', 'I', 'int', 'parameters_type_data_di'],
    ['I', 'I', 'int', 'data'], # length of data is depened on size
]

CONSTANT_POOL_META_TYPE = [
  ['I', 'Q', 'void*', 'vtable'],
  ['I', 'Q', 'Array<u1>*', 'tags'],
  ['I', 'Q', 'ConstantPoolCache*', 'cache'],
  ['I', 'Q', 'InstanceKlass*', 'pool_holder'],
  ['I', 'Q', 'Array<u2>*', 'operands'],
  ['I', 'Q', 'jobject', 'resolved_references'],
  ['I', 'Q', 'Array<u2>*', 'reference_map'],
  ['I', 'I', 'int', 'flags'],
  ['I', 'I', 'int', 'length'],
  ['I', 'I', 'int', 'saved'],
  ['I', 'Q', 'Monitor*', 'lock'],
]



CONST_METHOD_META_TYPE = [
    #['I', 'Q', 'void*', 'vtable'],
    ['Q', 'Q', 'uint64_t', 'fingerprint'],
    ['I', 'Q', 'ConstantPool*', 'constants'],
    ['I', 'Q', 'Array<u1>*', 'stackmap_data'],
    ['I', 'I', 'int', 'constMethod_size'],
    ['H', 'H', 'u2', 'flags'],
    ['H', 'H', 'u2', 'code_size'],
    ['H', 'H', 'u2', 'name_index'],
    ['H', 'H', 'u2', 'signature_index'],
    ['H', 'H', 'u2', 'method_idnum'],
    ['H', 'H', 'u2', 'max_stack'],
    ['H', 'H', 'u2', 'max_locals'],
    ['H', 'H', 'u2', 'size_of_parameters'],
]

METHOD_META_TYPE = [
    ['I', 'Q', 'void*', 'vtable'],
    ['I', 'Q', 'ConstMethod*', 'const_method'],
    ['I', 'Q', 'MethodData*', 'method_data'],
    ['I', 'Q', 'MethodCounters*', 'method_counters'],
    ['I', 'I', 'AccessFlags', 'access_flags'],
    ['I', 'I', 'int', 'vtable_index'],
    ['H', 'H', 'u2', 'method_size'],
    ['B', 'B', 'u1', 'intrinsic_id'],
    ['B', 'B', 'u1', 'intrinsic_flags'],
    ['I', 'Q', 'address', 'i2i_entry'],
    ['I', 'Q', 'AdapterHandlerEntry*', 'adapter'],
    ['I', 'Q', 'address', 'from_compiled_entry'],
    ['I', 'Q', 'nmethod*', 'code'],
    ['I', 'Q', 'address', 'from_interpreted_entry'],
]


CP_CACHE_ENTRY_META_TYPE = [
    ['I', 'I', 'intx', 'indices'],
    ['I', 'Q', 'MetaData*', 'f1'],
    ['I', 'I', 'intx', 'f2'],
    ['I', 'I', 'intx', 'flags'],
]

CP_CACHE_META_TYPE = [
    ['I', 'I', 'int', 'length'],
    ['I', 'Q', 'ConstantPool*', 'contant_pool'],
]


INVOCATION_COUNTER = [
    ['I', 'I', 'unsigned int', 'counter'],
]

KLASS_TYPE = [
    ['I', 'Q', 'void*', 'vtable'],
    ['I', 'I', 'jint', 'layout_helper'],
    ['I', 'I', 'juint', 'super_check_offset'],
    ['I', 'Q', 'Symbol*', 'name'],
    ['I', 'Q', 'Klass*', 'secondary_super_cache'],
    ['I', 'Q', 'Array<Klass*>*', 'secondary_supers'],
    ['8I', '8Q', 'Klass*', 'primary_supers'],
    ['I', 'Q', 'oop', 'java_mirror'],
    ['I', 'Q', 'Klass*', 'super'],
    ['I', 'Q', 'Klass*', 'subklass'],
    ['I', 'Q', 'Klass*', 'next_sibling'],
    ['I', 'Q', 'Klass*', 'next_link'],
    ['I', 'Q', 'ClassLoaderData*', 'class_loader_data'],
    ['I', 'I', 'jint', 'modifier_flags'],
    ['I', 'I', 'AccessFlags', 'access_flags'],
    ['Q', 'Q', 'jlong', 'last_biased_lock_bulk_revocation_time'],
    ['I', 'Q', 'markOop', 'prototype_header'],
    ['I', 'I', 'jint', 'biased_lock_revocation_count'],
    ['2B', '2B', 'PADDING', 'word_padding'],
    ['B', 'B', 'jbyte', 'modified_oops'],
    ['B', 'B', 'jbyte', 'accumulated_modified_oops'],
    ['I', 'I', 'int', 'trace_id',],
    ['I', 'I', 'PADDING', 'moar_padding',],
]

KLASS_TYPE_WIN = [
    ['I', 'Q', 'void*', 'vtable'],
    ['I', 'I', 'jint', 'layout_helper'],
    ['I', 'I', 'juint', 'super_check_offset'],
    ['I', 'Q', 'Symbol*', 'name'],
    ['I', 'Q', 'Klass*', 'secondary_super_cache'],
    ['I', 'Q', 'Array<Klass*>*', 'secondary_supers'],
    ['8I', '8Q', 'Klass*', 'primary_supers'],
    ['I', 'Q', 'oop', 'java_mirror'],
    ['I', 'Q', 'Klass*', 'super'],
    ['I', 'Q', 'Klass*', 'subklass'],
    ['I', 'Q', 'Klass*', 'next_sibling'],
    ['I', 'Q', 'Klass*', 'next_link'],
    ['I', 'Q', 'ClassLoaderData*', 'class_loader_data'],
    ['I', 'I', 'jint', 'modifier_flags'],
    ['I', 'I', 'AccessFlags', 'access_flags'],
    ['Q', 'Q', 'jlong', 'last_biased_lock_bulk_revocation_time'],
    ['I', 'Q', 'markOop', 'prototype_header'],
    ['I', 'I', 'jint', 'biased_lock_revocation_count'],
    ['2B', '2B', 'PADDING', 'word_padding'],
    ['B', 'B', 'jbyte', 'modified_oops'],
    ['B', 'B', 'jbyte', 'accumulated_modified_oops'],
    ['I', 'I', 'int', 'trace_id',],
    ['I', 'I', 'PADDING', 'moar_padding',],
    ['I', 'I', 'PADDING', 'moar_padding2',],
]

INSTANCE_KLASS_TYPE_OVERLAY =     [['I', 'Q', 'Annotations*', 'annotations'],
    ['I', 'Q', 'Klass*', 'array_klasses'],
    ['I', 'Q', 'ConstantPool*', 'constants'],
    ['I', 'Q', 'Array<jushort>*', 'inner_classes'],
    ['I', 'Q', 'char*', 'source_debug_extension'],
    ['I', 'Q', 'Symbol*', 'array_name'],
    ['I', 'I', 'int', 'nonstatic_field_size'],
    ['I', 'I', 'int', 'static_field_size'],
    ['H', 'H', 'u2', 'generic_signature'],
    ['H', 'H', 'u2', 'source_file_name_index'],
    ['H', 'H', 'u2', 'static_oop_field_count'],
    ['H', 'H', 'u2', 'java_fields_count'],
    ['I', 'I', 'int', 'nonstatic_oop_map_size'],
    ['H', 'B', 'bool', 'is_marked_dependent'],
    ['H', 'H', 'u2', 'misc_flags'],
    ['H', 'H', 'u2', 'minor_version'],
    ['H', 'H', 'u2', 'major_version'],
    ['I', 'Q', 'Thread*', 'init_thread'],
    ['I', 'I', 'int', 'vtable_len'],
    ['I', 'I', 'int', 'itable_len'],
    ['I', 'Q', 'OopMapCache*', 'oop_map_cache'],
    ['I', 'Q', 'MemberNameTable*', 'member_names'],
    ['I', 'Q', 'JNIid*', 'jni_ids'],
    ['I', 'Q', 'nmethodBucket*', 'dependencies'],
    ['I', 'Q', 'jmethodID*', 'methods_jmethod_ids'],
    ['I', 'Q', 'nmethod*', 'osr_nmethods_head'],
    ['I', 'Q', 'BreakpointInfo*', 'breakpoints'],
    ['I', 'Q', 'GrowableArray<PreviousVersionNode *>*', 'previous_versions'],
    ['I', 'Q', 'JvmtiCachedClassFileData*', 'cached_class_file'],
    ['H', 'H', 'u2', 'idnum_allocated_count'],
    ['B', 'B', 'u1', 'init_state'],
    ['B', 'B', 'u1', 'reference_type'],
    ['I', 'Q', 'JvmtiCachedClassFieldMap*', 'jvmti_cached_class_field_map'],
    ['I', 'Q', 'Array<Method*>*', 'methods'],
    ['I', 'Q', 'Array<Method*>*', 'default_methods'],
    ['I', 'Q', 'Array<Klass*>*', 'local_interfaces'],
    ['I', 'Q', 'Array<Klass*>*', 'transitive_interfaces'],
    ['I', 'Q', 'Array<int>*', 'method_ordering'],
    ['I', 'Q', 'Array<int>*', 'default_vtable_indices'],
    ['I', 'Q', 'Array<u2>*', 'fields'],
]

INSTANCE_KLASS_TYPE = KLASS_TYPE + INSTANCE_KLASS_TYPE_OVERLAY
INSTANCE_KLASS_TYPE_WIN = KLASS_TYPE_WIN + INSTANCE_KLASS_TYPE_OVERLAY

INSTANCE_MIRROR_KLASS_TYPE = INSTANCE_KLASS_TYPE
INSTANCE_MIRROR_KLASS_TYPE_WIN = INSTANCE_KLASS_TYPE_WIN

INSTANCE_CLASSLOADER_KLASS_TYPE = INSTANCE_KLASS_TYPE
INSTANCE_CLASSLOADER_KLASS_TYPE_WIN = INSTANCE_KLASS_TYPE_WIN

INSTANCE_REF_KLASS_TYPE = INSTANCE_KLASS_TYPE
INSTANCE_REF_KLASS_TYPE_WIN = INSTANCE_KLASS_TYPE_WIN

ARRAY_KLASS_TYPE_OVERLAY = [
    ['I', 'I', 'int', 'dimension'],
    ['I', 'Q', 'Klass*', 'higher_dimension'],
    ['I', 'Q', 'Klass*', 'lower_dimension'],
    ['I', 'I', 'int', 'vtable_len'],
    ['I', 'Q', 'oop', 'component_mirror'],
]

OBJ_ARRAY_KLASS_TYPE_OVERLAY = [
    ['I', 'Q', 'Klass*', 'element_klass'],
    ['I', 'Q', 'Klass*', 'bottom_klass'],
]

TYPE_ARRAY_KLASS_TYPE_OVERLAY = [
    ['I', 'I', 'jint', 'max_length'],
]

ARRAY_KLASS_TYPE = KLASS_TYPE + ARRAY_KLASS_TYPE_OVERLAY
ARRAY_KLASS_TYPE_WIN = KLASS_TYPE_WIN + ARRAY_KLASS_TYPE_OVERLAY

OBJ_ARRAY_KLASS_TYPE = ARRAY_KLASS_TYPE + OBJ_ARRAY_KLASS_TYPE_OVERLAY
OBJ_ARRAY_KLASS_TYPE_WIN = ARRAY_KLASS_TYPE_WIN + OBJ_ARRAY_KLASS_TYPE_OVERLAY

TYPE_ARRAY_KLASS_TYPE = ARRAY_KLASS_TYPE + TYPE_ARRAY_KLASS_TYPE_OVERLAY
TYPE_ARRAY_KLASS_TYPE_WIN = ARRAY_KLASS_TYPE_WIN + TYPE_ARRAY_KLASS_TYPE_OVERLAY

SYMBOL_TABLE_TYPE = [
    ['I', 'I', 'int', 'table_size'],
    ['I', 'Q', 'SymbolTableBucket*', 'buckets'],
    ['I', 'Q', 'SymbolTableEntry*', 'free_list'],
    ['I', 'Q', 'char*', 'first_free_entry'],
    ['I', 'Q', 'char*', 'end_block'],
    ['I', 'I', 'int', 'entry_size'],
    ['I', 'I', 'int', 'number_of_entries'],
]

SYMBOL_TABLE_BUCKET_TYPE = [
    ['I', 'Q', 'SymbolTableEntry*', 'entry'],
]

SYMBOL_TABLE_ENTRY_TYPE = [
    ['I', 'I', 'int', 'hash'],
    ['I', 'Q', 'SymbolTableEntry*', 'next'],
    ['I', 'Q', 'Symbol*', 'literal'],
]

STRING_TABLE_TYPE = [
    ['I', 'I', 'int', 'table_size'],
    ['I', 'Q', 'StringTableBucket*', 'buckets'],
    ['I', 'Q', 'StringTableEntry*', 'free_list'],
    ['I', 'Q', 'char*', 'first_free_entry'],
    ['I', 'Q', 'char*', 'end_block'],
    ['I', 'I', 'int', 'entry_size'],
    ['I', 'I', 'int', 'number_of_entries'],
]

STRING_TABLE_BUCKET_TYPE = [
    ['I', 'Q', 'StringTableEntry*', 'entry'],
]

STRING_TABLE_ENTRY_TYPE = [
    ['I', 'I', 'int', 'hash'],
    ['I', 'Q', 'StringTableEntry*', 'next'],
    ['I', 'Q', 'oop', 'literal'],
]

STRING_TYPE = [
    ['H', 'H', 'short', 'length'],
    ['H', 'H', 'short', 'ref_count'],
    ['I', 'I', 'int', 'identity_hash'],
    ['B', 'B', 'char[]', 'jbyte'],
]

SYMBOL_TYPE = [
    ['H', 'H', 'short', 'length'],
    ['H', 'H', 'short', 'ref_count'],
    ['I', 'I', 'int', 'identity_hash'],
    ['B', 'B', 'char[]', 'jbyte'],
]

VMSTRUCT_ENTRY_TYPE = [
    ['I', 'Q', 'char*', 'typeName_addr'],
    ['I', 'Q', 'char*', 'fieldName_addr'],
    ['I', 'Q', 'char*', 'typeString_addr'],
    ['I', 'I', 'uint32_t', 'isStatic'],
    ['Q', 'Q', 'uint64_t', 'offset'],
    ['I', 'Q', 'void*', 'address'],
]

DICTIONARY_TYPE = [
    ['I', 'I', 'int', 'table_size'],
    ['I', 'Q', 'DictionaryBucket*', 'buckets'],
    ['I', 'Q', 'DictionaryEntry*', 'free_list'],
    ['I', 'Q', 'char*', 'first_free_entry'],
    ['I', 'Q', 'char*', 'end_block'],
    ['I', 'I', 'int', 'entry_size'],
    ['I', 'I', 'int', 'number_of_entries'],
    ['I', 'Q', 'ProtectionDomainCacheTable*', 'pd_cache_table'],
]

DICTIONARY_BUCKET_TYPE = [
    ['I', 'Q', 'DictionaryBucket*', 'entry'],
]

DICTIONARY_ENTRY_TYPE = [
    ['I', 'I', 'int', 'hash'],
    ['I', 'Q', 'DictionaryEntry*', 'next'],
    ['I', 'Q', 'Klass*', 'literal'],
]

ARRAY_T_TYPE = [
    ['I', 'I', 'int', 'length'],
    ['I', 'Q', 'T', 'data'],
]

MEMREGION_TYPE = [
    ['I', 'Q', 'HeapWord*', 'start'],
    ['I', 'Q', 'size_t', 'word_size'],
]

COLLECTED_HEAP_TYPE = [
    ['I', 'Q', 'void*', 'vtable'],
    ['I', 'Q', 'GCHeapLog*', 'gc_heap_log'],
    ['I', 'Q', 'void*', 'UNKNOWN_hidden_field'],
    MEMREGION_TYPE[0],
    MEMREGION_TYPE[1],
    ['I', 'Q', 'BarrierSet*', 'barrier_set'],
    ['B', 'B', 'bool', 'is_gc_active'],
    ['3B', '3B', 'ALIGN', 'alignment_gc_active'],
    ['I', 'I', 'int', 'n_par_threads'],
    ['I', 'I', 'int', 'total_collections'],
    ['I', 'I', 'int', 'total_full_collections'],
    ['I', 'I', 'GCCause::Cause', 'gc_causes'],
    ['I', 'I', 'GCCause::Cause', 'gc_lastcause'],
    ['I', 'I', 'PerfStringVariable*', 'perf_gc_cause'],
    ['I', 'I', 'PerfStringVariable*', 'perf_gc_cause'],
]

SHARED_HEAP_TYPE = COLLECTED_HEAP_TYPE + [
    ['I', 'Q', 'SubTaskDone*', 'process_strong_tasks'],
    ['I', 'Q', 'GenRemSet*', 'rem_set'],
    ['I', 'Q', 'CollectorPolicy*', 'collector_policy'],
    ['I', 'Q', 'int', 'strong_roots_parity'],
    ['I', 'Q', 'FlexibleWorkGang*', 'workers'],
    ['B', 'B', 'bool', 'thread_holds_heap_lock_for_gc'],
    ['3B', '3B', 'ALIGN', 'alignment_gc_active'],
]

GEN_COLLECTED_HEAP_TYPE = SHARED_HEAP_TYPE + [
    # ['I', 'Q', 'void*', 'vtable_gen_collected_heap'],
    ['I', 'I', 'int', 'n_gens'],
    ['10I', '10Q', 'Generation*', 'gens'],
    ['I', 'Q', 'GenerationSpec**', 'gen_specs'],
    ['I', 'Q', 'GenerationPolicy*', 'gen_policy'],
    ['B', 'B', 'bool', 'thread_holds_heap_lock_for_gc'],
    ['3B', '3B', 'ALIGN', 'incremental_collection_failed'],
    ['I', 'I', 'int', 'full_collections_completed'],
    ['I', 'Q', 'SubTaskDone*', 'gen_process_strong_tasks'],
]

VIRTUAL_SPACE_TYPE = [
    ['I', 'Q', 'char*', 'low_boundary'],
    ['I', 'Q', 'char*', 'high_boundary'],
    ['I', 'Q', 'char*', 'low'],
    ['I', 'Q', 'char*', 'high'],
    ['B', 'B', 'bool', 'special'],
    ['B', 'B', 'bool'  , 'executable'],
    ['B', '2B', 'ALIGN', 'BOOL_ALIGNMENT'],
    ['I', 'Q', 'char*', 'lower_high'],
    ['I', 'Q', 'char*', 'middle_high'],
    ['I', 'Q', 'char*', 'upper_high'],
    ['I', 'Q', 'char*', 'lower_high_boundary'],
    ['I', 'Q', 'char*', 'middle_high_boundary'],
    ['I', 'Q', 'char*', 'upper_high_boundary'],
    ['I', 'Q', 'size_t', 'lower_alignment'],
    ['I', 'Q', 'size_t', 'middle_alignment'],
    ['I', 'Q', 'size_t', 'upper_alignment'],
]


RESERVED_SPACE_TYPE = [
    ['I', 'Q', 'char*', 'base'],
    ['I', 'Q', 'size_t', 'size'],
    ['I', 'Q', 'size_t', 'noaccess_prefix'],
    ['I', 'Q', 'size_t', 'alignment'],
    ['B', 'B', 'bool', 'special'],
    ['B', 'B', 'bool'  , 'executable'],
]
VIRTUAL_SPACE_NODE_TYPE = [
    ['I', 'Q', 'VirtualSpaceNode*', 'next'],
    #MEMREGION_TYPE + \
    ['I', 'Q', 'HeapWord*', 'reserved_start'],
    ['I', 'Q', 'size_t', 'reserved_word_size'],
    # End mem region type
    #RESERVED_SPACE_TYPE + \
    ['I', 'Q', 'char*', 'rs_base'],
    ['I', 'Q', 'size_t', 'rs_size'],
    ['I', 'Q', 'size_t', 'rs_noaccess_prefix'],
    ['I', 'Q', 'size_t', 'rs_alignment'],
    ['B', 'B', 'bool', 'rs_special'],
    ['B', 'B', 'bool'  , 'rs_executable'],
    # End reserved space type
    #VIRTUAL_SPACE_TYPE + \
    ['I', 'Q', 'char*', 'virtual_space_low_boundary'],
    ['I', 'Q', 'char*', 'virtual_space_high_boundary'],
    ['I', 'Q', 'char*', 'virtual_space_low'],
    ['I', 'Q', 'char*', 'virtual_space_high'],
    ['B', 'B', 'bool', 'virtual_space_special'],
    ['B', 'B', 'bool'  , 'virtual_space_executable'],
    ['B', '2B', 'ALIGN', 'virtual_space_BOOL_ALIGNMENT'],
    ['I', 'Q', 'char*', 'virtual_space_lower_high'],
    ['I', 'Q', 'char*', 'virtual_space_middle_high'],
    ['I', 'Q', 'char*', 'virtual_space_upper_high'],
    ['I', 'Q', 'char*', 'virtual_space_lower_high_boundary'],
    ['I', 'Q', 'char*', 'virtual_space_middle_high_boundary'],
    ['I', 'Q', 'char*', 'virtual_space_upper_high_boundary'],
    ['I', 'Q', 'size_t', 'virtual_space_lower_alignment'],
    ['I', 'Q', 'size_t', 'virtual_space_middle_alignment'],
    ['I', 'Q', 'size_t', 'virtual_space_upper_alignment'],
    # End virtual space type
    ['I', 'Q', 'MetaWord*', 'top'],
]


VIRTUAL_SPACE_LIST_TYPE = [
    ['I', 'Q', 'VirtualSpaceNode*', 'virtual_space_list'],
    ['I', 'Q', 'VirtualSpaceNode*', 'current_virtual_space'],
    ['B', 'B', 'bool', 'is_class'],
    ['3B', '3B', 'PADDING', 'padding'],
    ['I', 'Q', 'size_t', 'reserved_words'],
    ['I', 'Q', 'size_t', 'committed_words'],
    ['I', 'Q', 'size_t', 'virtual_space_count'],
]


SPLIT_WORD_TYPE = [
    ['I', 'Q', 'intptr_t', 'FullWord'],
    ['I', 'Q', 'void*', 'Address'],
    ['I', 'Q', 'jbyte', 'Bytes'],
]

MONITOR_TYPE = SPLIT_WORD_TYPE + [
    ['I', 'Q', 'Thread*', 'owner'],
    ['I', 'Q', 'ParkEvent*', 'EntryList'],
    ['I', 'Q', 'intptr_t', 'WaitLock'],
    ['I', 'Q', 'ParkEvent*', 'WaitSet'],
    ['I', 'Q', 'ParkEvent*', 'OnDeck'],
    ['B', 'B', 'bool', 'snuck'],
    ['3B', '3B', 'PADDING', 'padding'],
    ['I', 'I', 'int', 'NotifyCount'],
    ['I', 'I', 'int', 'NotifyCount'],
    ['B', 'B', 'bool', 'allow_vm_block'],
    ['3B', '3B', 'bool', 'allow_vm_block'],
]

FORMAT_BUFFER_TYPE = [
    ['I', 'Q', 'char*', 'buf'],
    ['I', 'Q', 'char*', 'bufsz'],
]

EVENT_LOG_TYPE = [
    ['I', 'Q', 'void*', 'vtable'],
    ['I', 'Q', 'EventLog*', 'next'],
]
#MONITOR_TYPE +\
EVENT_LOG_BASE_TYPE = EVENT_LOG_TYPE + [
    # ['d', 'd', 'double', 'timestamp'],
    # ['I', 'Q', 'Thread*', 'thread'],
    ['I', 'Q', 'char*', 'name'],
    ['I', 'I', 'int', 'length'],
    ['I', 'I', 'int', 'count'],
    ['I', 'Q', 'Event<T>*', 'records'],

]

GC_HEAP_LOG_TYPE  = EVENT_LOG_BASE_TYPE




GENERATION_TYPE = [
    # ['I', 'Q', 'void*', 'vtable_gen_collected_heap'],
    ['Q', 'Q', 'jlong', 'time_of_last_gc'],
    ['I', 'Q', 'HeapWord*', 'prev_used_region.start'],
    ['I', 'Q', 'size_t', 'prev_used_region.word_size'],
    ['I', 'Q', 'HeapWord*', 'reserved.start'],
    ['I', 'Q', 'size_t', 'reserved.word_size'],
] + VIRTUAL_SPACE_TYPE + \
[
    ['I', 'I', 'int', 'level'],
    ['I', 'Q', 'ReferenceProcessor', 'ref_processor'],
    ['I', 'Q', 'CollectorCounters', 'gc_counters'],
    ['I', 'Q', 'GCStats', 'gc_stats'],
]

CLASS_LOADER_DATA_TYPE = [
    ['I', 'Q', 'oop',  'class_loader'],
    ['I', 'Q', 'Dependencies',  'dependencies'],
    ['I', 'Q', 'Metaspace*',  'metaspace'],
    ['I', 'Q', 'Mutex*',  'metaspace_lock'],
    ['B', 'B', 'bool',  'unloading'],
    ['B', 'B', 'bool',  'keep_alive'],
    ['B', 'B', 'bool',  'is_anonymous'],
    ['B', 'B', 'PADDING',  'alignment'],
    ['I', 'Q', 'volatile int',  'claimed'],
    ['I', 'Q', 'Klass*',  'klasses'],
    ['I', 'Q', 'JNIHandleBlock*',  'handles'],
    ['I', 'Q', 'JNIMethodBlock*',  'jmethod_ids'],
    ['I', 'Q', 'GrowableArray<Metadata*>*',  'deallocate_list'],
    ['I', 'Q', 'ClassLoaderData*',  'next'],
]

METACHUNK_TYPE = [
    ['I', 'Q', 'size_t', 'word_size'],
    ['I', 'Q', 'Metachunk*', 'next'],
    ['I', 'Q', 'Metachunk*', 'prev'],
    ['I', 'Q', 'VirtualSpaceNode*', 'container'],
    ['I', 'Q', 'MetaWord*', 'top'],
]

METASPACE_TYPE = [
    ['I', 'Q', 'SpaceManager*', 'vsm'],
    ['I', 'Q', 'SpaceManager*', 'class_vsm'],
    ['I', 'Q', 'AllocRecord*', 'alloc_record_head'],
    ['I', 'Q', 'AllocRecord*', 'alloc_record_tail'],
]

ALLOC_RECORD_TYPE = [
    ['I', 'Q', 'AllocRecord*', 'next'],
    ['I', 'Q', 'address', 'ptr'],
    ['I', 'Q', 'MetaspaceObj::Type', 'type'],
    ['I', 'Q', 'int', 'byte_size'],
]

SPACE_MANAGER_TYPE = [
    ['I', 'Q', 'Mutex* const', 'lock'],
    ['I', 'Q', 'Metaspace::MetadataType', 'mdtype'],
    ['4I', '4Q', 'Metachunk*[NumberOfInUseLists]', 'chunks_in_use'],
    ['I', 'Q', 'Metachunk*', 'current_chunk'],
    ['I', 'Q', 'size_t', 'allocated_blocks_words'],
    ['I', 'Q', 'size_t', 'allocated_chunks_words'],
    ['I', 'Q', 'size_t', 'allocated_chunks_count'],
    ['I', 'Q', 'BlockFreelist', 'block_freelists'],
]

THREAD_SHADOW_TYPE = [
    ['I', 'Q', 'void*', 'vtable'],
    ['I', 'Q', 'oop', 'pending_exception'],
    ['I', 'Q', 'const char *', 'exception_file'],
    ['I', 'I', 'int', 'exception_line'],
]

FRAME_TYPE = [
    ['I', 'Q', 'intptr_t*', 'sp'],
    ['I', 'Q', 'address', 'pc'],
    ['I', 'Q', 'CodeBlob*', 'cb'],
    ['I', 'I', 'deopt_state', 'deopt_state'],
]

#TODO figure out the appropriate size of the register map
REGISTER_MAP_TYPE = [
    ['I', 'Q', 'intptr_t*', 'location'], #[reg_count]
    ['I', 'Q', 'LocationValidType', 'location_valid'], # [location_valid_size]
    ['B', 'B', 'bool', 'include_argument_oops'],
    ['3B', '3B', 'PADDING', 'padding'],
    ['I', 'Q', 'JavaThread*', 'thread'],
    ['B', 'B', 'bool', 'update_map'],
    ['3B', '3B', 'PADDING', 'padding1'],
]

VFRAME32_TYPE = [
    ['I', 'Q', 'intptr_t*', 'fr.sp'],
    ['I', 'Q', 'address', 'fr.pc'],
    ['I', 'Q', 'CodeBlob*', 'fr.cb'],
    ['I', 'I', 'deopt_state', 'fr.deopt_state'],
]

JAVA_FRAME_ANCHOR_TYPE = [
    ['I', 'Q', 'intptr_t* volatile', 'last_sp'],
    ['I', 'Q', 'volatile  address', 'last_pc'],
    ['I', 'Q', 'volatile intptr_t*', 'last_Java_fp'],
]

SYSTEM_PROPERTY_TYPE = [
    ['I', 'Q', 'char*', 'key'],
    ['I', 'Q', 'char*', 'value'],
    ['I', 'Q', 'SystemProperty*', 'next'],
    ['B', 'B', 'bool', 'writeable'],
]

COMPILED_RFRAME_TYPE = [
    ['I', 'Q', 'void *', 'vtable'],
    ['I', 'Q', 'const frame', 'fr'],
    ['I', 'Q', 'const JavaThread*', 'thread'],
    ['I', 'Q', 'RFrame*', 'caller'],
    ['I', 'Q', 'RFrame*const', 'callee'],
    ['I', 'I', 'const int', 'num'],
    ['I', 'I', 'int', 'invocations'],
    ['I', 'I', 'int', 'distance'],
    ['I', 'Q', 'nmethod*', 'nm'],
    ['I', 'Q', 'javaVFrame*', 'vf'],
    ['I', 'Q', 'methodHandle', 'method'],
]

INTERPRETTED_RFRAME_TYPE = [
    ['I', 'Q', 'void *', 'vtable'],
    ['I', 'Q', 'const JavaThread*', 'thread'],
    ['I', 'Q', 'RFrame*', 'caller'],
    ['I', 'Q', 'RFrame*const', 'callee'],
    ['I', 'I', 'const int', 'num'],
    ['I', 'I', 'int', 'invocations'],
    ['I', 'I', 'int', 'distance'],
    ['I', 'Q', 'javaVFrame*', 'vf'],
    ['I', 'Q', 'methodHandle', 'method'],
]

JNI_HANDLE_BLOCK_TYPE = [
    ['12I', '12Q', 'oop*', 'handles'],
    ['I', 'I', 'int', 'top'],
    ['I', 'Q', 'JNIHandleBlock*', 'next'],
    ['I', 'Q', 'JNIHandleBlock*', 'last'],
    ['I', 'Q', 'JNIHandleBlock*', 'pop_frame_link'],
    ['I', 'Q', 'oop*', 'free_list'],
    ['I', 'I', 'int', 'allocate_before_rebuild'],
]
# TODO figure out how to fill in the frame anchor
JAVA_CALL_WRAPPER_TYPE = [
    ['I', 'Q', 'JavaThread*', 'thread'],
    ['I', 'Q', 'JNIHandleBlock*', 'handles'],
    ['I', 'Q', 'Method*', 'callee_method'],
    ['I', 'Q', 'oop', 'receiver'],
    ['I', 'Q', 'JavaFrameAnchor', 'anchor'],
    ['I', 'Q', 'JavaValue*', 'result'],
]

# TODO figure out how to fill in the frame anchor
JAVA_CALL_ARGUMENTS_TYPE = [
    ['9I', '9Q', 'intptr_t*', 'value_buffer'],
    ['9B', '9B', 'bool', 'is_oop_buffer'],
    ['I', 'Q', 'intptr_t*', 'value'],
    ['I', 'Q', 'bool*', 'is_oop'],
    ['I', 'I', 'int', 'size'],
    ['I', 'I', 'int', 'max_size'],
    ['B', 'B', 'bool', 'start_at_zero'],
]

HANDLE_TYPE = [
    ['I', 'Q', 'oop*', 'handle'],
]

KLASS_HANDLE_TYPE = [
    ['I', 'Q', 'Klass*', 'value'],
]

INSTANCE_KLASS_HANDLE_TYPE = [
    ['I', 'Q', 'Klass*', 'value'],
]

CONSTANT_POOL_HANDLE_TYPE = [
    ['I', 'Q', 'Klass*', 'value'],
]

METHOD_HANDLE_TYPE = [
    ['I', 'Q', 'Klass*', 'value'],
]

CALL_INFO_TYPE = [
    ['I', 'Q', 'KlassHandle', 'resolved_klass'],
    ['I', 'Q', 'KlassHandle', 'selected_klass'],
    ['I', 'Q', 'methodHandle', 'resolved_method'],
    ['I', 'Q', 'methodHandle', 'selected_method'],
    ['I', 'I', 'CallKind', 'call_kind'],
    ['I', 'Q', 'Handle', 'resolved_appendix'],
    ['I', 'Q', 'Handle', 'resolved_method_type'],
]

INTERPRETER_CODELET_TYPE = [
    ['I', 'I', 'int', 'size'],
    ['I', 'Q', 'char*', 'description'],
    ['I', 'I', 'ByteCodes::Code', 'code'], # enum of the bytecode
]

BYTECODE_CODE_TYPE = [
    ['I', 'Q', 'address', 'bcp'], # enum of the bytecode
    ['I', 'I', 'ByteCodes::Code', 'code'], # enum of the bytecode
]

JAVA_FRAME_ANCHOR_X86 = [
    ['I', 'Q', 'intptr_t*', '_last_Java_sp'],
    ['I', 'Q', 'address', '_last_Java_pc'],
    ['I', 'Q', 'intptr_t*', '_last_Java_fp'],
]

JAVA_FRAME_ANCHOR = JAVA_FRAME_ANCHOR_X86

JAVA_THREAD_PARTIAL = [
    ['I', 'Q', 'JavaThread*', '_next'],
    ['I', 'Q', 'oop', '_threadObj'],
] + JAVA_FRAME_ANCHOR + \
[
['I', 'Q', 'ThreadFunction', '_entry_point'],
['I', 'Q', 'JNIEnv', '_jni_environment'],
['I', 'Q', 'DeoptResourceMark*', '_deopt_mark'],
['I', 'Q', 'intptr_t*', '_must_deopt_id'],
['I', 'Q', 'nmethod*', '_deopt_nmethod'],
['I', 'Q', 'vframeArray*', '_vframe_array_head'],
['I', 'Q', 'vframeArray*', '_vframe_array_last'],
['I', 'Q', 'GrowableArray<jvmtiDeferredLocalVariableSet*>*', '_deferred_locals_updates'],
['I', 'Q', 'Method*', '_callee_target'],
['I', 'Q', 'oop', '_vm_result'],
['I', 'Q', 'Metadata*', '_vm_result_2'],
]

JAVA_CALL_WRAPPER = [
    ['I', 'Q', 'JavaThread*', '_thread'],
    ['I', 'Q', 'JNIHandleBlock', '_handles'],
    ['I', 'Q', 'Method*', '_callee_method'],
    ['I', 'Q', 'oop', '_reciever'],
    ['I', 'Q', 'intptr_t*', '_last_Java_sp'],
    ['I', 'Q', 'address', '_last_Java_pc'],
    ['I', 'Q', 'intptr_t*', '_last_Java_fp'],
    ['I', 'Q', 'JavaValue*', '_result'],

]

JAVA_CALL_VALUE = [
    ['I', 'Q', 'BasicType', '_type'],
    ['I', 'Q', 'JavaCallValue', '_value'],
]

CODE_BLOB = [
    ['I', 'Q', 'char*', '_name'],
    ['I', 'I', 'int', '_size'],
    ['I', 'I', 'int', '_header_size'],
    ['I', 'I', 'int', '_relocation_size'],
    ['I', 'I', 'int', '_content_offset'],
    ['I', 'I', 'int', '_code_offset'],
    ['I', 'I', 'int', '_frame_complete_offset'],
    ['I', 'I', 'int', '_data_offset'],
    ['I', 'I', 'int', '_frame_size'],
    ['I', 'I', 'int', '_content_offset'],
    ['I', 'Q', 'OopMapSet*', '_oop_maps'],
    ['I', 'Q', 'CodeStrings', '_strings'],
]

OOP_MAP_VALUE = [
    ['H', 'H', 'short', '_value'],
    ['H', 'H', 'short', '_content_reg'],
]

OOP_MAP = [
    ['I', 'I', 'int', '_pc_offset'],
    ['I', 'I', 'int', '_omv_count'],
    ['I', 'Q', 'int', '_omv_data_size'],
#    ['I', 'I', 'padding', 'padding'],
    ['I', 'Q', 'unsigned char*', '_name'],
    ['I', 'Q', 'CompressedWriteStream*', '_writer_stream'],
]

OOP_MAP_SET = [
    ['I', 'I', 'int', '_om_count'],
    ['I', 'I', 'int', '_om_size'],
    ['I', 'Q', 'OopMap**', '_om_data'],
]

FRAME = [
    ['I', 'Q', 'intptr_t*', '_sp'],
    ['I', 'Q', 'intptr_t*', '_pc'],
    ['I', 'Q', 'CodeBlob*', '_cb'],
    ['I', 'I', 'deopt_state', '_deopt_state'],
    ['I', 'Q', 'intptr_t*', '_fp'],
    ['I', 'Q', 'intptr_t*', '_unextended_sp'],
]

FRAME_VALUE = [
    ['I', 'Q', 'intptr_t*', '_location'],
    ['B', 'B', 'char', 'description'],
    ['I', 'I', 'int', 'owner'],
    ['I', 'I', 'int', 'priority'],
]


FRAME_VALUES = [
    ['I', 'Q', 'GrowableArray<FrameValues>', '_values'],
]

VFRAME_ARRAY_ELEMENT = [
    ['I', 'Q', 'frame', '_frame'],
    ['I', 'Q', 'int',  '_bci'],
    ['I', 'Q', 'bool', '_reexecute'],
    ['I', 'Q', 'Method*',     '_method'],
    ['I', 'Q', 'MonitorChunk*',  '_monitors'],
    ['I', 'Q', 'StackValueCollection*',  '_locals'],
    ['I', 'Q', 'StackValueCollection*',  '_expressions'],
]

VFRAME_ARRAY = [
    ['I', 'Q', 'JavaThread*', '_owner_thread'],
    ['I', 'Q', 'vframeArray*', '_next'],
    ['I', 'Q', 'frame', '_original'],
    ['I', 'Q', 'frame', '_caller'],
    ['I', 'Q', 'frame', '_sender'],
    ['I', 'Q', 'Deoptimization::UnrollBlock*', '_unroll_block'],
    ['I', 'Q', 'int', '_frame_size'],
    ['I', 'Q', 'int', '_frames'],
    ['8I', '16Q', 'intptr_t', '_callee_registers'],
    ['8B', '16B', 'unsigned char', '_valid'],
#    ['I', 'Q', 'vframeArrayElement', '_elements'],
]
