PUBLIC= 'public'
PRIVATE = 'private'
PROTECTED = 'protected'
STATIC = 'static'
FINAL = 'final'
SUPER = 'super'
BRIDGE = 'bridge'
VARARGS = 'varargs'
NATIVE = 'native'
INTERFACE = 'interface'
ABSTRACT = 'abstract'
STRICT= 'strict'
SYNTHETIC = 'synthetic'
ANNOTATION = 'annotation'
ENUM = 'enum'
VOLATILE = 'volatile'
TRANSIENT = 'transient'
GENERIC = 'generic'
SYNCHRONIZED = 'synchronized'
CLASS_ACC_PUBLIC= 0x0001
CLASS_ACC_PRIVATE = 0x0002
CLASS_ACC_PROTECTED = 0x0004
CLASS_ACC_STATIC = 0x0008
CLASS_ACC_FINAL = 0x0010
CLASS_ACC_SUPER = 0x0020
CLASS_ACC_BRIDGE = 0x0040
CLASS_ACC_VARARGS = 0x0080
CLASS_ACC_NATIVE = 0x0100
CLASS_ACC_INTERFACE = 0x0200
CLASS_ACC_ABSTRACT = 0x0400
CLASS_ACC_STRICT= 0x0800
CLASS_ACC_SYNTHETIC = 0x1000
CLASS_ACC_ANNOTATION = 0x2000
CLASS_ACC_ENUM = 0x4000
FIELD_ACC_PUBLIC= 0x0001
FIELD_ACC_PRIVATE = 0x0002
FIELD_ACC_PROTECTED = 0x0004
FIELD_ACC_STATIC = 0x0008
FIELD_ACC_FINAL = 0x0010
FIELD_ACC_VOLATILE = 0x0040
FIELD_ACC_TRANSIENT = 0x0080
FIELD_ACC_SYNTHETIC = 0x1000
FIELD_ACC_ENUM = 0x4000
FIELD_ACC_GENERIC = 0x0800
METHOD_ACC_PUBLIC= 0x0001
METHOD_ACC_PRIVATE = 0x0002
METHOD_ACC_PROTECTED = 0x0004
METHOD_ACC_STATIC = 0x0008
METHOD_ACC_FINAL = 0x0010
METHOD_ACC_SYNCHRONIZED = 0x0020
METHOD_ACC_BRIDGE = 0x0040
METHOD_ACC_VARARGS = 0x0080
METHOD_ACC_NATIVE = 0x0100
METHOD_ACC_INTERFACE = 0x0200
METHOD_ACC_ABSTRACT = 0x0400
METHOD_ACC_STRICT= 0x0800
METHOD_ACC_SYNTHETIC = 0x1000
METHOD_ACC_ANNOTATION = 0x2000
METHOD_ACC_ENUM = 0x4000


TOP_OF_STACK_BTOS =  0
TOP_OF_STACK_CTOS =  1
TOP_OF_STACK_STOS =  2
TOP_OF_STACK_ITOS =  3
TOP_OF_STACK_LTOS =  4
TOP_OF_STACK_FTOS =  5
TOP_OF_STACK_DTOS =  6
TOP_OF_STACK_ATOS =  7
TOP_OF_STACK_VTOS =  8

CP_FLAGS_METHOD_TYPE = 0x1 << 5
CP_FLAGS_APPENDIX_ARG  = 0x1 << 4
CP_FLAGS_INTRFACE_VCALL = 0x1 << 3
CP_FLAGS_FINAL = 0x1 << 2
CP_FLAGS_VOLATILE = 0x1 << 1
CP_FLAGS_VIRTUAL_FINAL = 0x1 << 0

CP_FLAGS_MAPPING = {
    CP_FLAGS_METHOD_TYPE:"has_method_type",
    CP_FLAGS_APPENDIX_ARG:"has_appendix_argument",
    CP_FLAGS_INTRFACE_VCALL:"is_interface_vcall",
    CP_FLAGS_FINAL:"final",
    CP_FLAGS_VOLATILE:"volatile",
    CP_FLAGS_VIRTUAL_FINAL:"is_vfinal",
}

TOS_MAPPING = {
    TOP_OF_STACK_BTOS:"btos",
    TOP_OF_STACK_CTOS:"ctos",
    TOP_OF_STACK_STOS:"stos",
    TOP_OF_STACK_ITOS:"itos",
    TOP_OF_STACK_LTOS:"ltos",
    TOP_OF_STACK_FTOS:"ftos",
    TOP_OF_STACK_DTOS:"dtos",
    TOP_OF_STACK_ATOS:"atos",
    TOP_OF_STACK_VTOS:"vtos",
}
METHOD_MAPPING = {
    METHOD_ACC_PUBLIC:PUBLIC,
    METHOD_ACC_PRIVATE:PRIVATE,
    METHOD_ACC_PROTECTED:PROTECTED,
    METHOD_ACC_STATIC:STATIC,
    METHOD_ACC_FINAL:FINAL,
    METHOD_ACC_SYNCHRONIZED:SYNCHRONIZED,
    METHOD_ACC_BRIDGE:BRIDGE,
    METHOD_ACC_VARARGS:VARARGS,
    METHOD_ACC_NATIVE:NATIVE,
    METHOD_ACC_INTERFACE:INTERFACE,
    METHOD_ACC_ABSTRACT:ABSTRACT,
    METHOD_ACC_STRICT:STRICT,
    METHOD_ACC_SYNTHETIC:SYNTHETIC,
    METHOD_ACC_ANNOTATION:ANNOTATION,
    METHOD_ACC_ENUM:ENUM,
}

FIELD_MAPPING = {
    FIELD_ACC_PUBLIC:PUBLIC,
    FIELD_ACC_PRIVATE:PRIVATE,
    FIELD_ACC_PROTECTED:PROTECTED,
    FIELD_ACC_STATIC:STATIC,
    FIELD_ACC_FINAL:FINAL,
    FIELD_ACC_VOLATILE:VOLATILE,
    FIELD_ACC_TRANSIENT:TRANSIENT,
    FIELD_ACC_SYNTHETIC:SYNTHETIC,
    FIELD_ACC_ENUM:ENUM,
    FIELD_ACC_GENERIC:GENERIC,
}
CLASS_MAPPING = {
    CLASS_ACC_PUBLIC:PUBLIC,
    CLASS_ACC_PRIVATE:PRIVATE,
    CLASS_ACC_PROTECTED:PROTECTED,
    CLASS_ACC_STATIC:STATIC,
    CLASS_ACC_FINAL:FINAL,
    CLASS_ACC_SUPER:SUPER,
    CLASS_ACC_BRIDGE:BRIDGE,
    CLASS_ACC_VARARGS:VARARGS,
    CLASS_ACC_NATIVE:NATIVE,
    CLASS_ACC_INTERFACE:INTERFACE,
    CLASS_ACC_ABSTRACT:ABSTRACT,
    CLASS_ACC_STRICT:STRICT,
    CLASS_ACC_SYNTHETIC:SYNTHETIC,
    CLASS_ACC_ANNOTATION:ANNOTATION,
    CLASS_ACC_ENUM:ENUM,
}

class CPCacheEntryFlags(object):
    @classmethod
    def get_flag_information(cls, val, fvals={}):
        fvals = cls.get_cp_flag_info(val, fvals=fvals)
        fvals['entry_type'] = 'field' if cls.is_field_entry(val) else\
                              'method'
        fvals = cls.get_tos_flag_info(val, fvals)
        fvals['index'] = None
        fvals['psize'] = None
        if cls.is_field_entry(val):
             fvals['index'] = cls.get_field_index(val)
        else:
             fvals['psize'] = cls.get_psize(val)
        return fvals
        
    @classmethod
    def get_field_index(cls, val):
        return val & 0xFFFF            
        
    @classmethod
    def get_psize(cls, val):
        return val & 0xFF            
    
    @classmethod
    def is_field_entry(cls, val):
        v  = (val >> 26) & 0x01
        return v == 1
        
    @classmethod
    def is_method_entry(cls, val):
        return not cls.is_field_entry(val)

    @classmethod
    def get_cp_flag_info(cls, val, fvals = {}):
        v = (val >> 20) & 0x3f
        for t,s in CP_FLAGS_MAPPING.items():
            if t == (v&t):
               fvals[s] = 1
            else:
               fvals[s] = 0
        return fvals

    @classmethod
    def get_tos_flag_info(cls, val, fvals={}):
        tos = (val >> 28) & 0xf
        for t,s in TOS_MAPPING.items():
            if t == tos:
               fvals[s] = 1
            else:
               fvals[s] = 0
        return fvals

class AccessFlags(object):
    @classmethod
    def get_method_access_strings(cls, val):
        s = 0x1
        pos = 0
        flags = []
        while pos < 16:
            if (val&s) in METHOD_MAPPING:
                flags.append(METHOD_MAPPING[s])
            s = s << 1
            pos += 1
        return flags
    
    @classmethod
    def get_field_access_strings(cls, val):
        s = 0x1
        pos = 0
        flags = []
        while pos < 16:
            if (val&s) in FIELD_MAPPING:
                flags.append(FIELD_MAPPING[s])
            s = s << 1
            pos += 1
        return flags
    
    @classmethod
    def get_class_access_strings(cls, val):
        s = 0x1
        pos = 0
        flags = []
        while pos < 16:
            if (val&s) in CLASS_MAPPING:
                flags.append(CLASS_MAPPING[s])
            s = s << 1
            pos += 1
        return flags

    @classmethod
    def is_class_public(cls, val):
        return (val & CLASS_ACC_PUBLIC) != 0

    @classmethod
    def is_class_private(cls, val):
        return (val & CLASS_ACC_PRIVATE) != 0

    @classmethod
    def is_class_protected(cls, val):
        return (val & CLASS_ACC_PROTECTED) != 0

    @classmethod
    def is_class_static(cls, val):
        return (val & CLASS_ACC_STATIC) != 0

    @classmethod
    def is_class_final(cls, val):
        return (val & CLASS_ACC_FINAL) != 0

    @classmethod
    def is_class_super(cls, val):
        return (val & CLASS_ACC_SUPER) != 0

    @classmethod
    def is_class_bridge(cls, val):
        return (val & CLASS_ACC_BRIDGE) != 0

    @classmethod
    def is_class_varargs(cls, val):
        return (val & CLASS_ACC_VARARGS) != 0

    @classmethod
    def is_class_native(cls, val):
        return (val & CLASS_ACC_NATIVE) != 0

    @classmethod
    def is_class_interface(cls, val):
        return (val & CLASS_ACC_INTERFACE) != 0

    @classmethod
    def is_class_abstract(cls, val):
        return (val & CLASS_ACC_ABSTRACT) != 0

    @classmethod
    def is_class_strict(cls, val):
        return (val & CLASS_ACC_STRICT) != 0

    @classmethod
    def is_class_synthetic(cls, val):
        return (val & CLASS_ACC_SYNTHETIC) != 0

    @classmethod
    def is_class_annotation(cls, val):
        return (val & CLASS_ACC_ANNOTATION) != 0
        
    @classmethod
    def is_field_public(cls, val):
        return (val & FIELD_ACC_PUBLIC) != 0

    @classmethod
    def is_field_private(cls, val):
        return (val & FIELD_ACC_PRIVATE) != 0

    @classmethod
    def is_field_protected(cls, val):
        return (val & FIELD_ACC_PROTECTED) != 0

    @classmethod
    def is_field_static(cls, val):
        return (val & FIELD_ACC_STATIC) != 0

    @classmethod
    def is_field_final(cls, val):
        return (val & FIELD_ACC_FINAL) != 0

    @classmethod
    def is_field_volatile(cls, val):
        return (val & FIELD_ACC_VOLATILE) != 0

    @classmethod
    def is_field_transient(cls, val):
        return (val & FIELD_ACC_TRANSIENT) != 0

    @classmethod
    def is_field_synthetic(cls, val):
        return (val & FIELD_ACC_SYNTHETIC) != 0

    @classmethod
    def is_field_enum(cls, val):
        return (val & FIELD_ACC_ENUM) != 0

    @classmethod
    def is_field_generic(cls, val):
        return (val & FIELD_ACC_GENERIC) != 0

    @classmethod
    def is_method_public(cls, val):
        return (val & METHOD_ACC_PUBLIC) != 0

    @classmethod
    def is_method_private(cls, val):
        return (val & METHOD_ACC_PRIVATE) != 0

    @classmethod
    def is_method_protected(cls, val):
        return (val & METHOD_ACC_PROTECTED) != 0

    @classmethod
    def is_method_static(cls, val):
        return (val & METHOD_ACC_STATIC) != 0

    @classmethod
    def is_method_final(cls, val):
        return (val & METHOD_ACC_FINAL) != 0

    @classmethod
    def is_method_synchronized(cls, val):
        return (val & METHOD_ACC_SYNCHRONIZED) != 0

    @classmethod
    def is_method_bridge(cls, val):
        return (val & METHOD_ACC_BRIDGE) != 0

    @classmethod
    def is_method_varargs(cls, val):
        return (val & METHOD_ACC_VARARGS) != 0

    @classmethod
    def is_method_native(cls, val):
        return (val & METHOD_ACC_NATIVE) != 0

    @classmethod
    def is_method_interface(cls, val):
        return (val & METHOD_ACC_INTERFACE) != 0

    @classmethod
    def is_method_abstract(cls, val):
        return (val & METHOD_ACC_ABSTRACT) != 0

    @classmethod
    def is_method_strict(cls, val):
        return (val & METHOD_ACC_STRICT) != 0

    @classmethod
    def is_method_synthetic(cls, val):
        return (val & METHOD_ACC_SYNTHETIC) != 0

    @classmethod
    def is_method_annotation(cls, val):
        return (val & METHOD_ACC_ANNOTATION) != 0

    @classmethod
    def is_method_enum(cls, val):
        return (val & METHOD_ACC_ENUM) != 0
