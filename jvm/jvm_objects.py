import struct
import jvm_overlays
from jvm_overlays import VMSTRUCT_ENTRY_TYPE, GEN_COLLECTED_HEAP_TYPE,\
                        VIRTUAL_SPACE_TYPE, GENERATION_TYPE, GC_HEAP_LOG_TYPE,\
                        COLLECTED_HEAP_TYPE, VIRTUAL_SPACE_NODE_TYPE,\
                        THREAD_SHADOW_TYPE,\
                        CLASS_LOADER_DATA_TYPE, METASPACE_TYPE,\
                        SPACE_MANAGER_TYPE, ALLOC_RECORD_TYPE, METACHUNK_TYPE,\
                        JAVA_FRAME_ANCHOR, JAVA_CALL_VALUE, JAVA_CALL_WRAPPER,\
                        JAVA_THREAD_PARTIAL, CODE_BLOB, OOP_MAP_VALUE, OOP_MAP,\
                        OOP_MAP_SET, FRAME, FRAME_VALUE, FRAME_VALUES,\
                        VFRAME_ARRAY, VFRAME_ARRAY_ELEMENT

from jvm_overlays import get_bits32, get_bits64, get_named_array32, \
                         get_named_array64, get_field_types, name_fields,\
                         get_size32, get_size64

from jvm_base import BaseOverlay

class VMStructEntry(BaseOverlay):
    _name = "VMStructEntry"
    _overlay = VMSTRUCT_ENTRY_TYPE
    bits32 = get_bits32(VMSTRUCT_ENTRY_TYPE)
    bits64 = get_bits64(VMSTRUCT_ENTRY_TYPE)
    named32 = get_named_array32(VMSTRUCT_ENTRY_TYPE)
    named64 = get_named_array64(VMSTRUCT_ENTRY_TYPE)
    size32 = get_size32(VMSTRUCT_ENTRY_TYPE)
    size64 = get_size64(VMSTRUCT_ENTRY_TYPE)
    types = get_field_types(VMSTRUCT_ENTRY_TYPE)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__ (self):
        offset = getattr(self, 'offset', 0)
        address = getattr(self, 'address', 0)
        isStatic = getattr(self, 'isStatic', 0)
        typeStr = getattr(self, 'typeString_str', '')
        typeNam = getattr(self, 'typeName_str', '')
        fieldNam = getattr(self, 'fieldName_str', '')
        if isStatic == 0x01:
            return ("static %s %s::%s => 0x%08x"%(typeStr,
                   typeNam, fieldNam, address))
        return ("%s %s::%s => offset from %s => 0x%08x"%(typeStr,
                   typeNam, fieldNam, typeNam, offset))

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis, is_32bit=True, word_sz=4):
        is_32bit = jvm_analysis.is_32bit if jvm_analysis else is_32bit
        fmt = cls.bits32 if is_32bit else cls.bits64
        nfields = cls.named32 if is_32bit else cls.named64
        jva = jvm_analysis
        data_unpack = struct.unpack(fmt, _bytes)
        kargs = {"addr":addr, 'is_32bit':is_32bit, 'word_sz':word_sz,
                 'jvm_analysis':jvm_analysis, 'updated':False}
        name_fields(data_unpack, nfields, fields=kargs)

        kargs['typeName_str'] = ""
        kargs['fieldName_str'] = ""
        kargs['typeString_str'] = ""
        typeName = kargs['typeName_addr']
        fieldName = kargs['fieldName_addr']
        typeString = kargs['typeString_addr']

        if jvm_analysis and jvm_analysis.strings.has_addr(typeName):
            kargs['typeName_str'] = jva.strings.get_str_at_addr(typeName)
        elif jvm_analysis and jvm_analysis.try_discover_cstring(typeName):
            kargs['typeName_str'] = jva.strings.get_str_at_addr(typeName)

        if jvm_analysis and jvm_analysis.strings.has_addr(fieldName):
            kargs['fieldName_str'] = jva.strings.get_str_at_addr(fieldName)
        elif jvm_analysis and jvm_analysis.try_discover_cstring(fieldName):
            kargs['fieldName_str'] = jva.strings.get_str_at_addr(fieldName)

        if jvm_analysis and jvm_analysis.strings.has_addr(typeString):
            kargs['typeString_str'] = jva.strings.get_str_at_addr(typeString)
        elif jvm_analysis and jvm_analysis.try_discover_cstring(typeString):
            kargs['typeString_str'] = jva.strings.get_str_at_addr(typeString)

        d = VMStructEntry(**kargs)
        if jvm_analysis:
            jvm_analysis.add_internal_object(addr, d)
        return d

class GCLog(BaseOverlay):
    _name = "GCHeapLog"
    _overlay = GC_HEAP_LOG_TYPE
    bits32 = get_bits32(GC_HEAP_LOG_TYPE)
    bits64 = get_bits64(GC_HEAP_LOG_TYPE)
    named32 = get_named_array32(GC_HEAP_LOG_TYPE)
    named64 = get_named_array64(GC_HEAP_LOG_TYPE)
    size32 = get_size32(GC_HEAP_LOG_TYPE)
    size64 = get_size64(GC_HEAP_LOG_TYPE)
    types = get_field_types(GC_HEAP_LOG_TYPE)

class GenCollectedHeap(BaseOverlay):
    _name = "GenCollectedHeap"
    _overlay = GEN_COLLECTED_HEAP_TYPE
    bits32 = get_bits32(GEN_COLLECTED_HEAP_TYPE)
    bits64 = get_bits64(GEN_COLLECTED_HEAP_TYPE)
    named32 = get_named_array32(GEN_COLLECTED_HEAP_TYPE)
    named64 = get_named_array64(GEN_COLLECTED_HEAP_TYPE)
    size32 = get_size32(GEN_COLLECTED_HEAP_TYPE)
    size64 = get_size64(GEN_COLLECTED_HEAP_TYPE)
    types = get_field_types(GEN_COLLECTED_HEAP_TYPE)

    def __str__ (self):
        addr = getattr(self, 'addr', 0)
        return (" GenCollectedHeap => 0x%08x"%(addr))

class Generation(BaseOverlay):
    _name = "Generation"
    _overlay = GENERATION_TYPE
    bits32 = get_bits32(GENERATION_TYPE)
    bits64 = get_bits64(GENERATION_TYPE)
    named32 = get_named_array32(GENERATION_TYPE)
    named64 = get_named_array64(GENERATION_TYPE)
    size32 = get_size32(GENERATION_TYPE)
    size64 = get_size64(GENERATION_TYPE)
    types = get_field_types(GENERATION_TYPE)

class CollectedHeap(BaseOverlay):
    _name = "CollectedHeap"
    _overlay = COLLECTED_HEAP_TYPE
    bits32 = get_bits32(COLLECTED_HEAP_TYPE)
    bits64 = get_bits64(COLLECTED_HEAP_TYPE)
    named32 = get_named_array32(COLLECTED_HEAP_TYPE)
    named64 = get_named_array64(COLLECTED_HEAP_TYPE)
    size32 = get_size32(COLLECTED_HEAP_TYPE)
    size64 = get_size64(COLLECTED_HEAP_TYPE)
    types = get_field_types(COLLECTED_HEAP_TYPE)

    def __str__ (self):
        addr = getattr(self, 'addr', 0)
        return (" CollectedHeap => 0x%08x"%(addr))


class VirtualSpace(BaseOverlay):
    _name = "VirtualSpace"
    _overlay = VIRTUAL_SPACE_TYPE
    bits32 = get_bits32(VIRTUAL_SPACE_TYPE)
    bits64 = get_bits64(VIRTUAL_SPACE_TYPE)
    named32 = get_named_array32(VIRTUAL_SPACE_TYPE)
    named64 = get_named_array64(VIRTUAL_SPACE_TYPE)
    size32 = get_size32(VIRTUAL_SPACE_TYPE)
    size64 = get_size64(VIRTUAL_SPACE_TYPE)
    types = get_field_types(VIRTUAL_SPACE_TYPE)

class VirtualSpaceNode(BaseOverlay):
    _name = "VirtualSpaceNode"
    _overlay = VIRTUAL_SPACE_NODE_TYPE
    bits32 = get_bits32(VIRTUAL_SPACE_NODE_TYPE)
    bits64 = get_bits64(VIRTUAL_SPACE_NODE_TYPE)
    named32 = get_named_array32(VIRTUAL_SPACE_NODE_TYPE)
    named64 = get_named_array64(VIRTUAL_SPACE_NODE_TYPE)
    size32 = get_size32(VIRTUAL_SPACE_NODE_TYPE)
    size64 = get_size64(VIRTUAL_SPACE_NODE_TYPE)
    types = get_field_types(VIRTUAL_SPACE_NODE_TYPE)

class ClassLoaderData(BaseOverlay):
    _name = "ClassLoaderData"
    _overlay = CLASS_LOADER_DATA_TYPE
    bits32 = get_bits32(CLASS_LOADER_DATA_TYPE)
    bits64 = get_bits64(CLASS_LOADER_DATA_TYPE)
    named32 = get_named_array32(CLASS_LOADER_DATA_TYPE)
    named64 = get_named_array64(CLASS_LOADER_DATA_TYPE)
    size32 = get_size32(CLASS_LOADER_DATA_TYPE)
    size64 = get_size64(CLASS_LOADER_DATA_TYPE)
    types = get_field_types(CLASS_LOADER_DATA_TYPE)

    def get_klass(self):
        class_loader = self.get_class_loader()
        if class_loader:
           return class_loader.get_klass()
        return None

    def get_class_loader(self):
        return getattr(self, 'class_loader_value', None)


    def update_oops(self):
        if getattr(self, 'oop_updated', False):
            return
        setattr(self, "oop_updated", True)
        jva = self.get_jva()
        oop_addr = getattr(self, 'class_loader')
        oop = jva.lookup_known_oop(oop_addr)
        setattr(self, 'class_loader_value', oop)
        if oop:
            jva.add_oop(oop)


    def update_fields(self, force_update=False):
        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)
        jva = self.get_jva()
        mspace = Metaspace.from_jva(getattr(self, 'metaspace'),jva)
        setattr(self, 'metaspace_value', mspace)
        if mspace:
            mspace.update_fields()
        oop_addr = getattr(self, 'class_loader')
        #oop = jva.lookup_known_oop(oop_addr)
        #setattr(self, 'class_loader_value', oop)
        #if oop:
        #    jva.add_oop(oop)

    def get_metaspace(self):
        ms_value = getattr(self, 'metaspace_value', None)
        if ms_value is None:
             self.update_fields()
        return getattr(self, 'metaspace_value', None)

    def get_metaspaces(self):
        ms_val = self.get_metaspace()
        vsm = ms_val.get_vsm_contiguous_chunks()
        c_vsm = ms_val.get_class_vsm_contiguous_chunks()
        return vsm + c_vsm


    def get_metaspace_ranges(self):
        ms_value = self.get_metaspace()
        ms_chunks = ms_value.get_chunks()

        metaspace_value.vsm_value.build_contiguous_chunks()
        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)
        jva = self.get_jva()
        mspace = Metaspace.from_jva(getattr(self, 'metaspace'),jva)
        setattr(self, 'metaspace_value', mspace)
        if mspace:
            mspace.update_fields()


class SpaceManager(BaseOverlay):
    _name = "SpaceManager"
    _overlay = SPACE_MANAGER_TYPE
    bits32 = get_bits32(SPACE_MANAGER_TYPE)
    bits64 = get_bits64(SPACE_MANAGER_TYPE)
    named32 = get_named_array32(SPACE_MANAGER_TYPE)
    named64 = get_named_array64(SPACE_MANAGER_TYPE)
    size32 = get_size32(SPACE_MANAGER_TYPE)
    size64 = get_size64(SPACE_MANAGER_TYPE)
    types = get_field_types(SPACE_MANAGER_TYPE)

    def update_fields(self, force_update=False):
        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)
        jva = self.get_jva()
        # NumberOfInUseLists known from source code
        NumberOfInUseLists = 4
        chunks = []
        chunk_info = []
        chunk_by_addr = {}
	setattr(self, 'NumberOfInUseLists', 4)
	setattr(self, 'chunks', chunks)
        setattr(self, 'chunk_info', chunk_info)
        setattr(self, 'chunk_by_addr', chunk_by_addr)

        for i in xrange(0, NumberOfInUseLists):
            attr = "chunks_in_use_%d"%i
            addr = getattr(self, attr)
            chunk = None
            if jva.is_valid_addr(addr):
               chunk = Metachunk.from_jva(addr,jva)
               if not isinstance(chunk, Metachunk):
                   continue
               #chunk.print_dump()
               chunk.update_fields()
               chunks.append(chunk)
            setattr(self, attr+'_value', chunk)

        attr = "current_chunk"
        addr = getattr(self, attr)
        chunk = None
        if jva.is_valid_addr(addr) and not addr in chunk_by_addr:
           chunk = Metachunk.from_jva(addr,jva)
           chunk.update_fields()
           chunks.append(chunk)
        elif addr in chunk_by_addr:
           chunk = chunk_by_addr[addr]
        setattr(self, attr+'_value', chunk)

    def accumulate_chunks(self):
        acc_chunks = []
        visited = set()
        chunks = getattr(self, 'chunks', [])
        chunk_by_addr = getattr(self, 'chunk_by_addr', {})
        chunk_info = getattr(self, 'chunk_info', [])

        for chunk in chunks:
            acc_chunks += chunk.accumulate_chunks(visited=visited)

        for chunk in acc_chunks:
            addr = chunk.addr
            if not chunk.addr in chunk_by_addr:
                chunk_info.append({'start':chunk.addr, 'size':chunk.word_size})
                chunk_by_addr[chunk.addr] = chunk
        return chunk_by_addr

    def build_contiguous_chunks(self):
        chunk_by_addr = self.accumulate_chunks()
        addr_list = chunk_by_addr.keys()
        addr_list.sort()
        chunks = []
        last_chunk = None
        for addr in addr_list:
            c = chunk_by_addr[addr]
            if last_chunk and c.addr == last_chunk[0]+last_chunk[1]:
                last_chunk[1] += c.word_size
            else:
                last_chunk = [c.addr, c.word_size]
                chunks.append(last_chunk)
        return chunks



class AllocRecord(BaseOverlay):
    _name = "AllocRecord"
    _overlay = ALLOC_RECORD_TYPE
    bits32 = get_bits32(ALLOC_RECORD_TYPE)
    bits64 = get_bits64(ALLOC_RECORD_TYPE)
    named32 = get_named_array32(ALLOC_RECORD_TYPE)
    named64 = get_named_array64(ALLOC_RECORD_TYPE)
    size32 = get_size32(ALLOC_RECORD_TYPE)
    size64 = get_size64(ALLOC_RECORD_TYPE)
    types = get_field_types(ALLOC_RECORD_TYPE)

class Metaspace(BaseOverlay):
    _name = "Metaspace"
    _overlay = METASPACE_TYPE
    bits32 = get_bits32(METASPACE_TYPE)
    bits64 = get_bits64(METASPACE_TYPE)
    named32 = get_named_array32(METASPACE_TYPE)
    named64 = get_named_array64(METASPACE_TYPE)
    size32 = get_size32(METASPACE_TYPE)
    size64 = get_size64(METASPACE_TYPE)
    types = get_field_types(METASPACE_TYPE)

    def update_fields(self, force_update=False):
        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)
        jva = self.get_jva()
        addr = getattr(self, 'vsm')
        vsm = None
        if jva.is_valid_addr(addr):
            vsm = SpaceManager.from_jva(addr,jva)
            vsm.update_fields()
        setattr(self, 'vsm_value', vsm)

        csm = None
        addr = getattr(self, 'class_vsm')
        # TODO figure out why this class_vsm does not match up
        # in the Non-NULL class loader
        #if jva.is_valid_addr(addr):
        #    csm = SpaceManager.from_jva(addr,jva)
        #    csm.print_dump()
        #    csm.update_fields()
        setattr(self, 'class_vsm_value', csm)

    def get_vsm_value(self):
        return getattr(self, 'vsm_value', None)

    def get_class_vsm_value(self):
        return getattr(self, 'class_vsm_value', None)

    def get_vsm_chunks(self):
        vsm_value = self.get_vsm_value()
        if vsm_value is None:
            return {}
        return vsm_value.accumulate_chunks()

    def get_vsm_contiguous_chunks(self):
        vsm_value = self.get_vsm_value()
        if vsm_value is None:
            return []
        return vsm_value.build_contiguous_chunks()

    def get_class_vsm_chunks(self):
        class_vsm_value = self.get_class_vsm_value()
        if class_vsm_value is None:
            return {}
        return class_vsm_value.accumulate_chunks()

    def get_class_vsm_contiguous_chunks(self):
        class_vsm_value = self.get_class_vsm_value()
        if class_vsm_value is None:
            return []
        return class_vsm_value.build_contiguous_chunks()

class Metachunk(BaseOverlay):
    _name = "Metachunk"
    _overlay = METACHUNK_TYPE
    bits32 = get_bits32(METACHUNK_TYPE)
    bits64 = get_bits64(METACHUNK_TYPE)
    named32 = get_named_array32(METACHUNK_TYPE)
    named64 = get_named_array64(METACHUNK_TYPE)
    size32 = get_size32(METACHUNK_TYPE)
    size64 = get_size64(METACHUNK_TYPE)
    types = get_field_types(METACHUNK_TYPE)

    def update_fields(self, force_update=False):
        if self.is_updated(force_update):
            return
        setattr(self, "updated", True)
        jva = self.get_jva()
        addr = getattr(self, 'next')
        next_value = None
        if jva.is_valid_addr(addr):
            next_value = Metachunk.from_jva(addr,jva)
        setattr(self, 'next_value', next_value)

        addr = getattr(self, 'prev')
        prev_value = None
        if jva.is_valid_addr(addr):
            prev_value = Metachunk.from_jva(addr,jva)
        setattr(self, 'prev_value', prev_value)

        if next_value:
            next_value.update_fields()
        if prev_value:
            prev_value.update_fields()

    def accumulate_chunks(self, visited=set()):
        chunks = []
        addr = getattr(self, 'addr')
        if addr in visited:
            return chunks
        visited.add(addr)
        chunks.append(self)

        value = getattr(self, 'next_value', None)
        if value and not getattr(value, 'addr') in visited:
           chunks += value.accumulate_chunks(visited)

        value = getattr(self, 'prev_value', None)
        if value and not getattr(value, 'addr') in visited:
           chunks += value.accumulate_chunks(visited)
        return chunks

#class ThreadShadow(BaseOverlay):
#    _name = "ThreadShadow"
#    _overlay = THREAD_SHADOW_TYPE
#    bits32 = get_bits32(THREAD_SHADOW_TYPE)
#    bits64 = get_bits64(THREAD_SHADOW_TYPE)
#    named32 = get_named_array32(THREAD_SHADOW_TYPE)
#    named64 = get_named_array64(THREAD_SHADOW_TYPE)
#    size32 = get_size32(THREAD_SHADOW_TYPE)
#    size64 = get_size64(THREAD_SHADOW_TYPE)
#    types = get_field_types(THREAD_SHADOW_TYPE)


class JavaFrameAnchor(BaseOverlay):
    _name = "JavaFrameAnchor"
    _overlay = JAVA_FRAME_ANCHOR
    bits32 = get_bits32(JAVA_FRAME_ANCHOR)
    bits64 = get_bits64(JAVA_FRAME_ANCHOR)
    named32 = get_named_array32(JAVA_FRAME_ANCHOR)
    named64 = get_named_array64(JAVA_FRAME_ANCHOR)
    size32 = get_size32(JAVA_FRAME_ANCHOR)
    size64 = get_size64(JAVA_FRAME_ANCHOR)
    types = get_field_types(JAVA_FRAME_ANCHOR)

class JavaCallWrapper(BaseOverlay):
    _name = "JavaCallWrapper"
    _overlay = JAVA_CALL_WRAPPER
    bits32 = get_bits32(JAVA_CALL_WRAPPER)
    bits64 = get_bits64(JAVA_CALL_WRAPPER)
    named32 = get_named_array32(JAVA_CALL_WRAPPER)
    named64 = get_named_array64(JAVA_CALL_WRAPPER)
    size32 = get_size32(JAVA_CALL_WRAPPER)
    size64 = get_size64(JAVA_CALL_WRAPPER)
    types = get_field_types(JAVA_CALL_WRAPPER)

class JavaCallValue(BaseOverlay):
    _name = "JavaCallValue"
    _overlay = JAVA_CALL_VALUE
    bits32 = get_bits32(JAVA_CALL_VALUE)
    bits64 = get_bits64(JAVA_CALL_VALUE)
    named32 = get_named_array32(JAVA_CALL_VALUE)
    named64 = get_named_array64(JAVA_CALL_VALUE)
    size32 = get_size32(JAVA_CALL_VALUE)
    size64 = get_size64(JAVA_CALL_VALUE)
    types = get_field_types(JAVA_CALL_VALUE)

class JavaThreadPartial(BaseOverlay):
    _name = "JavaCallValue"
    _overlay = JAVA_THREAD_PARTIAL
    bits32 = get_bits32(JAVA_THREAD_PARTIAL)
    bits64 = get_bits64(JAVA_THREAD_PARTIAL)
    named32 = get_named_array32(JAVA_THREAD_PARTIAL)
    named64 = get_named_array64(JAVA_THREAD_PARTIAL)
    size32 = get_size32(JAVA_THREAD_PARTIAL)
    size64 = get_size64(JAVA_THREAD_PARTIAL)
    types = get_field_types(JAVA_THREAD_PARTIAL)

class CodeBlob(BaseOverlay):
    _name = "CodeBlob"
    _overlay = CODE_BLOB
    bits32 = get_bits32(CODE_BLOB)
    bits64 = get_bits64(CODE_BLOB)
    named32 = get_named_array32(CODE_BLOB)
    named64 = get_named_array64(CODE_BLOB)
    size32 = get_size32(CODE_BLOB)
    size64 = get_size64(CODE_BLOB)
    types = get_field_types(CODE_BLOB)

class OopMapValue(BaseOverlay):
    _name = "OopMapValue"
    _overlay = OOP_MAP_VALUE
    bits32 = get_bits32(OOP_MAP_VALUE)
    bits64 = get_bits64(OOP_MAP_VALUE)
    named32 = get_named_array32(OOP_MAP_VALUE)
    named64 = get_named_array64(OOP_MAP_VALUE)
    size32 = get_size32(OOP_MAP_VALUE)
    size64 = get_size64(OOP_MAP_VALUE)
    types = get_field_types(OOP_MAP_VALUE)


class OopMap(BaseOverlay):
    _name = "OopMap"
    _overlay = OOP_MAP
    bits32 = get_bits32(OOP_MAP)
    bits64 = get_bits64(OOP_MAP)
    named32 = get_named_array32(OOP_MAP)
    named64 = get_named_array64(OOP_MAP)
    size32 = get_size32(OOP_MAP)
    size64 = get_size64(OOP_MAP)
    types = get_field_types(OOP_MAP)


class OopMapSet(BaseOverlay):
    _name = "OopMapSet"
    _overlay = OOP_MAP_SET
    bits32 = get_bits32(OOP_MAP_SET)
    bits64 = get_bits64(OOP_MAP_SET)
    named32 = get_named_array32(OOP_MAP_SET)
    named64 = get_named_array64(OOP_MAP_SET)
    size32 = get_size32(OOP_MAP_SET)
    size64 = get_size64(OOP_MAP_SET)
    types = get_field_types(OOP_MAP_SET)

class Frame(BaseOverlay):
    _name = "Frame"
    _overlay = FRAME
    bits32 = get_bits32(FRAME)
    bits64 = get_bits64(FRAME)
    named32 = get_named_array32(FRAME)
    named64 = get_named_array64(FRAME)
    size32 = get_size32(FRAME)
    size64 = get_size64(FRAME)
    types = get_field_types(FRAME)

class FrameValues(BaseOverlay):
    _name = "FrameValues"
    _overlay = FRAME_VALUES
    bits32 = get_bits32(FRAME_VALUES)
    bits64 = get_bits64(FRAME_VALUES)
    named32 = get_named_array32(FRAME_VALUES)
    named64 = get_named_array64(FRAME_VALUES)
    size32 = get_size32(FRAME_VALUES)
    size64 = get_size64(FRAME_VALUES)
    types = get_field_types(FRAME_VALUES)

class FrameValue(BaseOverlay):
    _name = "FrameValue"
    _overlay = FRAME_VALUE
    bits32 = get_bits32(FRAME_VALUE)
    bits64 = get_bits64(FRAME_VALUE)
    named32 = get_named_array32(FRAME_VALUE)
    named64 = get_named_array64(FRAME_VALUE)
    size32 = get_size32(FRAME_VALUE)
    size64 = get_size64(FRAME_VALUE)
    types = get_field_types(FRAME_VALUE)

class VFrameArray(BaseOverlay):
    _name = "VFrameArray"
    _overlay = VFRAME_ARRAY
    bits32 = get_bits32(VFRAME_ARRAY)
    bits64 = get_bits64(VFRAME_ARRAY)
    named32 = get_named_array32(VFRAME_ARRAY)
    named64 = get_named_array64(VFRAME_ARRAY)
    size32 = get_size32(VFRAME_ARRAY)
    size64 = get_size64(VFRAME_ARRAY)
    types = get_field_types(VFRAME_ARRAY)

class VFrameArrayElement(BaseOverlay):
    _name = "VFrameArrayElement"
    _overlay = VFRAME_ARRAY_ELEMENT
    bits32 = get_bits32(VFRAME_ARRAY_ELEMENT)
    bits64 = get_bits64(VFRAME_ARRAY_ELEMENT)
    named32 = get_named_array32(VFRAME_ARRAY_ELEMENT)
    named64 = get_named_array64(VFRAME_ARRAY_ELEMENT)
    size32 = get_size32(VFRAME_ARRAY_ELEMENT)
    size64 = get_size64(VFRAME_ARRAY_ELEMENT)
    types = get_field_types(VFRAME_ARRAY_ELEMENT)

