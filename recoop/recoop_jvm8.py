import os, copy, sys, struct, socket
import recoop
import itertools
PATH_TO_JVM_MODULE = "/research_data/code/git/jvm_analysis"
from datetime import datetime
from jvm.jvm_klassoop import Oop
from jvm.jvm_base import JAVA_LANG_PRIMITIVES_LIST
from jvm.jvm_objects import JavaCallWrapper, VFrameArray

JAVA_LANG_PRIMITIVES_SET = set([i for i in JAVA_LANG_PRIMITIVES_LIST if i.find('java/lang/') > -1])
JAVA_LANG_PRIMITIVES_SET.add('java/lang/String')

def time_str():
    return str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))

APPLOADER_KLASS = 'sun/misc/Launcher$AppClassLoader'
THREAD_KLASS = 'java/lang/Thread'
SYSTEM_KLASS = 'java/lang/System'
PROPERTIES_KLASS = 'java/util/Properties'

DUMPS_DIR = "dumps"
DUMPS_LOCATION= lambda p: os.path.join(p, DUMPS_DIR)



class RecOOPJVM8(recoop.RecOOPInterface):
    def __init__(self, dump_java_process=False, path_to_dumps='/tmp/dumps', path_to_mem=None,
                 jvm_module_loc=PATH_TO_JVM_MODULE,
                 jvm_start_addr=None, is_32bit=True,
                 word_sz=4, little_endian=True, is_linux=True,
                 jvm_ver=None, pid=None, **kargs):

        recoop.RecOOPInterface.__init__(self, **kargs)
        self.dump_java_process = dump_java_process
        self.path_to_dumps= path_to_dumps
        self.path_to_mem = path_to_mem
        self.dump_location = None
        self.pid=pid
        self.ex_java=None
        sys.path.append(jvm_module_loc)
        self.is_32bit = True if not is_32bit in kargs else kargs['is_32bit']
        self.jvm_start_addr = jvm_start_addr
        self.word_sz = word_sz
        self.little_endian = little_endian
        self.jvm_ver=jvm_ver
        self.ranges = None
        self.jva = None
        self.logs = []
        self.libjvm = {'start':jvm_start_addr,'version':jvm_ver}
        self.is_linux = is_linux
        self.constant_pools = {}
        self.symbol_table_entries = {}
        self.methods_entries = {}
        self.string_table_entries = {}
        self.jm_oop_entries = {}
        self.klass_entries = {} # not usages
        self.jm_oop_addr_uses = {}
        self.jm_oop_range_uses = {}
        self.klass_addr_uses = {}
        self.klass_range_uses = {}
        self.tenure_oop_klasses = [
            APPLOADER_KLASS,
            THREAD_KLASS,
            SYSTEM_KLASS,
            PROPERTIES_KLASS,
        ]
        self.tenure_oop_klasses_locs = {}
        self.tenure_oop_klasses_locs = {}

        self.pot_heap_loc = None
        self.oop_pot_heap_loc = None
        self.oop_min_heap_loc = None
        self.oop_max_heap_loc = None
        self.klass_pot_heap_loc = None
        self.klass_min_heap_loc = None
        self.klass_max_heap_loc = None
        self.pot_oop_headers = []
        self.marked_oops = []
        self.not_valid_oops = []
        self.oop_py_objs = {}
        self.oop_dict = {}
        self.strings = {}
        self.env_vars = {}
        if jvm_start_addr:
           self.libjvm['start'] = jvm_start_addr
           self.libjvm['version'] = jvm_ver

        self.forwarded_oops = []
        self.forwarded_addrs = set()
        self.bias_oops = {}
        self.normal_oops = {}
        self.heap_thread_oops = {}
        self.unknown_oops = {}

        self.java_thread_start = {}
        self.confirmed_java_thread = {}
        self.oop_by_thread_obj = {}
        self.jthread_start_mapping_thread_oop = {}
        self.thread_oop_by_name = {}
        self.thread_oop_mapping_jthread = {}
        self.confirmed_java_thread = {}
        self.oop_by_thread_obj = {}
        self.pot_call_wrappers = {}
        self.thread_infos = {}

        self.pot_jthread_ranges_uses = {}
        self.pot_call_wrapper_results = {}
        self.pot_vframe_arrays = {}
        if (self.dump_java_process and self.path_to_mem is None) and self.path_to_dumps is None:
            raise Exception("Specify dumps location or memory image location")

        try:
            if self.dump_java_process:
                os.stat(self.path_to_mem)
            elif self.path_to_dumps:
                os.stat(self.path_to_dumps)
        except:
            raise Exception("Memory image or dumps location does not exist")

        if self.dump_java_process and self.path_to_dumps is None:
            self.dump_location = DUMPS_LOCATION(os.path.split(self.path_to_mem)[0])
            self.path_to_dumps = self.dump_location
        else:
            self.dump_location = self.path_to_dumps
        self.init_steps()
        self.initted = True

    def forget_py_obj(self, oop):
        addr = oop.addr
        self.forget_py_obj_at_addr(addr)

    def forget_py_obj(self, oop):
        addr = None
        if oop and hasattr(oop, 'addr'):
           addr = oop.addr
        if addr and addr in self.oop_dict:
            del self.oop_dict[addr]
        if addr and addr in self.oop_py_objs:
            del self.oop_py_objs[addr]
        if addr:
            self.jva.forget_all_for_addr(addr)

    def has_py_obj(self, addr):
        return addr in self.oop_py_objs

    def get_py_obj(self, addr):
        return self.oop_py_objs.get(addr, None)

    def add_py_obj(self, addr, py_obj, overwrite=False):
        if addr in self.oop_py_objs and not overwrite:
            raise Exception("Attempting to overwrite Python Object in known objects")
        self.oop_py_objs[addr] = py_obj

    def query_oop_type(self, addr):
        oop = self.get_oop_by_addr(addr)
        if oop is None:
            return None
        klass = oop.get_klass()
        return str(klass)

    def get_oop_by_addr(self, addr, perform_update=True):
        oop = self.jva.lookup_known_oop(addr)
        if perform_update and oop and oop._name.find('Oop') > -1:
            oop.update_fields()
            self.jva.save_oop(oop)
        elif oop and oop._name.find('Oop') == -1:
            return None
        return oop

    def is_prim_oop(self, addr):
        oop = self.get_oop_by_addr(addr)
        return oop.is_prim()

    def query_oop_klasses(self, addr):
        oop = self.get_oop_by_addr(addr)
        if oop is None or \
           oop.is_prim() or\
           oop.is_array_oop():
            return None
        return oop.get_ordered_klass_dependencies()

    def build_oop_python_values_by_addr(self, addr, klass_name=None, field_name=None):
        oop = self.get_oop_by_addr(addr)
        if oop is None:
            return None
        return self.build_oop_python_values(oop, klass_name=klass_name, field_name=field_name)

    def build_oop_python_values(self, oop, klass_name=None, field_name=None ):
        if oop is None:
            return None
        v2 = oop.python_value(klass_name=klass_name, field_name=field_name, bread_crumbs=self.oop_dict)
        self.debug_v2 = v2
        po = self.get_python_object(oop)
        self.debug_po = po
        return po

    def get_age(self, addr):
        if addr in self.bias_oops:
            return self.bias_oops[addr][1]
        elif addr in self.normal_oops:
            return self.normal_oops[addr][1]
        elif addr in self.unknown_oops:
            return self.heap_thread_oops[addr][1]
        else:
            return None

    def get_python_object_at_addr(self, addr):
        oop_dict = None
        if not addr in self.oop_dict:
            oop_dict = self.build_oop_python_values_by_addr(addr)
        if addr in self.oop_dict:
            oop_dict = self.oop_dict[addr]
        return self.create_python_oop_object(oop_dict)

    def get_python_object(self, oop, reset=False):
        oop_dict = None
        if oop is None:
            return None
        addr = oop.addr
        if self.has_py_obj(addr):
            po = self.get_python_object_at_addr(addr)
            oop_type = oop.klass_name()
            native = oop.is_python_native(po)
            if oop.is_prim() and oop.is_python_native(po) or\
               oop_type in JAVA_LANG_PRIMITIVES_SET and native:
                return po
            elif oop_type == "java/lang/String" and isinstance(po, str):
                return po
            elif not native and po.oop_type == oop_type:
                return po
            if reset:
                self.forget_py_obj(oop)
                oop = Oop.from_jva(addr, self.jva)
                return self.get_python_object(oop)
            return po
        return self.get_python_object_at_addr(oop.addr)

    def create_python_oop_object(self, oop_dict):
        return self.handle_create_python_oop(oop_dict)

    def handle_create_python_array_oop(self, oop_dict):
        addr = oop_dict['addr']
        if self.has_py_obj(addr):
            return self.get_py_obj(addr)
        if not oop_dict['is_array']:
           raise Exception('Attempting to create an array OOP with invalid oop dict')
        value = oop_dict['value']
        if value is None:
            self.add_py_obj(addr, value)
            return value
        elif oop_dict['is_prim'] and isinstance(value, str):
            self.add_py_obj(addr, value)
            return value
        elif self.is_python_native(value):
            self.log("[XXXX] Error, attempting to set an array with a value (%s) @ %s"%(value, hex(addr)))
            self.add_py_obj(addr, None)
            return None

        oop_type = self.query_oop_type(addr)
        po = recoop.RecOOPArray(addr, oop_type)
        self.add_py_obj(addr, po)
        for coop_dict in value:
            cpo = None
            if coop_dict and 'value' in coop_dict and coop_dict['value']:
                cpo = self.create_python_oop_object(coop_dict)
            po.append(cpo)
        return po

    def convert_java_lang_prim_to_python_oop(self, oop_dict, oop_type=None):
        if oop_dict is None:
            return None
        addr = oop_dict['addr']
        value = oop_dict['value']
        if oop_type is None:
            oop_type = self.query_oop_type(addr)
        value_key = "%s:value"%oop_type
        new_value = None
        if value and value_key in value and value[value_key]:
            new_value = value[value_key]['value'] \
                        if 'value' in value[value_key] \
                        else None
        new_oop_dict = {}
        new_oop_dict.update(oop_dict)
        new_oop_dict['value'] = new_value
        new_oop_dict['is_prim'] = True
        #print "converting a java/lang/PRIM to python primitive:", new_oop_dict
        return self.handle_create_python_prim_oop(new_oop_dict)

    def mark_java_metadata(self, po):
        marked = False
        jthread = None
        age = None
        hash_ = None
        value = None
        if self.is_python_native(po):
            return marked
        markOop_addr = po.addr
        if markOop_addr in self.bias_oops:
            jthread, age, klass = self.bias_oops[markOop_addr]
            marked = True
        if markOop_addr in self.heap_thread_oops:
            marked = True
            value, age,  klass = self.heap_thread_oops[markOop_addr]
        if markOop_addr in self.normal_oops:
            marked = True
            hash_, age, klass = self.normal_oops[markOop_addr]
        if markOop_addr in self.unknown_oops:
            marked = True
            value, age, klass = self.unknown_oops
        if value is None:
            value = self.jva.read_dword(markOop_addr)

        setattr(po, '__jthread__', jthread)
        setattr(po, '__java_hash__', hash_)
        setattr(po, '__age__', age)
        setattr(po, '__klass__', klass)
        setattr(po, '__mark_value__', value)
        setattr(po, '__has_meta_data__', marked)
        return marked


    def handle_create_python_oop(self, oop_dict):
        if oop_dict is None:
            return None
        addr = oop_dict['addr']
        value = oop_dict['value']
        if self.has_py_obj(addr):
            return self.get_py_obj(addr)
        if oop_dict['is_array']:
           return self.handle_create_python_array_oop(oop_dict)
        elif oop_dict['is_prim'] or value is None:
           return self.handle_create_python_prim_oop(oop_dict)

        oop_type = self.query_oop_type(addr)
        if oop_type in JAVA_LANG_PRIMITIVES_SET:
           return self.convert_java_lang_prim_to_python_oop(oop_dict)

        if not isinstance(value, dict) and not oop_dict['is_prim']:
           #print "handling PO:", oop_dict
           return self.handle_create_python_prim_oop(oop_dict)

        po = recoop.RecOOPObject(addr, oop_type)
        self.add_py_obj(addr, po)
        ordered_deps = self.query_oop_klasses(addr)
        field_keys = value.keys()
        field_keys.sort()

        for fld_key, coop_dict in value.items():
            klass, field = fld_key.split(':')
            #print "fld_key: ", fld_key,"type: ",type(coop_dict)
            cpo = self.handle_create_python_oop(coop_dict)
            if hasattr(po, field) and klass == po.oop_type:
                po.add_field(field, cpo)
            else:
                po.add_field(field, cpo)
                #setattr(po, field, cpo)
            po.add_field_by_key(fld_key, cpo)

        return po

    def handle_create_python_prim_oop(self, oop_dict, overwrite=False):
        value = oop_dict['value']
        addr = oop_dict['addr']
        if self.has_py_obj(addr) and not overwrite:
            return self.get_py_obj(addr)
        self.add_py_obj(addr, value)
        return value

    def init_steps(self):
        self.steps.append(self.perform_virtual_memory_reconstruction)
        self.steps.append(self.perform_extract_loaded_types)
        self.steps.append(self.perform_locate_managed_memory)
        self.steps.append(self.extract_pertinent_infos)

    def perform_virtual_memory_reconstruction(self, pid=None, profile=None, name="java", **kargs):
        try:
            import jvm
            from jvm.mem_chunks import MemChunk
            from jvm.extract_process import ExtractProc
            from jvm.mem_range import produce_ranges
            from jvm.jvm_analysis import JVMAnalysis
        except:
            raise

        if self.pid:
            pid = self.pid
        lookup_lib = False if self.libjvm['start'] else True
        name = None if not pid is None else name
        dump_file = self.path_to_mem
        self.ex_java = ExtractProc(the_file=dump_file, profile=profile)
        if pid or name:
            ex_java.update_process_info(pid=pid, name=name, lookup_lib=lookup_lib)
            if lookup_lib:
                self.libjvm['start'] = self.lib_start

        if self.dump_java_process:
            self.log ("Identifying the Java Process")
            self.log ("Dumping Process Virtual Memory")
            ex_java.dump_virtual_memory_form(self.dump_location)


        self.log ("Reading in all Memory Ranges")
        self.ranges = produce_ranges(self.dump_location)
        new_ranges = []
        page_size = 4096
        for r in self.ranges:
            csize = r.fsize
            ostart = r.start
            #self.log ("Left Trimming Ranges: 0x%08x-0x%08x"%(r.start, r.end))
            #r.ltrim_range(chunk_sz=page_size)
            if csize != r.fsize:
                self.log ("Left Trimmed 0x%08x to 0x%08x, old size: 0x%08x new size: 0x%08x "%(ostart, r.start, csize, r.fsize))

            #self.log ("Right Trimming Ranges: 0x%08x-0x%08x"%(r.start, r.end))
            #r.rtrim_range(chunk_sz=page_size*1024*100)
            if r.fsize >= page_size:
                new_ranges.append(r)

        self.ranges = new_ranges

        self.log ("Initializing the JVM Analysis Module")
        self.jva = JVMAnalysis(self.ranges, libjvm=self.libjvm, is_32bit=self.is_32bit,
                               little_endian=self.little_endian, word_sz=self.word_sz,
                               is_linux=self.is_linux)
        self.log ("Enumerating JVM Internal Symbols")
        return True

    def perform_extract_loaded_types(self, **kargs):
        if self.jva is None:
            raise Exception("JVM Analysis module not properly initialized")

        self.log ("Enumerating JVM Symbol Table")
        self.internal_symbol_table_result = self.jva.read_internal_symbol_table()
        self.log ("Enumerating JVM System Dictionary")
        self.system_dictionary_result  = self.jva.read_system_dictionary()
        self.log ("Enumerating JVM String Table")
        self.string_table_result = self.jva.read_internal_string_table()

        return True


    def perform_locate_managed_memory(self, **kargs):
        #self.log ("%s: Enumerating JVM Heap using GC Logs")
	#self.gen_heaps_from_gc_logs = self.jva.gen_heaps_from_gc_logs()
        self.log ("Enumerating and grouping internal object locations")
        self.enumerate_internal_object_groupings()
        self.log ("Identifying the chunk of memory with objects")
        self.identify_heaps_location()
        return True

    def extract_pertinent_infos(self, **kargs):
        include_unsafe = kargs.get('include_unsafe', False)
        self.log ("Enumerating all threads and thread vframe arrays")
        self.scan_for_java_vframes()
        ti = self.get_thread_infos(include_unsafe=include_unsafe)
        self.log ("Enumerating all Strings")
        strings = self.find_strings(include_unsafe=include_unsafe)
        self.log ("Enumerating all Sockets")
        socks = self.find_sockets(include_unsafe=include_unsafe)
        self.log ("Enumerating all Files")
        files = self.find_files(include_unsafe=include_unsafe)
        #self.log ("Enumerating all IO Streams and buffers")
        #files = self.find_streams_and_buffers(include_unsafe=include_unsafe)
        self.log ("Enumerating all Java environment variables")
        files = self.find_env_vars(include_unsafe=include_unsafe)
        return True


    def perform_locate_enumerate_objects(self, **kargs):
        t = time_str()
        self.log ("Enumerating JVM Heap for OOP Candidates")
        self.oop_candidate_results = self.jva.scan_all_heaps_for_oop_candidates()
        self.log ("Heap Scan started analysis: %s"%t)
        self.log ("Heap Scan completed analysis")
        self.log ("Enumerating Strings in the Internal JVM string table")
        self.internal_string_table_results = self.jva.read_internal_string_table()
        return True


    def perform_reconstruct_objects(self, **kargs):
        raise Exception("implement reconstruct objects")

    def perform_timeline(self, **kargs):
        raise Exception("implement timeline")

    def find_start_of_tenure_space(self, *kargs):
        apploaderOopLocs = self.find_locs_jm_oop_value(APPLOADER_KLASS)
        locs_interest = apploaderOopLocs[self.oop_pot_heap_loc]
        # TODO need something more scientific than just the min of the
        # all the locs_interest (maybe correlate with main and system threads
        # too?
        # Subtract four because the metadata is where location occurs
        # TODO figure out the correlation b/n threads and AppLoader Klass
        self.tenure_loc = min(locs_interest) - self.jva.word_sz


    def find_locs_klass_value(self, klass_name, **kargs):
        results = {}
        addr = self.jva.loaded_classes_by_name[klass_name].addr \
                     if klass_name in self.jva.loaded_classes_by_name \
                     else -1
        if addr == -1:
            return results

        for r, locs in self.klass_range_uses.items():
            l = [i[0] for i in locs if i[1] == addr]
            if len(l) > 0:
                results[r] = l
        return results

    def find_locs_jm_oop_value(self, klass_name, **kargs):
        results = {}
        addr = self.jva.loaded_jm_oop_by_name[klass_name].addr \
                     if klass_name in self.jva.loaded_classes_by_name \
                     else -1
        if addr == -1:
            return results

        for r, locs in self.jm_oop_range_uses.items():
            l = [i[0] for i in locs if i[1] == addr]
            if len(l) > 0:
                results[r] = l
        return results

    def identify_heaps_location(self, **kargs):
        self.pot_heap_loc = None
        target = None
        # identify potential heap location based on oop locations
        for r_addr, oop_uses in self.jm_oop_range_uses.items():
                if len(oop_uses) > len(self.jva.loaded_jm_oop_by_addr):
                    #print hex(r_addr), len(oop_uses)
                    if not target is None and len(oop_uses) > len(target[-1]):
                        target = (r_addr, oop_uses)
                    elif target is None:
                        target = (r_addr, oop_uses)

        self.pot_heap_loc = self.oop_pot_heap_loc = None if target is None else target[0]
        self.oop_min_heap_loc = min([i[0] for i in target[-1]])
        self.oop_max_heap_loc = max([i[0] for i in target[-1]])
        target = None
        # identify stuff based on Klass info
        for r_addr, oop_uses in self.klass_range_uses.items():
                if len(oop_uses) > len(self.jva.loaded_jm_oop_by_addr):
                    #print hex(r_addr), len(oop_uses)
                    if not target is None and len(oop_uses) > len(target[-1]):
                        target = (r_addr, oop_uses)
                    elif target is None:
                        target = (r_addr, oop_uses)

        self.klass_pot_heap_loc = None if target is None else target[0]
        self.klass_min_heap_loc = min([i[0] for i in target[-1]])
        self.klass_max_heap_loc = max([i[0] for i in target[-1]])
        self.pot_oop_headers = []

        klass_uses = self.klass_range_uses[self.oop_pot_heap_loc]
        for klass_ptr in klass_uses:
            markOop_addr = klass_ptr[0]-4
            klass_ref = klass_ptr[1]
            markOop_value = self.jva.read_dword(markOop_addr)
            self.pot_oop_headers.append([markOop_addr, markOop_value, klass_ptr[1]])

        oop_range = self.jva.find_range(self.oop_pot_heap_loc)
        for markOop_addr, value, klass in self.pot_oop_headers:
            kname = str(self.jva.loaded_classes_by_addr[klass])
            v = value & 0x3
            age = value & 0b1111000
            hash_ = value & ~ 0b1111111
            bias = value & 0b101 == 0b101
            normal_header = False if bias else 0x1 & value == 0x1
            jthread = 0 if not bias else value & ~ 0b111111111
            if v == 3 and\
                oop_range.in_range(value & (~0x3)):
                self.forwarded_oops.append((markOop_addr, value&~0x3, klass))
                self.forwarded_addrs.add(markOop_addr)
            elif kname == 'java/lang/Thread':
                self.heap_thread_oops[markOop_addr] =( value, age,  klass)
            elif bias:
                self.bias_oops[markOop_addr] = (jthread, age, klass)
            elif normal_header:
                self.normal_oops[markOop_addr] = (hash_, age, klass)
            else:
                self.unknown_oops[markOop_addr] = (value, age, klass)

    def klass_list(self):
        klass_list = self.jva.loaded_classes_by_name.keys()
        return klass_list

    def klass_dump(self, klass_name=None):
        if klass_name and klass_name in self.jva.loaded_classes_by_name:
            k = self.jva.loaded_classes_by_name[klass_name]
            return [{'class':klass_name,
                    'prototype':k.dump_class_prototypes()}]
        if klass_name is None:
            klasses = []
            for name, k in self.jva.loaded_classes_by_name.items():
                klasses.append({'class':name,
                                'prototype':k.dump_class_prototypes()})
            return klasses
        return []

    def scan_for_java_vframes(self):
        if len(self.jthread_start_mapping_thread_oop) == 0:
            self.find_all_loaded_thread_oops()

        # enumerate all uses of the given jthread
        if len(self.pot_jthread_ranges_uses) == 0:
            _, pot_jthread_ranges_uses = self.jva.scan_pages_for_dword_values(set(self.jthread_start_mapping_thread_oop.keys()))
            self.pot_jthread_ranges_uses = pot_jthread_ranges_uses

        pot_jthread_ranges_uses = self.pot_jthread_ranges_uses
        self.pot_call_wrapper_results = {}
        heap_loc_range = self.jva.find_range(self.pot_heap_loc)
        for r, locs in pot_jthread_ranges_uses.items():
            thread_results = []
            for addr, jthread_ptr in locs:
                loc = addr
                if not jthread_ptr in self.pot_vframe_arrays:
                    self.pot_vframe_arrays[jthread_ptr] = []
                m_addr = self.jva.read_dword(loc + 4*3)
                m = self.jva.get_method_only(m_addr) if m_addr else None
                if m is None:
                    continue
                vframe_array = VFrameArray.from_jva(loc, self.jva)
                if m and isinstance(vframe_array, VFrameArray):
                    res = {'klass':str(m.get_klass_holder()),
                           'caller':m.name(),
                           'vframe':vframe_array}
                    self.pot_vframe_arrays[jthread_ptr].append(res)
                elif isinstance(vframe_array, VFrameArray):
                    self.jva.forget_all_for_addr(loc)
        return self.pot_vframe_arrays


    def scan_for_java_call_wrappers(self):
        if len(self.jthread_start_mapping_thread_oop) == 0:
            self.find_all_loaded_thread_oops()

        # enumerate all uses of the given jthread
        if len(self.pot_jthread_ranges_uses) == 0:
            _, pot_jthread_ranges_uses = self.jva.scan_pages_for_dword_values(set(self.jthread_start_mapping_thread_oop.keys()))
            self.pot_jthread_ranges_uses = pot_jthread_ranges_uses

        pot_jthread_ranges_uses = self.pot_jthread_ranges_uses
        self.pot_call_wrapper_results = {}
        heap_loc_range = self.jva.find_range(self.pot_heap_loc)
        for r, locs in pot_jthread_ranges_uses.items():
            thread_results = []
            for addr, jthread_ptr in locs:
                callee_method_addr = self.jva.read_dword(addr+8)
                callee_method = self.jva.get_method_only(callee_method_addr)
                if callee_method is None:
                    continue
                oop_reciever_addr =  self.jva.read_dword(addr+0xc)
                oop_reciever = None
                if heap_loc_range.in_range(oop_reciever_addr):
                    oop_reciever = self.get_oop_by_addr(oop_reciever_addr)
                else:
                    continue
                call_wrapper = JavaCallWrapper.from_jva(addr, self.jva)
                results = {'jthread_addr':jthread_ptr,
                           'call_wrapper_addr':addr,
                           'call_wrapper_struct':call_wrapper, }
                results['callee_info'] = (callee_method_addr, callee_method)
                results['oop_info'] = (oop_reciever_addr, oop_reciever)
                thread_results.append(results)

                if not jthread_ptr in self.pot_call_wrapper_results:
                    self.pot_call_wrapper_results[jthread_ptr] = []
                self.pot_call_wrapper_results[jthread_ptr].append(results)

        return self.pot_call_wrapper_results

    def get_thread_infos(self, include_unsafe=False):
        self.thread_infos = {}
        if len(self.thread_oop_mapping_jthread) == 0:
            self.find_all_loaded_thread_oops()
        oops = []
        for k, eetop in self.thread_oop_mapping_jthread.items():
            oop = self.get_oop_by_addr(k)
            if oop and not oop.is_prim()  and 'java/lang/Thread' in oop.get_ordered_klass_dependencies():
                oop_values = getattr(oop, 'oop_field_values_by_name', None)
                kname = oop.klass_name()
                tid = None
                tname = None
                if oop_values and THREAD_KLASS in oop.oop_field_values_by_name:
                    tid = oop_values[THREAD_KLASS]['tid'].python_value()\
                                 if oop_values[THREAD_KLASS]['tid'] \
                                 else None
                    tname = oop_values[THREAD_KLASS]['name'].python_value()\
                                 if oop_values[THREAD_KLASS]['name'] \
                                 else None
                    self.thread_infos[k] = {'heap_address':k,
                                            'native_address':eetop,
                                        'name':tname, 'tid':tid}
        return self.thread_infos


    def scan_next_n_word_for_value(self, addr, n_dwords, values):
        r = self.jva.find_range(addr)
        dwords = r.read_all_as_ndwords_at_addr(addr, n_dwords)
        offset = 0
        results = []
        for dword in dwords:
            if dword in values:
                results.append((offset, dword))
            offset += 4
        return results

    def find_all_loaded_klass_oops(self, klass_name, **kargs):
        perform_update = kargs.get('perform_update', False)
        if not klass_name in self.jva.loaded_classes_by_name:
            return None
        klass = self.jva.loaded_classes_by_name[klass_name]
        filter_refs = set([klass.addr])
        pot_t_locs = [markOop_addr for markOop_addr, _, kref in self.pot_oop_headers if kref in filter_refs]
        oops = []
        if perform_update:
            oops = [self.get_oop_by_addr(addr) for addr in pot_t_locs]
        else:
            oops = [self.get_oop_by_addr(addr, False) for addr in pot_t_locs]
        valid_oops = []
        for oop in oops:
            if oop is None:
                continue
            fields = getattr(oop, 'oop_field_values_by_name', None)
            if perform_update and not fields is None:
                valid_oops.append(oop)
            else:
                valid_oops.append(oop)
        return valid_oops

    def find_env_vars(self, include_unsafe=False):
        property_uses = []
        properties_klass = self.jva.loaded_classes_by_name['java/util/Properties']
        for m, i in self.normal_oops.items():
            if i[-1] ==  properties_klass.addr:
                property_uses.append(self.get_python_object_at_addr(m))

        for m, i in self.bias_oops.items():
            if i[-1] ==  properties_klass.addr:
                property_uses.append(self.get_python_object_at_addr(m))

        if include_unsafe:
            for m,i in self.unknown_oops.items():
                if i[-1] ==  properties_klass.addr:
                    property_uses.append(self.get_python_object_at_addr(m))

        for po in property_uses:
            items = {}
            if po is None or po.table is None:
                continue

            for e in po.table:
                if e:
                    items[e.key] = e.value

            self.env_vars.update(items)
        return self.env_vars

    def find_sockets(self, include_unsafe=False):
        self.socket_info = {}
        socket_klass = []
        if 'java/net/DatagramSocket' in self.jva.loaded_classes_by_name:
            socket_klass.append(self.jva.loaded_classes_by_name['java/net/DatagramSocket'])
        if 'java/net/Socket' in self.jva.loaded_classes_by_name:
            socket_klass.append(self.jva.loaded_classes_by_name['java/net/Socket'])
        if len(socket_klass) == 0:
            return self.sockets
        socket_addrs = [i.addr for i in socket_klass]
        socket_pos = []
        for m,i in self.normal_oops.items():
            if i[-1] in socket_addrs:
                socket_pos.append(self.get_python_object_at_addr(m))

        for m,i in self.bias_oops.items():
            if i[-1] in socket_addrs:
                socket_pos.append(self.get_python_object_at_addr(m))

        if include_unsafe:
            for m,i in self.unknown_oops.items():
                if i[-1] in socket_addrs:
                    socket_pos.append(self.get_python_object_at_addr(m))

        socket_info = []
        get_inets = lambda x: socket.inet_ntoa(struct.pack(">I", x))
        for po in socket_pos:
            if po is None:
                continue
            res = {'localport':po.impl.localport,
                   'serverport':po.impl.port,
                   'connected':po.connected,
                   'remoteIp':get_inets(po.impl.address.holder.address),
                   'object_age':po.get_age()
                   }
            self.socket_info[po.addr] = res
        return self.socket_info

    def find_streams_and_buffers(self, include_unsafe=False):
        self.failed_streams_and_buffers = []
        klasses = [i for i in self.jva.loaded_classes_by_name if i.find('Input') > -1 or i.find('Output') > -1 ] + \
                  [i for i in self.jva.loaded_classes_by_name if i.find('Reader') > -1 or i.find('Writer') > -1 ]
        klasses = [i for i in klasses if i.find('java/util/zip/ZipFile') == -1 and\
                         i.find('java/io/FileInput') == -1 and i.find('java/io/FileOutput') == -1 ]
        klasses_addrs = [ self.jva.loaded_classes_by_name[i].addr for i in klasses]

        ko_uses = [m for m,i in self.normal_oops.items() if i[-1] in klasses_addrs] +\
                  [m for m,i in self.bias_oops.items() if i[-1] in klasses_addrs]


        if include_unsafe:
            for m,i in self.unknown_oops.items():
                if i[-1] in klasses_addrs:
                    ko_uses.append(m)


        ko_objs = []
        for i in ko_uses:
            po = self.get_python_object_at_addr(i)
            if po:
                ko_objs.append(po)

        self.io_streams = {}
        self.readers_writers = {}
        self.encoders_decoders = {}
        for po in ko_objs:
            if po is None:
                continue
            oop_type = po.oop_type
            encoder_decoder = hasattr(po, 'sd') or hasattr(po, 'se') or\
                              oop_type.find('Decoder') > -1 or oop_type.find('Encoder') > -1
            io_stream = oop_type.find('Input') > -1 or oop_type.find('Output') > -1
            reader_writer = oop_type.find('Reader') > -1 or oop_type.find('Writer') > -1

            if encoder_decoder:
                if not hasattr(po, 'sd') and not hasattr(po, 'se'):
                    #print ("Failed to add %s.sd. to encoder or decoder streams"%oop_type)
                    self.failed_streams_and_buffers.append((po.addr, oop_type))
                    continue
                if not oop_type in self.encoders_decoders:
                    self.encoders_decoders[oop_type] = []
                if hasattr(po, 'se') and\
                   po.se and hasattr(po.se, 'out') and\
                   po.se.out and hasattr(po.se.out, 'textOut') and\
                   po.se.out.textOut:
                    try:
                        self.encoders_decoders[oop_type].append((po.addr, po.se.out.textOut.cb))
                    except:
                        #print ("Failed to add %s.buf to encoder or decoder stream"%oop_type)
                        self.failed_streams_and_buffers.append((po.addr, oop_type))

                elif hasattr(po, 'sd') and\
                   po.sd and hasattr(po.sd, 'in') and\
                   getattr(po.sd, 'in') and hasattr(getattr(po.sd, 'in'), 'cb') and\
                   getattr(getattr(po.sd, 'in'), 'cb'):
                    try:
                        inbuf = getattr(getattr(po.sd, 'in'))
                        self.encoder_decoder[oop_type].append((po.addr, inbuf.cb))
                    except:
                        #print ("Failed to add %s.buf to encoder and decoder streams"%oop_type)
                        self.failed_streams_and_buffers.append((po.addr, oop_type))

            elif io_stream:
                if not hasattr(po, 'buf') and\
                   not hasattr(po, 'buffer') and \
                   not hasattr(po, 'out') and \
                   not hasattr(po, 'in'):
                    #print ("Failed to add %s.buf to io_streams @ %s"%(oop_type, hex(po.addr)))
                    self.failed_streams_and_buffers.append((po.addr, oop_type))
                    continue
                po_in = None
                if hasattr(po, 'in'):
                    po_in = getattr(po, 'in')

                if not oop_type in self.io_streams:
                    self.io_streams[oop_type] = []
                if po and hasattr(po, 'buf') and po.buf:
                    try:
                        self.io_streams[oop_type].append((po.addr, po.buf))
                    except:
                        #print ("Failed to add %s to io_streams for po @ %s"%(oop_type, hex(po.addr)))
                        self.failed_streams_and_buffers.append((po.addr, oop_type))
                elif po and hasattr(po, 'buffer') and po.buffer:
                    try:
                        self.io_streams[oop_type].append((po.addr, po.buffer.buf))
                    except:
                        #print ("Failed to add %s to io_streams for po @ %s"%(oop_type, hex(po.addr)))
                        self.failed_streams_and_buffers.append((po.addr, oop_type))
                elif po and hasattr(po, 'in') and po_in:
                    try:
                        self.io_streams[oop_type].append((po.addr, po.buffer.buf))
                    except:
                        #print ("Failed to add %s to io_streams for po @ %s"%(oop_type, hex(po.addr)))
                        self.failed_streams_and_buffers.append((po.addr, oop_type))
                else:
                    #print ("Failed to add %s to io_streams for po @ %s"%(oop_type, hex(po.addr)))
                    self.failed_streams_and_buffers.append((po.addr, oop_type))
            elif reader_writer:
                if not hasattr(po, 'cb'):
                    #print "Failed to add %s.cb to reader_writers"%oop_type
                    self.failed_streams_and_buffers.append((po.addr, oop_type))
                    continue
                if not oop_type in self.readers_writers:
                    self.readers_writers[oop_type] = []
                try:
                    self.readers_writers[oop_type].append((po.addr, po.cb))
                except:
                    #print "Failed to add %s.cb to reader_writers"%oop_type
                    self.failed_streams_and_buffers.append((po.addr, oop_type))


    def find_files(self, include_unsafe=False):
        self.file_infos = {}
        self.files = set()
        file_klass = 'java/io/File'
        filedesc_klass = 'java/io/FileDescriptor'
        fileoutputstream_klass = 'java/io/FileOutputStream'
        fileintputstream_klass = 'java/io/FileOutputStream'
        zipfile = 'java/util/zip/ZipFile'
        jarfile = 'java/util/jar/JarFile'
        zipfileInflater = 'java/util/zip/ZipFile$ZipFileInflaterInputStream'
        zipfileIs = 'java/util/zip/ZipFile$ZipFileInputStream'

        klasses = [file_klass,
                   filedesc_klass,
                   fileoutputstream_klass,
                   fileintputstream_klass,
                   zipfile,
                   jarfile,
                   zipfileInflater,
                   zipfileIs,
                   ]
        klasses_addrs = [ self.jva.loaded_classes_by_name[i].addr for i in klasses]

        ko_uses = [m for m, i in self.normal_oops.items() if i[-1] in klasses_addrs] +\
                  [m for m, i in self.bias_oops.items() if i[-1] in klasses_addrs]


        if include_unsafe:
            for m,i in self.unknown_oops.items():
                if i[-1] in klasses_addrs:
                    ko_uses.append(m)

        ko_objs = []
        for i in ko_uses:
            po = self.get_python_object_at_addr(i)
            ko_objs.append(po)

        for o in ko_objs:
            if o is None:
                continue
            oop_type = o.oop_type
            if oop_type == 'java/util/zip/ZipFile$ZipFileInputStream' or\
               oop_type == 'java/util/zip/ZipFile$ZipFileInflaterInputStream' and\
               hasattr(o, 'this$0'):
                zip_this = getattr(o, 'this$0')
                if hasattr(zip_this, 'name'):
                    self.files.add(zip_this.name)
                    if not zip_this.name in self.file_infos:
                        self.file_infos[zip_this.name] = []
                    self.file_infos[zip_this.name].append((o.addr, oop_type))
            elif oop_type == 'java/io/FileDescriptor' and \
                 o.parent and o.parent.path:
                self.files.add(o.parent.path)
                if not o.parent.path in self.file_infos:
                    self.file_infos[o.parent.path] = []
                self.file_infos[o.parent.path].append((o.addr, oop_type))
            elif oop_type == 'java/io/File' and \
                 o.path:
                self.files.add(o.path)
                if not o.path in self.file_infos:
                    self.file_infos[o.path] = []
                self.file_infos[o.path].append((o.addr, oop_type))

            elif oop_type == 'java/util/jar/JarFile' or oop_type == 'java/util/zip/ZipFile' and \
                 o.name:
                self.files.add(o.name)
                if not o.name in self.file_infos:
                    self.file_infos[o.name] = []
                self.file_infos[o.name].append((o.addr, oop_type))

        return self.file_infos, self.files


    def find_strings(self, include_unsafe=False):

        klasses = ['java/lang/String',
                   ]
        klasses_addrs = [ self.jva.loaded_classes_by_name[i].addr for i in klasses]

        ko_uses = [m for m, i in self.normal_oops.items() if i[-1] in klasses_addrs] +\
                  [m for m, i in self.bias_oops.items() if i[-1] in klasses_addrs]


        if include_unsafe:
            for m,i in self.unknown_oops.items():
                if i[-1] in klasses_addrs:
                    ko_uses.append(m)

        ko_objs = []
        for i in ko_uses:
            po = self.get_python_object_at_addr(i)
            if po:
                self.strings[i] = (po, self.get_age(i))
        return self.strings

    def get_thread_name(self, jthread_or_oop):
        if len(self.confirmed_java_thread) == 0:
            self.find_all_loaded_thread_oops()
        if jthread_or_oop in self.jthread_start_mapping_thread_oop:
            jthread_or_oop = self.jthread_start_mapping_thread_oop[jthread_or_oop]
        elif jthread_or_oop in self.thread_oop_mapping_jthread:
            jthread_or_oop = jthread_or_oop
        elif hasattr(jthread_or_oop, 'addr') and \
             hasattr(jthread_or_oop, '_name') and \
             jthread_or_oop._name.find('Oop') > -1 and \
             jthread_or_oop.addr in self.thread_oop_mapping_jthread:
            jthread_or_oop = jthread_or_oop.addr
        else:
            jthread_or_oop = None
        if jthread_or_oop:
            po = self.get_python_object_at_addr(jthread_or_oop)
            if po and hasattr(po, 'name'):
                return po.name
        return None

    def get_main_thread(self):
        if len(self.confirmed_java_thread) == 0:
            self.find_all_loaded_thread_oops()
        for t in self.confirmed_java_thread.values():
            po = self.get_python_object(t)
            if po.name == 'main':
                return po
        return None

    def enumerate_threads_from_thread(self, thread_py_obj, known_threads):
        tk_name = 'java/lang/Thread'
        tgk_name = 'java/lang/ThreadGroup'
        res = []
        if thread_py_obj is None or\
           thread_py_obj.group is None or\
           thread_py_obj.group.threads is None:
           return res
        for t_obj in thread_py_obj.group.threads:
            if t_obj and not t_obj.addr in known_threads:
                known_threads.add(t_obj.addr)
                res.append(self.get_oop_by_addr(t_obj.addr))
                tres = self.enumerate_threads_from_thread(t_obj, known_threads)
                res = res + tres
        return res

    def find_all_loaded_thread_oops(self):
        # identify potential class derivatives
        tk_name = 'java/lang/Thread'
        tgk_name = 'java/lang/ThreadGroup'
        thread_derivatives = set()
        filter_thread_refs = set()
        for klass in self.jva.loaded_classes_by_name.values():
            if tk_name in klass.klass_dependencies:
                thread_derivatives.add(str(klass))
                filter_thread_refs.add(klass.addr)

        # enumerate potential thread mark oop addresses
        pot_t_locs = [markOop_addr for markOop_addr, _, kref in self.pot_oop_headers if kref in filter_thread_refs and not markOop_addr in self.forwarded_addrs]
        oops = []
        for oop_addr in pot_t_locs:
            #print "Forgettting Oop: %s"%hex(oop_addr)
            #self.jva.forget_all_for_addr(oop_addr)
            oop = self.get_oop_by_addr(oop_addr)
            #print "Found Oop: %s"%str(oop)
            oops.append(oop)

        #oops = [self.get_oop_by_addr(addr) for addr in pot_t_locs]
        known_threads = set([oop.addr for oop in oops if oop])
        main_oop = None
        discovered_oops = []
        for toop in oops:
            fields = getattr(toop, 'oop_field_values_by_name', None) if toop\
                              else None
            if fields is None or\
               toop._name.find('Oop') < 0:
                continue
            #print "Converting %s to Python object: %s"%(hex(toop.addr), str(toop))
            po = self.get_python_object(toop, reset=True)
            if po is None or\
               isinstance(po, long) or\
               isinstance(po, int) or\
               not hasattr(po, 'group') or\
               po.group is None or\
               po.group.threads is None:
               continue
            if po.eetop == 0:
                continue

            self.jthread_start_mapping_thread_oop[po.eetop] = po.addr
            self.thread_oop_mapping_jthread[po.addr] = po.eetop
            self.thread_oop_by_name[po.name] = po
            self.confirmed_java_thread[po.addr] = toop
            self.oop_by_thread_obj[po.addr] = set()

            for t in po.group.threads:
                if t and not t.addr in known_threads:
                    self.log( "%s not in known threads"%t.name)
                if t:
                    oop = self.get_oop_by_addr(t.addr)
                    self.jthread_start_mapping_thread_oop[t.eetop] = t.addr
                    self.thread_oop_mapping_jthread[t.addr] = t.eetop
                    self.confirmed_java_thread[t.addr] = oop
                    self.oop_by_thread_obj[t.addr] = set()


        valid_bias_oops = {}
        for markOop_addr, t  in self.bias_oops.items():
            jthread, age, klass = t
            if jthread in self.jthread_start_mapping_thread_oop:
                to_addr = self.jthread_start_mapping_thread_oop[jthread]
                self.oop_by_thread_obj[to_addr].add(markOop_addr)
                valid_bias_oops[markOop_addr] = (jthread, age, klass)
            else:
                value = self.jva.read_dword(markOop_addr)
                self.unknown_oops[markOop_addr] = (value, age, klass)
        self.bias_oops = valid_bias_oops




    def find_all_mirror_and_klass_refs(self, **kargs):
        self.jm_oop_addr_uses, self.jm_oop_range_uses = self.jva.scan_pages_for_java_mirrors_32()
        self.klass_addr_uses, self.klass_range_uses = self.jva.scan_pages_for_klasses_32()
        return True

    def find_key_oop_values(self):
        apploaderKlass = 'sun/misc/Launcher$AppClassLoader'
        apploader_addr = self.jva.loaded_classes_by_name[apploaderKlass]
        threadKlass = 'java/lang/Thread'
        thread_addr = self.jva.loaded_classes_by_name[threadKlass]
        systemKlass = 'java/lang/System'
        system_addr = self.jva.loaded_classes_by_name[systemKlass]
        propertiesKlass = 'java/util/Properties'
        properties_addr = self.jva.loaded_classes_by_name[propertiesKlass]
        self.key_objs = {apploader_addr:[], system_addr:[], properties_addr:[]}

    def get_metaspace_pointers(self, **kwargs):
        pointer_lists = []
        for e in self.klass_entries.values():
            pointer_lists.append(e)
        for e in self.constant_pools.values():
            pointer_lists.append(e)
        for e in self.symbol_table_entries.values():
            pointer_lists.append(e)
        for e in self.methods_entries.values():
            pointer_lists.append(e)
        return list(itertools.chain(*pointer_lists))


    def enumerate_internal_object_groupings(self, **kargs):
        self.find_all_mirror_and_klass_refs()
        self.constant_pools = {}
        self.symbol_table_entries = {}
        self.methods_entries = {}
        self.string_table_entries = {}
        self.jm_oop_entries = {}
        self.klass_entries = {} # not usages

        for entry in self.jva.vm_symboltable.get_bucket_values():
            symtr = self.jva.find_range(entry.addr)
            if symtr and symtr.start not in self.symbol_table_entries:
                self.symbol_table_entries[symtr.start] = []
            if symtr:
                self.symbol_table_entries[symtr.start].append(entry.addr)

        for entry in self.jva.vm_stringtable.get_bucket_values():
            strt = self.jva.find_range(entry.addr)
            if strt and strt.start not in self.string_table_entries:
                self.string_table_entries[strt.start] = []
            if strt:
                self.string_table_entries[strt.start].append(entry.addr)

        for jm_oop in self.jva.loaded_jm_oop_by_name.values():
            jmr = self.jva.find_range(jm_oop.addr)
            if jmr and jmr.start not in self.jm_oop_entries:
                self.jm_oop_entries[jmr.start] = []
            if jmr:
                self.jm_oop_entries[jmr.start].append(jm_oop.addr)

        for klass in self.jva.loaded_classes_by_addr.values():
            kr = self.jva.find_range(klass.addr)
            if kr:
                if not kr.start in self.klass_entries:
                    self.klass_entries[kr.start] = []
                self.klass_entries[kr.start].append(klass.addr)

            constants = getattr(klass, 'constants', None)
            cpr = self.jva.find_range(constants)
            if cpr:
                if not cpr.start in self.constant_pools:
                    self.constant_pools[cpr.start] = []
                cp_value = getattr(klass, 'constants_value', None)
                entries = None if cp_value is None else getattr(cp_value, 'entrys', None)
                if entries:
                    for e in entries:
                        if e is None:
                            continue
                        er = self.jva.find_range(e.addr)
                        if er is None:
                            continue
                        if not er.start in self.constant_pools:
                            self.constant_pools[er.start] = []
                        self.constant_pools[er.start].append(e.addr)

            methods = getattr(klass, 'methods', None)
            mr = self.jva.find_range(methods)
            if mr:
                if not mr.start in self.methods_entries:
                    self.methods_entries[mr.start] = []
                methods_value = getattr(klass, 'methods_value', None)
                entries = None if methods_value is None else getattr(methods_value, 'elem', None)
                if entries:
                    for e in entries:
                        if e is None:
                            continue
                        er = self.jva.find_range(e.addr)
                        if er is None:
                            continue
                        if not er.start in self.methods_entries:
                            self.methods_entries[er.start] = []
                        self.methods_entries[er.start].append(e.addr)
                        ecmd = getattr(e, 'const_method_value', None)
                        if ecmd is None:
                            continue

                        ecmdr = self.jva.find_range(ecmd.addr)
                        if ecmdr is None:
                            continue

                        self.methods_entries[ecmdr.start].append(ecmd.addr)
                        if ecmd.stackmap_data > 0:
                            self.methods_entries[ecmdr.start].append(ecmd.stackmap_data)
        return True






