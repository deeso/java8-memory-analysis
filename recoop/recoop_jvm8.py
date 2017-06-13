from tabulate import tabulate
import os, copy, sys, struct, socket, threading
from datetime import datetime, timedelta
import recoop
import itertools
PATH_TO_JVM_MODULE = "/research_data/code/git/jvm_analysis"
from datetime import datetime
from jvm.jvm_klassoop import Oop
from jvm.jvm_base import JAVA_LANG_PRIMITIVES_LIST
from jvm.jvm_objects import JavaCallWrapper, VFrameArray, BytecodeInterpreter

JAVA_LANG_PRIMITIVES_SET = set([i for i in JAVA_LANG_PRIMITIVES_LIST if i.find('java/lang/') > -1])
JAVA_LANG_PRIMITIVES_SET.add('java/lang/String')

def time_str():
    return str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))

APPLOADER_KLASS = 'sun/misc/Launcher$AppClassLoader'
THREAD_KLASS = 'java/lang/Thread'
SYSTEM_KLASS = 'java/lang/System'
PROPERTIES_KLASS = 'java/util/Properties'
NULL_OOP_TYPE = "null"
DUMPS_DIR = "dumps"
DUMPS_LOCATION= lambda p: os.path.join(p, DUMPS_DIR)



class RecOOPJVM8(recoop.RecOOPInterface):
    def __init__(self, dump_java_process=False, path_to_dumps=None, path_to_mem=None,
                 jvm_module_loc=PATH_TO_JVM_MODULE,
                 jvm_start_addr=None, is_32bit=True,
                 word_sz=4, little_endian=True, is_linux=True,
                 jvm_ver=None, pid=None, **kargs):

        recoop.RecOOPInterface.__init__(self, **kargs)
        self.po_to_update = []
        self.overwrite = True
        self.imported_prims = False
        self.found_values = {}
        self.updated = {}
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

        self.instream_linkage = {}
        self.outstream_linkage = {}
        self.outputstream_buffers = {}
        self.inputstream_buffers = {}
        self.reader_buffers = {}
        self.writer_buffers = {}
     
        self.reader_linkage = {}
        self.writer_linkage = {}
        self.buffered_streams = {}
        self.reader_writers = {}
        self.java_fd_users = {}
        self.fd_oops = {}

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
        self.strings_rev_mapping = {}
        self.strings_set = set()
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
        self.pot_interpretter_state = {}
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

    #def forget_py_obj(self, oop):
    #    addr = oop.addr
    #    self.forget_py_obj_at_addr(addr)

    def forget_py_obj(self, oop):
        addr = None
        if oop and hasattr(oop, 'addr'):
           addr = oop.addr
        if addr and addr in self.updated:
            del self.updated[addr]
        if addr and addr in self.found_values:
            del self.found_values[addr]
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
            return
            #raise Exception("Attempting to overwrite Python Object in known objects")
        self.oop_py_objs[addr] = py_obj

    def query_oop_type(self, addr):
        oop = self.get_oop_by_addr(addr)
        if oop is None:
            return None
        klass = oop.get_klass()
        return str(klass)

    def get_oop_by_addr(self, addr, perform_update=True, expected_klass_name=None):
        oop = self.jva.lookup_known_oop(addr)
        if perform_update and oop and oop._name.find('Oop') > -1:
            if expected_klass_name and \
               oop.klass_name().find(expected_klass_name) == -1:
                return -1
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

    def build_oop_python_values_by_addr(self, addr, recurse_oops=True, use_internals_knowledge=False):
        oop = self.get_oop_by_addr(addr)
        if oop is None:
            return False
        return self.build_oop_python_values(oop, recurse_oops=recurse_oops, use_internals_knowledge=use_internals_knowledge)

    def build_oop_python_values(self, oop, recurse_oops=True, use_internals_knowledge=False, set_oop_dicts=True):
        if oop is None:
            self.debug_v2 = None
            return False
        found_values = {}
        bread_crumbs = {}
        updated = {}
        if use_internals_knowledge:
            found_values = self.found_values
            bread_crumbs = self.oop_dict
            updated = self.updated
        #v2 = oop.python_value(klass_name=klass_name, field_name=field_name, bread_crumbs=self.oop_dict)
        v2 = None
        if oop.is_prim() and (not hasattr(oop, 'oop_dict') or not hasattr(oop, 'updated_value')):
            v2 = oop.python_value(set_bread_crumbs=set_oop_dicts, found_values=found_values, bread_crumbs=bread_crumbs, updated=updated)
            self.found_values[oop.addr] = v2
            self.updated[oop.addr] = v2
            setattr(oop, 'oop_dict', bread_crumbs)
            #setattr(oop, 'found_values', found_values)
            setattr(oop, 'updated_value', updated)

                  
        elif (not hasattr(oop, 'oop_dict') or not hasattr(oop, 'updated_value')):
            v2 = oop.build_python_value(set_bread_crumbs=set_oop_dicts, found_values=found_values, bread_crumbs=bread_crumbs, updated=updated)
            #setattr(oop, 'oop_dict', bread_crumbs)
            #setattr(oop, 'found_values', found_values)
            #setattr(oop, 'updated_value', updated)
            
        #if oop.is_prim() and addr in self.oop_dict:
        #    self.updated[oop.addr] = self.oop_dict[addr]['value']
        #for v in self.oop_dict.values():
        #    if 'ref_addrs' in v:
        #        del v['ref_addrs']

        self.debug_v2 = v2
        #po = self.get_python_object(oop)
        #self.debug_po = po
        return True

    def get_age(self, addr):
        if addr in self.bias_oops:
            return self.bias_oops[addr][1]
        elif addr in self.normal_oops:
            return self.normal_oops[addr][1]
        elif addr in self.unknown_oops:
            return self.heap_thread_oops[addr][1]
        else:
            return None
    # FIXME rename this back to get original functionality
    # get_python_object_at_addr
    #def get_python_object_at_addr(self, addr):
    #    oop_dict = None
    #    if not addr in self.oop_dict:
    #        oop_dict = self.build_oop_python_values_by_addr(addr)
    #    if addr in self.oop_dict:
    #        oop_dict = self.oop_dict[addr]
    #    return self.create_python_oop_object(oop_dict)
    # created this to simplify object creation

    def get_python_object_at_addr(self, addr):
        return self.get_python_object_at_addr_updated(addr)

    def get_python_object_at_addr_updated(self, addr, reanalyse=False):
        no_py_obj = not addr in self.oop_py_objs
        if reanalyse:
            self.build_oop_python_values_by_addr(addr)
        if no_py_obj and not addr in self.oop_dict:
            self.build_oop_python_values_by_addr(addr)
        elif no_py_obj and not addr in self.updated:
            self.build_oop_python_values_by_addr(addr)
        return self.get_python_obj(addr, reanalyse=reanalyse)
        #return self.handle_create_python_oop_updated(addr)

    def get_python_obj(self, addr, recurse_oops=True, use_internals_knowledge=False, reanalyse=False):
        if not reanalyse and addr in self.oop_py_objs:
            return self.oop_py_objs[addr]
        return self.load_update_python_objects(addr, recurse_oops=recurse_oops, use_internals_knowledge=use_internals_knowledge)
    
    def load_update_python_objects(self, addr, recurse_oops=True, use_internals_knowledge=False):
        #if not addr in self.oop_dict:
        #    self.build_oop_python_values_by_addr(addr, recurse_oops=recurse_oops, use_internals_knowledge=use_internals_knowledge)
        #elif not addr in self.updated:
        #    self.build_oop_python_values_by_addr(addr, recurse_oops=recurse_oops, use_internals_knowledge=use_internals_knowledge)
        oop = self.get_oop_by_addr(addr)
        if not hasattr(oop, 'oop_dict') or not hasattr(oop, 'updated_value'):
            self.build_oop_python_values_by_addr(addr, recurse_oops=recurse_oops, use_internals_knowledge=use_internals_knowledge)
        if (use_internals_knowledge and (not addr in self.updated or not addr in self.oop_dict)) or\
           not hasattr(oop, 'oop_dict') or not hasattr(oop, 'updated_value'):
            self.build_oop_python_values_by_addr(addr, recurse_oops=recurse_oops, use_internals_knowledge=use_internals_knowledge)
        po_to_update, oop_dict, updated = self.scan_create_relevant_oops(addr)
        for is_array, addr in po_to_update:
            if is_array:
                self.update_po_array(addr, oop_dict, updated )
            else:
                self.update_po(addr, oop_dict, updated)
        #po = self.get_python_object_at_addr_updated(addr, oop_dict, updated)
        po = self.get_python_object_at_addr_updated(addr)
        return po
            
    def update_po_array(self, addr, oop_dict, updated):
        po = None if not addr in self.oop_py_objs\
                       else self.oop_py_objs[addr]
        oop_type = self.query_oop_type(addr)
        oop = self.get_oop_by_addr(addr)
        oop_values = getattr(oop, "oop_values", None)
        if oop is None:
            return
        if not isinstance(po, recoop.RecOOPArray):
            po = recoop.RecOOPArray(addr, oop_type)
            self.add_py_obj(addr, po, overwrite=True)
            if oop_values is None:
                return
            for value in oop_values:
                po.append(None)
            
            
        pos = 0
        logit = False# if oop_type.find('Hashtable') == -1 else True
        for coop in oop_values:
            cpo = None if coop is None or not coop.addr in self.oop_py_objs\
                       else self.oop_py_objs[coop.addr]
            if logit:
                self.log("Handling insertion python object %s creation for: %s @ 0x%08x"%( str(coop), oop_type, addr))
            po[pos] = cpo
            pos += 1

    def update_po(self, addr, oop_dict, updated):
        po = None if not addr in self.oop_py_objs\
                       else self.oop_py_objs[addr]
        value = None if not addr in updated\
                       else updated[addr]
        oop_dict = None if not addr in oop_dict\
                       else oop_dict[addr]
        oop = self.get_oop_by_addr(addr)
        if oop is None:
            return
        klass_fld_values = getattr(oop, 'oop_field_values_by_name', None)
        
        klasses = oop.get_ordered_klass_dependencies()
        for klass_name in klasses:
            if not klass_name in klass_fld_values:
                continue
            for field, foop in klass_fld_values[klass_name].items():
                res_key = "%s:%s"%(klass_name, field)
                cpo = None if not foop or not foop.addr in self.oop_py_objs\
                           else self.oop_py_objs[foop.addr]
                if hasattr(po, field) and klass_name == po.oop_type:
                    po.add_field(field, cpo)
                else:
                    po.add_field(field, cpo)
                po.add_field_by_key(res_key, cpo)

    def accumulate_oop_addrs(self, addr):
        addrs = set()
        oop = self.get_oop_by_addr(addr)
        if oop is None:
            return addrs
        oops_to_accumulate = [(oop.addr, oop)]
        while len(oops_to_accumulate) > 0:
            addr, oop = oops_to_accumulate.pop()
            if addr in addrs:
                continue
                
            addrs.add(addr)
                   
            oop_type = self.query_oop_type(addr)
            if oop is None or oop.is_prim(): 
               continue
            elif not oop.is_array_oop():
                klass_fld_values = getattr(oop, 'oop_field_values_by_name', None)
                for klass_name in klass_fld_values:
                    for field, foop in klass_fld_values[klass_name].items():
                        if foop and not foop.addr in addrs:
                            oops_to_accumulate.append((foop.addr, foop))
            elif oop.is_array_oop():
                oop_values = getattr(oop, "oop_values", None)
                if oop_values is None:
                    continue

                for oop_value in oop_values:
                    if oop_value and not oop_value.addr in addrs:
                        oops_to_accumulate.append((oop_value.addr, oop_value))
        return addrs
    def create_recoop_obj(self, addr, oop_type, is_array=False, overwrite=False):
        po = None
        if is_array:
            po = recoop.RecOOPArray(addr, oop_type)
        else:
            po = recoop.RecOOPObject(addr, oop_type)
        self.add_py_obj(addr, po, overwrite=overwrite)
        return po
    
    def scan_create_relevant_oops(self, addr):
        # find all the related oops from addr
        oop = self.get_oop_by_addr(addr)
        if oop is None:
            return []
        init_addrs = self.accumulate_oop_addrs(addr)
        if len(init_addrs) == 0:
            return []
        po_to_update = []
        
        _updated = {}
        _oop_dict = {}
        for addr in init_addrs:
            oop = self.get_oop_by_addr(addr)
            oop_dict = None if oop is None \
                       else getattr(oop, 'oop_dict', {}).get(addr, None)
            value = None if oop is None \
                     else getattr (oop, 'updated_value', {}).get( addr, None)
            _updated[addr] = value
            _oop_dict[addr] = oop_dict
            if oop is None or oop.is_prim():
                value = self.handle_create_python_prim_oop_updated(addr)
                #if addr in oop_dict:
                #    oop_dict[addr]['value'] = value
                #oop.updated_value[addr] = value
                #_updated[addr] = value
                continue
                
            oop_type = self.query_oop_type(addr)
            if oop_type in JAVA_LANG_PRIMITIVES_SET:
               self.convert_java_lang_prim_to_python_oop_updated(addr, oop_type)
            elif oop.is_array_oop():
                oop_values = getattr(oop, "oop_values", None)
                po = self.create_recoop_obj(addr, oop_type, is_array=True, overwrite=False)
                for oop_value in oop_values:
                    if oop_value is None:
                        po.append(None)
                    elif oop_value.addr in self.oop_py_objs:
                        po.append(self.oop_py_objs[oop_value.addr])
                    elif not oop_value.addr in init_addrs:
                        raise Exception("Oop addr (0x%08x) not in init_addrs for %s @ 0x%08x"%(oop_value.addr, oop_type, addr))
                        #po.append(None)
                    else:
                        po.append(None)
                #pos = len(oop_values) if oop_values else 0
                #while pos > 0:
                #    po.append(None)
                #    pos += -1
                po_to_update.append((True, addr))
            else:
                po = self.create_recoop_obj(addr, oop_type, is_array=False, overwrite=False)
                po_to_update.append((False, addr))

        return po_to_update, _oop_dict, _updated

    def update_internal_knowledge_by_addr(self, addr):
        addrs = self.accumulate_oop_addrs( addr)
        for addr in addrs:
            oop = self.get_oop_by_addr(addr)
            if oop:
                self.oop_dict.update(getattr(oop, 'oop_dict', {}))
                self.updated.update(getattr(oop, 'updated_value', {}))

    def update_internal_knowledge_just_oop(self, oop):
        if oop:
            self.oop_dict.update(getattr(oop, 'oop_dict', {}))
            self.updated.update(getattr(oop, 'updated_value', {}))
        

    def create_python_oop_object_updated(self, addr):
        return self.handle_create_python_oop_updated(addr)

    def convert_java_lang_prim_to_python_oop_updated(self, addr, oop_type=None):
        oop = self.get_oop_by_addr(addr)
        oop_dict = None if oop is None \
                       else getattr(oop, 'oop_dict', {}).get(addr, None)
        value = None if oop is None \
                     else getattr(oop, 'updated_value', {}).get( addr, None)
        if oop_dict is None and value is None:
            po = recoop.RecOOPObject(addr, NULL_OOP_TYPE)
            self.add_py_obj(addr, po)
            return po

        if oop_type is None:
            oop_type = self.query_oop_type(addr)

        value_key = "%s:value"%oop_type
        prim_value = None
        if value and value_key in value:
           prim_value = value[value_key]
        
        self.add_py_obj(addr, prim_value, overwrite=self.overwrite)
        return prim_value
 
    def handle_create_python_prim_oop_updated(self, addr, overwrite=False):
        oop = self.get_oop_by_addr(addr)
        oop_dict = None if oop is None \
                       else getattr(oop, 'oop_dict', {}).get(addr, None)
        value = None if oop is None  or oop_dict is None\
                     else oop_dict['value']


        if self.has_py_obj(addr) and not overwrite:
            return self.get_py_obj(addr)

        if oop and value is None:
            value = oop.python_value()
        elif value is None:
            po = recoop.RecOOPObject(addr, NULL_OOP_TYPE)
            self.add_py_obj(addr, po)
            return po
        self.add_py_obj(addr, value)
        return value

    def handle_create_python_oop_updated(self, addr):
        po = None if not addr in self.oop_py_objs\
                       else self.oop_py_objs[addr]
        value = None if not addr in self.updated\
                       else self.updated[addr]
        oop_dict = None if not addr in self.oop_dict\
                       else self.oop_dict[addr]

        oop = self.get_oop_by_addr(addr)
        oop_type = self.query_oop_type(addr)
        if po:
            return po
        elif oop is None or (oop_dict is None and update is None):
            po = recoop.RecOOPObject(addr, NULL_OOP_TYPE)
            self.add_py_obj(addr, po)
            return po

        if oop_dict['is_array']:
           return self.handle_create_python_array_oop_updated(addr)
        elif oop_dict['is_prim']:
           return self.handle_create_python_prim_oop_updated(addr)

        oop_type = self.query_oop_type(addr)
        if oop_type in JAVA_LANG_PRIMITIVES_SET:
           return self.convert_java_lang_prim_to_python_oop_updated(addr, oop_type)

        #if not isinstance(value, dict) and not oop_dict['is_prim']:
        #   #print "handling PO:", oop_dict
        #   return self.handle_create_python_prim_oop_updated(oop_dict)

        po = recoop.RecOOPObject(addr, oop_type)
        klass_fld_values = getattr(oop, 'oop_field_values_by_name', None)
        if klass_fld_values is None:
            self.add_py_obj(addr, po)
            return po
        
        klasses = oop.get_ordered_klass_dependencies()
        for klass_name in klasses:
            if not klass_name in klass_fld_values:
                continue
            for field, foop in klass_fld_values[klass_name].items():
                res_key = "%s:%s"%(klass_name, field)
                cpo = None
                if foop:
                    cpo = self.handle_create_python_oop_updated(foop.addr)
                if hasattr(po, field) and klass_name == po.oop_type:
                    po.add_field(field, cpo)
                else:
                    po.add_field(field, cpo)
                po.add_field_by_key(res_key, cpo)

        return po

    def handle_create_python_array_oop_updated(self, addr):
        if self.has_py_obj(addr):
            return self.get_py_obj(addr)
        value = None if not addr in self.updated \
                     else self.updated[addr]
        oop_dict = None if not addr in self.oop_dict\
                     else self.oop_dict[addr]
        if value is None or oop_dict is None:
            self.add_py_obj(addr, value)
            return value
        elif oop_dict['is_prim'] and isinstance(value, str):
            self.add_py_obj(addr, value)
            return value
        #elif self.is_python_native(value):
        #    self.log("[XXXX] Error, attempting to set an array with a value (%s) @ %s"%(value, hex(addr)))
        #    self.add_py_obj(addr, None)
        #    return None

        oop_type = self.query_oop_type(addr)
        po = recoop.RecOOPArray(addr, oop_type)
        self.add_py_obj(addr, po)
        oop = self.get_oop_by_addr(addr)
        oop_values = getattr(oop, "oop_values", None)
        for coop in oop_values:
            cpo = None
            if coop and coop.addr:
                cpo = self.handle_create_python_oop_updated(coop.addr)
            po.append(cpo)
        return po

    def get_python_object_updated(self, oop, reset=False):
        if oop is None:
            return None
        return self.get_python_object_at_addr_updated(oop.addr)

    def get_python_object(self, oop, reset=False):
        if oop is None:
            return None
        return self.get_python_object_at_addr_updated(oop.addr)
        #return self.get_python_object_updated(oop)
    #def get_python_object(self, oop, reset=False):
    #    oop_dict = None
    #    if oop is None:
    #        return None
    #    addr = oop.addr
    #    if self.has_py_obj(addr):
    #        po = self.get_python_object_at_addr(addr)
    #        if po is None:
    #            return None
    #        oop_type = oop.klass_name()
    #        native = oop.is_python_native(po)
    #        if oop.is_prim() and oop.is_python_native(po) or\
    #           oop_type in JAVA_LANG_PRIMITIVES_SET and native:
    #            return po
    #        elif oop_type == "java/lang/String" and isinstance(po, str):
    #            return po
    #        elif not native and po.oop_type == oop_type:
    #            return po
    #        if reset:
    #            self.forget_py_obj(oop)
    #            oop = Oop.from_jva(addr, self.jva)
    #            return self.get_python_object(oop)
    #        return po
    #    return self.get_python_object_at_addr(oop.addr)

    #def create_python_oop_object(self, oop_dict):
    #    return self.handle_create_python_oop(oop_dict)

    #def handle_create_python_array_oop(self, oop_dict):
    #    addr = oop_dict['addr']
    #    if self.has_py_obj(addr):
    #        return self.get_py_obj(addr)
    #    if not oop_dict['is_array']:
    #       raise Exception('Attempting to create an array OOP with invalid oop dict')
    #    value = oop_dict['value']
    #    if value is None:
    #        self.add_py_obj(addr, value)
    #        return value
    #    elif oop_dict['is_prim'] and isinstance(value, str):
    #        self.add_py_obj(addr, value)
    #        return value
    #    elif self.is_python_native(value):
    #        self.log("[XXXX] Error, attempting to set an array with a value (%s) @ %s"%(value, hex(addr)))
    #        self.add_py_obj(addr, None)
    #        return None
    #    oop_type = self.query_oop_type(addr)
    #    po = recoop.RecOOPArray(addr, oop_type)
    #    self.add_py_obj(addr, po)
    #    for coop_dict in value:
    #        cpo = None
    #        if coop_dict and 'value' in coop_dict and coop_dict['value']:
    #            cpo = self.create_python_oop_object(coop_dict)
    #        po.append(cpo)
    #    return po

    #def convert_java_lang_prim_to_python_oop(self, oop_dict, oop_type=None):
    #    if oop_dict is None:
    #        return None
    #    addr = oop_dict['addr']
    #    value = oop_dict['value']
    #    if oop_type is None:
    #        oop_type = self.query_oop_type(addr)
    #    value_key = "%s:value"%oop_type
    #    new_value = None
    #    if value and value_key in value and value[value_key]:
    #        new_value = value[value_key]['value'] \
    #                    if 'value' in value[value_key] \
    #                    else None
    #    new_oop_dict = {}
    #    new_oop_dict.update(oop_dict)
    #    new_oop_dict['value'] = new_value
    #    new_oop_dict['is_prim'] = True
    #    #print "converting a java/lang/PRIM to python primitive:", new_oop_dict
    #    return self.handle_create_python_prim_oop(new_oop_dict)

    def mark_java_metadata(self, po):
        marked = False
        jthread = None
        age = None
        hash_ = None
        value = None
        if self.is_python_native(po):
            return marked
        markOop_addr = po.get_addr()
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


    #def handle_create_python_oop(self, oop_dict):
    #    if oop_dict is None:
    #        return None
    #    addr = oop_dict['addr']
    #    value = oop_dict['value']
    #    if self.has_py_obj(addr):
    #        return self.get_py_obj(addr)
    #    if oop_dict['is_array']:
    #       return self.handle_create_python_array_oop(oop_dict)
    #    elif oop_dict['is_prim'] or value is None:
    #       return self.handle_create_python_prim_oop(oop_dict)
    #    oop_type = self.query_oop_type(addr)
    #    if oop_type in JAVA_LANG_PRIMITIVES_SET:
    #       return self.convert_java_lang_prim_to_python_oop(oop_dict)
    #    if not isinstance(value, dict) and not oop_dict['is_prim']:
    #       #print "handling PO:", oop_dict
    #       return self.handle_create_python_prim_oop(oop_dict)
    #    po = recoop.RecOOPObject(addr, oop_type)
    #    self.add_py_obj(addr, po)
    #    ordered_deps = self.query_oop_klasses(addr)
    #    field_keys = value.keys()
    #    field_keys.sort()
    #    for fld_key, coop_dict in value.items():
    #        klass, field = fld_key.split(':')
    #        #print "fld_key: ", fld_key,"type: ",type(coop_dict)
    #        cpo = self.handle_create_python_oop(coop_dict)
    #        if hasattr(po, field) and klass == po.oop_type:
    #            po.add_field(field, cpo)
    #        else:
    #            po.add_field(field, cpo)
    #            #setattr(po, field, cpo)
    #        po.add_field_by_key(fld_key, cpo)
    #    return po

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
        #self.steps.append(self.extract_pertinent_infos)

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
        if pid or name and self.ex_java:
            self.ex_java.update_process_info(pid=pid, name=name, lookup_lib=lookup_lib)
            if lookup_lib and self.ex_java:
                self.libjvm['start'] = self.ex_java.lib_start

        if self.dump_java_process:
            self.log ("Identifying the Java Process")
            self.log ("Dumping Process Virtual Memory")
            self.ex_java.dump_virtual_memory_form(self.dump_location)


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
        include_unsafe = kargs.get('include_unsafe', False)
        convert_oop_to_pyobj = kargs.get('convert_oop_to_pyobj', False)
        #self.log ("%s: Enumerating JVM Heap using GC Logs")
	#self.gen_heaps_from_gc_logs = self.jva.gen_heaps_from_gc_logs()
        self.log ("Enumerating and grouping internal object locations")
        self.enumerate_internal_object_groupings()
        self.log ("Identifying the chunk of memory with objects")
        self.identify_heaps_location()
        self.log ("Enumerating all threads and thread vframe arrays")
        #self.scan_for_java_vframes()
        ti = self.get_thread_infos(include_unsafe=include_unsafe, convert_oop_to_pyobj=convert_oop_to_pyobj)
        return True

    def extract_pertinent_infos(self, **kargs):
        include_unsafe = kargs.get('include_unsafe', False)
        convert_oop_to_pyobj = kargs.get('convert_oop_to_pyobj', False)
        #self.log ("Enumerating all threads and thread vframe arrays")
        #self.scan_for_java_vframes()
        #ti = self.get_thread_infos(include_unsafe=include_unsafe, convert_oop_to_pyobj=convert_oop_to_pyobj)
        self.log ("Enumerating all Buffered Input and Output streams")
        buffered_streams = self.find_buffered_streams()
        #self.log ("Enumerating all Buffered Readers and Writers")
        #reader_writers = self.find_buffered_io()
        self.log ("Enumerating all Strings")
        strings = self.find_strings(include_unsafe=include_unsafe, convert_oop_to_pyobj=convert_oop_to_pyobj)
        self.log ("Enumerating all Sockets")
        socks = self.find_sockets(include_unsafe=include_unsafe, convert_oop_to_pyobj=convert_oop_to_pyobj)
        self.log ("Enumerating all Files")
        files = self.find_files(include_unsafe=include_unsafe, convert_oop_to_pyobj=convert_oop_to_pyobj)
        #self.log ("Enumerating all IO Streams and buffers")
        #files = self.find_streams_and_buffers(include_unsafe=include_unsafe, convert_oop_to_pyobj=convert_oop_to_pyobj)
        self.log ("Enumerating all Java environment variables")
        env_vars = self.find_env_vars(include_unsafe=include_unsafe)
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
        targets = {}
        # identify potential heap location based on oop locations
        for r_addr, oop_uses in self.jm_oop_range_uses.items():
                if len(oop_uses) > len(self.jva.loaded_jm_oop_by_addr):
                    #print hex(r_addr), len(oop_uses)
                    targets[r_addr] = oop_uses
                    if not target is None and len(oop_uses) > len(target[-1]):
                        target = (r_addr, oop_uses)
                    elif target is None:
                        target = (r_addr, oop_uses)

        self.pot_heap_loc = self.oop_pot_heap_loc = None if target is None else target[0]
        self.pot_heap_locs = targets
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
        for r_addr, oop_uses in self.pot_heap_locs.items():
            klass_uses = self.klass_range_uses[r_addr]
            for klass_ptr in klass_uses:
                markOop_addr = klass_ptr[0]-4
                klass_ref = klass_ptr[1]
                markOop_value = self.jva.read_dword(markOop_addr)
                if markOop_value is None:
                    self.log("markOop @ 0x%08x (%s) could not be read, ignoring"%(markOop_addr, klass_ref))
                    continue
                self.pot_oop_headers.append([markOop_addr, markOop_value, klass_ptr[1]])
        oop_ranges = [self.jva.find_range(t) for t in self.pot_heap_locs]
        oop_ranges = [ i for i in oop_ranges if not i is None]
        check_all_ranges = lambda x: sum([1 for i in oop_ranges if i.in_range(x)]) > 0
        bu_pot_oop_headers = []
        for markOop_addr, value, klass in self.pot_oop_headers:
            if not klass in self.jva.loaded_classes_by_addr:
                continue
            bu_pot_oop_headers.append((markOop_addr, value, klass))
            kname = str(self.jva.loaded_classes_by_addr[klass])
            kname = str(self.jva.loaded_classes_by_addr[klass])
            v = value & 0x3
            age = value & 0b1111000
            hash_ = value & ~ 0b1111111
            bias = value & 0b101 == 0b101
            normal_header = False if bias else 0x1 & value == 0x1
            jthread = 0 if not bias else value & ~ 0b111111111
            if v == 3 and\
                check_all_ranges(value & (~0x3)):
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
        self.pot_oop_headers = bu_pot_oop_headers

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

    def scan_for_java_bc_interpretter_state(self, convert_oop_to_pyobj=False, traverse_thread_groups=False):
        if len(self.jthread_start_mapping_thread_oop) == 0:
            self.find_all_loaded_thread_oops(convert_oop_to_pyobj=convert_oop_to_pyobj, traverse_thread_groups=traverse_thread_groups)

        # enumerate all uses of the given jthread
        if len(self.pot_jthread_ranges_uses) == 0:
            tvals = set([i for i in self.jthread_start_mapping_thread_oop.keys() if i > 0])
            _, pot_jthread_ranges_uses = self.jva.scan_pages_for_dword_values(tvals, in_parallel=True)
            self.pot_jthread_ranges_uses = pot_jthread_ranges_uses

        pot_jthread_ranges_uses = self.pot_jthread_ranges_uses
        self.pot_call_wrapper_results = {}
        heap_loc_range = self.jva.find_range(self.pot_heap_loc)
        for r, locs in pot_jthread_ranges_uses.items():
            thread_results = []
            for addr, jthread_ptr in locs:
                if not jthread_ptr in self.pot_interpretter_state:
                    self.pot_interpretter_state[jthread_ptr] = {}
                m_addr = self.jva.read_dword(loc + 4*4)
                m = self.jva.get_method_only(m_addr) if m_addr else None
                cpc_addr = self.jva.read_dword(loc + 4*3)
                m = self.jva.get_method_only(m_addr) if m_addr else None
                cpc = self.jva.get_cpcache_only(cpc_addr) if cpc_addr else None
                if not m is None and cpc is None:
                    continue
                bci_state = BytecodeInterpreter.from_jva(loc, self.jva)
                self.pot_interpretter_state[jthread_ptr][loc] = bci_state
        return self.pot_interpretter_state


    def scan_for_java_vframes(self, convert_oop_to_pyobj=False, traverse_thread_groups=False):
        if len(self.jthread_start_mapping_thread_oop) == 0:
            self.find_all_loaded_thread_oops(convert_oop_to_pyobj=convert_oop_to_pyobj, traverse_thread_groups=traverse_thread_groups)

        self.log( "Preparing to scan for Java VFrames")
        # enumerate all uses of the given jthread
        if len(self.pot_jthread_ranges_uses) == 0:
            tvals = set([i for i in self.jthread_start_mapping_thread_oop.keys() if i > 0])
            _, pot_jthread_ranges_uses = self.jva.scan_pages_for_dword_values(tvals, in_parallel=True)
            self.pot_jthread_ranges_uses = pot_jthread_ranges_uses

        pot_jthread_ranges_uses = self.pot_jthread_ranges_uses
        self.pot_call_wrapper_results = {}
        #heap_loc_range = self.jva.find_range(self.pot_heap_loc)
        pot_vfa = 0
        pot_bis = 0
        all_jthread_locs = set()
        all_jthread_ptrs = set()
        for locs in pot_jthread_ranges_uses.values():
            for addr, ptr in locs:
                all_jthread_locs.add(addr)
                all_jthread_ptrs.add(ptr)

        for ptr in all_jthread_ptrs:
            if not ptr in self.pot_vframe_arrays:
                self.pot_vframe_arrays[ptr] = []
            if not ptr in self.pot_interpretter_state:
                self.pot_interpretter_state[ptr] = []

        self.log( "Starting scan for Java VFrame Arrays and Bytecode Interpreter States, scanning 0x%08x uses of %d threads."%(len(all_jthread_locs), len(all_jthread_ptrs)))
        check_vframe_next = lambda vfa_next: self.jva.read_dword(vfa_next)        
        for r, locs in pot_jthread_ranges_uses.items():
            for addr, jthread_ptr in locs:
                loc = addr
                # VFrameArray._next should point to a Another VFrameArray, and 
                # the first elem is JavaThread*
                vfa_next = loc+4*1
                if vfa_next in all_jthread_locs:
                    #vframe_array = VFrameArray.from_jva(loc, self.jva)
                    res = {'vframe_addr':loc, 'vframe_next':vfa_next,
                           'jthread':jthread_ptr}
                    self.pot_vframe_arrays[jthread_ptr].append(res)

                # is it a potential ByteInterpretterState?
                m_addr = self.jva.read_dword(loc + 4*4)
                cpc_addr = self.jva.read_dword(loc + 4*3)
                m = self.jva.get_method_only(m_addr) if m_addr else None
                cpc = self.jva.get_cpcache_only(cpc_addr) if cpc_addr else None
                if not m is None and not cpc is None:
                    res = {"method_addr":m_addr, "cpc_addr":cpc_addr, 
                           "jthread":jthread_ptr, "bci_addr":loc}
                    #bci_state = BytecodeInterpreter.from_jva(loc, self.jva)
                    self.pot_interpretter_state[jthread_ptr].append(res)
                    pot_bis += 1
        self.log( "Completed. Found %d Java VFrame Arrays and %d Bytecode Interpreter States"%(pot_vfa, pot_bis))
        return self.pot_vframe_arrays


    def scan_for_java_call_wrappers(self, convert_oop_to_pyobj=False, traverse_thread_groups=False):
        if len(self.jthread_start_mapping_thread_oop) == 0:
            self.find_all_loaded_thread_oops(convert_oop_to_pyobj=convert_oop_to_pyobj, traverse_thread_groups=traverse_thread_groups)

        # enumerate all uses of the given jthread
        if len(self.pot_jthread_ranges_uses) == 0:
            _, pot_jthread_ranges_uses = self.jva.scan_pages_for_dword_values(set(self.jthread_start_mapping_thread_oop.keys()), in_parallel=True)
            self.pot_jthread_ranges_uses = pot_jthread_ranges_uses

        pot_jthread_ranges_uses = self.pot_jthread_ranges_uses
        self.pot_call_wrapper_results = {}
        heap_loc_range = self.jva.find_range(self.pot_heap_loc)
        pot_jcw = 0
        self.log( "Starting scan for Java Call Wrappers, scanning 0x%08x uses."%len(pot_jthread_ranges_uses))
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
                pot_jcw += 1

                if not jthread_ptr in self.pot_call_wrapper_results:
                    self.pot_call_wrapper_results[jthread_ptr] = []
                self.pot_call_wrapper_results[jthread_ptr].append(results)

        self.log( "Completed. Found %d potential Java Call Wrappers."%pot_jcw)
        return self.pot_call_wrapper_results

    def get_thread_infos(self, include_unsafe=False, convert_oop_to_pyobj=False, traverse_thread_groups=False):
        self.thread_infos = {}
        if len(self.thread_oop_mapping_jthread) == 0:
            self.find_all_loaded_thread_oops(convert_oop_to_pyobj=convert_oop_to_pyobj, traverse_thread_groups=traverse_thread_groups)
        oops = []
        for k, eetop in self.thread_oop_mapping_jthread.items():
            oop = self.get_oop_by_addr(k)
            if oop and not oop.is_prim()  and 'java/lang/Thread' in oop.get_ordered_klass_dependencies():
                #self.update_internal_knowledge_by_addr(oop.addr)
                oop_values = getattr(oop, 'oop_field_values_by_name', None)
                kname = oop.klass_name()
                tid = None
                tname = None
                if oop_values and THREAD_KLASS in oop.oop_field_values_by_name:
                    if oop.has_oop_field_not_none('name', any_klass=True):
                        name_oop = oop.get_oop_first_field_in_klasses('name')
                        if name_oop.ooptype == 'ObjArrayKlassOop':
                            tname = name_oop.python_value()
                        elif name_oop.ooptype == 'OopInstance' and \
                            self.query_oop_type(name_oop.addr).find('java/lang/String') > -1 and\
                            name_oop.has_oop_field_not_none('value', any_klass=True):
                            tname = name_oop.get_oop_first_field_in_klasses('value')\
                                   .python_value()

                    tid = oop_values[THREAD_KLASS]['tid'].python_value()\
                                 if oop_values[THREAD_KLASS]['tid'] \
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

    def find_env_vars(self, include_unsafe=False, convert_oop_to_pyobj=False, known_only=True):
        property_uses = []
        klasses_addrs = [self.jva.loaded_classes_by_name['java/util/Properties'].addr]
        ko_uses = [i.addr for i in self.jva.all_oops.values() if not i.is_prim() and\
                          i.klass_value and\
                          i.klass_value.addr in klasses_addrs]

        if not known_only:
            ko_uses = ko_uses +\
                      [m for m, i in self.normal_oops.items() if i[-1] in klasses_addrs] +\
                      [m for m, i in self.bias_oops.items() if i[-1] in klasses_addrs]
            if include_unsafe:
                ko_uses = ko_uses +\
                      [m for m, i in self.unknown_oops.items() if i[-1] in klasses_addrs]
                        
            ko_uses = [i for i in set(ko_uses)]
            ko_uses.sort()

        convert_oop_to_pyobj=True
        if convert_oop_to_pyobj:
            for m in ko_uses:
                property_uses.append(self.get_python_object_at_addr(m))
                property_uses.append(self.get_python_object_at_addr(m))


        for po in property_uses:
            items = {}
            if po is None or getattr(po, 'table', None) is None:
                continue
            for e in po.table:
                if e:
                    items[e.key] = e.value
            self.env_vars.update(items)
        return self.env_vars

    def update_socket_infos_with_oops(self, socket_addrs, include_unsafe=False):
       socket_oops = []
       for m in socket_addrs:
           socket_oops.append(self.get_oop_by_addr(m))
    
       get_inets = lambda x: socket.inet_ntoa(struct.pack(">I", x))
       socket_oops = [oop for oop in socket_oops  \
           if not oop is None and not oop.get_oop_first_field_in_klasses('impl') is None]

       for oop in socket_oops:
           impl_oop = oop.get_oop_field('impl')
           if impl_oop is None or not hasattr(impl_oop, 'oop_field_values_by_name'):
                continue
           sis = impl_oop.get_oop_first_field_in_klasses('socketInputStream')
           in_ = None if sis is None else sis.get_oop_first_field_in_klasses('in_')
           sos = impl_oop.get_oop_first_field_in_klasses('socketOutputStream')
           in_addr = in_buf = None
           out_addr = out_buf = None
           if sos and self.check_stream_link(sos):
               out_addr = self.check_stream_link(sos)
               out_buf = self.get_io_buffer_from_addr(self.check_stream_link(sos))
           if in_ and self.check_stream_link(in_):
               in_addr = self.check_stream_link(in_)
               in_buf = self.get_io_buffer_from_addr(self.check_stream_link(in_))

           # find localport klassname (could be SocketImpl or DatagramSocket.*?
           impl_kname = [k for k,v in impl_oop.oop_field_values_by_name.items() if 'localport' in v]
           if len(impl_kname) == 0:
               continue
           kname = impl_kname[0]
           localport = impl_oop.get_oop_first_field_in_klasses('localport')
           localport = localport.python_value() if localport else -1
           port = impl_oop.get_oop_first_field_in_klasses('port')
           port = port.python_value() if port else -1
           connected = impl_oop.get_oop_first_field_in_klasses('connected')
           connected = connected.python_value() if connected else False
           object_age = self.get_age(oop.addr)
           remoteIp = "-1.-1.-1.-1"
           if impl_oop.get_oop_first_field_in_klasses('address'):
               addr_oop = impl_oop.get_oop_first_field_in_klasses('address')
               # find the IP Address holder class
               holder_oop = addr_oop.get_oop_first_field_in_klasses('holder')
               if holder_oop:
                   a_addr_oop = holder_oop.get_oop_first_field_in_klasses('address')
                   if a_addr_oop:
                      remoteIp = get_inets(a_addr_oop.python_value()) 
                       
              
           
           res = {'localport':localport,
                  'serverport':port,
                  'connected':connected,
                  'remoteIp':remoteIp,
                  'object_age':object_age,
                  'input_addr':in_addr,
                  'output_addr':out_addr,
                  'input_buffer':in_buf,
                  'output_buffer':out_buf
                  }
           self.socket_info[oop.get_addr()] = res


    def update_socket_infos_with_python_objects(self, socket_addrs, include_unsafe=False):
       socket_pos = []
       for m in socket_addrs:
           socket_pos.append(self.load_update_python_objects(m))
    
       get_inets = lambda x: socket.inet_ntoa(struct.pack(">I", x))
       for po in socket_pos:
           if po is None or not hasattr(po, 'impl'):
               continue
           res = {'localport':po.impl.localport,
                  'serverport':po.impl.port,
                  'connected':po.connected,
                  'remoteIp':get_inets(po.impl.address.holder.address),
                  'object_age':po.get_age()
                  }
           self.socket_info[po.get_addr()] = res

    def find_sockets(self, include_unsafe=False, convert_oop_to_pyobj=False, known_only=True):
        self.socket_info = {}
        socket_klass = []
        klasses_addrs = []
        socket_klasses_addrs_use = self.find_locs_klass_value('java/net/Socket')
        socket_oop_addrs_use = self.find_locs_jm_oop_value('java/net/Socket')
        for r, klass_uses in socket_klasses_addrs_use.items():
            klasses_addrs = klasses_addrs + klass_uses
        
        datagram_klasses_addrs_use = self.find_locs_klass_value('java/net/DatagramSocket')
        datagram_oop_addrs_use = self.find_locs_klass_value('java/net/DatagramSocket')
        for r, klass_uses in datagram_klasses_addrs_use.items():
            if r in datagram_oop_addrs_use:
                klasses_addrs = klasses_addrs + klass_uses

        oops = []
        for addr in klasses_addrs:
            oop = self.get_oop_by_addr(addr-4, perform_update=True, expected_klass_name="Socket")
            if oop is None or not (oop.ooptype == 'Oop' or oop.ooptype == 'OopInstance'):
                continue
            oops.append(oop)

        ko_uses = [oop.addr for oop in oops]
        if not known_only:
            ko_uses = ko_uses +\
                      [m for m, i in self.normal_oops.items() if i[-1] in klasses_addrs] +\
                      [m for m, i in self.bias_oops.items() if i[-1] in klasses_addrs]
            if include_unsafe:
                ko_uses = ko_uses +\
                      [m for m, i in self.unknown_oops.items() if i[-1] in klasses_addrs]
            ko_uses = [i for i in set(ko_uses)]
            ko_uses.sort()

        if convert_oop_to_pyobj:
            self.update_socket_infos_with_python_objects(ko_uses, include_unsafe=include_unsafe)
        else: 
            self.update_socket_infos_with_oops(ko_uses, include_unsafe=include_unsafe)
        return self.socket_info

    def read_writers(self, oop):
        get_stream_hb_raw = lambda _oop: "".join([chr(i) for i in _oop.get_oop_first_field_in_klasses('hb').raw_value()])
        get_stream_hb_oop = lambda _oop: _oop.get_oop_first_field_in_klasses('hb')
        has_stream_hb = lambda _oop: _oop.has_oop_field_not_none('hb', any_klass=True)
        
        get_stream_bb = lambda _oop: _oop.get_oop_first_field_in_klasses('bb')
        has_stream_bb = lambda _oop: _oop.has_oop_field_not_none('bb', any_klass=True)
        
        get_stream_decoder = lambda _oop: _oop.get_oop_first_field_in_klasses('sd')
        has_stream_decoder = lambda _oop: _oop.has_oop_field_not_none('sd', any_klass=True)
        
        known_stream_buf = set()
        not_known_stream_hb = lambda _oop: not get_stream_hb_addr(_oop) in known_buffers
        get_stream_hb_addr = lambda _oop: get_stream_hb_oop(get_stream_bb(get_stream_decoder(_oop))).addr
        get_stream_hb = lambda _oop: get_stream_hb_raw(get_stream_bb(get_stream_decoder(_oop)))
        is_stream_reader = lambda _oop: has_stream_decoder(_oop) and \
                 has_stream_bb(get_stream_decoder(_oop)) and \
                 has_stream_hb(get_stream_bb(get_stream_decoder(_oop)))

        get_stream_cb_raw = lambda _oop: _oop.get_oop_first_field_in_klasses('cb').raw_value()
        get_stream_cb_oop = lambda _oop: _oop.get_oop_first_field_in_klasses('cb')
        has_stream_cb = lambda _oop: _oop.has_oop_field_not_none('cb', any_klass=True)

        get_stream_textout = lambda _oop: _oop.get_oop_first_field_in_klasses('textOut')
        has_stream_textout = lambda _oop: _oop.has_oop_field_not_none('textOut', any_klass=True)
        
        get_stream_out = lambda _oop: _oop.get_oop_first_field_in_klasses('out')
        has_stream_out = lambda _oop: _oop.has_oop_field_not_none('out', any_klass=True)
        
        get_stream_encoder = lambda _oop: _oop.get_oop_first_field_in_klasses('se')
        has_stream_encoder = lambda _oop: _oop.has_oop_field_not_none('se', any_klass=True)

        known_stream_cb = set()
        get_stream_cb_addr = lambda _oop: get_stream_cb_oop(get_stream_textout(get_stream_out(get_stream_encoder(_oop)))).addr
        not_known_stream_cb = lambda _oop: not get_stream_cb_addr(_oop) in known_buffers
        get_stream_cb = lambda _oop: get_stream_cb_raw(get_stream_textout(get_stream_out(get_stream_encoder(_oop))))
        is_stream_writer = lambda _oop: has_stream_encoder(_oop) and \
                 has_stream_out(get_stream_encoder(_oop)) and \
                 has_stream_textout(get_stream_out(get_stream_encoder(_oop))) and \
                 has_stream_cb(get_stream_textout(get_stream_out(get_stream_encoder(_oop))))
        
        

        get_chr_buf = lambda _oop: "".join([chr(i) for i in get_buf(_oop)])
        get_buf = lambda _oop: _oop.get_oop_first_field_in_klasses('buf').raw_value()
        get_buf_addr = lambda _oop: _oop.get_oop_first_field_in_klasses('buf').addr
        has_buffer = lambda _oop: _oop.has_oop_field_not_none('buf', any_klass=True)
        
        known_buffers = set()
        not_known_buffer = lambda _oop: not get_buf_addr(_oop) in known_buffers
        is_buffer = lambda _oop: has_buffer(_oop)
        
        res = {'cb_addr':None, 'cb_data':None, 'cb_str':None,
               'io_addr':None, 'raw':None, 'str':None}
        out_oop = oop.get_oop_first_field_in_klasses('out')
        if is_stream_writer(oop):
            data = get_stream_cb(oop)
            addr = get_stream_cb_addr(oop)
            #str_ = "".join([chr(i) for i in raw])
            res.update({'io_addr':addr, 'raw':data, 'str':data})
        elif out_oop and is_stream_writer(out_oop):
            data = get_stream_cb(oop)
            addr = get_stream_cb_addr(oop)
            #str_ = "".join([chr(i) for i in raw])
            res.update({'io_addr':addr, 'raw':data, 'str':data})
            
        if oop.get_oop_first_field_in_klasses('cb'):
            cb = oop.get_oop_first_field_in_klasses('cb')
            raw = "".join( [i.raw_value() for i in cb.oop_values])
            data = cb.raw_value()
            res['cb_str'] = data
            res['cb_raw'] = raw
            res['cb_addr'] = cb.addr
        return res

    def read_readers(self, oop):
        get_stream_hb_raw = lambda _oop: "".join([chr(i) for i in _oop.get_oop_first_field_in_klasses('hb').raw_value()])
        get_stream_hb_oop = lambda _oop: _oop.get_oop_first_field_in_klasses('hb')
        has_stream_hb = lambda _oop: _oop.has_oop_field_not_none('hb', any_klass=True)
        
        get_stream_bb = lambda _oop: _oop.get_oop_first_field_in_klasses('bb')
        has_stream_bb = lambda _oop: _oop.has_oop_field_not_none('bb', any_klass=True)
        
        get_stream_decoder = lambda _oop: _oop.get_oop_first_field_in_klasses('sd')
        has_stream_decoder = lambda _oop: _oop.has_oop_field_not_none('sd', any_klass=True)
        
        known_stream_buf = set()
        not_known_stream_hb = lambda _oop: not get_stream_hb_addr(_oop) in known_buffers
        get_stream_hb_addr = lambda _oop: get_stream_hb_oop(get_stream_bb(get_stream_decoder(_oop))).addr
        get_stream_hb = lambda _oop: get_stream_hb_raw(get_stream_bb(get_stream_decoder(_oop)))
        is_stream_reader = lambda _oop: has_stream_decoder(_oop) and \
                 has_stream_bb(get_stream_decoder(_oop)) and \
                 has_stream_hb(get_stream_bb(get_stream_decoder(_oop)))

        get_stream_cb_raw = lambda _oop: _oop.get_oop_first_field_in_klasses('cb').raw_value()
        get_stream_cb_oop = lambda _oop: _oop.get_oop_first_field_in_klasses('cb')
        has_stream_cb = lambda _oop: _oop.has_oop_field_not_none('cb', any_klass=True)

        get_stream_textout = lambda _oop: _oop.get_oop_first_field_in_klasses('textOut')
        has_stream_textout = lambda _oop: _oop.has_oop_field_not_none('textOut', any_klass=True)
        
        get_stream_out = lambda _oop: _oop.get_oop_first_field_in_klasses('out')
        has_stream_out = lambda _oop: _oop.has_oop_field_not_none('out', any_klass=True)
        
        get_stream_encoder = lambda _oop: _oop.get_oop_first_field_in_klasses('se')
        has_stream_encoder = lambda _oop: _oop.has_oop_field_not_none('se', any_klass=True)

        known_stream_cb = set()
        get_stream_cb_addr = lambda _oop: get_stream_cb_oop(get_stream_textout(get_stream_out(get_stream_encoder(_oop)))).addr
        not_known_stream_cb = lambda _oop: not get_stream_cb_addr(_oop) in known_buffers
        get_stream_cb = lambda _oop: get_stream_cb_raw(get_stream_textout(get_stream_out(get_stream_encoder(_oop))))
        is_stream_writer = lambda _oop: has_stream_encoder(_oop) and \
                 has_stream_out(get_stream_encoder(_oop)) and \
                 has_stream_textout(get_stream_out(get_stream_encoder(_oop))) and \
                 has_stream_cb(get_stream_textout(get_stream_out(get_stream_encoder(_oop))))
        
        

        get_chr_buf = lambda _oop: "".join([chr(i) for i in get_buf(_oop)])
        get_buf = lambda _oop: _oop.get_oop_first_field_in_klasses('buf').raw_value()
        get_buf_addr = lambda _oop: _oop.get_oop_first_field_in_klasses('buf').addr
        has_buffer = lambda _oop: _oop.has_oop_field_not_none('buf', any_klass=True)
        
        known_buffers = set()
        not_known_buffer = lambda _oop: not get_buf_addr(_oop) in known_buffers
        is_buffer = lambda _oop: has_buffer(_oop)
        
        res = {'cb_addr':None, 'cb_data':None, 'cb_str':None,
               'io_addr':None, 'raw':None, 'str':None}
        in_oop = oop.get_oop_first_field_in_klasses('in')
        if is_stream_reader(oop):
            data = get_stream_cb(oop)
            addr = get_stream_cb_addr(oop)
            #str_ = "".join([chr(i) for i in raw])
            res.update({'io_addr':addr, 'raw':data, 'str':data})
        elif in_oop and is_stream_reader(in_oop):
            data = get_stream_cb(oop)
            addr = get_stream_cb_addr(oop)
            #str_ = "".join([chr(i) for i in raw])
            res.update({'io_addr':addr, 'raw':data, 'str':data})
        
        if oop.get_oop_first_field_in_klasses('cb'):
            cb = oop.get_oop_first_field_in_klasses('cb')
            raw = "".join( [i.raw_value() for i in cb.oop_values])
            data = cb.raw_value()
            res['cb_str'] = data
            res['cb_raw'] = raw
            res['cb_addr'] = cb.addr
        return res
        
    def read_buffer(self, oop):
        get_stream_hb_raw = lambda _oop: "".join([chr(i) for i in _oop.get_oop_first_field_in_klasses('hb').raw_value()])
        get_stream_hb_oop = lambda _oop: _oop.get_oop_first_field_in_klasses('hb')
        has_stream_hb = lambda _oop: _oop.has_oop_field_not_none('hb', any_klass=True)
        
        get_stream_bb = lambda _oop: _oop.get_oop_first_field_in_klasses('bb')
        has_stream_bb = lambda _oop: _oop.has_oop_field_not_none('bb', any_klass=True)
        
        get_stream_decoder = lambda _oop: _oop.get_oop_first_field_in_klasses('sd')
        has_stream_decoder = lambda _oop: _oop.has_oop_field_not_none('sd', any_klass=True)
        
        known_stream_buf = set()
        not_known_stream_hb = lambda _oop: not get_stream_hb_addr(_oop) in known_buffers
        get_stream_hb_addr = lambda _oop: get_stream_hb_oop(get_stream_bb(get_stream_decoder(_oop))).addr
        get_stream_hb = lambda _oop: get_stream_hb_raw(get_stream_bb(get_stream_decoder(_oop)))
        is_stream_reader = lambda _oop: has_stream_decoder(_oop) and \
                 has_stream_bb(get_stream_decoder(_oop)) and \
                 has_stream_hb(get_stream_bb(get_stream_decoder(_oop)))

        get_stream_cb_raw = lambda _oop: _oop.get_oop_first_field_in_klasses('cb').raw_value()
        get_stream_cb_oop = lambda _oop: _oop.get_oop_first_field_in_klasses('cb')
        has_stream_cb = lambda _oop: _oop.has_oop_field_not_none('cb', any_klass=True)

        get_stream_textout = lambda _oop: _oop.get_oop_first_field_in_klasses('textOut')
        has_stream_textout = lambda _oop: _oop.has_oop_field_not_none('textOut', any_klass=True)
        
        get_stream_out = lambda _oop: _oop.get_oop_first_field_in_klasses('out')
        has_stream_out = lambda _oop: _oop.has_oop_field_not_none('out', any_klass=True)
        
        get_stream_encoder = lambda _oop: _oop.get_oop_first_field_in_klasses('se')
        has_stream_encoder = lambda _oop: _oop.has_oop_field_not_none('se', any_klass=True)

        known_stream_cb = set()
        get_stream_cb_addr = lambda _oop: get_stream_cb_oop(get_stream_textout(get_stream_out(get_stream_encoder(_oop)))).addr
        not_known_stream_cb = lambda _oop: not get_stream_cb_addr(_oop) in known_buffers
        get_stream_cb = lambda _oop: get_stream_cb_raw(get_stream_textout(get_stream_out(get_stream_encoder(_oop))))
        is_stream_writer = lambda _oop: has_stream_encoder(_oop) and \
                 has_stream_out(get_stream_encoder(_oop)) and \
                 has_stream_textout(get_stream_out(get_stream_encoder(_oop))) and \
                 has_stream_cb(get_stream_textout(get_stream_out(get_stream_encoder(_oop))))
        
        

        get_chr_buf = lambda _oop: "".join([chr(i) for i in get_buf(_oop)])
        get_buf = lambda _oop: _oop.get_oop_first_field_in_klasses('buf').raw_value()
        get_buf_addr = lambda _oop: _oop.get_oop_first_field_in_klasses('buf').addr
        has_buffer = lambda _oop: _oop.has_oop_field_not_none('buf', any_klass=True)
        
        known_buffers = set()
        not_known_buffer = lambda _oop: not get_buf_addr(_oop) in known_buffers
        is_buffer = lambda _oop: has_buffer(_oop)
        
        res = {'io_addr':None, 'raw':None, 'str':None}
        if is_buffer(oop) and has_buffer(oop):
            raw = get_buf(oop)
            addr = get_buf_addr(oop)
            str_ = "".join([chr(i) for i in raw])
            res = {'io_addr':addr, 'raw':raw, 'str':str_, 'owner':oop.addr}
        elif oop.get_oop_first_field_in_klasses('cb'):
            cb = oop.get_oop_first_field_in_klasses('cb')
            raw = "".join( [i.raw_value() for i in cb.oop_values])
            data = cb.raw_value()
            res = {'io_addr':cb.addr, 'raw':data, 'str':data}
        return res


    def find_streams_and_buffers(self, oops=None, include_unsafe=False, convert_oop_to_pyobj=False, known_only=True):
        get_stream_hb_raw = lambda _oop: "".join([chr(i) for i in _oop.get_oop_first_field_in_klasses('hb').raw_value()])
        get_stream_hb_oop = lambda _oop: _oop.get_oop_first_field_in_klasses('hb')
        has_stream_hb = lambda _oop: _oop.has_oop_field_not_none('hb', any_klass=True)
        
        get_stream_bb = lambda _oop: _oop.get_oop_first_field_in_klasses('bb')
        has_stream_bb = lambda _oop: _oop.has_oop_field_not_none('bb', any_klass=True)
        
        get_stream_decoder = lambda _oop: _oop.get_oop_first_field_in_klasses('sd')
        has_stream_decoder = lambda _oop: _oop.has_oop_field_not_none('sd', any_klass=True)
        
        known_stream_buf = set()
        not_known_stream_hb = lambda _oop: not get_stream_hb_addr(_oop) in known_buffers
        get_stream_hb_addr = lambda _oop: get_stream_hb_oop(get_stream_bb(get_stream_decoder(_oop))).addr
        get_stream_hb = lambda _oop: get_stream_hb_raw(get_stream_bb(get_stream_decoder(_oop)))
        is_stream_reader = lambda _oop: has_stream_decoder(_oop) and \
                 has_stream_bb(get_stream_decoder(_oop)) and \
                 has_stream_hb(get_stream_bb(get_stream_decoder(_oop)))

        get_stream_cb_raw = lambda _oop: _oop.get_oop_first_field_in_klasses('cb').raw_value()
        get_stream_cb_oop = lambda _oop: _oop.get_oop_first_field_in_klasses('cb')
        has_stream_cb = lambda _oop: _oop.has_oop_field_not_none('cb', any_klass=True)

        get_stream_textout = lambda _oop: _oop.get_oop_first_field_in_klasses('textOut')
        has_stream_textout = lambda _oop: _oop.has_oop_field_not_none('textOut', any_klass=True)
        
        get_stream_out = lambda _oop: _oop.get_oop_first_field_in_klasses('out')
        has_stream_out = lambda _oop: _oop.has_oop_field_not_none('out', any_klass=True)
        
        get_stream_encoder = lambda _oop: _oop.get_oop_first_field_in_klasses('se')
        has_stream_encoder = lambda _oop: _oop.has_oop_field_not_none('se', any_klass=True)

        known_stream_cb = set()
        get_stream_cb_addr = lambda _oop: get_stream_cb_oop(get_stream_textout(get_stream_out(get_stream_encoder(_oop)))).addr
        not_known_stream_cb = lambda _oop: not get_stream_cb_addr(_oop) in known_buffers
        get_stream_cb = lambda _oop: get_stream_cb_raw(get_stream_textout(get_stream_out(get_stream_encoder(_oop))))
        is_stream_writer = lambda _oop: has_stream_encoder(_oop) and \
                 has_stream_out(get_stream_encoder(_oop)) and \
                 has_stream_textout(get_stream_out(get_stream_encoder(_oop))) and \
                 has_stream_cb(get_stream_textout(get_stream_out(get_stream_encoder(_oop))))
        
        

        get_chr_buf = lambda _oop: "".join([chr(i) for i in get_buf(_oop)])
        get_buf = lambda _oop: _oop.get_oop_first_field_in_klasses('buf').raw_value()
        get_buf_addr = lambda _oop: _oop.get_oop_first_field_in_klasses('buf').addr
        has_buffer = lambda _oop: _oop.has_oop_field_not_none('buf', any_klass=True)
        
        known_buffers = set()
        not_known_buffer = lambda _oop: not get_buf_addr(_oop) in known_buffers
        is_buffer = lambda _oop: has_buffer(_oop)



        self.failed_streams_and_buffers = []
        interested_klasses = [
            'java/io/BufferedInputStream',
            'java/io/BufferedOutputStream',
            'java/io/BufferedReader',
            'java/io/BufferedWriter',
            'java/io/ByteArrayInputStream',
            'java/io/ByteArrayOutputStream',
            'java/io/DataInputStream',
            'java/io/DataOutputStream',
            'java/io/FileReader',
            'java/io/FileWriter',
            'java/io/InputStreamReader',
            'java/io/OutputStreamWriter',
            'java/net/SocketInputStream',
            'java/net/SocketOutputStream',
        ]
        klasses = [i for i in self.jva.loaded_classes_by_name if i.find('Input') > -1 or i.find('Output') > -1 ] + \
                  [i for i in self.jva.loaded_classes_by_name if i.find('Reader') > -1 or i.find('Writer') > -1 ]
        klasses = [i for i in klasses if i.find('java/util/zip/ZipFile') == -1 and\
                         i.find('java/io/FileInput') == -1 and i.find('java/io/FileOutput') == -1 ]
        klasses = [i for i in klasses if i in interested_klasses]
        klasses_addrs = [ self.jva.loaded_classes_by_name[i].addr for i in klasses]

        #ko_uses = [m for m,i in self.normal_oops.items() if i[-1] in klasses_addrs] +\
        #          [m for m,i in self.bias_oops.items() if i[-1] in klasses_addrs]

        ko_uses = [i.addr for i in self.jva.all_oops.values() if not i.is_prim() and\
                          i.klass_value and\
                          i.klass_value.addr in klasses_addrs]

        if not known_only:
            ko_uses = ko_uses +\
                      [m for m, i in self.normal_oops.items() if i[-1] in klasses_addrs] +\
                      [m for m, i in self.bias_oops.items() if i[-1] in klasses_addrs]
            ko_uses = [i for i in set(ko_uses)]
            if include_unsafe:
                ko_uses = ko_uses +\
                      [m for m, i in self.unknown_oops.items() if i[-1] in klasses_addrs]
            ko_uses.sort()

        # second one is not a typo, do it to ensure everything loads completely
        ko_oops = [self.get_oop_by_addr(m) for m in ko_uses if not self.get_oop_by_addr(m) is None]
        ko_oops = [self.get_oop_by_addr(m) for m in ko_uses if not self.get_oop_by_addr(m) is None]

        writers = [oop for oop in ko_oops if is_stream_writer(oop)]
        readers = [oop for oop in ko_oops if is_stream_reader(oop)]
        buffers = [ oop for oop in ko_oops if is_buffer(oop) and has_buffer(oop)]

        self.known_buffers_buf = {}
        self.known_readers_buf = {}
        self.known_writers_buf = {}

        self.shared_data_buffers = {}
        
        for oop in readers:
            data = get_stream_hb(oop)
            addr = get_stream_hb_addr(oop)
            self.known_readers_buf[addr] = data
            oop_type = self.query_oop_type(oop.addr)
            if not addr in self.shared_data_buffers:
                self.shared_data_buffers[addr] = []
            self.shared_data_buffers[addr].append((oop_type, oop))

        for oop in readers:
            res = self.read_readers(oop)
            if res['io_addr']:
                addr = res['io_addr']
                self.known_readers_buf[addr] = res
            oop_type = self.query_oop_type(oop.addr)
            if not addr in self.shared_data_buffers:
                self.shared_data_buffers[addr] = []
            self.shared_data_buffers[addr].append((oop_type, oop))

        for oop in writers:
            res = self.read_writers(oop)
            if res['io_addr']:
                addr = res['io_addr']
                self.known_writers_buf[addr] = res
            oop_type = self.query_oop_type(oop.addr)
            if not addr in self.shared_data_buffers:
                self.shared_data_buffers[addr] = []
            self.shared_data_buffers[addr].append((oop_type, oop))

        for oop in buffers:
            res = self.read_buffer(oop)
            if res['io_addr']:
                addr = res['io_addr']
                self.known_buffers_buf[addr] = res
            oop_type = self.query_oop_type(oop.addr)
            if not addr in self.shared_data_buffers:
                self.shared_data_buffers[addr] = []
            self.shared_data_buffers[addr].append((oop_type, oop))

        if convert_oop_to_pyobj:
            ko_objs = []
            for i in ko_uses:
                po = self.get_python_object_at_addr(i)
                if po:
                    ko_objs.append(po)


    def update_file_info_with_python_objects(self, ko_objs):
        for o in ko_objs:
            if o is None:
                continue
            addr = o.get_addr() if hasattr(o, "__addr") else None
            if addr is None:
                continue
            oop_type = getattr(o, 'oop_type', '')
            if (oop_type == 'java/util/zip/ZipFile$ZipFileInputStream' or\
               oop_type == 'java/util/zip/ZipFile$ZipFileInflaterInputStream') and\
               hasattr(o, 'this$0'):
                zip_this = getattr(o, 'this$0', None)
                if zip_this and hasattr(zip_this, 'name'):
                    self.files.add(zip_this.name)
                    if not zip_this.name in self.file_infos:
                        self.file_infos[zip_this.name] = []
                    self.file_infos[zip_this.name].append((addr, oop_type))
            elif oop_type == 'java/io/FileDescriptor' and \
                 hasattr(o, 'parent') and hasattr(o.parent, 'path'):
                self.files.add(o.parent.path)
                if not o.parent.path in self.file_infos:
                    self.file_infos[o.parent.path] = []
                self.file_infos[o.parent.path].append((addr, oop_type))
            elif oop_type == 'java/io/File' and \
                 hasattr(o, 'path'):
                self.files.add(o.path)
                if not o.path in self.file_infos:
                    self.file_infos[o.path] = []
                self.file_infos[o.path].append((addr, oop_type))

            elif (oop_type == 'java/util/jar/JarFile' or \
                  oop_type == 'java/util/zip/ZipFile') and \
                 hasattr(o, 'name'):
                self.files.add(o.name)
                if not o.name in self.file_infos:
                    self.file_infos[o.name] = []
                self.file_infos[o.name].append((addr, oop_type))

    def update_file_info_with_oops(self, ko_oops):
        for oop in ko_oops:
            if oop is None:
                continue
            addr = oop.addr
            if addr is None:
                continue
            # Use get_oop_field('value'). to get the python string value of the java/lang/String class
            oop_type = self.query_oop_type(addr)
            if (oop_type == 'java/util/zip/ZipFile$ZipFileInputStream' or\
               oop_type == 'java/util/zip/ZipFile$ZipFileInflaterInputStream') and\
               oop.has_oop_field_not_none('this$0') and \
               oop.get_oop_field('this$0').has_oop_field_not_none('name', 'java/util/zip/ZipFile'):
                name = oop.get_oop_field('this$0').get_oop_field('name', klass_name='java/util/zip/ZipFile').get_oop_field('value').python_value()
                self.files.add(name)
                if not name in self.file_infos:
                    self.file_infos[name] = []
                self.file_infos[name].append((addr, oop_type))
            elif oop_type == 'java/io/FileDescriptor' and \
               oop.has_oop_field_not_none('parent') and \
               oop.get_oop_field('parent').has_oop_field_not_none('path') and \
               oop.get_oop_field('parent').get_oop_field('path').has_oop_field_not_none('value'):
                path = oop.get_oop_field('parent').get_oop_field('path').get_oop_field('value').python_value()
                self.files.add(path)
                if path and not path in self.file_infos:
                    self.file_infos[path] = []
                self.file_infos[path].append((addr, oop_type))
            elif oop_type == 'java/io/File' and \
                 oop.has_oop_field_not_none('path', any_klass=True):
                path_oop = oop.get_oop_first_field_in_klasses('path')
                path = None
                if path_oop and path_oop.ooptype == 'ObjArrayKlassOop':
                    path = path_oop.python_value()
                    if len(path) == 0 or isinstance(path, list):
                        continue
                elif path_oop and path_oop.ooptype == 'OopInstance' and \
                    self.query_oop_type(path_oop.addr).find('java/lang/String') > -1 and \
                    path_oop.has_oop_field_not_none('value', any_klass=True):
                    path = path_oop.get_oop_first_field_in_klasses('value')\
                           .python_value()
                self.files.add(path)
                if not path in self.file_infos:
                    self.file_infos[path] = []
                self.file_infos[path].append((addr, oop_type))

            elif (oop_type == 'java/util/jar/JarFile'  or oop_type == 'java/util/zip/ZipFile') and \
                 oop.has_oop_field_not_none('name', klass_name='java/util/zip/ZipFile'):
                name = oop.get_oop_field('name', klass_name='java/util/zip/ZipFile').get_oop_field('value').python_value()
                self.files.add(name)
                if not name in self.file_infos:
                    self.file_infos[name] = []
                self.file_infos[name].append((addr, oop_type))

    def find_files(self, include_unsafe=False, convert_oop_to_pyobj=False, known_only=True):
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
        klasses_addrs = set([ self.jva.loaded_classes_by_name[i].addr for i in klasses])

        ko_uses = [i.addr for i in self.jva.all_oops.values() if not i.is_prim() and\
                          i.klass_value and\
                          i.klass_value.addr in klasses_addrs]

        if not known_only:
            ko_uses = ko_uses +\
                      [m for m, i in self.normal_oops.items() if i[-1] in klasses_addrs] +\
                      [m for m, i in self.bias_oops.items() if i[-1] in klasses_addrs]
            if include_unsafe:
                ko_uses = ko_uses +\
                      [m for m, i in self.unknown_oops.items() if i[-1] in klasses_addrs]
            ko_uses = [i for i in set(ko_uses)]
            ko_uses.sort()


        if convert_oop_to_pyobj:
            ko_objs = []
            for i in ko_uses:
                #po = self.get_python_object_at_addr(i)
                po = self.get_python_obj(i, use_internals_knowledge=True)
                oop = self.get_oop_by_addr(i)
                #self.update_internal_knowledge_just_oop(oop)
                ko_objs.append(po)
            self.update_file_info_with_python_objects(ko_objs)
        else:
            ko_oops = [self.get_oop_by_addr(m) for m in ko_uses]
            self.update_file_info_with_oops(ko_oops)

        return self.file_infos, self.files


    def find_strings(self, include_unsafe=False, convert_oop_to_pyobj=False, known_only=True):

        klasses = ['java/lang/String',
                   ]

        klasses_addrs = set([ self.jva.loaded_classes_by_name[i].addr for i in klasses])

        ko_uses = [i.addr for i in self.jva.all_oops.values() if not i.is_prim() and\
                          i.klass_value and\
                          i.klass_value.addr in klasses_addrs]

        if not known_only:
            ko_uses = ko_uses +\
                      [m for m, i in self.normal_oops.items() if i[-1] in klasses_addrs] +\
                      [m for m, i in self.bias_oops.items() if i[-1] in klasses_addrs]
            if include_unsafe:
                ko_uses = ko_uses +\
                      [m for m, i in self.unknown_oops.items() if i[-1] in klasses_addrs]
            ko_uses = [i for i in set(ko_uses)]
            ko_uses.sort()


        if include_unsafe:
            for m,i in self.unknown_oops.items():
                if i[-1] in klasses_addrs:
                    ko_uses.append(m)

        ko_objs = []
        for i in ko_uses:
            #po = self.get_python_object_at_addr(i)
            val = None
            oop = self.get_oop_by_addr(i)
            if oop and oop.ooptype == 'OopInstance' and \
                self.query_oop_type(oop.addr).find('java/lang/String') > -1 and\
                oop.has_oop_field_not_none('value', any_klass=True):
                v_oop =oop.get_oop_first_field_in_klasses('value')
                if v_oop and ( not v_oop.is_prim() or not hasattr(v_oop, 'ebt')):
                    continue
                if v_oop and v_oop.ebt != 5:
                    for i in v_oop.oop_values:
                        self.forget_py_obj(i.addr)
                    self.forget_py_obj(v_oop.addr)
                    V_oop = self.jva.lookup_known_oop(v_oop.addr)
                    #V_oop = Oop.from_bytes(v_oop.addr, self.jva)
                    V_oop.ebt = 5
                    V_oop.klass_value = self.jva.loaded_classes_by_name['[C']
                    V_oop.klass = oop.klass_value.addr
                    V_oop.update_fields(True)
                    oop.oop_field_values_by_name['java/lang/String']['value'] = V_oop
                    v_oop = V_oop
                val = v_oop.raw_value()

            if convert_oop_to_pyobj:
                po = self.get_python_obj(i)
                #if po:
                #    self.strings[i] = (po, self.get_age(i))
            if val:
                self.strings[oop.addr] = val
                if not val in self.strings_rev_mapping:
                    self.strings_rev_mapping[val] = []
                self.strings_rev_mapping[val].append(oop.addr)
                self.strings_rev_mapping[val].append(v_oop.addr)
                self.strings[oop.addr] = val
                self.strings_set.add(val)
            #self.update_internal_knowledge_just_oop(oop)
        return self.strings

    def get_thread_name(self, jthread_or_oop, convert_oop_to_pyobj=False):
        if len(self.confirmed_java_thread) == 0:
            self.find_all_loaded_thread_oops(convert_oop_to_pyobj=convert__to_pyobj)
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
            if self.has_py_obj(jthread_or_oop):
                po = self.get_python_object(t)
                po = self.get_python_object_at_addr(jthread_or_oop)
                if po and hasattr(po, 'name'):
                    return po.name
            else:
                t = self.get_oop_by_addr(jthread_or_oop)
                name = t.get_oop_field('name')
                return name.python_value()
        return None

    def get_main_thread(self, convert_oop_to_pyobj=True):
        if len(self.confirmed_java_thread) == 0:
            self.find_all_loaded_thread_oops(convert_oop_to_pyobj=convert_oop_to_pyobj)
        for t in self.confirmed_java_thread.values():
            if self.has_py_obj(t.addr):
                po = self.get_python_object(t)
                if po.name == 'main':
                    return po
            elif convert_oop_to_pyobj:
                name = t.get_oop_field('name')
                if name and name.python_value() == 'main':
                    return self.get_python_object(t)
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
            if t_obj and not t_obj.get_addr() in known_threads:
                known_threads.add(t_obj.get_addr())
                res.append(self.get_oop_by_addr(t_obj.get_addr()))
                tres = self.enumerate_threads_from_thread(t_obj, known_threads)
                res = res + tres
        return res

    def find_all_loaded_thread_oops(self, convert_oop_to_pyobj=False, traverse_thread_groups=True):
        # identify potential class derivatives
        tk_name = 'java/lang/Thread'
        tgk_name = 'java/lang/ThreadGroup'
        thread_derivatives = set()
        tgk_filter_thread_refs = set()
        filter_thread_refs = set()
        self.log( "Enumerating klasses that extend or implement a Thread class")
        for klass in self.jva.loaded_classes_by_name.values():
            if tk_name in klass.klass_dependencies or \
               tk_name == klass.klass_name():
                thread_derivatives.add(str(klass))
                filter_thread_refs.add(klass.addr)
            elif tgk_name in klass.klass_dependencies or \
                 tgk_name == klass.klass_name():
                tgk_filter_thread_refs.add(klass.addr)
        
        # looking for thread addresses klass name usages
        ftr = filter_thread_refs
        tgk_ftr = filter_thread_refs
        t_oops = []
        tk_addrs = []
        tgk_addrs = []
        for addr_vals in self.klass_range_uses.values():
            tks = [addr for addr, val in addr_vals if val in ftr]
            tk_addrs = tk_addrs + tks

        for addr_vals in self.klass_range_uses.values():
            tks = [addr for addr, val in addr_vals if val in tgk_ftr]
            tgk_addrs = tgk_addrs + tks

        
        for addr in tgk_addrs:
            if addr-self.word_sz in self.jva.known_oops:
                self.jva.forget_all_for_addr(addr-self.word_sz)
            oop = Oop.from_jva(addr-self.word_sz, self.jva)
            if oop is None:
                continue
            oop.update_fields()
            if oop.has_oop_field_not_none('threads'):
                threads =  oop.get_oop_first_field_in_klasses('threads')
                for t_toop in threads.oop_values:
                    if t_oop and toop.get_oop_first_field_in_klasses('name') and\
                       not t_oop.addr in tk_addrs:
                        tk_addrs.append(t_oop.addr) 

        for addr in tk_addrs:
            if addr-self.word_sz in self.jva.known_oops:
                self.jva.forget_all_for_addr(addr-self.word_sz)
            oop = Oop.from_jva(addr-self.word_sz, self.jva)
            if oop is None: 
                continue
            oop.update_fields()
            if oop.get_oop_first_field_in_klasses('name'):
                oop_name = oop.get_oop_first_field_in_klasses('name')
                if oop_name.klass_name().find('[C') == 0:
                    t_oops.append(oop)
        # enumerate potential thread mark oop addresses
        pot_t_locs = [markOop_addr for markOop_addr, _, kref in self.pot_oop_headers if kref in ftr and not markOop_addr in self.forwarded_addrs]
        pot_t_locs = [oop.addr for oop in t_oops] + pot_t_locs
        oops = []
        self.log( "Enumerated %d Thread mark OOP addresses"%(len(pot_t_locs)))
        self.log( "Loading and updating all the thread OOP addresses")
        pos = 0
        for oop_addr in pot_t_locs:
            #print "Forgettting Oop: %s"%hex(oop_addr)
            #self.jva.forget_all_for_addr(oop_addr)
            self.log("Loading thread OOP %d @ 0x%08x all the thread OOP addresses"%(pos, oop_addr))
            oop = self.get_oop_by_addr(oop_addr)
            if oop:
                self.jva.forget_all_for_addr(oop_addr)
            
            oop = Oop.from_jva(oop_addr, self.jva)
            if oop is None:
                self.log("Failed to load thread OOP %d @ 0x%08x all the thread OOP addresses"%(pos, oop_addr))
                continue
            oop.update_fields()
            fields = getattr(oop, 'oop_field_values_by_name', None) if oop\
                              else None
            if oop is None or fields is None or len(fields) == 0:
                self.log("Failed to load thread OOP %d @ 0x%08x all the thread OOP addresses"%(pos, oop_addr))
                pos += 1
                continue
            #print "Found Oop: %s"%str(oop)
            oops.append(oop)
            pos += 1 

        #oops = [self.get_oop_by_addr(addr) for addr in pot_t_locs]
        known_threads = set([oop.addr for oop in oops if oop])
        self.log( "Loaded and updated %d Known Threads"%len(known_threads))
        main_oop = None
        discovered_oops = []
        self.log( "Attempting to convert the Thread OOPs into python objects")
        pos = 0
        conversion_threads = []
        wait_time = 1200
        start = datetime.now()
        period = timedelta(seconds=wait_time)
        next_time = datetime.now() + period

        for toop in oops:
            #t = threading.Thread(target=self.convert_thread_oop_to_python, args=(toop, pos))
            if convert_oop_to_pyobj:
                self.convert_thread_oop_to_python(toop, pos, known_threads)
                pos += 1
                continue
            else:
                toop_type = self.query_oop_type(toop.addr)
                if toop_type is None:
                    self.log( "Failed to resolve oop_type for %s pos=%d addr=0x%08x"% (str(toop), pos, toop.addr))
                    pos += 1
                    continue
                eetop = None
                name = None
                try:
                    if toop.has_oop_field_not_none('name', any_klass=True):
                        name_oop = toop.get_oop_first_field_in_klasses('name')
                        if name_oop.ooptype == 'ObjArrayKlassOop':
                            name = name_oop.python_value()
                        elif name_oop.ooptype == 'OopInstance' and \
                            self.query_oop_type(name_oop.addr).find('java/lang/String') > -1 and\
                            name_oop.has_oop_field_not_none('value', any_klass=True):
                            name = name_oop.get_oop_first_field_in_klasses('value')\
                                   .python_value()

                    if toop.has_oop_field_not_none('eetop', any_klass=True):
                        eetop = toop.get_oop_first_field_in_klasses('eetop')\
                                   .python_value()

                    if name is None:
                        name=oop_type+":%d"%(pos)

                    if eetop is None:
                        raise Exception('ignored')
 
                except:
                    self.log( "Failed to resolve name(%s) or eetop(%s) for %s pos=%d addr=0x%08x"% (str(name), hex(eetop) if isinstance(eetop,long) else str(eetop), str(toop), pos, toop.addr))
                    pos += 1
                    continue

                self.jthread_start_mapping_thread_oop[eetop] = toop.addr
                self.thread_oop_mapping_jthread[toop.addr] = eetop
                self.thread_oop_by_name[name] = toop
                self.confirmed_java_thread[toop.addr] = toop
                self.oop_by_thread_obj[toop.addr] = set()
                group = toop.get_oop_first_field_in_klasses('group')
                threads = None if group is None else group.get_oop_first_field_in_klasses('threads')
                if group is None and threads is None:
                    self.log( "thread.group.threads[] is null for for %s pos=%d addr=0x%08x"% (str(toop), pos, toop.addr))
                    pos += 1
                    continue
                elif not traverse_thread_groups:
                    pos += 1
                    continue

                self.log( "Analyzing thread.group.threads[] for for %s pos=%d addr=0x%08x"% (str(toop), pos, toop.addr))
                threads_pos = 0
                for t in threads.oop_values:
                    if t is None or t.is_prim():
                        threads_pos += 1
                        continue
                    oop_type = self.query_oop_type(t.addr)
                    if oop_type is None:
                        continue
                    try:
                        eetop = t.get_oop_first_field_in_klasses('eetop')
                        name = t.get_oop_field('name')
                    except:
                        self.log( "Failed to resolve name or eetop for %s pos=%d addr=0x%08x from 0x%08x"% (str(t), threads_pos, t.addr, toop.addr))
                        threads_pos += 1
                        continue
                        
                    if eetop is None:
                        threads_pos += 1
                        continue
                    else:
                        eetop = eetop.python_value()
                    if name:
                        name = name.python_value()

                    if name is None:
                        name = ("Unknown: pos=%d addr=0x%08x from 0x%08x"%(threads_pos, t.addr, toop.addr))

                    if not t.addr in known_threads:
                        self.log( "%s (%d in threads array) (oop_type=%s) not in known threads"% (name , threads_pos, oop_type))

                    self.jthread_start_mapping_thread_oop[eetop] = t.addr
                    self.thread_oop_mapping_jthread[t.addr] = eetop
                    self.confirmed_java_thread[t.addr] = t
                    self.oop_by_thread_obj[t.addr] = set()
                    threads_pos += 1
                pos += 1
            #t.start()
            #conversion_threads.append(t)
        
        while len(conversion_threads) > 0:
            _tmp = [t for t in conversion_threads if t.isAlive()]
            conversion_threads = _tmp
            now = datetime.now()
            if now >= next_time:
                # TODO term the threads
                break
        
            
        self.update_biased_oops_by_threads()


    def update_biased_oops_by_threads(self):
        valid_bias_oops = {}
        self.log( "Attempting to group/enumerate thread-biased OOPs")
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
        self.log( "Done enumerating all the Thread OOPs")


    def convert_thread_oop_to_python(self, toop, pos=0, known_threads=[]):
            self.log("Converting thread OOP %d @ 0x%08x to po"%(pos, toop.addr))
            fields = getattr(toop, 'oop_field_values_by_name', None) if toop\
                              else None
            if fields is None or len(fields) == 0 or\
               toop._name.find('Oop') < 0:# or\
               #not 'java/lang/Thread' in fields or\
               #len(fields['java/lang/Thread']) == 0:
                self.log("Failed (not thread) Converting thread OOP %d @ 0x%08x to po"%(pos, toop.addr))
                return
            #print "Converting %s to Python object: %s"%(hex(toop.addr), str(toop))
            po = self.get_python_obj(toop.addr, use_internals_knowledge=True)
            #po = self.get_python_object(toop, reset=True)
            if po is None or\
               isinstance(po, long) or\
               isinstance(po, int) or\
               not hasattr(po, 'group') or\
               po.group is None or\
               po.group.threads is None:
                self.log("Failed (not valid type) Converting thread OOP %d @ 0x%08x to po"%(pos, toop.addr))
                return
            if po.eetop == 0:
                self.log("Failed (eetop == 0) Converting thread OOP %d @ 0x%08x to po"%(pos, toop.addr))
                return
            self.jthread_start_mapping_thread_oop[po.eetop] = po.get_addr()
            self.thread_oop_mapping_jthread[po.get_addr()] = po.eetop
            self.thread_oop_by_name[po.name] = po
            self.confirmed_java_thread[po.get_addr()] = toop
            self.oop_by_thread_obj[po.get_addr()] = set()

            for t in po.group.threads:
                if t is None or not hasattr(t, 'oop_type') or t.oop_type != 'java/lang/Thread':
                    report_type = t.oop_type if t and hasattr(t, 'oop_type') else  str(type(t))
                    self.log("Thread @ 0x%08x has %s type in thread groups"%(toop.addr, report_type))
                    continue
                if not t.get_addr() in known_threads:
                    self.log( "%s not in known threads"%t.name)

                oop = self.get_oop_by_addr(t.get_addr())
                self.jthread_start_mapping_thread_oop[t.eetop] = t.get_addr()
                self.thread_oop_mapping_jthread[t.get_addr()] = t.eetop
                self.confirmed_java_thread[t.get_addr()] = oop
                self.oop_by_thread_obj[t.get_addr()] = set()

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
                        if not ecmdr.start in self.methods_entries:
                            self.methods_entries[ecmdr.start] = []
                        self.methods_entries[ecmdr.start].append(ecmd.addr)
                        if ecmd.stackmap_data > 0:
                            self.methods_entries[ecmdr.start].append(ecmd.stackmap_data)
        # Update the constant pool object caches
        update_cpc = set([i.update_cache() for i in self.jva.known_metas.values() if i._name == 'ConstantPool'])
        # Update the methods and fields
        update_methods = set([i.update_fields() for i in self.jva.known_metas.values() if i._name == 'Method'])
        return True

    def build_oop_references(self):
        self.references_out = {}
        self.references_in = {}
    
        all_oops = self.jva.all_oops
        for addr, oop in all_oops.items():
            if oop is None:
                continue
            if not addr in self.references_out:
                self.references_out[addr] = set()
            if not addr in self.references_in:
                self.references_in[addr] = set()
    
            if oop.ooptype == 'OopInstance':
                oop_values = oop.oop_field_values_by_name
                if oop_values is None:
                    oop.update_fields()
                    if oop.oop_field_values_by_name is None:
                        continue
                    oop_values = oop.oop_field_values_by_name
                for klass, fields in oop_values.items():
                    for field, f_oop in fields.items():
                        if f_oop is None:
                            continue
                        if not f_oop.addr in self.references_out:
                            self.references_out[f_oop.addr] = set()
                        if not f_oop.addr in self.references_in:
                            self.references_in[f_oop.addr] = set()
                        self.references_out[oop.addr].add(f_oop.addr)
                        self.references_in[f_oop.addr].add(oop.addr)
            elif oop.ooptype == 'ObjArrayKlassOop':
                oop_values = oop.oop_values
                if oop_values is None:
                    oop.update_fields()
                    if oop.oop_values is None:
                        continue
                    oop_values = oop.oop_values
                for f_oop in oop_values:
                    if f_oop is None:
                        continue
                    if not f_oop.addr in self.references_out:
                        self.references_out[f_oop.addr] = set()
                    if not f_oop.addr in self.references_in:
                        self.references_in[f_oop.addr] = set()
                    self.references_out[oop.addr].add(f_oop.addr)
                    self.references_in[f_oop.addr].add(oop.addr)

    def get_oop_thread_name(self, oop):
        if not oop or not hasattr(oop, 'oop_field_values_by_name') or\
           not 'java/lang/Thread' in oop.oop_field_values_by_name:
            return None
        name_oop = oop.oop_field_values_by_name['java/lang/Thread']['name']
        oop_type = self.query_oop_type(name_oop.addr)\
                   if name_oop\
                   else None
        name = None
        if oop_type == '[C':
            name = name_oop.raw_value()
        elif oop_type == 'java/lang/String':
            name = name_oop.get_oop_first_field_in_klasses('value').raw_value()
        return name

    def get_thread_infos_table(self, tablefmt='simple'):
        if self.thread_infos is None or len(self.thread_infos) == 0:
            return ""
        table = []
        headers = ["TID", "Native Address", "Heap Address", "Thread Name"]
        format_hex = lambda a: "0x%08x"%a
        addrs = [(a, self.thread_infos[a]['tid']) for a in self.thread_infos.keys()]
        addrs = sorted(addrs, key=lambda a_k: a_k[1])
        tinfos = [self.thread_infos[a_k[0]] for a_k in addrs]
        for vals in tinfos:
            entry = [vals['tid'], format_hex(vals['native_address']),
                    format_hex(vals['heap_address']), vals['name']]
            table.append(entry)
        table_str = tabulate(table, headers=headers, tablefmt=tablefmt)
        return table_str
    
    def print_thread_infos_table(self, tablefmt='simple'):
        dat = self.get_thread_infos_table(tablefmt=tablefmt)
        print dat


    def get_recovered_vframes(self, thread_locs=[], thread_name=None, tablefmt='simple'):
        if thread_name:
            for loc, ti in self.thread_infos.items():
                if ti['name'].find(thread_name) > -1:
                    thread_locs.append(loc)
        elif len(thread_locs) == 0:
            thread_locs = self.thread_infos.keys()
        elif len(thread_locs) > 0:
            thread_locs = [i for i in thread_locs if i in self.thread_infos]
        if len(thread_locs) == 0:
            return ''
        
        format_hex = lambda a: "0x%08x"%a
        addrs = [(a, self.thread_infos[a]['tid']) for a in thread_locs]
        addrs = sorted(addrs, key=lambda a_k: a_k[1])
        thread_locs = [a_k[0] for a_k in addrs]

        
    def create_block_data(self, baddr, num_dwords=1, offset=0, word_sz=4):
        r = self.jva.find_range(baddr)
        dwords = r.read_dwords_at_addr(baddr+offset,num_dwords)
        block_data = {'addr':baddr, 'dwords':dwords, 'word_sz':word_sz, 'dword_offset':offset}
        return block_data
   
    def dump_block_data(self, block_data):
        block_sz = len(block_data['dwords'])
        word_sz = block_data['word_sz']
        offset = block_data['dword_offset']
        baddr = block_data['addr']
        _addrs = [i for i in xrange(baddr, baddr+block_sz*4+offset, word_sz)]
        pos_ = ["%4d"%i for i in xrange(0, block_sz)]
        addrs = [ "0x%08x  <==="%i if i == baddr else "0x%08x      "%i for i in _addrs]
        #addrs[0] = addrs[0] + "  <==="
        #addrs = addrs[:1] + [i+ "      " for i in addrs[1:]]
        dwords = ["0x%08x"%i for i in block_data['dwords']]
        struct_extras = [self.get_overlay_info(i) for i in _addrs]
        padding = max([len(i) for i in struct_extras])
        pad_fmt = "%{0}s".format(padding)
        struct_extras = [i.ljust(padding) for i in struct_extras]
        extras = [self.get_extra(i) for i in block_data['dwords']]
        padding = max([len(i) for i in extras])
        pad_fmt = "%{0}s".format(padding)
        extras = [i.ljust(padding) for i in extras]
        dumps = zip(pos_, addrs, dwords, extras, struct_extras)
        dump_str = "\n".join(["%s %s %s %s %s"%(i[0], i[1], i[2], i[3], i[4]) for i in dumps])
        return dump_str

    def get_overlay_info(self, addr):
        if addr in self.jva.known_overlay_mapping:
            res = self.jva.known_overlay_mapping[addr]
            if res['name']:
                _t = res['type'] if len(res['type']) < 20 else res['type'][:20]
                _n = res['name'] if len(res['name']) < 20 else res['name'][:20]
                return "[struct_field: %s %s]"%(_t, _n)
        return ''

    def get_extra(self, addr):
        if addr > 0 and addr in self.jthread_start_mapping_thread_oop:
            oop_addr = self.jthread_start_mapping_thread_oop[addr]
            thread_name = self.thread_infos[oop_addr]['name']
            return "Thread Native: %s @ Heap: 0x%08x"%(thread_name, oop_addr)
        elif addr > 0 and addr in self.thread_oop_mapping_jthread:
            oop_addr = addr
            #oop_addr = self.jthread_start_mapping_thread_oop[addr]
            thread_name = self.thread_infos[oop_addr]['name']
            return "JavaThread OOP: %s @ Heap: 0x%08x"%(thread_name, oop_addr)
        elif addr in self.jva.known_oops:
            return "Oop: %s"%self.jva.known_oops[addr]
        elif addr in self.jva.known_oops:
            return "Oop: %s"%self.jva.known_arrayoops[addr]
        elif addr in self.jva.loaded_classes_by_addr:
            return "Klass: %s"%self.jva.loaded_classes_by_addr[addr]
        elif addr in self.jva.symboltable_values:
            return "Symbol: %s"%self.jva.symboltable_values[addr]
        elif addr in self.jva.known_metas and \
             self.jva.known_metas[addr]._name == 'Method':
            m = self.jva.known_metas[addr]
            return "Method: %s.%s"%(m.klass_holder_value, m.name())
        elif addr in self.jva.known_metas and \
             self.jva.known_metas[addr]._name == 'ConstantPoolCache':
            cpc = self.jva.known_metas[addr]
            cp = self.jva.known_metas[cpc.contant_pool]
            return "CPCache: %s"%(cp.pool_holder_value)
        elif addr in self.jva.known_metas and \
             self.jva.known_metas[addr]._name == 'ConstantPool':
            cp = self.jva.known_metas[addr]
            return "CP: %s"%(cp.pool_holder_value)
        elif addr in self.jva.known_overlay_mapping:
            res = self.jva.known_overlay_mapping[addr]
            if res['name']:
                return "[--> %s %s]"%(res['type'], res['name'])
        elif addr in self.jva.known_metas:
            meta = self.jva.known_metas[addr]
            return "%s"%(meta._name)
        return ''

    def analyse_block_structure(self, blocks):
        # analyse block structures for addresses and value occurrences
        # withing each block value.  helpful for finding dependent structures
        # within a group of blocks
        valid_addrs = set()
        addr_occurence = {}
        addr_uses = {}
        val_occurrence = {}
        val_uses = {}
        # accumulate addrs
        baddrs = []
        for baddr, block_data in blocks.items():
            offset = block_data['offset']
            word_sz = block_data['word_sz']
            block_sz = len(block_data['dwords'])
            valid_addrs |= set([baddr+i+offset for i in xrange(0, block_sz, word_sz)])
        
        for baddr, block_data in blocks.items():
            _blocks = block_data['dwords']
            value = block_data['val']
            offset = block_data['offset']
            word_sz = block_data['word_sz']
            pos = 0
            for val in _blocks:
                addr = 4*pos + baddr + offset
                if val in valid_addrs:
                    if not val in addr_occurence:
                        addr_occurence[val] = {'tot':0}
                        addr_uses[val] = []
                    if not pos in addr_occurence[val]:
                        addr_occurence[val][pos] = 0
                    addr_occurence[val]['tot'] += 1
                    addr_occurence[val][pos] += 1
                    addr_uses[val].append((baddr, addr))
                if not val in val_occurrence:
                    val_occurrence[val] = {'tot':0}
                    val_uses[val] = []
                if not pos in val_occurrence[val]:
                    val_occurrence[val][pos] = 0
                val_occurrence[val]['tot'] += 1
                val_occurrence[val][pos] += 1
                val_uses[val].append((baddr, addr))
                pos += 1        
    
        res_dict = {}
        res_dict['addr_uses'] = addr_uses
        res_dict['addr_occurrence'] = addr_occurence
        res_dict['val_uses'] = val_uses
        res_dict['val_occurrence'] = val_occurrence
        return res_dict

    def extract_proc_builder_command(self):
        p_oops = {}
        
        p_classes2 =  [i for i in self.jva.loaded_classes_by_name if i.find('ProcessBuilder') > -1]
        for cname in p_classes2:
            p_oops[cname] = []
            oops = self.find_all_loaded_klass_oops(cname)
            for oop in oops:
                self.jva.forget_all_for_addr(oop.addr) #update_fields()
                oop = Oop.from_jva(oop.addr, self.jva)
                if oop:
                    oop.update_fields()
                    p_oops[cname].append(oop)
        
        self.proc_builder_commands = {}
        xoops = [oop for oop in p_oops['java/lang/ProcessBuilder']]
        for oop in xoops:
            if oop is None:
                continue
            cmd_oop = oop.get_oop_first_field_in_klasses('command')
            eData = None if cmd_oop is None else cmd_oop.get_oop_first_field_in_klasses('elementData')
            cmd = []
            if eData:
                eData.update_fields()
                for arg_oop in eData.oop_values:
                    v = None
                    if arg_oop:
                        arg_oop.update_fields()
                        v = arg_oop.get_oop_first_field_in_klasses('value').python_value()
                    if v:
                        cmd.append(v)
                    else:
                        cmd.append("ERROR_UNRECOVERABLE")
            if len(cmd) > 0:
                self.proc_builder_commands[oop.addr] = " ".join(cmd)
            else:
                self.proc_builder_commands[oop.addr] = 'ERROR_UNRECOVERABLE'
        return self.proc_builder_commands

    def extract_process(self):
        p_oops = {}
        p_classes1 =  [i for i in recoop_1.jva.loaded_classes_by_name if i.find('java/lang/UNIXProcess') > -1]
        for cname in p_classes1:
            p_oops[cname] = []
            oops = self.find_all_loaded_klass_oops(cname)
            for oop in oops:
                self.jva.forget_all_for_addr(oop.addr) #update_fields()
                oop = Oop.from_jva(oop.addr, self.jva)
                if oop:
                    oop.update_fields()
                    p_oops[cname].append(oop)
        
        self.proc_builder_commands = {}
        xoops = [oop for oop in p_oops['java/lang/ProcessBuilder']]
        for oop in xoops:
            if oop is None:
                continue
            cmd_oop = oop.get_oop_first_field_in_klasses('command')
            eData = self.extract_arraylist(cmd_oop)
            cmd = []
            if eData:
                for arg_oop in eData.oop_values:
                    v = None
                    if arg_oop:
                        v = arg_oop.get_oop_first_field_in_klasses('value').python_value()
                    if v:
                        cmd.append(v)
                    else:
                        cmd.append("ERROR_UNRECOVERABLE")
            if len(cmd) > 0:
                self.proc_builder_commands[oop.addr] = " ".join(cmd)
            else:
                self.proc_builder_commands[oop.addr] = 'ERROR_UNRECOVERABLE'
        return self.proc_builder_commands

    def find_procs(self):
        lambdas = ['java/lang/UNIXProcess$$Lambda$6',
        'java/lang/UNIXProcess$$Lambda$4',
        'java/lang/UNIXProcess$$Lambda$5',
        'java/lang/UNIXProcess$$Lambda$7',]    
        process = [
        'java/lang/UNIXProcess',
        ]    
        process_io = [
        'java/lang/UNIXProcess$ProcessPipeOutputStream',
        'java/lang/UNIXProcess$DeferredCloseInputStream',
        'java/lang/UNIXProcess$ProcessPipeInputStream',
        ]
        pids = []
        lam_procs = {}
        for  i in lambdas:
            for oop in p_oops[i]:
                oop = oop.get_oop_first_field_in_klasses('arg$1')
                if oop:
                    lam_procs[oop.addr] = oop
                    pid_oop = oop.get_oop_first_field_in_klasses('pid') 
                    if pid_oop:
                        pid = pid_oop if isinstance(pid_oop, int) else pid_oop.raw_value()
                        pids.append((pid, oop))
        
        ori_procs = {}
        for  i in process:
            for oop in p_oops[i]:
                if oop:
                    ori_procs[oop.addr] = oop
                    pid_oop = oop.get_oop_first_field_in_klasses('pid') 
                    if pid_oop:
                        pid = pid_oop if isinstance(pid_oop, int) else pid_oop.raw_value()
                        pids.append((pid, oop))
        
        self.proc_info = {}
        for pid, oop in pids:
            procs[pid] = {"oops":{}, "oop_addrs":[], "stdin_addrs":[], "stdout_addrs":[], "stderr_addrs":[],
                          "stdin":{}, "stdout":{}, "stderr":{}}
            if not oop.addr in procs[pid]["oop_addrs"]:
                procs[pid]["oop_addrs"].append(oop.addr)
                procs[pid]["oops"][oop.addr] = oop
        
            stdout = oop.get_oop_first_field_in_klasses('stdout')
            stdin = oop.get_oop_first_field_in_klasses('stdout')
            stderr = oop.get_oop_first_field_in_klasses('stderr')
            if stderr:
                data = self.read_buffer(stderr)
                procs[pid]["stderr"][stderr.addr] = data
            if stdout:
                data = self.read_buffer(stdout)
                procs[pid]["stdout"][stdout.addr] = data
            if stdin:
                data = self.read_buffer(stdin)
                procs[pid]["stdout"][stdin.addr] = data
        return self.proc_info

    def extract_map(self, map_oop):
        result = []
        if map_oop is None:
            return None
        table = map_oop.get_oop_first_field_in_klasses('table')
        if table is None:
            return None
        for oop in table.oop_values:
            if oop is None:
                continue
            hash_oop = oop.get_oop_first_field_in_klasses('hash')
            hv = None
            if hash_oop:
                hv = hash_oop.raw_value()
            key_oop = oop.get_oop_first_field_in_klasses('key')
            value_oop = oop.get_oop_first_field_in_klasses('value')
            result.append((hv, key_oop, value_oop)) 
    
        return result
    
    def extract_hashmap(self, map_oop):
        result = []
        if map_oop is None:
            return None
        table = map_oop.get_oop_first_field_in_klasses('table')
        if table is None:
            return None
        for oop in table.oop_values:
            if oop is None:
                continue
            hash_oop = oop.get_oop_first_field_in_klasses('hash')
            hv = None
            if hash_oop:
                hv = hash_oop.raw_value()
            key_oop = oop.get_oop_first_field_in_klasses('key')
            value_oop = oop.get_oop_first_field_in_klasses('value')
            result.append((hv, key_oop, value_oop)) 
        return result

    def extract_arraylist(self, al_oop):
        result = []
        eData = None if al_oop is None else al_oop.get_oop_first_field_in_klasses('elementData')
        if eData is None:
            return None

        eData.update_fields()
        for oop in eData.oop_values:
            v = None
            if oop:
                oop.update_fields()
                v = oop.get_oop_first_field_in_klasses('value')
            if v:
                result.append(v)
            else:
                result.append(None)
        return result

    
    def link_inputstream_impl(self, oop1, oop2 ):
        self.instream_linkage[oop1.addr] = oop2.addr
        self.instream_linkage[oop2.addr] = oop1.addr

    def link_outputstream_impl(self, oop1, oop2 ):
        self.outstream_linkage[oop1.addr] = oop2.addr
        self.outstream_linkage[oop2.addr] = oop1.addr

    def check_stream_link(self, oop):
        if oop and  oop.addr in self.outstream_linkage:
            return self.outstream_linkage[oop.addr]
        elif oop and  oop.addr in self.instream_linkage:
            return self.instream_linkage[oop.addr]
        return None

    def get_io_buffer_from_oop(self, oop):
        using_addr = self.check_stream_link(oop)
        if using_addr:
            return get_io_buffer_from_addr(self, using_addr)
        using_addr = self.check_consumer_io(oop)
        if using_addr:
            return get_io_buffer_from_addr(self, using_addr)
        return None

    def get_io_buffer_from_addr(self, addr):
        if addr in self.outputstream_buffers:
            return self.outputstream_buffers[addr]
        elif addr in self.inputstream_buffers:
            return self.inputstream_buffers[addr]
        if addr in self.reader_buffers:
            return self.reader_buffers[addr]
        elif addr in self.writer_buffers:
            return self.writer_buffers[addr]
        return None

    def link_reader_io(self, oop1, oop2 ):
        self.reader_linkage[oop1.addr] = oop2.addr
        self.reader_linkage[oop2.addr] = oop1.addr

    def link_writer_io(self, oop1, oop2 ):
        self.writer_linkage[oop1.addr] = oop2.addr
        self.writer_linkage[oop2.addr] = oop1.addr

    def check_consumer_io(self, oop):
        if oop and  oop.addr in self.reader_linkage:
            return self.reader_linkage[oop.addr]
        elif oop and  oop.addr in self.writer_linkage:
            return self.writer_linkage[oop.addr]
        return None

    def add_fd_user(self, oop, fd_oop=None):
        fd = None
        if fd_oop is None:
            fd_oop = oop.get_oop_first_field_in_klasses('fd')
        if fd_oop and \
           fd_oop.klass_name() == 'java/io/FileDescriptor':
            if not fd_oop.addr in self.fd_oops:
                self.fd_oops[fd_oop.addr] = []
            
            self.fd_oops[fd_oop.addr].append(oop)
            fd = fd_oop.get_oop_first_field_in_klasses('fd')
            
            if fd and not isinstance(fd, int):
                fd = fd.raw_value()
            if fd and not isinstance(fd, int):
                fd = None

            if not fd is None and \
               not fd in self.java_fd_users:
                self.java_fd_users[fd] = []
            self.java_fd_users[fd].append(oop)
        elif fd_oop and \
           fd_oop.ooptype == 'IntOop':
            fd = fd_oop.raw_value()
            if not fd is None and \
               not fd in self.java_fd_users:
                self.java_fd_users[fd] = []
            self.java_fd_users[fd].append(oop)
        return fd 
                
            
    
    def find_buffered_streams(self):
        bufferedInputStream = self.find_locs_klass_value('java/io/BufferedInputStream')
        bufferedOutputStream = self.find_locs_klass_value('java/io/BufferedOutputStream')
    
        all_klass_uses = [
            # outputStreams,
            # inputStreams,
            #bufferedReader,
            #bufferedWriter,
            bufferedInputStream,
            bufferedOutputStream,
        ]
        klass_addrs = []
        for use in all_klass_uses:
            for addrs in use.values():
                klass_addrs = addrs + klass_addrs

        oops = []
        for addr in klass_addrs:
            if addr-self.word_sz in self.jva.known_oops:
                self.jva.forget_all_for_addr(addr-self.word_sz)
            oop = Oop.from_jva(addr-self.word_sz, self.jva)
            if oop is None or not (oop.ooptype == 'Oop' or oop.ooptype == 'OopInstance'):
                continue
            oop.update_fields()
            oops.append(oop)
            out = oop.get_oop_first_field_in_klasses('out')
            in_ = oop.get_oop_first_field_in_klasses('in')
            err = oop.get_oop_first_field_in_klasses('err')
            if out:
                self.link_outputstream_impl(oop, out)
                self.outputstream_buffers[oop.addr] = self.read_buffer(oop)
                self.buffered_streams[oop.addr] = oop
                fd = out.get_oop_first_field_in_klasses('fd')
                self.add_fd_user(oop, fd)
            if in_:
                self.link_inputstream_impl(oop, in_)
                self.inputstream_buffers[oop.addr] = self.read_buffer(oop)
                self.buffered_streams[oop.addr] = oop
                fd = in_.get_oop_first_field_in_klasses('fd')
                self.add_fd_user(oop, fd)
            if err:
                self.link_inputstream_impl(oop, in_)
                self.errstream_buffers[oop.addr] = self.read_buffer(oop)
                self.buffered_streams[oop.addr] = oop
                fd = in_.get_oop_first_field_in_klasses('fd')
                self.add_fd_user(oop, fd)
        return self.buffered_streams

    def find_buffered_io(self):
        # filteredOutputStreams = self.find_locs_klass_value('java/io/FilterOutputStream')
        # filteredInputStreams = self.find_locs_klass_value('java/io/FilterInputStream')
        # outputStreams = self.find_locs_klass_value('java/io/OutputStreams')
        # inputStreams = self.find_locs_klass_value('java/io/InputStreams')
        # bufferedReader = self.find_locs_klass_value('java/io/BufferedReader')
        # bufferedWriter = self.find_locs_klass_value('java/io/BufferedWriter')
        bufferedInput = self.find_locs_klass_value('java/io/BufferedReader')
        bufferedOutput = self.find_locs_klass_value('java/io/BufferedWriter')
    
        all_klass_uses = [
            # outputStreams,
            # inputStreams,
            #bufferedReader,
            #bufferedWriter,
            bufferedInput,
            bufferedOutput,
        ]
        klass_addrs = []
        for use in all_klass_uses:
            for addrs in use.values():
                klass_addrs = addrs + klass_addrs
    
        oops = []
        for addr in klass_addrs:
            if addr-self.word_sz in self.jva.known_oops:
                self.jva.forget_all_for_addr(addr-self.word_sz)
            oop = Oop.from_jva(addr-self.word_sz, self.jva)
            if oop is None or not (oop.ooptype == 'Oop' or oop.ooptype == 'OopInstance'):
                continue
            oop.update_fields()
            oops.append(oop)
            out = oop.get_oop_first_field_in_klasses('out')
            in_ = oop.get_oop_first_field_in_klasses('in')
            cb = oop.get_oop_first_field_in_klasses('cb')
            locs = None
            if oop.klass_name().find('Writer') > -1:
                self.link_writer_(oop, out)
                self.writer_buffers[oop.addr] = self.read_writer(oop)
                self.reader_writers[oop.addr] = oop
                fd = out.get_oop_first_field_in_klasses('fd')
                self.add_fd_user(oop, fd)
            if oop.klass_name().find('Reader') > -1:
                self.link_reader_io(oop, in_)
                self.reader_buffers[oop.addr] = self.read_reader(oop)
                self.reader_writers[oop.addr] = oop
                fd = in_.get_oop_first_field_in_klasses('fd')
                self.add_fd_user(oop, fd)
        return self.reader_writers
