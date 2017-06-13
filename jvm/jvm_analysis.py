from zipfile import ZipFile
from StringIO import StringIO
from multiprocessing.managers import BaseManager
from multiprocessing import Pool, TimeoutError, Queue, Manager, Lock
import os, copy, time, copy, collections
from findstructs import FindStructs
from bitstring import ConstBitStream
import struct
from jvm_objects import VMStructEntry, CollectedHeap, GCLog, ClassLoaderData
from jvm_symboltable import SymbolTable, Symbol
from jvm_stringtable import StringTable
from jvm_systemdictionary import Dictionary
from jvm_klass import get_klass_info, KlassInstance, Klass, ObjArrayKlass, TypeArrayKlass, \
                      restrict_klass_parsing, ArrayKlass
from jvm_meta import Method, CPCache
from jvm_klassoop import Oop, ObjArrayKlassOop
from jvm_base import BaseOverlay
from jvm_entry_offsets import VERSION_OFFSET, DICTIONARY, SHAREDHEAP, \
                       SHAREDDICTIONARY, COLLECTEDHEAP, SYMBOLTABLE, \
                       STRINGTABLE, PLACEHOLDERS
#from jvm_klassoop import KlassOop, ArrayKlassOop, ObjArrayKlassOop,\
#                         TypeArrayKlassOop, Oop
#import BaseException
from datetime import datetime
def time_str():
    return str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))

parse_cls_line = lambda line: (long(line.split()[1], 16), line.split('(name=')[1].split(',')[0])

RECOOP_INTERFACE = None
def set_recoop_interface(recoop_interface):
    global RECOOP_INTERFACE
    RECOOP_INTERFACE = recoop_interface

def log_recoop_interface(msg):
    global RECOOP_INTERFACE
    if RECOOP_INTERFACE:
        recoop_interface.log(msg)
    else:
        print ("[%s]: %s"%(time_str(), msg))

def log_no_recoop(msg):
    print ("[%s]: %s"%(time_str(), msg))



def compress_dictionary_values(dict_vals):
    inMemoryOutputFile = StringIO()
    zipFile = ZipFile(inMemoryOutputFile, 'w')
    for k, v in dict_vals.items():
        zipFile.writestr(k, str(v))
    zipFile.close()
    inMemoryOutputFile.seek(0)
    data = inMemoryOutputFile.read()
    return data

def uncompress_dictionary_values(data):
    inMemoryOutputFile = StringIO(data)
    zipfile = ZipFile(inMemoryOutputFile)
    res = {}
    for name in zipfile.namelist():
        res[name] = eval(zipfile.read(name))
    return res

def create_bci_ranges(methods):
    bci_ranges = []
    for m in methods:
        if not hasattr(m, 'bci_addr') or\
           not hasattr(m, 'bci_size'):
           continue
        bci_range = {}
        bci_range['method'] = m.addr
        bci_range['start'] = m.bci_addr
        bci_range['end'] = m.bci_addr+m.bci_size
        bci_range['values'] = set([i for i in xrange(bci_range['start'], bci_range['end'])])
        bci_ranges.append(bci_range)
    return bci_ranges


def build_found_value_summarys(value_range_locs):
    found_addrs_locs = dict([(baddr, 0) for baddr in value_range_locs])
    found_val_locs = dict([(baddr, 0) for baddr in value_range_locs])
    for baddr, lst_addr_val_tup in value_range_locs.items():
        found_addrs_locs[baddr] += len(lst_addr_val_tup)
        if len(lst_addr_val_tup) > 0 and \
              isinstance(list(lst_addr_val_tup)[0], collections.Iterable) and\
              len(list(lst_addr_val_tup)[0]) > 0:
           found_val_locs[baddr] += len(set([k[1] for k in lst_addr_val_tup]))
        elif len(lst_addr_val_tup) > 0: 
           found_val_locs[baddr] += len(lst_addr_val_tup)

    skeys = found_addrs_locs.keys()
    skeys.sort()
    logs = []
    for baddr in skeys:
        logs.append("Range: 0x%08x # of addrs %5d, # of values %5d"%(baddr, found_addrs_locs[baddr], found_val_locs[baddr]))
    return logs


def impl_par_scan_page_for_bci_addrs(arg_items):
    filter_bci = lambda val, bci_range: None if not val in bci_range['values'] \
                                             else bci_range['method']
    baddr, offset, vals, bci_ranges_constraint, values, method_mapping = arg_items

    #vals = r.read_all_as_dword()
    #baddr = r.start
    value_range_locs = {}
    value_addr_locs = {}
    value_range_locs[baddr] = []
    pos = offset
    log_no_recoop("Scanning chunk: 0x%08x with %d values with %d constraints"%(baddr+offset, len(vals), len(bci_ranges_constraint)))
    found_vals = dict([(i, 0) for i in set(method_mapping.values())])
    for val in vals:
        m = None
        if val in values:
            method = method_mapping[val]
            t = (baddr+pos, val, method)
            value_range_locs[baddr].append(t)
            found_vals[method]+= 1
        pos += 4
        
    dict_values = {
          'value_range_locs':value_range_locs
    }
    all_vals = found_vals.values()
    log_no_recoop("Completed scanning chunk: 0x%08x.  Found %d values, %d unique"%(baddr+offset, len(all_vals), sum(all_vals)))
    return [baddr, dict_values]

POOL = None
def par_scan_page_for_bci_addrs(bci_ranges, bci_ranges_constraint, num_procs=20, max_send=666628):
    global POOL
    value_range_locs = {}
    pool = Pool(processes=num_procs)
    POOL = pool
    required_items = 0
    ranges = sorted(bci_ranges, key=lambda r: r.fsize, reverse=True)
    values = set()
    method_mapping = {}
    for brc in bci_ranges_constraint:
        _values = brc['values']
        values |= _values
        maddr = brc['method']
        method_mapping.update(dict([(v, maddr) for v in _values]))

    iter_data = build_par_bci_scan_page_iter(ranges, bci_ranges_constraint, values, method_mapping, max_send)
    #data = [(r, values, found_locations ) for r in ranges]
    pool_map_results = pool.imap_unordered(impl_par_scan_page_for_bci_addrs,iter_data )
    for vals in pool_map_results:
        baddr, res = vals
        log_no_recoop("Master Proc: Processed %d ranges: Reading values chunk: 0x%08x with %d values"%(required_items, baddr, len(res['value_range_locs'][baddr])))
        required_items += 1
        _value_range_locs = res['value_range_locs']
        for baddr, lst_addr_val_tup in _value_range_locs.items():
            if not baddr in value_range_locs:
                value_range_locs[baddr] = lst_addr_val_tup #copy.deepcopy(lst_addr_val_tup)
            else:
                l = value_range_locs[baddr] + lst_addr_val_tup
                value_range_locs[baddr] = l
    
    summary = build_found_value_summarys(value_range_locs)
    log_no_recoop("\n".join(summary))

    pool.close()
    POOL = None
    return value_range_locs

def build_par_bci_scan_page_iter(bci_ranges, bci_ranges_constraint, values, method_mapping, max_send=666628):
    data = []
    for r in bci_ranges:
        baddr = r.start
        offset = 0
        e = r.fsize/4
        vals = r.read_all_as_dword()
        if (r.fsize/4) < max_send:
            _v = vals
            t = (baddr, offset*4, _v, bci_ranges_constraint, values, method_mapping)
            data.append(t)
        else:
            while offset < e:
                _v = vals[offset:offset+max_send]
                t = (baddr, offset*4, _v, bci_ranges_constraint, values, method_mapping)
                data.append(t)
                offset += max_send
    return data

def get_pot_intersecting_scan_ranges(recoop_inf, target_addrs, target_addr_uses, other_addr_uses={}):
    return get_pot_bci_ranges(recoop_inf, target_addrs, target_addr_uses, other_addr_uses)

def get_pot_bci_ranges(recoop_inf, method_addrs, method_addr_uses, cpc_addr_uses):
    ignore_ranges = set()
    for ma in method_addrs:
        r = recoop_inf.jva.find_range(ma)
        ignore_ranges.add(r.start)

    int_ranges = {}
    for baddr in method_addr_uses.keys():
        if baddr in ignore_ranges or\
           not baddr in cpc_addr_uses:
            continue
        r = recoop_inf.jva.find_range(baddr)
        int_ranges[r.start] = r
    
    sorted_ranges = sorted(int_ranges.items(), key=lambda k_v: k_v[0], reverse=True)
    return [r[1] for r in sorted_ranges]

def impl_par_scan_page_for_dword_values(arg_items):
    baddr, offset, vals, values= arg_items
    if isinstance(values, list):
        values = set(values)
    elif isinstance(values, long) or isinstance(values, int):
        x = set()
        x.add(values)
        values = x

    #vals = r.read_all_as_dword()
    #baddr = r.start
    value_range_locs = {}
    value_addr_locs = {}
    value_range_locs[baddr] = []
    pos = offset
    log_no_recoop("Scanning chunk: 0x%08x with %d values for %d values"%(baddr+offset, len(vals), len(values)))
    found_vals = {}
    for val in vals:
        if val in values:
            t = (baddr+pos, val)
            value_range_locs[baddr].append(t)
            if not val in value_addr_locs:
                value_addr_locs[val] = set()
                found_vals[val] = 0
            value_addr_locs[val].add(baddr+pos)
            found_vals[val] += 1
        pos += 4

    all_vals = found_vals.values()
    log_no_recoop("Completed scanning chunk: 0x%08x.  Found %d values, %d unique"%(baddr+offset, len(all_vals), sum(all_vals)))
    #log_no_recoop("Returning values chunk: 0x%08x with %d values"%(baddr, r.fsize/4))
    dict_values = {
          'value_addr_locs':value_addr_locs,
          'value_range_locs':value_range_locs
    }
    #log_no_recoop("Compressing values chunk: 0x%08x with %d values"%(baddr, r.fsize/4))
    #data = compress_dictionary_values(dict_values)
    #return [baddr, data]
    return [baddr, dict_values]
    #log_no_recoop("Completed compressing values chunk: 0x%08x with %d values"%(baddr, r.fsize/4))

def build_par_scan_page_iter(_ranges, values, max_send=666628):
    data = []
    for r in _ranges:
        baddr = r.start
        offset = 0
        e = r.fsize/4
        vals = r.read_all_as_dword()
        if (r.fsize/4) < max_send:
            _v = vals
            t = (baddr, offset*4, _v, values)
            data.append(t)
        else:
            while offset < e:
                _v = vals[offset:offset+max_send]
                t = (baddr, offset*4, _v, values)
                data.append(t)
                offset += max_send
    return data

DWORD_SCAN_POOL = None
def par_scan_page_for_dword_values(_ranges, values, num_procs=20, max_send=666628):
    global DWORD_SCAN_POOL
    value_addr_locs = {}
    value_range_locs = {}
    pool = Pool(processes=num_procs)
    DWORD_SCAN_POOL = pool
    required_items = 0
    ranges = sorted(_ranges, key=lambda r: r.fsize, reverse=True) 
    iter_data = build_par_scan_page_iter(_ranges, values, max_send)        
    #data = [(r, values, found_locations ) for r in ranges]
    pool_map_results = pool.imap_unordered(impl_par_scan_page_for_dword_values,iter_data )

    for vals in pool_map_results:
        #baddr, data = vals
        #if data is None:
        #     log_no_recoop("Master Proc: Processed %d ranges: Reading values chunk: 0x%08x, but it was updated with a proxy"%(required_items, baddr))
        #     required_items += 1
        #     continue
        #res = uncompress_dictionary_values(data)

        baddr, res = vals
        log_no_recoop("Master Proc: Processed %d ranges: Reading values chunk: 0x%08x with %d values"%(required_items, baddr, len(res['value_range_locs'][baddr])))
        required_items += 1
        #value_addr_locs.update(res['value_addr_locs'])
        _value_addr_locs = res['value_addr_locs']
        _value_range_locs = res['value_range_locs']
        for val, loc_set in _value_addr_locs.items():
            if val in value_addr_locs:
                value_addr_locs[val] |= loc_set
            else:
                value_addr_locs[val] = loc_set #copy.deepcopy(loc_set)
            
        for baddr, lst_addr_val_tup in _value_range_locs.items():
            if not baddr in value_range_locs:
                value_range_locs[baddr] = lst_addr_val_tup #copy.deepcopy(lst_addr_val_tup)
            else:
                l = value_range_locs[baddr] + lst_addr_val_tup
                value_range_locs[baddr] = l
    summary = build_found_value_summarys(value_range_locs)
    log_no_recoop("\n".join(summary))
        
    pool.close()
    DWORD_SCAN_POOL = None
    return value_addr_locs, value_range_locs

class JVMAnalysis (object):
    VERSION_OFFSET = VERSION_OFFSET
    MAX_SEARCH_THREADS = 50
    MAX_STR_SIZE = 1024
    STATIC_TARGET_TYPES = [
        ['Universe', '_main_thread_group', 'oop',],
        ['Universe', '_system_thread_group', 'oop',],
        ['Universe', '_the_empty_class_klass_array', 'objArrayOop',],
        ['Universe', '_the_null_string', 'oop',],
        ['Universe', '_the_min_jint_string', 'oop',],
        ['Universe', '_throw_illegal_access_error', 'Method*',],
        ['Universe', '_bootstrapping', 'bool',],
        ['Universe', '_fully_initialized', 'bool',],
        ['Universe', '_byte_mirror', 'oop',],
        ['Universe', '_int_mirror', 'oop',],
        ['Universe', '_double_mirror', 'oop',],
        ['Universe', '_float_mirror', 'oop',],
        ['Universe', '_char_mirror', 'oop',],
        ['Universe', '_long_mirror', 'oop',],
        ['Universe', '_short_mirror', 'oop',],
        ['Universe', '_collectedHeap', 'CollectedHeap*',],
        ["Universe", "_boolArrayKlassObj","Klass*",],
        ["Universe", "_byteArrayKlassObj","Klass*",],
        ["Universe", "_charArrayKlassObj","Klass*",],
        ["Universe", "_intArrayKlassObj","Klass*",],
        ["Universe", "_shortArrayKlassObj","Klass*",],
        ['SharedHeap', '_sh', 'SharedHeap*',],
        ['SystemDictionary', '_placeholders', 'PlaceholderTable*',],
        ['SystemDictionary', '_dictionary', 'Dictionary*',],
        ['SystemDictionary', '_shared_dictionary', 'Dictionary*',],
        ['SystemDictionary', '_loader_constraints', 'LoaderConstraintTable*',],
        ['SharedRuntime', 'RuntimeStub*', '_wrong_method_blob',],
        ['SharedRuntime', 'RuntimeStub*', '_ic_miss_blob',],
        ['SharedRuntime', 'RuntimeStub*', '_resolve_opt_virtual_call_blob',],
        ['SharedRuntime', 'RuntimeStub*', '_resolve_virtual_call_blob',],
        ['SharedRuntime', 'RuntimeStub*', '_resolve_static_call_blob',],
        ['SharedRuntime', 'DeoptimizationBlob*', '_deopt_blob',],
        ['SharedRuntime', 'RicochetBlob*', '_ricochet_blob',],
        ['SharedRuntime', 'SafepointBlob*', '_polling_page_safepoint_handler_blob',],
        ['SharedRuntime', 'SafepointBlob*', '_polling_page_return_handler_blob',],
        ['SymbolTable', '_the_table', 'SymbolTable*',],
        ['StringTable', '_the_table', 'StringTable*',],
        ['Threads',  '_thread_list', 'JavaThread*',],
        ['Threads', '_number_of_threads', 'int',],
        ['Threads', '_number_of_non_daemon_threads', 'int',],
        ['Threads', '_return_code', 'int',],
        ]
    REDIS_STRINGS = "strings"
    REDIS_STRINGS_SET_KEY = "strings"
    REDIS_ADDRS_SET_KEY = "addrs"
    REDIS_STRING_BY_ADDR_HSET = "stringsbyaddr"
    REDIS_STRING_BY_STR_HSET = "stringsbystr"

    def log(self, msg):
        log_recoop_interface(msg)

    def __init__(self, mem_ranges, os_type="linux", libjvm = {},
            is_32bit=True, little_endian = True, redis_strings_con=None,
            redis_ptrs_con = None, word_sz = 4, jre=None, is_linux=True,
            start_symt_bf=None, end_symt_bf=None, start_sys_dict_bf=None, end_sys_dict_bf= None, start_strt_bf=None, end_strt_bf=None):
        # little_endian cause i dont know how to get that from the volatility
        # layer
        #libjvm = {"start":vaddr, "end":vaddr, "name":libname}
        self._init_params = {'mem_ranges':mem_ranges, 'os_type':os_type,
                'libjvm':libjvm,'is_32bit':is_32bit, 'little_endian':little_endian,
                'redis_strings_con':redis_strings_con,'redis_ptrs_con':redis_ptrs_con, 'word_sz':word_sz,
                'jre':jre, 'is_linux':is_linux, 'start_symt_bf':start_symt_bf,
                'end_symt_bf':end_symt_bf, 'start_sys_dict_bf':start_sys_dict_bf,
                'end_sys_dict_bf':end_sys_dict_bf, 'start_strt_bf':start_strt_bf,
                'end_strt_bf':end_strt_bf}
        self.ranges = mem_ranges
        self.is_win = False
        self.java_version = "8u40" if not 'version' in libjvm or \
                                      libjvm['version'] is None \
                                   else libjvm['version']
        if type(self.ranges) == list:
            ranges_ = {}
            for r in self.ranges:
                addr = r.start
                ranges_[addr] = r
            self.ranges = ranges_

        if not is_linux:
            BaseOverlay.is_win = True
            Klass.set_win_type()
            KlassInstance.set_win_type()
            ObjArrayKlass.set_win_type()
            TypeArrayKlass.set_win_type()
            ArrayKlass.set_win_type()
            self.os_version = 'win'
            self.is_win = True
        else:
            self.os_version = 'lin'


        self.ignore_klasses = set([
            'sun/invoke/util/Wrapper',
            'sun/awt/X11/XToolkit',
            'sun/font/EAttribute',
            'com/sun/java/swing/plaf/windows/TMSchema$Part',
            'java/awt/Toolkit',
            'java/awt/Toolkit$1',
            'java/awt/Toolkit$2',
            'java/awt/Toolkit$3',
            'java/awt/Toolkit$4',
            'java/awt/Toolkit$5',
            'java/awt/Toolkit$DesktopPropertyChangeSupport',
            'java/awt/Toolkit$DesktopPropertyChangeSupport$1',
            'sun/awt/AWTAccessor$ToolkitAccessor',
            'sun/awt/HeadlessToolkit',
            'sun/awt/SunToolkit',
            'sun/awt/SunToolkit$ModalityListenerList',
            'sun/awt/windows/WToolkit',
            'sun/awt/windows/WToolkit$$Lambda$2',
            'sun/awt/windows/WToolkit$$Lambda$3',
            'sun/awt/windows/WToolkit$$Lambda$4',
            'sun/awt/windows/WToolkit$$Lambda$5',
            'sun/awt/windows/WToolkit$$Lambda$7',
            'sun/awt/windows/WToolkit$1',
            'sun/awt/windows/WToolkit$2',
            'sun/awt/windows/WToolkit$3',
            'sun/awt/windows/WToolkit$ToolkitDisposer',
            'java/util/concurrent/CopyOnWriteArrayList$COWIterator',
             ])
        self.min_symbols= 200
        self.os_type = os_type
        self.libjvm = libjvm
        self.word_sz = word_sz
        self.sorted_rangeaddrs = [i for i in self.ranges.keys()]
        self.sorted_rangeaddrs.sort()
        self.loading_strings = False
        self.cached_range = None
        self.loading_thread = None
        self.shared_list = None
        self.string_to_chunk = {}
        self.little_endian = True
        self.genned_signatures = {}
        self.target_str_addrs = {}
        self.is_32bit = is_32bit
        self.little_endian = little_endian
        self.strings = None #redis_strings_con
        self.ptrs = None #redis_ptrs_con
        self.struct_groupings = None
        self.symbol_groups = None
        self.vmstructentrys = {}
        self.vm_symboltable = None
        self.symboltable_values = {}
        self.vm_stringtable = None
        self.stringtable_values = {}
        self.known_internals = {}
        self.known_overlay_mapping = {}
        self.known_metas = {}
        #self.observed_metas = {}
        self.all_oops = {}
        self.all_klasses = {}
        self.failed_klass_updates = []
        self.known_klasses = {}
        self.known_instanceklasses = {}
        self.known_arrayklasses = {}
        self.known_errorklasses = {}
        self.known_oops = {}
        self.known_instanceoops = {}
        self.known_arrayoops = {}
        self.known_erroroops = {}
        self.libjvm_range = None
        self.oop_addrs_by_heap = {}
        self.partitioned_age_locations = {}
        self.ooptable_values = {}
        self.vm_dictionary = None
        self.vm_shared_dictionary = None
        self.vm_gc_heap = None
        self.loaded_jm_oop_by_name = {}
        self.loaded_jm_oop_by_addr = {}
        self.loaded_jm_oop_addr_to_name = {}
        self.loaded_jm_oop_name_to_vtable = {}
        self.loaded_classes_by_name = {}
        self.loaded_classes_by_addr = {}
        self.loaded_classes_name_to_vtable = {}
        self.klass_vtables_observed = {}
        self.vtable_threshhold = 10
        self.vtables_to_klass = {}
        self.observed_klass_addrs = {}
        self.gc_log_str = None
        self.heap_oop_klasses = {}
        self.heap_pot_oops = set()
        self.gc_heaps = []
        self.heap_oops = {}
        self.failed_klasses = []
        self.unknown_vtable = {}
        self.heap_pages = set()
        self.page_mask = 0xfffff000
        self.page_size = 0x1000

        self.klass_loader_addrs = set()
        self.klass_loaders = {}
        self.metaspaces = {}
        self.heap_age_locs = {}

        self._dictionary_addr = None
        self._string_table_addr = None
        self._symbol_table_addr = None
        self._placeholders_addr = None
        self._shared_dictionary_addr = None
        self._collectedHeap_addr = None

        self.klass_pages = {}
        self.est_heap_pages = {}

        self.klass_addr_refs = None
        self.dword_addrs = None
        self.dword_values = None

        #self.align_pad = lambda a, align: (align - (a % align)) % align
        #self.align_addr = lambda a, align: a + self.align_pad(a, align)
        self.page_tables = {}
        self.gen_page_tables()
        self.start_sys_dict_bf=start_sys_dict_bf if not start_sys_dict_bf is None else self.get_libjvm_base()&0xf0000000
        self.end_sys_dict_bf=end_sys_dict_bf if not end_sys_dict_bf is None else self.get_libjvm_base()|0x0fff0000
        self.start_symt_bf=start_symt_bf if not start_symt_bf is None else self.get_libjvm_base()&0xf0000000
        self.end_symt_bf=end_symt_bf if not end_symt_bf is None else self.get_libjvm_base()|0x0fff0000
        self.start_strt_bf=start_strt_bf if not start_strt_bf is None else self.get_libjvm_base()&0xf0000000
        self.end_strt_bf=end_strt_bf if not end_strt_bf is None else self.get_libjvm_base()|0x0fff0000
        self.num_strs_to_observe = 200
        self.num_klasses_to_observe = 200

    def gen_page_tables (self):
        self.page_tables = {}
        for r in self.ranges.values():
            addr = r.start
            end = r.fsize + r.start
            for p in xrange(addr, end, self.page_size):
                self.page_tables[p] = r


    @staticmethod
    def align_pad(a, align):
        return (align - (a % align)) % align

    @staticmethod
    def align_addr(a, align):
        return a + JVMAnalysis.align_pad(a, align)

    def __getstate__(self):
        #odict = copy.deepcopy(self.__dict__)
        return self.__dict__

    def __setstate__(self, _dict):
        self.__dict__.update(_dict)
        for v in self.all_klasses.values():
             v.set_jvm_analysis(self)
        for v in self.symboltable_values.values():
             v.set_jvm_analysis(self)
        for v in self.all_oops.values():
             v.set_jvm_analysis(self)
        for v in self.all_methods.values():
             v.set_jvm_analysis(self)
        for v in self.failed_klasses:
             v.set_jvm_analysis(self)
        for v in self.known_internals.values():
             v.set_jvm_analysis(self)
        for v in self.known_metas.values():
             v.set_jvm_analysis(self)

    def set_place_holders_addr(self):
        tsyms = self.get_symbol_by_field_name("_placeholders")
        if len(tsyms) == 0 or tsyms[0] is None:
            try:
                self._placeholders_addr = self.calc_hardcoded_placeholders()
                return self._placeholders_addr
            except:
                pass
            BaseException("Cant find the _placeholders!!!")
        sz = VMStructEntry.size32 if self.is_32bit else VMStructEntry.size64

        sym = syms[0]
        sdict_addr = self.deref32(sym.address) if self.is_32bit else\
                      self.deref64(sym.address)
        self._placeholders_addr = sdict_addr
        return sdict_addr

    def set_shared_dictionary_addr(self):
        tsyms = self.get_symbol_by_field_name("_shared_dictionary")

        if len(tsyms) == 0 or tsyms[0] is None:
            try:
                self._shared_dictionary_addr = self.calc_hardcoded_shared_dictionary()
                return self._shared_dictionary_addr
            except:
                pass
            BaseException("Cant find the _shared_dictionary!!!")
        sz = VMStructEntry.size32 if self.is_32bit else VMStructEntry.size64

        sym = tsyms[0]
        sdict_addr = self.deref32(sym.address) if self.is_32bit else\
                      self.deref64(sym.address)
        self._placeholders_addr = sdict_addr
        return sdict_addr

    def set_dictionary_addr (self):
        tsyms = self.get_symbol_by_type_and_name ("Dictionary*", "_dictionary")
        #self.log tsyms
        #if tsyms is None or len(tsyms) == 0:
        #    tsyms = self.get_symbol_by_field_name("_shared_dictionary")
        #    if len(tsyms) == 0 or tsyms[0] is None:
        #        BaseException("Cant find the system dictionary!!!")
        #    sz = VMStructEntry.size32 if self.is_32bit else VMStructEntry.size64
        #    if tsyms and len(tsyms) > 0:
        #        tsym = tsyms[0]
        #        if (tsym.addr - (2*sz)) in self.vmstructentrys:
        #            tsyms[0] = self.vmstructentrys[tsym.addr-(2*sz)]
        #        else:
        #            tsyms = None
        #    else:
        #        tsyms = None
        #if tsyms is None or len(tsyms) == 0:
        #    tsyms = self.get_symbol_by_field_name("_placeholders")
        #    if len(tsyms) == 0 or tsyms[0] is None:
        #        BaseException("Cant find the system dictionary!!!")
        #    sz = VMStructEntry.size32 if self.is_32bit else VMStructEntry.size64
        #    if tsyms and len(tsyms) > 0:
        #        tsym = tsyms[0]
        #        if (tsym.addr - sz) in self.vmstructentrys:
        #            tsyms[0] = self.vmstructentrys[tsym.addr-sz]
        #        else:
        #            tsyms = None
        sym = None if tsyms is None or len(tsyms) == 0 else tsyms[0]
        if sym is None:
            syms = self.get_symbol_by_typename_and_typestring ("SystemDictionary", "Dictionary*")
            for sym in syms:
                if len(sym.fieldName_str) == 0:
                    break
                sym = None
        # ok this is bad, no symbol for the system dictionary, so we will
        # make a guesstimate
        # find the placeholder and then use the pointer in the "SystemDictionary"
        # -1 1 word

        if sym is None:
            try:
                di = self.brute_force_identify_system_dictionary(start=self.start_sys_dict_bf, end=self.end_sys_dict_bf)
                if not di is None:
                    self.log("Found system dictionary using brute force method at %0x08x"%di.addr)
                    self._dictionary_addr = di.addr

                if self._dictionary_addr is None:
                    self._dictionary_addr = self.calc_hardcoded_dictionary()

                return self._dictionary_addr
            except:
               raise
               self._dictionary_addr = None
               return None

        sdict_addr = self.deref32(sym.address) if self.is_32bit else\
                      self.deref64(sym.address)
        self._dictionary_addr = sdict_addr
        return sdict_addr

    def set_symbol_table_addr (self):
        syms = self.get_symbol_by_type_and_name ("SymbolTable*", "_the_table")
        if syms is None or len(syms) == 0:
            try:
                symt = self.brute_force_identify_symbol_table(start=self.start_symt_bf, end=self.end_symt_bf)
                if not symt is None:
                    #print symt
                    self.log("Found symbol table using brute force method at %0x08x"%symt.addr)
                    self._symbol_table_addr = symt.addr
                else:
                    self._symbol_table_addr = self.calc_hardcoded_symbol_table_addr()
                return self._symbol_table_addr
            except:
                self._symbol_table_addr = None
                import traceback
                traceback.print_exc()
                return None
        sym = syms[0]
        stable_addr = self.deref32(sym.address) if self.is_32bit else\
                      self.deref64(sym.address)
        self._symbol_table_addr = stable_addr
        return stable_addr

    def set_collected_heap_addr (self):
        syms = self.get_symbol_by_field_name ("_collectedHeap")
        if syms is None or len(syms) == 0:
            try:
                self._collectedHeap_addr = list(set([self.calc_hardcoded_collected_heap()]))
                return self._collectedHeap_addr
            except:
                pass

        self._collectedHeap_addr = list(set( [sym.address for sym in syms \
                         if getattr(sym, 'address', None)] ))
        return self._collectedHeap_addr

    def set_string_table_addr (self):
        syms = self.get_symbol_by_type_and_name ("StringTable*", "_the_table")
        if syms is None or len(syms) == 0:
            try:
                strt = self.brute_force_identify_string_table( start=self.start_strt_bf, end=self.end_strt_bf)
                if not strt is None:
                    self.log("Found string table using brute force method at %0x08x"%strt.addr)
                    self._string_table_addr = strt.addr
                else:
                    self._string_table_addr = self.calc_hardcoded_string_table_addr()
                return self._string_table_addr
            except:
                self._string_table_addr = None
                return None
        sym = syms[0]
        stable_addr = self.deref32(sym.address) if self.is_32bit else\
                      self.deref64(sym.address)
        self._string_table_addr = stable_addr
        return stable_addr

    def calc_hardcoded_symbol_table_addr(self):
        libjvm_base = self.get_libjvm_base()
        addr = libjvm_base + self.get_version_addr(self.get_os()+':'+SYMBOLTABLE+':'+self.get_java_version())
        #self.log ("Looking for symbol table @ 0x%08x"%addr)
        saddr = self.read_addr(addr)
        #self.log ("Addr @ x%08x = 0x%08x"%(addr, saddr))
        return saddr

    def calc_hardcoded_string_table_addr(self):
        libjvm_base = self.get_libjvm_base()
        addr = libjvm_base + self.get_version_addr(self.get_os()+':'+STRINGTABLE+':'+self.get_java_version())
        #self.log ("Looking for symbol table @ 0x%08x"%addr)
        saddr = self.read_addr(addr)
        #self.log ("Addr @ x%08x = 0x%08x"%(addr, saddr))
        return saddr

    def calc_hardcoded_dictionary(self):
        libjvm_base = self.get_libjvm_base()
        addr = libjvm_base + self.get_version_addr(self.get_os()+':'+DICTIONARY+':'+self.get_java_version())
        #self.log ("Looking for symbol table @ 0x%08x"%addr)
        #saddr = self.read_addr(addr)
        #self.log ("Addr @ x%08x = 0x%08x"%(addr, saddr))
        #return saddr
        return addr

    def calc_hardcoded_placeholders(self):
        libjvm_base = self.get_libjvm_base()
        addr = libjvm_base + self.get_version_addr(self.get_os()+':'+PLACEHOLDERS+':'+self.get_java_version())
        #self.log ("Looking for symbol table @ 0x%08x"%addr)
        saddr = self.read_addr(addr)
        #self.log ("Addr @ x%08x = 0x%08x"%(addr, saddr))
        return saddr

    def calc_hardcoded_shared_dictionary(self):
        libjvm_base = self.get_libjvm_base()
        addr = libjvm_base + self.get_version_addr(self.get_os()+':'+SHAREDDICTIONARY+':'+self.get_java_version())
        #self.log ("Looking for symbol table @ 0x%08x"%addr)
        saddr = self.read_addr(addr)
        #self.log ("Addr @ x%08x = 0x%08x"%(addr, saddr))
        return saddr

    def calc_hardcoded_shared_heap(self):
        libjvm_base = self.get_libjvm_base()
        addr = libjvm_base + self.get_version_addr(self.get_os()+':'+SHAREDHEAP+':'+self.get_java_version())
        #self.log ("Looking for symbol table @ 0x%08x"%addr)
        saddr = self.read_addr(addr)
        #self.log ("Addr @ x%08x = 0x%08x"%(addr, saddr))
        return saddr

    def calc_hardcoded_collected_heap(self):
        libjvm_base = self.get_libjvm_base()
        addr = libjvm_base + self.get_version_addr(self.get_os()+':'+COLLECTEDHEAP+':'+self.get_java_version())
        #self.log ("Looking for symbol table @ 0x%08x"%addr)
        saddr = self.read_addr(addr)
        #self.log ("Addr @ x%08x = 0x%08x"%(addr, saddr))
        return saddr

    def get_java_version (self):
        return self.java_version

    def get_os (self):
        return self.os_version

    def get_version_addr(self, key):
        return self.VERSION_OFFSET[key]

    def build_heap_pages(self):
        for heap in self.gc_heaps:
            start = heap['start']
            end = heap['start'] + heap['size']
            while start < end:
                self.heap_pages.add(start)
                start += self.page_size

    def add_addr_heap_pages(self, addr):
        self.heap_pages.add(addr&self.page_mask)

    def pages_contain_addr(self, addr):
        return not addr is None and (addr&self.page_mask) in self.heap_pages

    def is_valid_heap_addr (self, addr):
        return self.is_valid_addr(addr)
       #return (addr&self.page_mask) in self.heap_pages

    def add_klass_addr_to_pages(self, klass):
        #TODO support other fields like supers and all that
        if klass:
            klass_addr = klass.addr
            self.add_addr_heap_pages(klass_addr)

    def add_heap_oop_klass(self, addr, klass):
        if not klass:
            return
        #klass_name = getattr(klass, "name_value", None)
        #if klass_name and not self.knows_klass_vtable(klass):
        #    self.add_klass(klass)
        self.heap_oop_klasses[addr] = klass

    def get_pot_heap_oops_based_on_refs(self, klass):
        if not klass:
            return
        #klass_name = getattr(klass, "name_value", None)
        #if klass_name and not self.knows_klass_vtable(klass):
        #    self.add_klass(klass)
        addr = klass.addr
        klass_refs = [ a for a,k in self.heap_oop_klasses.items() if k and k.addr == addr]
        return klass_refs

    def add_heap_pot_oop(self, addr):
        self.heap_pot_oops.add(addr)

    def forget_oop(self, addr):
        if addr in self.all_oops:
            del self.all_oops[addr]
        if addr in self.known_oops:
            del self.known_oops[addr]
        if addr in self.known_instanceoops:
            del self.known_instanceoops[addr]
        if addr in self.known_arrayoops:
            del self.known_arrayoops[addr]
        if addr in self.known_erroroops:
            del self.known_erroroops[addr]
        if addr in self.heap_oops:
            del self.heap_oops[addr]

    def forget_internal_obj(self, addr):
        if self.has_internal_object(addr):
            _object = self.known_internals[addr]
            overlay_info = _object.get_overlay_info()
            if addr in self.known_overlay_mapping:
                del self.known_overlay_mapping[addr]
            for _addr in overlay_info:
                if _addr in self.known_overlay_mapping:
                    del self.known_overlay_mapping[_addr]

            if addr in self.known_internals:
                del self.known_internals[addr]

    def forget_meta (self, addr):
        if addr in self.known_metas:
            del self.known_metas[addr]

    def add_meta (self, meta_obj):
        name = getattr(meta_obj, "metatype", None)
        if name and len(name) > 0:
            self.known_metas[meta_obj.addr] = meta_obj
            if hasattr(meta_obj, 'vtable'):
                vtable = meta_obj.vtable
                self.add_vtable_entry(vtable, meta_obj)
            self.add_klass_addr_to_pages(meta_obj)
            return True
        return False

    def knows_klass_vtable_addr(self, addr):
        return addr in self.vtables_to_klass

    def knows_klass_vtable(self, klass):
        if klass:
            self.knows_klass_vtable_addr(klass.vtable)
        return False

    def has_vtable_entry(self, vtable_addr):
        return vtable_addr in self.vtables_to_klass

    def add_vtable_entry(self, vtable, obj):
        if not vtable in self.vtables_to_klass:
            self.vtables_to_klass[vtable] = set()
        self.vtables_to_klass[vtable].add(obj)

    def add_oop (self, oop):
        if oop is None:
            return
        otype = getattr(oop, "ooptype", '').lower()
        if otype.find('instance') > -1:
            self.known_instanceoops[oop.addr] = oop
        elif otype.find('array') > -1:
            self.known_arrayoops[oop.addr] = oop
        elif otype.find('oop') > -1:
            self.known_oops[oop.addr] = oop
        elif otype.find('ERROR') > -1:
            self.known_erroroops[oop.addr] = oop

        if len(otype) > 0:
            self.all_oops[oop.addr] = oop
            return True
        return False

    def forget_klass(self, addr):
        #addr = klass.addr
        if addr in self.known_instanceklasses:
             del self.known_instanceklasses[addr]
        if addr in self.known_arrayklasses:
             del self.known_arrayklasses[addr]
        if addr in self.known_klasses:
             del self.known_klasses[addr]
        if addr in self.known_errorklasses:
             del self.known_errorklasses[addr]
        if addr in self.all_klasses:
             del self.all_klasses[addr]

    def forget_all_for_addr(self, addr):
        self.forget_meta(addr)
        self.forget_klass(addr)
        self.forget_oop(addr)
        self.forget_internal_obj(addr)
        self.forget_vtables(addr)

    def forget_vtables(self, addr):
        for v,s_klass in self.vtables_to_klass.items():
            for klass in s_klass:
                if klass.addr == addr:
                    self.vtables_to_klass[v].remove(klass)
                    break


    def identify_valid_vtable(self, vtable):
        klass_vtable_identified = False
        klass_cnt = len(self.klass_vtables_observed[vtable])
        if klass_cnt >= self.vtable_threshhold:
            # add all the klasses
            klass_vtable_identified = True
            fmt = "Klass vtable (0x%08x) surpassed threshhold, adding klasses"
            self.log (fmt%vtable)
            self.move_klasses_from_observed_to_known(vtable)
        return klass_vtable_identified

    def move_klasses_from_observed_to_known(self, vtable):
        if vtable in self.klass_vtables_observed:
            if not vtable in self.vtables_to_klass:
                self.vtables_to_klass[vtable] = set()

            klasses = self.klass_vtables_observed[vtable]
            del self.klass_vtables_observed[vtable]
            for klass in klasses.values():
                del self.observed_klass_addrs[klass.addr]
                self.add_klass(klass, check_vtable=False)

    def add_klass (self, klass, check_vtable=True):

        if klass is None:
            return False
        elif klass and not self.is_valid_addr(klass.vtable):
            return False

        klass_name = getattr(klass, "name_value", None)

        if klass_name and len(str(klass_name)) > 0:
            # bypass the vtable check if the name is correctly
            # stated
            check_vtable = False


        if klass and check_vtable:
            if not klass.vtable in self.klass_vtables_observed:
                self.klass_vtables_observed[klass.vtable] = {}
            self.observed_klass_addrs[klass.addr] = klass
            self.klass_vtables_observed[klass.vtable][klass.addr]=klass
            self.log ("Failed in the klass and check_vtable")
            return self.identify_valid_vtable(klass.vtable)
        elif klass and not check_vtable\
            and klass.vtable in self.klass_vtables_observed:
            self.move_klasses_from_observed_to_known(klass.vtable)
            self.log ("Failed in the klass and check_vtable")
            return True
        elif klass and not check_vtable\
             and klass.addr in self.observed_klass_addrs:
             del self.observed_klass_addrs[klass.addr]

        if check_vtable and not self.knows_klass_vtable(klass):
           #fmt = "Klass vtable not known: 0x%08x %s @ 0x%08x"
           #self.log (fmt%(klass.vtable, str(klass), klass.addr))
           return False
        ktype = getattr(klass, "klasstype", '').lower()
        if ktype.find('instance') > -1:
            self.known_instanceklasses[klass.addr] = klass
        elif ktype.find('array') > -1:
            self.known_arrayklasses[klass.addr] = klass
        elif ktype.find('klass') > -1:
            self.known_klasses[klass.addr] = klass
        elif ktype.find('ERROR') > -1:
            self.known_errorklasses[klass.addr] = klass

        if len(ktype) > 0:
            kname = str(klass.name_value)
            vtable = klass.vtable
            self.all_klasses[klass.addr] = klass
            self.loaded_classes_by_name[kname] = klass
            self.loaded_classes_by_addr[klass.addr] = klass
            self.loaded_classes_name_to_vtable[kname] = vtable
            self.add_vtable_entry(vtable, klass)
            self.add_klass_addr_to_pages(klass)
            return True
        return False

    def lookup_known_klass (self, addr):
        if type(addr) == str:
            return self.lookup_known_klass_by_name(addr)
        if addr in self.all_klasses:
            return self.all_klasses[addr]
        elif addr in self.observed_klass_addrs:
            return self.observed_klass_addrs[addr]
        return None

    def has_klass(self, addr):
        has_klass = addr in self.observed_klass_addrs or\
                    addr in self.all_klasses
        return has_klass

    def lookup_known_klass_by_name (self, name):
        if type(name) == long or type(name) == int:
            return self.lookup_known_klass(name)

        if name in self.loaded_classes_by_name:
            return self.loaded_classes_by_name[name]
        return None

    def lookup_known_oop_only(self, addr):
        if addr in self.all_oops:
            return self.all_oops[addr]
        return None

    def get_oop_only(self, addr):
        return lookup_known_oop_only(addr)
        
    def lookup_known_oop(self, addr):
        if addr in self.all_oops:
            return self.all_oops[addr]
        elif self.is_valid_addr(addr):
            return self.get_oop(addr)
        return None

    def save_oop(self, oop):
        if oop is None or oop._name.find('Oop') == -1:
            return
        self.all_oops[oop.addr] = oop
        self.known_oops[oop.addr] = oop
        self.known_instanceoops[oop.addr] = oop
        if oop.is_array_oop():
            self.known_arrayoops[oop.addr] = oop

    def has_oop(self, addr):
        return addr in self.all_oops

    def lookup_oop_by_klass_name(self, str):
        #TODO
        pass

    def lookup_known_meta (self, addr, cls=None):
        if addr in self.known_metas:
            km = self.known_metas[addr]
            if cls and not isinstance(km, cls):
                return None
            return km
        return None

    def get_klass(self, addr):
        if addr == 0:
            return None
        return Klass.from_jva (addr, self)

    def get_cpcache_only(self, addr):
        return self.get_meta_only(addr, CPCache)

    def get_method_only(self, addr):
        return self.get_meta_only(addr, Method)

    def get_method(self, addr):
        return self.get_meta(addr, Method)

    def get_meta_only(self, addr, cls=None):
        if addr == 0:
            return None
        if self.lookup_known_klass(addr):
            return None
        return self.lookup_known_meta(addr, cls)

    def get_meta(self, addr, cls=None):
        if addr == 0:
            return None
        if self.lookup_known_klass(addr):
            return None
        meta = self.lookup_known_meta(addr, cls)
        if not meta is None or cls is None:
            return meta
        return cls.from_jva(addr, self)

    def check_is_oop_instance(self, addr):
        # klass is the oop metadata
        klass = self.get_oop_metadata(addr)
        if klass is None:
            return False

        kvalue = self.lookup_known_klass(klass)
        if kvalue is None:
            kvalue = Klass.from_jva(klass, self)
        return not kvalue is None


    def get_oop_metadata(self, addr):
        metadata = None
        sz = Oop.size32 if self.is_32bit else \
                Oop.size64
        if addr == 0 or not self.is_valid_addr(addr):
            return metadata
        _bytes = self.read(addr, sz)
        if not _bytes is None:
            metadata = Oop.get_metadata(addr, _bytes, self)
        return metadata

    def is_oop_type_class(self, addr, str_klass_name, resolve_oop=False):
       oop = self.lookup_known_oop_only(addr)
       if not oop is None and\
          not getattr(oop, 'klass_value', None) is None:
           kvalue = oop.klass_value
           kname = str(getattr(kvalue, 'name_value', None))
           return kname == str_klass_name
       elif not oop is None:
           # Klass name should have been resolved at this point
           return False
       # resolve oop
       if oop is None and resolve_oop:
           oop = self.get_oop(addr)
           if not oop is None and\
              not getattr(oop, 'klass_value', None) is None:
              kvalue = oop.klass_value
              kname = str(getattr(kvalue, 'name_value', None))
              return kname == str_klass_name
           return False
       # resolve metadata only
       oop_meta = self.get_oop_metadata(addr)
       if not oop_meta is None:
           kvalue = self.lookup_known_klass(oop_meta)
           if kvalue is None:
               kvalue = Klass.from_jva(oop_meta, self)
           if kvalue:
               kname = str(getattr(kvalue, 'name_value', None))
               return kname == str_klass_name
       return False


    def get_oop(self, addr):
        if addr == 0:
            return None
        return Oop.from_jva(addr, self)

    def get_oaklassoop(self, addr):
        if addr == 0:
            return None
        return ObjArrayKlassOop.from_jva(addr, self)

    def dump_r2_loader(self, r2_loader_script):
        ranges = self.ranges
        import os
        r2_loader_out = open (r2_loader_script, 'w')
        _ranges = {}

        for r in ranges.values():
            if r.fsize == 0:
                continue
            _ranges[r.start] = r

        sorted_ranges = _ranges.keys()
        mapped_load_fmt = "on %s 0x%08x"
        for addr in sorted_ranges:
            filename = _ranges[addr].filename
            base_dir = _ranges[addr].base_dir
            filename = os.path.join(base_dir, filename)
            # dump chunks
            load_str = mapped_load_fmt% (filename, addr)
            r2_loader_out.write (load_str+'\n')

    def has_internal_object (self, addr):
        return addr in self.known_internals

    def get_internal_object (self, addr):
        if self.has_internal_object(addr):
            return self.known_internals[addr]
        return None

    def add_internal_object (self, addr, _object):
        self.known_internals[addr] = _object
        try:
            overlay_info = _object.get_overlay_info()
            self.known_overlay_mapping.update(overlay_info)
        except:
            import traceback
            traceback.print_exc()
            self.log("Error: Attempting to get overlay info failed")

    def find_range (self, vaddr):
        if vaddr is None:
            return None
        elif not isinstance(vaddr, int) and\
            not isinstance(vaddr, long):
            return None

        t = self.cached_range
        if not t is None and t.in_range(vaddr):
            return t

        p = vaddr & self.page_mask
        if p in self.page_tables:
            r = self.page_tables[p]
            self.cached_range = r
            return r

        for r in self.ranges.values():
            if r.in_range(vaddr):
                self.cached_range = r
                return r
        return None

    def slice_gte_addrs (self, addr, cnt=-1):
        v = -1
        pos = 0
        for _addr in self.sorted_rangeaddrs:
            if _addr < addr and self.ranges[_addr].fsize + _addr < addr:
                pos += 1
            else:
                v = _addr
                break

        if v == -1:
            return []
        # getting the chunks
        if cnt == -1:
            return [self.ranges[i] for i in self.sorted_rangeaddrs[pos:]]
        return [self.ranges[i] for i in self.sorted_rangeaddrs[pos:cnt+pos]]

    def slice_lte_addrs (self, addr, cnt=-1):
        v = -1
        pos = 0
        for _addr in self.sorted_rangeaddrs:
            if _addr > addr:
                break
            else:
                pos += 1

        # getting the chunks
        if cnt == -1:
            return [self.ranges[i] for i in self.sorted_rangeaddrs[:pos]]
        return [self.ranges[i] for i in self.sorted_rangeaddrs[cnt:pos]]

    def get_libjvm_base(self):
        return self.libjvm['start']

    # def find_libjvm (self):
    #     if self.os_type == "linux" and self.tas:
    #         return self.find_libjvm_linux()
    #     raise "OS Type %s not supported"%self.os_type

    def set_libjvm(self, start, end, name):
        self.libjvm = {"start":start, "end":end, "name":name}
        self.libjvm_range = self.find_range(self.libjvm['start'])

    def find_libjvm_linux (self, vol_task):
        libjvm = [i for i in vol_task.elfs() if i[-2].find("libjvm") == 0]
        if len(libjvm) == 0:
            return None
        libjvm = libjvm[0]
        self.set_libjvm(libjvm[1], libjvm[2], libjvm[-2])
        return self.libjvm

    def get_target_string_set(self):
        target_set = set()
        for i in self.STATIC_TARGET_TYPES:
            target_set |= set(i)
        return target_set


    def get_pointer_bytes(self, val):
        endian = "<" if self.little_endian else ">"
        size = "I" if self.is_32bit else "Q"
        return self.get_bytes(endian+size, val)

    def get_int_bytes(self, val):
        endian = "<" if self.little_endian else ">"
        return self.get_bytes(endian, val)

    def get_long_bytes(self, val):
        endian = "<" if self.little_endian else ">"
        size = "I" if self.is_32bit else "Q"
        return self.get_bytes(endian+size, val)

    def get_long_long_bytes(self, val):
        endian = "<" if self.little_endian else ">"
        return self.get_bytes(endian, val)

    def get_bytes (self, val, fmt):
        return struct.unpack(fmt, val)

    def find_vm_struct_containing(self, string):
        res = []
        for sym in self.vmstructentrys.values():
            if sym.typeName_str.find(string) > -1:
                res.append (sym)
            elif sym.typeString_str.find(string) > -1:
                res.append (sym)
            elif sym.fieldName_str.find(string) > -1:
                res.append (sym)
        return res

    def get_symbol_by_typename_and_typestring (self, typeName, typeString):
        resTN = self.get_symbol_by_type_string(typeString)
        res = []
        for sym in resTN:
            if sym.typeName_str.find(typeName) == 0:
                res.append (sym)
        return res

    def get_symbol_by_type_and_name (self, typeString, fieldName):
        resTN = self.get_symbol_by_type_string(typeString)
        res = []
        for sym in resTN:
            if sym.fieldName_str == fieldName:
                res.append (sym)
        return res

    def get_symbol_by_field_name (self, string):
        res = []
        for sym in self.vmstructentrys.values():
            if sym.fieldName_str == string:
                res.append (sym)
        return res

    def get_symbol_by_type_name (self, string):
        res = []
        for sym in self.vmstructentrys.values():
            if sym.typeName_str == string:
                res.append (sym)
        return res

    def get_symbol_by_type_string (self, string):
        res = []
        for sym in self.vmstructentrys.values():
            if sym.typeString_str == string:
                res.append (sym)
        return res

    def get_string_addresses (self, strings):
        string_addresses = {}
        for i in strings:
            addrs = [] #self.strings.get_addrs_for_str(i)
            if len(addrs) > 0:
                string_addresses[i] = [long(j) for j in addrs]
        return string_addresses

    def find_potential_dictionarys(self, start=None, end=None, word_sz=4):
        CONST_OFFSET = 0x28
        dict_table_size = 0x003f1
        results = []
        if end is None:
            end = self.get_libjvm_base()
        ranges = self.slice_lte_addrs(end)
        if start is None:
            start = ranges[0].start

        results = []
        addr = start
        for r in ranges:
            pos = 0
            if r.start < addr and r.start + r.fsize < addr:
                continue
            elif r.start < addr:
                pos = addr-r.start

            msize = r.fsize
            s = ConstBitStream(bytes=r.fdata)
            s.pos = pos*8
            while pos < msize:
                p = s.find('0xf1030000', start=s.pos, bytealigned=True)
                if len(p) == 0:
                    break
                v = s.bytepos + r.start
                s.bytepos += word_sz
                v2 = s.read('uintle:32')
                results.append(v)
                s.bytepos += 0x10
                #else:
                #    s.bytepos += 0x8
                pos = s.bytepos
                s.pos = pos*8
        # TODO determine the correct element
        return results

    def find_potential_string_table(self, start=None, end=None, word_sz=4):
        CONST_OFFSET = 0x20
        dict_table_size = 0x04e2b
        results = []
        ranges = self.slice_lte_addrs(self.get_libjvm_base())
        if end is None:
            end = self.get_libjvm_base()
        ranges = self.slice_lte_addrs(end)
        if start is None:
            start = ranges[0].start

        results = []
        addr = start
        for r in ranges:
            pos = 0
            if r.start < addr and r.start + r.fsize < addr:
                continue
            elif r.start < addr:
                pos = addr-r.start

            msize = r.fsize
            s = ConstBitStream(bytes=r.fdata)
            s.pos = pos*8
            while pos < msize:
                p = s.find('0xf1030000', start=s.pos, bytealigned=True)
                if len(p) == 0:
                    break
                v = s.bytepos + r.start
                s.bytepos += word_sz
                v2 = s.read('uintle:32')
                if v2%8==0:#v+CONST_OFFSET == v2:
                    results.append(v)
                    s.bytepos += 0x30
                else:
                    s.bytepos += 0x8
                pos = s.bytepos
                s.pos = pos*8
        # TODO determine the correct element
        return results


    def find_potential_symbol_table(self, start=None, end=None, word_sz=4):
        CONST_OFFSET = 0x20
        dict_table_size = 0x04e2b
        results = []
        ranges = self.slice_lte_addrs(self.get_libjvm_base())
        if end is None:
            end = self.get_libjvm_base()
        ranges = self.slice_lte_addrs(end)
        if start is None:
            start = ranges[0].start

        results = []
        addr = start
        pos = 0
        for r in ranges:
            pos = 0
            if r.start < addr and r.start + r.fsize < addr:
                continue
            elif r.start < addr:
                pos = addr-r.start

            msize = r.fsize
            s = ConstBitStream(bytes=r.fdata)
            s.pos = pos*8
            while pos < msize:
                p = s.find('0x2b4e0000', start=s.pos, bytealigned=True)
                if len(p) == 0:
                    break
                v = s.bytepos + r.start
                s.bytepos += word_sz
                v2 = s.read('uintle:32')
                results.append(v)
                s.bytepos += 0x20
                #if v+CONST_OFFSET == v2:
                #    results.append(v)
                #    s.bytepos += 0x30
                #else:
                #    s.bytepos += 0x8
                pos = s.bytepos
                s.pos = pos*8
        # TODO determine the correct element
        return results



    def find_symbols (self):
       field_name_lists = self.STATIC_TARGET_TYPES
       field_sizes = []
       for fields in field_name_lists:
           sizes = [self.word_sz for i in fields]
           field_sizes.append(sizes)
       target_structs = {}
       target_structs['field_sizes'] = field_sizes
       target_structs['field_names'] = field_name_lists
       fstructs = FindStructs(self.strings, self.ptrs,
                               word_sz=self.word_sz,
                               target_structs=target_structs)
       self.struct_groupings = fstructs.create_bf_candidates()
       return self.struct_groupings

    def try_discover_cstring (self, addr, len_=None):
        len_ = len_ if len_ else self.MAX_STR_SIZE
        sr = self.find_range(addr)
        if sr is None:
            return False
        pot_string = sr.read_at_addr(addr, len_)
        while (pot_string.find("\x00")) == -1 and \
            sr.fsize < len_*2:
            len_ *=2
            pot_string = sr.read_at_addr(addr, len_)

        strings = pot_string.split("\x00")
        if len(strings) > 0 and strings[0].isalnum():
            #self.log "Updating Strings DB, Discovered: %s %s"%(hex(addr), strings[0])
            #self.strings.add_discovered_string(addr, strings[0])
            return True
        return False


    def group_closest_symbols (self):
        # perform kmeans
        all_symbols = {}
        mapped_1_dim = {}
        all_symbols = {}
        mapped_1_dim = []
        for sym, saddrs in self.struct_groupings.items():
            pos = 0
            for saddr in saddrs:
                mapped_val = (sum(saddr)/len(saddr))/self.word_sz
                all_symbols[sym+"::%d"%pos] = saddr
                mapped_1_dim.append([sym+"::%d"%pos, mapped_val])
                pos += 1
        # do kmeans here

        # calculate min mapped_val for each group
        # start from the min and read out each symbol
        #  OK doing cool machine learning tricks would be
        #  fun, but lets speed this up a little going to
        # just check all groups

    def print_enumerated_symbols(self, static_only=False, no_static=False):
        s_keys = set()
        if not no_static:
            s_keys |= set([s_key for s_key in self.vmstructentrys if self.vmstructentrys[s_key].isStatic == 1])
        if not static_only:
            s_keys |= set([s_key for s_key in self.vmstructentrys if self.vmstructentrys[s_key].isStatic == 0])

        s_keys = list(s_keys)
        s_keys.sort()

        for s_key in s_keys:
            if self.vmstructentrys[s_key].isStatic:
                self.log (hex(s_key), str(self.vmstructentrys[s_key]))

    def enumerate_sym_entrys (self):
        addrs = set()
        t = None
        for name, addr_grps in self.struct_groupings.items():
            if name.find("_boolArrayKlassObj")>0:
                continue
            for addr_grp in addr_grps:
                addrs.add(addr_grp[0])
        for addr in addrs:
            if not addr in self.vmstructentrys:
                t = self.enumerate_sym_entrys_addr_anchor(addr)
        # min_addrs = []
        # for sym_group in self.symbol_groups:
        #     for name, addrs in sym_group.keys():
        #         min_addr = min ([min(addrs), min_addr])
        #     min_addrs.append(min_addr)
        # for addr in min_addrs:
        #     t = self.enumerate_sym_entrys_addr_anchor(addr)
        return t

    def enumerate_sym_entrys_addr_anchor (self, addr):
        t = self.enumerate_entrys_fwd_from_addr(addr)
        t = self.enumerate_entrys_bwd_from_addr(addr)
        # cleaning up the symbols here
        for k, v in self.vmstructentrys.items():
            clean = str(v).strip()
            if len(clean) == 0 or clean == "::":
                del self.vmstructentrys[k]
        return t

    def enumerate_entrys_fwd_from_addr (self, addr, range_=None):
        if range_ is None:
            range_ = self.find_range(addr)
        o = addr - range_.start
        start = range_.start
        while True:
            entry = None
            loc = o+start
            entry = VMStructEntry.from_jva(loc, self)
            o += entry.size()
            #symbols.append(sym)
            self.vmstructentrys[loc] = entry
            if entry.fieldName_addr == 0:
                break
            if len(entry.typeName_str) == 0 and \
               len(entry.fieldName_str) == 0 and \
               len(entry.typeString_str) == 0:
                break
            elif entry.fieldName_str == "" and \
                entry.typeName_str == "" and \
                entry.typeString_str == "":
                break
        return self.vmstructentrys

    def enumerate_entrys_bwd_from_addr (self, addr, range_=None):
        if range_ is None:
            range_ = self.find_range(addr)
        o = addr - range_.start
        start = range_.start
        while True:
            entry = None
            loc = o+start
            entry = VMStructEntry.from_jva(loc, self)
            if entry is None:
                break
            o -= entry.size()
            #symbols.append(sym)
            self.vmstructentrys[loc] = entry
            # first static variable in the Universe (klassOop _boolArrayKlassObj)
            if entry.fieldName_str.find("_boolArrayKlassObj") == 0:
                break
            elif entry.fieldName_str == "" and \
                entry.typeName_str == "" and \
                entry.typeString_str == "":
                break
        return self.vmstructentrys

    def is_valid_addr(self, addr):
        return not addr is None and (self.pages_contain_addr(addr) or \
               not self.find_range(addr) is None)

    def read (self, addr, size):
        bytes_ = None
        sr = self.find_range(addr)
        if sr:
            bytes_ = sr.read_at_addr(addr, size)
        return bytes_

    def read_addr (self, addr):
        if self.word_sz == 4:
            return self.read_dword(addr)
        else:
            return self.read_qword(addr)

    def read_dword (self, addr):
        val = None
        sr = self.find_range(addr)
        if sr:
            val = sr.read_dword_at_addr(addr)
        return val

    def read_qword (self, addr):
        val = None
        sr = self.find_range(addr)
        if sr:
            val = sr.read_qword_at_addr(addr)
        return val

    def deref32 (self, addr, little_endian = True):
        bytes_ = self.read(addr, 4)
        addr = None
        if bytes_:
            addr = struct.unpack("<I", bytes_)[0] if little_endian \
                   else struct.unpack(">I", bytes_)[0]
        return addr

    def deref64 (self, addr, little_endian = True):
        bytes_ = self.read(addr, 8)
        addr = None
        if bytes_:
            addr = struct.unpack("<Q", bytes_)[0] if little_endian \
                   else struct.unpack(">Q", bytes_)[0]
        return addr

    def insert_symbol (self, addr, symbol):
        if symbol._name != "Symbol":
            raise BaseException("%s is Not a symbol"%(symbol._name))
        self.symboltable_values [addr] = symbol

    def insert_oop (self, addr, oop):
        if oop and oop._name != "Oop":
            raise BaseException("%s is Not a symbol"%(oop._name))
        self.ooptable_values [addr] = oop

    def read_internal_symbol_table(self):
        if self._symbol_table_addr is None:
            self.set_symbol_table_addr()
            if self._symbol_table_addr is None:
                raise Exception("Unable to locate the internal symbol")
        if not self.vm_symboltable is None:
            return self.vm_symboltable
        stable_addr = self._symbol_table_addr
        #self.log ("Looking for symbol table @ 0x%08x"%stable_addr)
        self.vm_symboltable = SymbolTable.from_jva(stable_addr,self)
        symbols = self.vm_symboltable.get_bucket_values()
        for sym in symbols:
            if sym is None:
                continue
            self.insert_symbol(sym.addr, sym)

        return self.vm_symboltable

    def read_internal_string_table(self):
        if self._string_table_addr is None:
            restrict_klass_parsing(False)
            self.set_string_table_addr()
            restrict_klass_parsing(True)
            if self._string_table_addr is None:
                raise Exception("Unable to locate the internal symbol")
        stable_addr = self._string_table_addr
        self.vm_stringtable = StringTable.from_jva(stable_addr, self)
        strings = self.vm_stringtable.get_bucket_values()
        for oop in strings:
            if oop is None:
                continue
            oop.update_fields(self)
            self.insert_oop(oop.addr, oop)

        return self.vm_stringtable

    def get_internal_syms(self):
        if self.vm_symboltable:
            return self.vm_symboltable.get_bucket_values()
        return None

    def lookup_internal_string_only (self, addr):
        if addr in self.stringtable_values:
            return self.stringtable_values[addr]
        elif addr in self.known_internals:
            obj = self.known_internals[addr]
            if obj._name != "Oop":
                raise BaseException("Object (%s) @ 0x%08x is not a oop"%(obj._name, addr))
        return None

    def lookup_internal_symbol_only (self, addr):
        if addr in self.symboltable_values:
            return self.symboltable_values[addr]
        return None

    def lookup_internal_symbol (self, addr):
        sym = None
        if addr in self.symboltable_values:
            sym = self.symboltable_values[addr]
        #elif addr in self.known_internals:
        #    sym = self.known_internals[addr]
        #    if sym._name.find("HashTableEntry<Symbol*>") > -1:
        #        self.log (sym._name)
        #        sym = sym.get_value()

        #    if sym._name != "Symbol":
        #        self.log (sym._name)
        #        raise BaseException("Object (%s) @ 0x%08x is not a symbol"%(sym._name, addr))
        elif self.is_valid_addr(addr):
            sym = Symbol.from_jva (addr, self)
            if sym:
                self.insert_symbol(sym.addr, sym)
        return sym

    def update_loaded_klass_constant_pools(self):
        updated_fields = 0
        updated = 0
        klasses = self.loaded_classes_by_name.values()
        self.log ("Updating the cp caches for klasses")
        for klass in klasses:
            try:
                if klass:
                    try:
                        if klass.is_instance() and not klass.is_instance_array():
                            self.log ("Updating java cache for: %s"%( str(klass)))
                            klass.get_constant_pool().phase2_update_fields()
                            updated_fields+=1
                        #self.log ("Completed updating %s java mirror"%( str(klass)))
                    except:
                        import traceback
                        traceback.print_exc()
                        self.log ("Failed to update the klass cp cache: %s"%str(klass))
                        #pass
                    updated += 1
            except:
                import traceback
                traceback.print_exc()
                self.log ("Failed to update the klass mirror: %s"%str(klass))
        return updated

    def update_loaded_klass_mirrors(self):
        updated_fields = 0
        updated = 0
        klasses = self.loaded_classes_by_name.values()
        self.log ("Update %d java mirror klasses"%( len(klasses)))
        for klass in klasses:
            try:
                if klass:
                    try:
                        #self.log ("Updating java mirror for: %s"%( str(klass)))
                        if not klass.klass_name() in self.ignore_klasses:
                            self.log ("Updating java mirror for klass: %s"%str(klass))
                            klass.update_java_mirror()
                            name = None if getattr(klass, 'name_value', None) is None \
                                        else str(klass.name_value)
                            jm_oop = None if getattr(klass, 'java_mirror_value', None) is None \
                                        else klass.java_mirror_value

                            if not name is None and not jm_oop is None:
                                self.loaded_jm_oop_by_addr[jm_oop.addr] = jm_oop
                                self.loaded_jm_oop_by_name[name] = jm_oop
                                self.loaded_jm_oop_addr_to_name[jm_oop.addr] = name
                            #self.add_oop(klass.java_mirror_value)
                            updated_fields+=1
                        #self.log ("Completed updating %s java mirror"%( str(klass)))
                    except:
                        import traceback
                        traceback.print_exc()
                        self.log ("Failed to update the klass: %s"%str(klass))
                        #pass
                    updated += 1
            except:
                import traceback
                traceback.print_exc()
                self.log ("Failed to update the klass mirror: %s"%str(klass))
        return updated_fields

    def update_loaded_klass_fields2(self):
        # follow up update
        for n,k in self.loaded_classes_by_name.items():
            addr = k.addr
            if not hasattr(k, 'method_info') or not hasattr(k, 'field_info'):
                self.forget_klass(addr)
                klass = self.get_klass(addr)
                try:
                    self.log ("Updating (second attempt) %s klass fields"%( klass))
                    klass.update_fields()
                    klass.set_klass_dependencies()
                    klass.update_all_field_infos()
                except:
                    self.log ("Falied: Updating (second attempt) %s klass fields"%( klass))
            elif len(k.method_info) == 0 and len(k.field_info) == 0:
                self.forget_klass(addr)
                klass = self.get_klass(addr)
                try:
                    self.log ("Updating (second attempt) %s klass fields"%( klass))
                    klass.update_fields()
                    klass.set_klass_dependencies()
                    klass.update_all_field_infos()
                except:
                    self.log ("Falied: Updating (second attempt) %s klass fields"%( klass))


    def update_loaded_klass_fields(self):
        updated_fields = 0
        updated = 0
        for klass in self.loaded_classes_by_name.values():
            try:
                if klass:
                    try:
                        self.log ("Updating %s klass fields"%( klass))
                        klass.update_fields()
                        #self.log ("Updated %s klass fields"%( klass))
                        updated_fields+=1
                    except:
                        import traceback
                        traceback.print_exc()
                        self.log ("Failed to update the klass: %s"%str(klass))
                        self.failed_klass_updates.append(klass)
                        #pass
                    # TODO lets see if this really works
                    if not self.add_klass(klass, check_vtable=False):
                        self.log("Failed to add klass: %s"%str(klass))
                    updated += 1
            except:
                import traceback
                traceback.print_exc()
                self.log ("Failed to update the klass: %s"%str(klass))
                if klass:
                    self.forget_klass(klass.addr)
                    klass.klasstype = "ERROR unable to update"
                    self.add_klass(klass, check_vtable=True)
        updated = 0
        for klass in self.loaded_classes_by_name.values():
            try:
                if klass:
                    try:
                        self.log ("Updating %s klass fields"%( klass))
                        klass.set_klass_dependencies()
                        klass.update_all_field_infos()
                        #self.log ("Updated %s klass fields"%( klass))
                        updated_fields+=1
                    except:
                        import traceback
                        traceback.print_exc()
                        self.log ("Failed to update the klass: %s"%str(klass))
                        self.failed_klass_updates.append(klass)
                        #pass
                    # TODO lets see if this really works
                    if not self.add_klass(klass, check_vtable=False):
                        self.log("Failed to add klass: %s"%str(klass))
                    updated += 1
            except:
                import traceback
                traceback.print_exc()
                self.log ("Failed to update the klass: %s"%str(klass))
                if klass:
                    self.forget_klass(klass.addr)
                    klass.klasstype = "ERROR unable to update"
                    self.add_klass(klass, check_vtable=True)
        self.update_loaded_klass_fields2()
        restrict_klass_parsing(True)
        return updated_fields

    def read_system_dictionary(self):
        if self._dictionary_addr is None:
            self.set_dictionary_addr()
            if self._dictionary_addr is None:
                raise Exception("Unable to locate the internal symbol")
        self.log ("Reading _dictionary structure")
        sdict_addr = self._dictionary_addr
        self.vm_dictionary = Dictionary.from_jva(sdict_addr, self)
        self.known_internals[sdict_addr] = self.vm_dictionary
        #if 1:
        #    return
        klasses = {}
        klass_loaders = set()
        for klass in self.vm_dictionary.get_bucket_values():
            klass_sym_addr = klass.name
            if klass._name == "KlassInstance" and \
                    not klass_sym_addr in self.symboltable_values:
                r = self.find_range(klass_sym_addr)
                _bytes = r.read_at_addr(klass_sym_addr, r.fsize)
                sym = Symbol.from_bytes(klass_sym_addr,_bytes, self)
                setattr(klass, 'name_value', sym)

        for klass in self.vm_dictionary.get_bucket_values():
            if klass:
                klasses[klass.addr] = klass
                self.klass_loader_addrs.add(klass.class_loader_data)

        self.log ("Enumerating klass_loaders")
        self.klass_loaders = {}
        failed_kloader_update = []
        for kaddr in self.klass_loader_addrs:
            if not kaddr in self.klass_loaders:
                kloader = ClassLoaderData.from_jva(kaddr, self)
                self.klass_loaders[kloader.addr] = kloader
                try:
                    kloader.update_fields()
                except:
                    failed_kloader_update.append(kloader)
                    self.log("Failed to update kloader @ 0x%08x"%kloader.addr)
        for f in failed_kloader_update:
            self.log("Second attempt to update kloader @ 0x%08x"%f.addr)
            try:
                f.update_fields()
                self.log("^^ Update worked @ 0x%08x"%f.addr)
            except:
                self.log("^^ Update failed worked @ 0x%08x"%f.addr)



        for kloader in self.klass_loaders.values():
            ms = kloader.get_metaspaces()
            for space in ms:
                start_addr = space[0]
                self.metaspaces[start_addr] = space

        #enum current set of klasses via the klass loaders
        for kloader in self.klass_loaders.values():
            klass = self.get_klass(kloader.klasses)
            klasses[klass.addr] = klass
            while True:
                nklass = self.get_klass(klass.next_link)
                setattr(klass, 'next_value', nklass)
                if nklass is None:
                    break
                klass = nklass
        kloader_cnt = len(self.klass_loaders.values())
        self.log ("Found %d class loaders"%(kloader_cnt))
        for kloader in self.klass_loaders.values():
            self.log ("\tKlass loader: 0x%08x %s"%(kloader.addr, str(kloader)))

        self.log ("Updating %d klass fields"%(len(klasses)))
        updated_fields = 0
        updated = 0
        #if 1:
        #    return
        self.update_loaded_klass_fields()

        self.log ("Completed initial update %d klasses"%( len(klasses)))
        updated_fields = 0
        updated = 0

        updated_fields = self.update_loaded_klass_mirrors()
        #self.log ("Successfully updated %d class mirrors out of %d classes"%(updated_fields, len(self.all_klasses)))
        #if self.get_os() == 'win':
        #    return
        updated_fields = self.update_loaded_klass_constant_pools()
        #self.log ("Successfully updated %d class mirrors out of %d classes"%(updated_fields, len(self.all_klasses)))
        self.log ("Completed initial update %d of class mirrors"%( updated_fields))
        #self.correct_klasses()
        self.log ("Updating klasses with their respective methods")
        #self.update_klass_methods_constants()

    def update_klass_methods_constants(self):
        self.update_klass_methods()
        # update all of the klass CP cache entries
        # done here after all of the klasses have been
        # linked to there methods
        for klass in self.all_klasses.values():
            try:
                if klass and str(klass).find('[') != 0 and\
                   not str(klass) in self.ignore_klasses:
                    cp = klass.get_constant_pool()
                    cp.update_cache()
            except:
                import traceback
                traceback.print_exc()
                self.log ("Failed to update the klass CP CP cache: %s"%str(klass))

        return self.vm_dictionary

    def gen_heaps_from_gc_logs(self):
        addr_set = self.set_collected_heap_addr()
        size = 1024
        self.log ("Looking for the heap log string in the collected heap")
        for addr in addr_set:
            # find the log string
            heap_addr = self.read_addr (addr)
            collected_heap = CollectedHeap.from_jva(heap_addr, self)
            gc_log = GCLog.from_jva(collected_heap.gc_heap_log, self)
            data = self.read(gc_log.addr, size)
            pos = 0

            while pos < size:
                if data[pos:].startswith("{Hea"):
                    break
                pos += self.word_sz

            log_str = None
            if pos < size:
                log_str = self.read_cstring(pos + collected_heap.gc_heap_log)
                break
        if not log_str is None:
            self.log ("Found the heap log string, extracting the heap locations and size")
            self.gc_log_str = log_str
            self.gc_heaps = self.parse_collected_heap_log(log_str)
            self.log ("Found %d different heaps:"%(len(self.gc_heaps)))
            for heap in self.gc_heaps:
                self.log ("%s 0x%08x-0x%08x"%(heap['name'], heap['start'],
                                       heap['start']+heap['size']))
            #self.scan_heap_for_oops ()
            self.build_heap_pages()
        else:
            self.log ("Did not find a log string, need to scan process memory "+\
                   "for potential memory locations")
        return self.gc_heaps

    def scan_metaspaces(self):
        ms_chunks = self.metaspaces

        for addr, sz in ms_chunks.values():
            self.log ("Scanning 0x%08x-0x%08x"%(addr,addr+sz))
            self.scan_heap_for_klasses(addr, sz)
        return self.heap_oops, self.failed_klasses


    def scan_heap_for_klasses (self, addr, sz, stop_at_failed_read=True):
        # lets ignore oops and look for the klass instances
        # if we see something that looks like an age bit we
        # can save that
        naddr = addr
        #data = self.read(addr, sz)
        pos = 0
        end_addr = sz+addr
        failed_read = False
        word_sz = self.word_sz

        heap_age_locs, heap_oop_klasses, pot_oop = \
                        self.prelim_scan_heap_for_klasses(addr,sz,stop_at_failed_read)
        for loc,age in heap_age_locs.items():
            self.heap_age_locs[loc] = age

        for loc, klass in heap_oop_klasses.items():
            self.add_heap_oop_klass(loc, klass)

        for addr in pot_oop:
            self.add_heap_pot_oop(addr)

        return self.heap_age_locs

    def scan_pages_for_dword_value (self, value, start=None, end=None, omit_ranges=[], in_parallel=False, num_procs=10):
        return self.scan_pages_for_dword_values([value],start, end, omit_ranges, in_parallel, num_procs)
        
        


    def scan_page_for_dword_values(self, r, values, start=None, end=None, omit_ranges=[]):
        if isinstance(values, list):
            values = set(values)
        elif isinstance(values, long) or isinstance(values, int):
            x = set()
            x.add(values)
            values = x

        self.log("Starting scan for %d values in ranges"%len(values))
        if start is None:
           start = self.sorted_rangeaddrs[0]
        if end is None:
            ba = self.sorted_rangeaddrs[-1]
            end = self.ranges[ba].fsize + ba

        _ranges = self.slice_gte_addrs(start)
        value_range_locs = {}
        value_addr_locs = {}
        baddr = r.start
        skip_range = False
        for o in omit_ranges:
            if r.in_range(o):
                skip_range = True
        if skip_range:
            self.log("Skipping chunk: 0x%08x with %d values"%(baddr, r.fsize/4))
            return value_addr_locs, value_range_locs
        self.log("Scanning chunk: 0x%08x with %d values"%(baddr, r.fsize/4))
        vals = r.read_all_as_dword()
        value_range_locs[baddr] = []
        pos = 0
        found_vals = {}
        for val in vals:
            if val in values:
                t = (baddr+pos, val)
                value_range_locs[baddr].append(t)
                if not val in value_addr_locs:
                    value_addr_locs[val] = set()
                    found_vals[val] = 0
                value_addr_locs[val].add(baddr+pos)
                found_vals[val] += 1
            pos += 4
            if (pos + baddr) > end:
                break
        all_vals = found_vals.values()
        self.log("Completed scanning chunk: 0x%08x.  Found %d values, %d unique"%(baddr, len(all_vals), sum(all_vals)))
        return value_addr_locs, value_range_locs

    def scan_pages_for_dword_values(self, values, start=None, end=None, omit_ranges=[], in_parallel=False, num_procs=10):
        if isinstance(values, list):
            values = set(values)
        elif isinstance(values, long) or isinstance(values, int):
            x = set()
            x.add(values)
            values = x

        self.log("Starting scan for %d values in ranges"%len(values))
        if start is None:
           start = self.sorted_rangeaddrs[0]
        if end is None:
            ba = self.sorted_rangeaddrs[-1]
            end = self.ranges[ba].fsize + ba

        _ranges = self.slice_gte_addrs(start)
        _ranges = [r for r in _ranges if r.start < end]
        value_range_locs = {}
        value_addr_locs = {}
        if not in_parallel:
            for r in _ranges:
                _value_addr_locs, _value_range_locs = self.scan_page_for_dword_values(r, values, start, end, omit_ranges)
                value_addr_locs.update(_value_addr_locs)
                value_range_locs.update(_value_range_locs)
        else:
            _value_addr_locs, _value_range_locs = par_scan_page_for_dword_values(_ranges, values, num_procs)
            value_addr_locs.update(_value_addr_locs)
            value_range_locs.update(_value_range_locs)
        self.log("Completed scan for all values in ranges")
        return value_addr_locs, value_range_locs

    def scan_pages_for_java_mirrors_32 (self, start=None, end=None):
        # OOPs start on 8-byte addressable boundaries
        # e.g. 0, 8, 0x10, etc
        # klass addresss (wide and non-wide) are the
        # next value after narrow classes need to be
        # bit shifted, so we for now we assume 32bit
        # Uncompressed OOP addresses
        self.log("Starting scan for all Klass addresses in ranges")
        values = set()
        for k in self.loaded_classes_by_addr.values():
            if not k is None and not getattr(k, 'java_mirror_value', None) is None:
                values.add(k.java_mirror)

        jm_oop_addr_locs, jm_oop_range_locs = self.scan_pages_for_dword_values(values, start, end, in_parallel=True)
        self.log("Completed scan for all Klass addresses in ranges")
        return jm_oop_addr_locs, jm_oop_range_locs

    def scan_pages_for_klasses_32 (self, start=None, end=None):
        # OOPs start on 8-byte addressable boundaries
        # e.g. 0, 8, 0x10, etc
        # klass addresss (wide and non-wide) are the
        # next value after narrow classes need to be
        # bit shifted, so we for now we assume 32bit
        # Uncompressed OOP addresses
        self.log("Starting scan for all Klass addresses in ranges")
        values = self.loaded_classes_by_addr.keys()
        klass_addr_locs, klass_range_locs = self.scan_pages_for_dword_values(values, start, end, in_parallel=True)
        self.log("Completed scan for all Klass addresses in ranges")
        return klass_addr_locs, klass_range_locs


    def prelim_scan_heap_for_klasses (self, addr, sz, stop_at_failed_read=True):
        # lets ignore oops and look for the klass instances
        # if we see something that looks like an age bit we
        # can save that
        naddr = addr
        #data = self.read(addr, sz)
        pos = 0
        end_addr = sz+addr
        failed_read = False
        word_sz = self.word_sz
        heap_age_locs = {}
        heap_oop_klasses = {}
        pot_oop = set()
        while naddr < end_addr:
            incr = 8
            klass_addr = self.read_addr(naddr+self.word_sz)
            if klass_addr is None:
                if not failed_read:
                    self.log ("Missing address range starting at 0x%08x"%naddr)
                failed_read = True
                if stop_at_failed_read:
                    break
                naddr+= incr
                continue
            if failed_read:
                failed_read = False
                self.log("Range started again at 0x%08x"%naddr)
            if klass_addr == 0xffffffff or klass_addr == 0: #or\
               #not self.is_valid_addr(klass_addr):
                naddr += incr
                continue

            klass = self.lookup_known_klass(klass_addr)
            if klass:
                heap_age_locs[naddr] = self.read_dword(naddr) if self.is_32bit else\
                                      self.read_qword(naddr)
                heap_oop_klasses[naddr] = klass
                name = getattr(klass, "name_value", None)
                #if name:
                #    self.log ("[+++] Found class ref at [0x%08x] = %08x %s"%(naddr, klass_addr, str(name)))
            elif self.is_valid_addr(klass_addr):
                # likely an oop on the heap
                pot_oop.add(naddr)
                heap_age_locs[naddr] = self.read_dword(naddr) \
                       if self.is_32bit else self.read_qword(naddr)

            naddr += incr
        return heap_age_locs, heap_oop_klasses, pot_oop



    def scan_heap (self, addr, sz):
        end = addr + sz
        pos = 0
        while pos < end:
            incr = 8 # the oop must be aligned with 0x8
            #TODO this may need to change due to narrowOop
            if (pos+addr) % 8 != 0:
                raise BaseException("something is wrong with increment"+\
                      "the addr is not 8-byte aligned: 0x%08x"%(addr+pos))
            pot_age = self.read_addr(pos+addr)
            age = 0 if self.is_valid_addr(pot_age) else pot_age & 0xff
            dword = self.read_addr(pos+addr+self.word_sz)
            if age > 0 and dword != 0 and dword != 0xfffffff and \
                dword %8 == 0 and self.is_valid_addr(dword):
                #self.log("Found an oop candidate @ 0x%08x"%(addr+pos))
                # strategy, check that it is a klass with get klass info
                # if so, treat as a klass
                klass_info = get_klass_info(dword, self)
                if klass_info['is_meta'] or \
                   klass_info['is_instance'] or\
                   klass_info['is_array']:
                    #self.log("++ Successfully identified a klass")
                    klass = None
                    if not dword in self.all_klasses:
                        klass = Klass.from_jva(dword, self)
                        if klass:
                            klass.update_fields()
                            self.add_klass(klass, check_vtable=True)
                    else:
                        klass = self.get_klass(dword)

                    oop = None
                    #otherwise treat as an oop
                    klass_name = None
                    if klass:
                        klass_name = str(getattr(klass, "name_value", None))
                    else:
                        klass_name = str(None)
                    self.add_klass(klass, check_vtable=True)
                    if klass and self.knows_klass_vtable(klass):
                        oop = Oop.from_jva(addr+pos,self)
                    elif klass:
                        vt = klass.vtable
                        a = klass.addr
                        self.log ("Unknown klass vtable: 0x%08x for klass %s 0x%08x"%(vt, klass_name, a))

                    if oop:
                        #self.log("++ Successfully identified an oop")
                        self.heap_oops[addr+pos] = oop
                        sz = oop.agg_size()
                        if sz % 8 != 0:
                            sz = self.align_addr(sz, 8)
                        if sz > 512:
                            self.log ("large skip @ 0x%08x of 0x%08x"%(pos+addr, sz))
                        incr = sz
                    else:
                        self.log("Failed to read oop @ 0x%08x"%(addr+pos))
                else:
                    self.failed_klasses.append(addr+pos)
                    self.log("Error: No klass at 0x%08x"%(addr+pos+self.word_sz))
            pos += incr

    def scan_all_heaps_for_oop_candidates(self):
        for heap in self.gc_heaps:
            name = heap['name']
            addr = heap['start']
            sz = heap['size']
            self.log ("Scanning %s of size: 0x%08x"%(name, sz))
            #self.scan_heap(addr, sz)
            self.scan_heap_for_klasses(addr, sz)
        return self.heap_oops, self.failed_klasses

    def print_known_heaps(self):
        for heap in self.gc_heaps:
            name = heap['name']
            addr = heap['start']
            sz = heap['size']
            self.log ("Heap: %s 0x%08x-0x%08x sz=0x%08x"%(name, addr, addr+sz, sz))

    #def srcs_for_addr(self, addr):
    #    return [int(i) for i in self.ptrs.get_sink_srcs_set(addr)]

    #def srcs_for_obj(self, obj):
    #    return [int(i) for i in self.ptrs.get_sink_srcs_set(obj.addr)]

    def gross_check_oops(self, klass):
        # how to find the oops for a given instance
        #1) use the pointers from the precomputed pointer map
        #2) check that the pointer is within -4 bytes of a valid markoop header
        #    check are 1) value sits on a 0x8-byte aligned address
        #                 (not looking for arrays here)
        #              2) the age and lock bits can be used grossly to
        #                 distinguish between valid addresses and a hash+bits
        #                 for now I am just using the 0x79 determined from
        #                 observation
        addrs = self.srcs_for_obj(klass)
        word_sz = self.word_sz
        candidates_oops = [addr for addr in addrs if (addr-word_sz) % 8 == 0]
        # looking at the age bits and the lock bits (7 lsb)
        potential_cand = []
        for addr in candidates_oops:
            data = self.read(addr-word_sz, word_sz)
            # FIXME can I really use 0x79 as a good value to search for objects?
            if data and len(data) == word_sz:
                age_biased_lock, = struct.unpack('B', data[0])
                # FIXME this is a bad hack, needs experimental verification
                if age_biased_lock > 0 and age_biased_lock == 0x79:
                    potential_cand.append(addr-word_sz)
        return potential_cand

    def extract_cstring_from_data(self, addr, max_len=1024):
        string = None
        sz = 512 if max_len > 512 else max_len

        while sz < max_len+1:
            sz <<= 1
            if sz > max_len:
                sz = max_len
            sbytes = self.read(addr, sz)
            if sbytes.find("\x00") > -1:
                string= sbytes.split('\x00')[0]
                break
        return string

    def read_cstring(self, addr):
        string = None
        # if self.strings.has_addr(addr):
        #     return self.strings.get_str_at_addr(addr)

        sr = self.find_range(addr)
        if sr:
            string = self.extract_cstring_from_data(addr, sr.fsize)

        return string

    @staticmethod
    def extract_size_from_entry(entry):
        size = 0
        sz = entry.split()[2]
        if sz.find("K") > 0:
            size = int(sz.split("K")[0])*1024
        elif sz.find("M") > 0:
            size = int(sz.split("M")[0])*1024*1024
        elif sz.find("G") > 0:
            size = int(sz.split("G")[0])*1024*1024*1024
        return size

    def parse_collected_heap_log(self, log_str):
        lines = [i.strip() for i in log_str.splitlines() if len(i.strip()) > 0]
        eden_space_lines = [i for i in lines if i.find("eden") == 0]
        to_space_lines = [i for i in lines if i.find("to") == 0]
        from_space_lines = [i for i in lines if i.find("from") == 0]
        the_space_lines = [i for i in lines if i.find("the") == 0]
        heaps = []
        # extract edenspace
        pos = 0
        for entry in eden_space_lines:
            size = self.extract_size_from_entry(entry)
            start = entry.split("[")[1].split(",")[0]
            name = "eden_space_%d"%pos
            heaps.append({"start":int(start, 16), "size":size, "name":name})
            pos += 1

        # extract fromspace
        pos = 0
        for entry in from_space_lines:
            size = self.extract_size_from_entry(entry)
            start = entry.split("[")[1].split(",")[0]
            name = "from_space_%d"%pos
            heaps.append({"start":int(start, 16), "size":size, "name":name})
            pos += 1

        # extract tospace
        pos = 0
        for entry in to_space_lines:
            size = self.extract_size_from_entry(entry)
            start = entry.split("[")[1].split(",")[0]
            name = "to_space_%d"%pos
            heaps.append({"start":int(start, 16), "size":size, "name":name})
            pos += 1

        # extract thespace
        pos = 0
        for entry in the_space_lines:
            size = self.extract_size_from_entry(entry)
            start = entry.split("[")[1].split(",")[0]
            name = "the_space_%d"%pos
            heaps.append({"start":int(start, 16), "size":size, "name":name})
            pos += 1
        return heaps

    def cluster_cp_in_pages_32bit(self):
        # cluster klasses
        cp_addrs = [k.constants for k in self.all_klasses.values()]

        cp_addrs.sort()

        # find min page
        page_mask = 0xfffff000
        start_page = min(cp_addrs) & page_mask
        end_page = max(cp_addrs) & page_mask
        page = start_page
        cp_pages = {}
        while page <= end_page:
            cp_pages[page] = set()
            page += 4096

        for addr in cp_addrs:
            cp_pages[addr&page_mask].add(addr)

        cp_page_counts = []
        for page,addrs in cp_pages.items():
            cp_page_counts.append((page, len(addrs)))

        cp_klass_pages_counts = sorted(cp_page_counts, key=lambda k: k[1])
        cp_klass_pages_counts.reverse()
        return cp_klass_pages_counts, cp_pages

    def cluster_klasses_in_pages_32bit(self):
        # cluster klasses

        klass_addrs = [k.addr for k in self.all_klasses.values()]
        klass_addrs.sort()

        # find min page
        page_mask = 0xfffff000
        start_page = min(klass_addrs) & page_mask
        end_page = max(klass_addrs) & page_mask
        page = start_page
        self.klass_pages = {}
        klass_pages = self.klass_pages
        while page <= end_page:
            klass_pages[page] = set()
            page += 4096

        for addr in klass_addrs:
            klass_pages[addr&page_mask].add(addr)

        klass_page_counts = []
        for page,addrs in klass_pages.items():
            klass_page_counts.append((page, len(addrs)))

        sorted_klass_pages_counts = sorted(klass_page_counts, key=lambda k: k[1])
        sorted_klass_pages_counts.reverse()
        return sorted_klass_pages_counts, klass_pages

    def get_klass_addr_refs(self, addr):
        if self.klass_addr_refs is None:
            self.log ("%s: First time call to get class refs, may take a while")
            self.klass_addr_refs = self.scan_ranges_for_klass_addrs()
            self.log ("%s: Completed klass ref enumeration")
        if addr in self.klass_addr_refs:
            return self.klass_addr_refs[addr]
        return []


    def cluster_oops_in_pages_32bit(self):
        self.cluster_klasses_in_pages_32bit()
        self.est_heap_pages = {}
        est_heap = {}
        addr_set = set()
        # mine redis for locations
        page_mask = 0xfffff000
        for page_set in self.klass_pages.values():
            addr_set |= page_set

        # query the pointers from redis
        for addr in addr_set:
            # HERE
            res = self.get_klass_addr_refs(addr)
            #res = self.ptrs.get_sink_srcs_set(addr)
            for a in res:
                if a & page_mask in self.klass_pages:
                    continue
                p = a & page_mask
                if not p in est_heap:
                    est_heap[p] = set()
                est_heap[p].add(a)
        return est_heap



    def cluster_syms_in_pages_32bit(self):
        # cluster klasses

        klass_addrs = [k.addr for k in self.all_klasses.values()]
        klass_addrs.sort()
        klass_symbol_addrs = self.symboltable_values.keys()
        klass_symbol_addrs.sort()
        page_mask = 0xfffff000
        start_page = min(klass_symbol_addrs) & page_mask
        end_page = max(klass_symbol_addrs) & page_mask
        page = start_page
        klass_symbol_pages = {}
        while page <= end_page:
            klass_symbol_pages[page] = set()
            page += 4096

        for addr in klass_symbol_addrs:
            klass_symbol_pages[addr&page_mask].add(addr)

        klass_sym_page_counts = []
        for page,addrs in klass_symbol_pages.items():
            klass_sym_page_counts.append((page, len(addrs)))

        sorted_klass_sym_pages = sorted(klass_sym_page_counts, key=lambda k: k[1])
        sorted_klass_sym_pages.reverse()
        # find min page

        return sorted_klass_sym_pages, klass_symbol_pages

#    def group_oop_age_locs_by_heap(self):
#        in_heap = lambda addr, start, sz: start <= addr and addr <= start+sz
#        oop_addrs_by_heap = {}
#        for heap in self.gc_heaps:
#            oop_addrs_by_heap[heap['name']] = []
#
#        addrs = self.heap_age_locs.keys()
#        addrs.sort()
#
#        for addr in addrs:
#            for heap in self.gc_heaps:
#                if in_heap (addr, heap['start'], heap['size']):
#                    oop_addrs_by_heap[heap['name']].append(addr)
#        self.oop_addrs_by_heap = oop_addrs_by_heap
#        return self.oop_addrs_by_heap

    def partition_pot_oops(self):
        # TODO this may change with different GC implementations
        # TODO finish this implementation so that the klass is mapped
        # to an OOP if the class is not an array
        wanted_age_locations = dict([(k,v) for k,v in self.heap_age_locs.items() if v < 257])
        self.partitioned_age_locations = dict([(v, set()) for v in wanted_age_locations.values()])
        for addr, age in wanted_age_locations.items():
            self.partitioned_age_locations[age].add(addr)
        return self.partitioned_age_locations

    def extract_oops_for_ages(self, ages=[0x0, 0x79, 0x59, 0x01]):
        for age in ages:
            addrs = self.partitioned_age_locations[age]
            for addr in addrs:
                try:
                    self.heap_oops[addr] = Oop.from_jva(addr, self)
                except:
                    self.log ("Failed to extract oop at: 0x%08x"%addr)

    def group_addrs_by_heap(self, addr_list):
        in_heap = lambda addr, start, sz: start <= addr and addr <= start+sz
        oop_addrs_by_heap = {}
        for heap in self.gc_heaps:
            oop_addrs_by_heap[heap['name']] = []

        addrs = addr_list
        addrs.sort()

        for addr in addrs:
            for heap in self.gc_heaps:
                if in_heap (addr, heap['start'], heap['size']):
                    oop_addrs_by_heap[heap['name']].append(addr)

        return oop_addrs_by_heap

    def identify_heap_klass_refs_by_name(self, name):
        if not name in self.loaded_classes_by_name:
            return None
        klass = self.loaded_classes_by_name[name]
        klass_addr = klass.addr

        pot_oop_addrs = self.get_pot_heap_oops_based_on_refs(klass)

        oop_results = []

        for addr in pot_oop_addrs:
            try:
                oop = Oop.from_jva(addr, self)
                if oop and str(oop.klass_value).find(name) == 0:
                    #oop.update_fields()
                    # TODO disabled to aid with saving and verifications
                    #self.add_oop(oop)
                    oop_results.append(oop)
            except:
                pass

        return oop_results

    def update_klass_methods(self):
        # find a method class
        method_cpp_vtable = None

        for metaklass_set in self.vtables_to_klass.values():
            e = next(iter(metaklass_set))
            for e in metaklass_set:
                if e._name == "Method":
                    method_cpp_vtable = e.vtable
                    break
                if method_cpp_vtable:
                    break

        if method_cpp_vtable is None:
            raise BaseException("Unable to identify a Method meta-klass")

        all_methods = self.vtables_to_klass[method_cpp_vtable]

        for method in all_methods:
            name = method.name()
            idnum = method.get_idnum()
            klass_holder = method.get_klass_holder()
            klass_holder.add_method_value(name, idnum, method)

    def correct_klasses(self):
        import operator
        # find a method clas
        #1) Group vtables by name and value
        #2) vtables with the most names and values get the "win"
        #3) update the old addresses with the correct values
        object_klass = self.loaded_classes_by_name['java/lang/Object']
        object_kname = getattr(object_klass, '_name')
        object_vtable = getattr(object_klass, 'vtable')
        misclassified_metas = set()
        for vtable, klasses in self.vtables_to_klass.items():
            remove_klasses_set = set()
            for k in klasses:
                if k.vtable == object_vtable and\
                   k._name != object_kname:
                   self.forget_all_for_addr(k.addr)
                   misclassified_metas.add(k.addr)
                   remove_klasses_set.add(k.addr)
            for a in remove_klasses_set:
                klasses.remove(a)
        for a in misclassified_metas:
            klass = self.get_klass(a)
            if klass:
                klass.update_fields()
                self.add_klass(klass)
        #vtable_names_counts = {}
        #for vtable, klasses in self.vtables_to_klass.items():
        #    vtable_klass_counts = {}
        #    for k in klasses:
        #        if not type(k) in vtable_klass_counts:
        #            vtable_klass_counts[type(k)] = 0
        #        vtable_klass_counts[type(k)] += 1
        #    candidates = [(t, c) for t,c in vtable_klass_counts.items()]
        #    # mac_value is at 1
        #    max_index, max_value = max(enumerate(candidates), key=operator.itemgetter(-1))
        #    T_klass = max_value[0]
        #    temp = [(k.addr, k) for k in klasses]
        #    for a, k in temp:
        #        if type(k) != T_klass:
        #            klass = T_klass.from_jva(a, self)
        #            if klass:
        #                try:
        #                    self.forget_all_for_addr(k.addr)
        #                    self.log ("Attempting to update klass: %s"%str(klass))
        #                    klass.update_fields()
        #                    self.add_klass(klass)
        #                except:
        #                    import traceback
        #                    traceback.print_exc()
        #                    self.log ("Failed to correct the klass: %s"%str(klass))
    def get_nonessential_classes (self):
        klass_names = self.loaded_classes_by_name.keys()
        non_essential = []
        for ki in klass_names:
            if ki.find('sun/') == -1 and\
               ki.find("java") != 0 and\
               ki.find("[") == -1 and\
               ki.find("com/oracle") == -1:
               non_essential.append(ki)
        return non_essential

    def cluster_page_addrs (self, page_addrs, dist = 4096):
        clusters = {}
        cluster_ranges = []
        if len(page_addrs) == 0:
            return clusters, cluster_ranges

        page_addrs.sort()
        last = page_addrs[0]
        cur = last
        pos = 1
        clusters[cur] = [cur]
        end = len(page_addrs)
        while pos < end:
            next_v = page_addrs[pos]
            #self.log (next_v-last)
            if next_v - last > dist:
                cur = next_v
                clusters[cur] = []

            clusters[cur].append(next_v)
            last = next_v
            pos += 1


        for start, addr_list in clusters.items():
            end = max(addr_list)
            sz = end - start + self.page_size
            cluster_ranges.append((start, end, sz))

        return clusters, cluster_ranges

    def scan_for_dwords_in_data(self, data, addrs_dict, values_dict, base_addr = 0, omit_ranges=[]):
        end = len(data)
        self.log ("Scanning %d bytes"%end)
        dpos = 0
        while dpos < end-4:
            addr = base_addr + dpos
            value = struct.unpack("<I",data[dpos:dpos+4])[0]
            addrs_dict[addr] = value
            if not value in values_dict:
                values_dict[value] = []
            values_dict[value].append(addr)
            dpos += 4
        self.log ("Completed scanning %d bytes"%end)

    def scan_ranges_for_klass_addrs(self):
        klass_addr_set = set(self.loaded_classes_by_addr.keys())
        self.dword_addrs = {}
        self.dword_values = {}
        for r in self.ranges.values():
            self.scan_for_dwords_in_data(r.fdata, self.dword_addrs, self.dword_values, base_addr=r.start)


        pot_klass_refs = dict([(addr, []) for addr in klass_addr_set])
        for klass_addr in klass_addr_set:
            if klass_addr in self.dword_values:
                pot_klass_refs[klass_addr] = self.dword_values[klass_addr]

        return pot_klass_refs

    def brute_force_identify_symbol_table(self, start=None, end=None):
        if start is None:
            start = 0x0
        if end is None:
            end = self.get_libjvm_base() | 0x0fff0000
        symts = []
        q = list(set(self.find_potential_symbol_table(start=start, end=end)))
        q.sort()
        self.log("Attempting to isolate symbol table from %d candidates"%(len(q)))
        for i in q:
            if i < start and i > end:
                continue
            try:
                _jva = JVMAnalysis(**self._init_params)
                symt = SymbolTable.from_jva(i, _jva)
                if not symt is None and len(symt.get_bucket_values()) > self.min_symbols:
                    symts.append(symt)
                    self.log("Found symbol table cand. at 0x%08x (entrys=%d)"%(symt.addr, len(symt.get_bucket_values())))
            except:
                #import traceback
                #traceback.print_exc()
                pass
        _symt = SymbolTable.find_best_match(symts, self)
        if _symt is None and len(symts) > 0:
            _symt = symts[0]
        if _symt:
            self.log("Using symbol table cand. at 0x%08x (entrys=%d)"%(_symt.addr, len(_symt.get_bucket_values())))
        else:
            self.log("Failed to find symbol table cand")
        #symt = SymbolTable.from_jva(_symt.addr, self)
        #if not symt is None:
        #    self._symbol_table_addr = symt.addr
        return _symt

    def brute_force_identify_system_dictionary(self, start=None, end=None):
        if start is None:
            start = min(self.ranges)
        if end is None:
            end = max(self.ranges) + self.ranges[max(self.ranges)].fsize
        dis = []
        q = set(self.find_potential_dictionarys(start=start, end=end))
        for i in q:
            try:
                _jva = JVMAnalysis(**self._init_params)
                m = Dictionary.bruteforce_testing(i, _jva, num_to_observe=self.num_klasses_to_observe)
                if not m is None and m['num_observed'] >=self.num_klasses_to_observe:
                    dis.append(m)
            except:
                pass
        # parse the dictionary table *fully* with self not the other jva
        _di = Dictionary.find_best_match(dis, self)
        #if not symt is None:
        #    self._symbol_table_addr = symt.addr
        return _di

    def brute_force_identify_string_table(self, start=None, end=None):
        if start is None:
            start = 0x0
        if end is None:
            end = self.get_libjvm_base() | 0x0fff0000
        dis = []
        q = set(self.find_potential_string_table(start=start, end=end))
        for i in q:
            try:
                _jva = JVMAnalysis(**self._init_params)
                m = StringTable.bruteforce_testing(i, _jva, num_to_observe=self.num_strs_to_observe)
                if not m is None and m['num_observed'] >=self.num_strs_to_observe:
                    dis.append(m)
            except:
                pass
        _di = StringTable.find_best_match(dis, self)
        #if not symt is None:
        #    self._symbol_table_addr = symt.addr
        return _di
