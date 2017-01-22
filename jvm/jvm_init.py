import sys
# requires redis
from redis_backed_ptrs import PtrsRedisConn
from redis_backed_strings import StringsRedisConn
# requires volatility
#import jvm_analysis
from jvm_analysis import JVMAnalysis
#from jva import JVMAnalysis
from findstructs import FindStructs
from mem_range import produce_ranges
from jvm_overlays import *
from jvm_klass import *
from jvm_meta import ConstantPool, CPCache
from jvm_templates import ArrayT
from jvm_klassoop import *
from datetime import datetime
def time_str():
    return str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))

def init_jva_only( dumps_dir, jvm_start_addr=None, is_32bit=True,
                         word_sz=4, little_endian=True, is_linux=True,
                         jvm_ver=None):
    start_time = time_str()
    ranges = produce_ranges(dumps_dir)
    libjvm={}
    if jvm_start_addr:
       libjvm = {'start':jvm_start_addr, 'version':jvm_ver}
    jva = JVMAnalysis(ranges, libjvm = libjvm,
        is_32bit=True, little_endian = True, word_sz = 4, is_linux=is_linux)
    return jva

def init_jva_environment(dumps_dir, jvm_start_addr=None, is_32bit=True,
                         word_sz=4, little_endian=True, is_linux=True,
                         jvm_ver=None):
    start_time = time_str()
    ranges = produce_ranges(dumps_dir)
    libjvm={}
    if jvm_start_addr:
       libjvm = {'start':jvm_start_addr, 'version':jvm_ver}
    jva = JVMAnalysis(ranges, libjvm = libjvm,
        is_32bit=True, little_endian = True,
        word_sz = 4, is_linux=is_linux)

    #print ("Enumerating VM Structs and program symbols")
    #_ = jva.find_symbols()
    #_ = jva.enumerate_sym_entrys()
    #jva.print_enumerated_symbols()
    print ("Enumerating Symbols in the Internal JVM symbol table")
    _ = jva.read_internal_symbol_table()
    print ("[%s] Reading system dictionary"%(str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))))
    print ("Enumerating Klasses in the Internal JVM System Dictionary")
    _ = jva.read_system_dictionary()
    print ("[%s] Done reading system dictionary"%(str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))))
    print ("Parsing GC log, and scanning heap for potential oops at boundarys")
    _ = jva.gen_heaps_from_gc_logs()
    print ("Scanning heap for class references and potential oops at boundarys")
    start_time2 = time_str()
    #
    _ = jva.scan_all_heaps_for_oop_candidates()
    print ("[%s] Heap Scan started analysis"%(start_time2))
    print ("[%s] Heap Scan completed analysis"%(time_str()))
    print ("Enumerating Strings in the Internal JVM string table")
    _ = jva.read_internal_string_table()
    print ("[%s] Started analysis"%(start_time))
    print ("[%s] Completed analysis"%(time_str()))

    return jva

def init_jva_environment_klass_refs( dumps_dir, jvm_start_addr=None,
                  is_32bit=True, word_sz=4, little_endian=True, is_linux=True,
                  jvm_ver=None):
    start_time = time_str()
    ranges = produce_ranges(dumps_dir)
    libjvm={}
    if jvm_start_addr:
       libjvm = {'start':jvm_start_addr, 'version':jvm_ver}
    jva = JVMAnalysis(ranges, libjvm = libjvm,
        is_32bit=True, little_endian = True, word_sz = 4, is_linux=is_linux)

    #print ("Enumerating VM Structs and program symbols")
    #_ = jva.find_symbols()
    #_ = jva.enumerate_sym_entrys()
    #jva.print_enumerated_symbols()
    print ("Enumerating Symbols in the Internal JVM symbol table")
    _ = jva.read_internal_symbol_table()
    print ("[%s] Reading system dictionary"%(str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))))
    print ("Enumerating Klasses in the Internal JVM System Dictionary")
    _ = jva.read_system_dictionary()
    print ("[%s] Done reading system dictionary"%(str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))))
    print ("Using klass references to enumerated OOPs")
    est_heap_pages = jva.cluster_oops_in_pages_32bit()
    print ("Identified %d pages for heap"%(len(est_heap_pages)))
    clusters, cluster_ranges = jva.cluster_page_addrs(est_heap_pages.keys(),
                                                      dist=4096*3)
    sorted_cluster_range = sorted(cluster_ranges, key=lambda c: c[-1])
    print ("Sorted the clusters, and scanning for OOPs")
    for c in sorted_cluster_range:
        start = c[0]
        sz = c[2]
        name = "unknown_0x%08x"%start
        heap_age_locs, heap_oop_klasses, pot_oop = \
                      jva.prelim_scan_heap_for_klasses(start, sz)
        if len(heap_oop_klasses):
            jva.gc_heaps.append({'name':name, 'start':start, 'size':sz})

        for loc,age in heap_age_locs.items():
            jva.heap_age_locs[loc] = age

        for loc, klass in heap_oop_klasses.items():
            jva.add_heap_oop_klass(loc, klass)

        for addr in pot_oop:
            jva.add_heap_pot_oop(addr)

    print ("Scanning heap for class references and potential oops at boundarys")
    start_time2 = time_str()
    #
    #_ = jva.scan_all_heaps_for_oop_candidates()
    print ("[%s] Heap Scan started analysis"%(start_time2))
    print ("[%s] Heap Scan completed analysis"%(time_str()))
    print ("Enumerating Strings in the Internal JVM string table")
    _ = jva.read_internal_string_table()
    print ("[%s] Started analysis"%(start_time))
    print ("[%s] Completed analysis"%(time_str()))

    return jva
