import sys, os
from path_var import *
#PATH_TO_JVM_MODULE = "/research_data/code/git/jvm_analysis/"
sys.path.append(PATH_TO_JVM_MODULE)
# requires redis
# requires volatility
import socket, struct
from jvm.jvm_init import init_jva_only, init_jva_environment,\
                         init_jva_environment_klass_refs, time_str

# path to the preprocessed JVM memory dumps from
# volatility
lpath_to_dumps = '/research_data/malware_runs/lin/malware-a51f0'
lmalware_9a51f0 = os.path.join(lpath_to_dumps, 'java_dumps')

wpath_to_dumps = '/research_data/malware_runs/win/malware-a51f0'

wmalware_9a51f0_1396 = os.path.join(wpath_to_dumps, 'java_dumps_1396')
wmalware_9a51f0_2124 = os.path.join(wpath_to_dumps, 'java_dumps_2124')


word_sz = 4
jva_win_1396 = init_jva_environment_klass_refs(wmalware_9a51f0_1396,
             word_sz=word_sz, is_linux=False, jvm_start_addr=0x6d160000,
             jvm_ver="8u40")
jva_win_2124 = init_jva_environment_klass_refs(wmalware_9a51f0_2124,
             word_sz=word_sz, is_linux=False, jvm_start_addr=0x6d160000,
             jvm_ver="8u40")

# pina_class_refs = jva.identify_heap_klass_refs_by_name('extras/CLM')
# pina = pina_class_refs[-1]
# pina_klass = pina.get_klass()
# pina_cp = pina_klass.get_constant_pool()
# pina_cp_cache = pina_cp.cache_value
# pina_cp_cache.cp_cache_entrys[1].flags_info
# pina_cp_cache.cp_cache_entrys[0].flags_info

non_system_classes_1396 = jva_win_1396.get_nonessential_classes()
non_system_classes_2124 = jva_win_2124.get_nonessential_classes()

FOS_CLASS = 'java/io/FileOutputStream'
FIS_CLASS = 'java/io/FileInputStream'
INET_CLASS = 'java/net/InetAddress$InetAddressHolder'
file_input_stream_refs_2124 = jva_win_2124.identify_heap_klass_refs_by_name(FIS_CLASS)
file_input_stream_refs_1396 = jva_win_1396.identify_heap_klass_refs_by_name(FIS_CLASS)

file_output_stream_refs_2124 = jva_win_2124.identify_heap_klass_refs_by_name(FOS_CLASS)
file_output_stream_refs_1396 = jva_win_1396.identify_heap_klass_refs_by_name(FOS_CLASS)

inet_refs_1396 = jva_win_1396.identify_heap_klass_refs_by_name(INET_CLASS)
inet_refs_2124 = jva_win_2124.identify_heap_klass_refs_by_name(INET_CLASS)

for fos in file_output_stream_refs_1396:
    try:
        print fos.get_oop_field_value('path')
    except:
        pass

for fos in file_output_stream_refs_2124:
    try:
        print fos.get_oop_field_value('path')
    except:
        pass

for inet in inet_refs_1396:
    try:
        addr = inet.get_oop_field_value('address')
        addr_bytes = struct.pack('>I', addr)
        print "%s @ 0x%08x IP: %s"%(str(inet.get_klass()), inet.addr, socket.inet_ntoa(addr_bytes))
    except:
        pass

for inet in inet_refs_2124:
    try:
        addr = inet.get_oop_field_value('address')
        addr_bytes = struct.pack('>I', addr)
        print "%s @ 0x%08x IP: %s"%(str(inet.get_klass()), inet.addr, socket.inet_ntoa(addr_bytes))
    except:
        pass

for fis in file_input_stream_refs_1396:
    try:
        print fis.get_oop_field_value('path')
    except:
        pass

for fis in file_input_stream_refs_2124:
    try:
        print fis.get_oop_field_value('path')
    except:
        pass
