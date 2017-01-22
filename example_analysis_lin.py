import sys, os
from path_var import *
#PATH_TO_JVM_MODULE = "/research_data/code/git/jvm_analysis/"
sys.path.append(PATH_TO_JVM_MODULE)
# requires redis
# requires volatility
import socket, struct
from jvm.jvm_init import init_jva_only, init_jva_environment,\
                         init_jva_environment_klass_refs

# path to the preprocessed JVM memory dumps from
# volatility
lpath_to_dumps = '/research_data/malware_runs/lin/malware-a51f0'
lmalware_9a51f0 = os.path.join(lpath_to_dumps, 'java_dumps')

word_sz = 4
jva_lin = init_jva_environment_klass_refs( lmalware_9a51f0, word_sz=word_sz,
        jvm_start_addr=0x00b6b53000, jvm_ver="8u40")



# pina_class_refs = jva_lin.identify_heap_klass_refs_by_name('opciones/Pina')
# pina = pina_class_refs[-1]
# pina_klass = pina.get_klass()
# pina_cp = pina_klass.get_constant_pool()
# pina_cp_cache = pina_cp.cache_value
# pina_cp_cache.cp_cache_entrys[1].flags_info
# pina_cp_cache.cp_cache_entrys[0].flags_info

non_system_classes = jva_lin.get_nonessential_classes()
FOS_CLASS = 'java/io/FileOutputStream'
FIS_CLASS = 'java/io/FileInputStream'
INET_CLASS = 'java/net/InetAddress$InetAddressHolder'
file_input_stream_refs = jva_lin.identify_heap_klass_refs_by_name(FIS_CLASS)
file_output_stream_refs = jva_lin.identify_heap_klass_refs_by_name(FOS_CLASS)
inet_refs = jva_lin.identify_heap_klass_refs_by_name(INET_CLASS)

for inet in inet_refs:
    try:
        addr = inet.get_oop_field_value('address')
        addr_bytes = struct.pack('>I', addr)
        print "%s @ 0x%08x IP: %s"%(str(inet.get_klass()), inet.addr, socket.inet_ntoa(addr_bytes))
    except:
        pass

for fos in file_output_stream_refs:
    try:
        print fos.get_oop_field_value('path')
    except:
        pass


for fis in file_input_stream_refs:
    try:
        print fis.get_oop_field_value('path')
    except:
        pass
