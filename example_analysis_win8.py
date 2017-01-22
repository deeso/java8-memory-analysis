
import sys, os
from path_var import *
#PATH_TO_JVM_MODULE = "/research_data/code/git/jvm_analysis/"
sys.path.append(PATH_TO_JVM_MODULE)
# requires redis
# requires volatility
import socket, struct
from jvm.jvm_init import init_jva_only, init_jva_environment,\
                         init_jva_environment_klass_refs, time_str

wmalware_9a51f0_160 = "/research_data/malware_runs/win/malware-win8-9a51f0/java_dumps"
# [21:43:43.681029 04-07-2015] Started analysis
# [22:09:43.844645 04-07-2015] Completed analysis
word_sz = 4
jva_win_160 = init_jva_environment_klass_refs(wmalware_9a51f0_160,
             word_sz=word_sz, is_linux=False, jvm_start_addr=0x65e20000,
             jvm_ver="8u40")

FILE = 'java/io/File'
is_160 = jva_win_160.identify_heap_klass_refs_by_name(FILE)
for f in file_160:
    print f.get_oop_field_value('path')

FIS_CLASS = 'java/io/FileInputStream'
INET_CLASS = 'java/net/InetAddress$InetAddressHolder'
file_input_stream_refs_160 = jva_win_160.identify_heap_klass_refs_by_name(FIS_CLASS)


inet_refs_160 = jva_win_160.identify_heap_klass_refs_by_name(INET_CLASS)
for inet in inet_refs_160:
    try:
        addr = inet.get_oop_field_value('address')
        addr_bytes = struct.pack('>I', addr)
        print "%s @ 0x%08x IP: %s"%(str(inet.get_klass()), inet.addr, socket.inet_ntoa(addr_bytes))
    except:
        pass

non_system_classes_160 = jva_win_160.get_nonessential_classes()

for fis in file_input_stream_refs_160:
    try:
        print fis.get_oop_field_value('path')
    except:
        pass

FOS_CLASS = 'java/io/FileOutputStream'
file_output_stream_refs_160 = jva_win_160.identify_heap_klass_refs_by_name(FOS_CLASS)
for fos in file_output_stream_refs_160:
    try:
        print fos.get_oop_field_value('path')
    except:
        pass

DOCUMENT = 'org/w3c/dom/Document'
doc_160 = jva_win_160.identify_heap_klass_refs_by_name(DOCUMENT)
for doc in doc_160:
    try:
        print doc.get_oop_field_value('path')
    except:
        pass

INPUT_SOURCE = 'org/xml/sax/InputSource'
is_160 = jva_win_160.identify_heap_klass_refs_by_name(INPUT_SOURCE)
for is_ in doc_160:
    try:
        print doc.get_oop_field_value('path')
    except:
        pass

FILE = 'java/io/File'
is_160 = jva_win_160.identify_heap_klass_refs_by_name(FILE)
for f in file_160:
    print f.get_oop_field_value('path')
