import sys, os, socket, struct
from path_var import *
from recoop import recoop_jvm8
from jvm.mem_chunks import MemChunk
from jvm.jvm_analysis import JVMAnalysis
from jvm.jvm_systemdictionary import Dictionary
from jvm.jvm_stringtable import StringTable
from jvm.jvm_klassoop import Oop
from jvm.jvm_objects import JavaThreadPartial, JavaFrameAnchor, Frame, VFrameArray

dump_java_process = False
profile = 'LinuxUbuntu1504-whatx86'
dump_dir = '/research_data/code/git/jvm_analysis_old/java-rat/proxy/experiment_five/t0/memory-dump.bin'
dumps_dir = '/research_data/code/git/jvm_analysis_old/java-rat/proxy/experiment_five/t0/dumps/'
recoop_1 = recoop_jvm8.RecOOPJVM8(path_to_dumps=dumps_dir, path_to_mem=dump_dir,jvm_ver="8u60", dump_java_process=dump_java_process)

recoop_1.next_step(profile=profile)
recoop_1.next_step(profile=profile, convert_oop_to_pyobj=False)
recoop_1.next_step(profile=profile, convert_oop_to_pyobj=False)
recoop_1.next_step(profile=profile, convert_oop_to_pyobj=False)


jva5 = recoop_jva5.jva
jva5._string_table_addr = 3059240304L
jva5._dictionary_addr = 3059293496L
jva5._symbol_table_addr = 3059160168L
jva5.read_internal_symbol_table()
jva5.read_system_dictionary()
jva5.read_internal_string_table()