import sys, os, socket, struct
from path_var import *
from recoop import recoop_jvm8
from jvm.mem_chunks import MemChunk
from jvm.jvm_analysis import JVMAnalysis
from jvm.jvm_systemdictionary import Dictionary
from jvm.jvm_stringtable import StringTable
from jvm.jvm_klassoop import Oop
from jvm.jvm_objects import JavaThreadPartial, JavaFrameAnchor, Frame, VFrameArray


profile = 'LinuxUbuntu1504-whatx86'
dumps_dir = '/research_data/code/git/jvm_analysis/java-rat/g1gc-process/dumps/'
dump_dir = '/research_data/code/git/jvm_analysis/java-rat/g1gc-process/memory-work.dump'
dump_java_process=True
libjvm = 0x00b66e7000
recoop_jva5 = recoop_jvm8.RecOOPJVM8(path_to_dumps=dumps_dir, path_to_mem=dump_dir,jvm_start_addr=libjvm, jvm_ver="8u60", dump_java_process=dump_java_process)

recoop_jva5.next_step(profile=profile)
recoop_jva5.next_step()
recoop_jva5.next_step()
recoop_jva5.next_step()


jva5 = recoop_jva5.jva
jva5._string_table_addr = 3059240304L
jva5._dictionary_addr = 3059293496L
jva5._symbol_table_addr = 3059160168L
jva5.read_internal_symbol_table()
jva5.read_system_dictionary()
jva5.read_internal_string_table()