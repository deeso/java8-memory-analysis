import sys, os
#PATH_TO_JVM_MODULE = "/research_data/code/git/jvm_analysis/"
from path_var import *
sys.path.append(PATH_TO_JVM_MODULE)
import pefile, struct
from jvm.extract_jvm_entrys import ExtractELFJVMEntrys

import pefile, struct
from jvm.extract_jvm_entrys import ExtractDLLJVMEntrys

#TARGET_VERSION = '8u60'
#JVM_ELF = "/home/dso/java8-u60/libjvm.so"
#JVM_DLL = "/home/dso/java8-u60/jvm.dll"
#OUTPUT_FILE = "/home/dso/java8-u60/entry_offsets.py"
#
#ex_elf = ExtractELFJVMEntrys(JVM_ELF)
#ex_elf.enumerate_sym_entrys()
#
#ex_dll = ExtractDLLJVMEntrys(JVM_DLL)
#ex_dll.enumerate_sym_entrys()
#
#fields = []
#fmt = "{%s}"
#k_v_fmt = "'%s':0x%08x,\n"
#for k,v in ex_dll.get_sym_dictionary(ver=TARGET_VERSION).items():
#    fields.append(k_v_fmt%(k, max(-v, v)))
#
#for k,v in ex_elf.get_sym_dictionary(ver=TARGET_VERSION).items():
#    fields.append(k_v_fmt%(k, max(-v, v)))
#
ERROR_FMT = "%s <-w|-l> <libjvm.so|jvm.dll> <version (e.g. 8u60)> <outputfile>"
#open(OUTPUT_FILE, 'w').write('{\n'+"".join(fields)+'\n}')

if __name__ == "__main__":
    k_v_fmt = "'%s':0x%08x,\n"
    if len(sys.argv) < 5:
        print (ERROR_FMT%sys.argv[0])
        sys.exit(-1)
    use_elf = True if sys.argv[1] == '-l' else False
    use_win = True if sys.argv[1] == '-w' else False
    filename = sys.argv[2]
    version = sys.argv[3]
    outputfile = sys.argv[4]
    ex_lib = None
    if not use_win and not use_elf:
        print (ERROR_FMT%sys.argv[0])
        sys.exit(-1)
   
    try:
        os.stat(filename)
        ex_lib = ExtractDLLJVMEntrys(filename) if use_win else ExtractELFJVMEntrys(filename)
        ex_lib.enumerate_sym_entrys()
    except:
        print ("Error: JVM Library %s does not exist"%filename)
        sys.exit(-1)

    
    sym_dict = ex_lib.get_sym_dictionary(ver=version)
    if sym_dict is None:
        print ("Error: JVM Library does not contain VMStructs for version %s"%version)
        sys.exit(-1)

    fields = []
    for k,v in sym_dict.items():
        fields.append(k_v_fmt%(k, max(-v, v)))
    
    open(outputfile, 'w').write('{\n'+"".join(fields)+'\n}')
