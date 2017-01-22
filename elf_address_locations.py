import sys, os
from path_var import *
#PATH_TO_JVM_MODULE = "/research_data/code/git/jvm_analysis/"
sys.path.append(PATH_TO_JVM_MODULE)
import pefile, struct
from jvm.extract_jvm_entrys import ExtractELFJVMEntrys


JVM_ELF = "/home/dso/java-8-oracle/jre/lib/i386/client/libjvm.so"

ex = ExtractELFJVMEntrys(JVM_ELF)
syms = ex.enumerate_sym_entrys()
ex.print_enumerated_symbols()

fields = []
fmt = "{%s}"
k_v_fmt = "'%s':%s,\n"
for k,v in ex.get_sym_dictionary(ver="8u40").items():
    fields.append(k_v_fmt%(k, v))

print fmt%("".join(fields))

print ex.get_sym_dictionary(ver="8u31")
