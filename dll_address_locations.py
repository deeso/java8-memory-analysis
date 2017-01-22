import sys, os
from path_var import *
#PATH_TO_JVM_MODULE = "/research_data/code/git/jvm_analysis/"
sys.path.append(PATH_TO_JVM_MODULE)
import pefile, struct
from jvm.extract_jvm_entrys import ExtractDLLJVMEntrys


JVM_DLL = "/home/dso/jvm-8u40.dll"

ex = ExtractDLLJVMEntrys(JVM_DLL)
syms = ex.enumerate_sym_entrys()
ex.print_enumerated_symbols()
print ex.get_sym_dictionary(ver="8u40")
