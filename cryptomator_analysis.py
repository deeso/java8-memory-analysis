# /research_data/analyse_cryptomator/win732-left_running.vmem
# /research_data/analyse_cryptomator/win732-locked_vault.vmem
# /research_data/analyse_cryptomator/win732-mounting_drive.vmem
# /research_data/analyse_cryptomator/win732-reloaded_window.vmem
# /research_data/analyse_cryptomator/win732-saved_file.vmem
#
# -p 3140
# libjvm=0x67b10000
#
# python vol.py --profile Win7SP0x86 -p 3140 -f /research_data/analyse_cryptomator/win732-locked_vault.vmem volshell
# python vol.py --profile Win7SP0x86 -p 3140 -f /research_data/analyse_cryptomator/win732-left_running.vmem volshell
# python vol.py --profile Win7SP0x86 -p 3140 -f /research_data/analyse_cryptomator/win732-mounting_drive.vmem volshell
# python vol.py --profile Win7SP0x86 -p 3140 -f /research_data/analyse_cryptomator/win732-reloaded_window.vmem volshell
# python vol.py --profile Win7SP0x86 -p 3140 -f /research_data/analyse_cryptomator/win732-saved_file.vmem volshell

# LOCATIONS OF MEMORY dumps
# /research_data/cryptomator/java_dumps/locked_vault
# /research_data/cryptomator/java_dumps/left_running
# /research_data/cryptomator/java_dumps/mounting_drive
# /research_data/cryptomator/java_dumps/reloaded_window
# /research_data/cryptomator/java_dumps/saved_file

# Volatility dumping script
#
# outdir = "LOCATION TO MEMORY CHUNKS"
# import sys, os
# PATH_TO_JVM_MODULE = "/research_data/code/git/jvm_analysis/"
# sys.path.append(PATH_TO_JVM_MODULE)
# from jvm.mem_chunks import MemChunk
# chunks = MemChunk.chunks_from_task_or_file(task=proc(), MChunkCls=MemChunk)
# for chunk in chunks.values():
#     chunk.dump_data(outdir=outdir)

import sys, os
from path_var import *
#PATH_TO_JVM_MODULE = "/research_data/code/git/jvm_analysis/"
sys.path.append(PATH_TO_JVM_MODULE)
import socket, struct
from jvm.jvm_init import init_jva_only, init_jva_environment,\
                         init_jva_environment_klass_refs, time_str

# path to the preprocessed JVM memory dumps from
# volatility
wpath_to_dumps = '/research_data/cryptomator/java_dumps/left_running/java_dumps'

# this is /research_data/cryptomator/java_dumps/
# word_sz = 4
# jva_win = init_jva_environment_klass_refs(wpath_to_dumps,
#              word_sz=word_sz, is_linux=False, jvm_start_addr=0x67b10000,
#              jvm_ver="8u40")

wpath_to_dumps = '/research_data/dogsarecool_cryptomator/mount_running/java_dumps'
# this is /research_data/dogsarecool_cryptomator/
word_sz = 4
jva_win = init_jva_environment_klass_refs(wpath_to_dumps,
             word_sz=word_sz, is_linux=False, jvm_start_addr=0x6a750000,
             jvm_ver="8u40")
