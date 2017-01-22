import sys, os
from path_var import *
#PATH_TO_JVM_MODULE = "/research_data/code/git/jvm_analysis/"
sys.path.append(PATH_TO_JVM_MODULE)
import jvm
from jvm.mem_chunks import MemChunk
from jvm.extract_process import ExtractProc

if __name__ == "__main__":

    if len(sys.argv) < 4:
        fmt = "{0} <memory_dump> <profile> <location_to_dump_java_process>"
        print (fmt.format(sys.argv[0]))
        sys.exit(-1)
    prepend = 'file:///' if sys.argv[1].strip().find('file:///') != 0 else ''
    the_file = prepend+sys.argv[1]
    profile = sys.argv[2]
    dump_dir = sys.argv[3]

    ex_java = ExtractProc(the_file=the_file, profile=profile)
    ex_java.update_process_info(name="java", lookup_lib=False)
    chunks = MemChunk.chunks_from_task_or_file(task=ex_java.proc,
                                                MChunkCls=MemChunk)
    for chunk in chunks.values():
        chunk.check_load()

    for chunk in chunks.values():
        chunk.dump_data(outdir=dump_dir)

