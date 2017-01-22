import os
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.win32.network as network
import volatility.utils as utils
import volatility.plugins.linux.pslist as pslist
import volatility.plugins.linux.library_list as liblist

from mem_chunks import MemChunk
# configure volatility
registry.PluginImporter()
CONFIG = conf.ConfObject()
registry.register_global_options(CONFIG, commands.Command)

BASE_CONF = {'profile': None,
    'use_old_as': None,
    'kdbg': None,
    'help': False,
    'kpcr': None,
    'tz': None,
    'pid': None,
    'output_file': None,
    'physical_offset': None,
    'conf_file': None,
    'dtb': None,
    'output': None,
    'info': None,
    'location': None,
    #'plugins': plugins,
    'debug': None,
    'cache_dtb': True,
    'filename': None,
    'cache_directory': None,
    'verbose': None, 'write':False}

def get_base_conf():
    return dict(BASE_CONF.items())

class ExtractProc(object):
    # had to set the plugins value in the ~/.volatilityrc with the following
    #[DEFAULT]
    #plugins=/research_data/vol_profiles/

    def __init__(self, config=None, the_file=None, profile=None, plugins=None):
        if the_file.strip().find("file://") < 0:
            the_file = "file://"+the_file
        self.base_conf = get_base_conf()
        self.base_conf["profile"] = profile
        self.base_conf["location"] = the_file
        self.base_conf['plugins'] = plugins
        # configure volatility
        self.config = config if config else CONFIG
        self.config.default_opts['filename'] = the_file
        self.config.PROFILE = profile
        #self.update_process_info()
        self.chunks = None


    def update_space_conf(self):
        self.update_config ()
        self.addr_space = utils.load_as(self.config)


    def update_process_info(self, pid=None, name="java", libname='libjvm', lookup_lib=False):
        self.update_space_conf()
        if pid is None:
            self.proc = self.find_process_by_name(name)
        else:
            self.proc = self.find_process_by_pid(pid)
        self.pid = self.get_proc_pid(self.proc)
        self.base_conf['pid'] = str(self.pid)

        self.update_space_conf()
        if not libname is None and lookup_lib:
            self.lib = self.find_lib_by_name(name=libname)
            self.lib_start = self.lib.l_addr.v()

    def get_proc_pid(self, proc_):
        # get thread 0's pid
        t0 = proc_.threads()[0]
        pid = int(t0.pid.v())
        return pid

    def compare_command_line(self, cmd, name):
        if cmd is None or len(cmd) == 0:
           return False
        elif cmd.find(name) == 0:
           return True
        elif len(cmd.split()) == 0:
           return False
        cmd_f = cmd.split()[0]
        cmd_ = os.path.split(cmd_f)[-1]
        if cmd_.find(name) == 0:
            return True
        return False

    def find_process_by_pid(self, pid):
        processes = [k for k in pslist.linux_pslist(self.config).calculate()]
        proc_ = None
        for proc_ in processes:
            if pid == self.get_proc_pid(proc_):
                return proc_
            proc_ = None

        if proc_ is None:
            raise Exception("Epic fail, did not find %s in %s"%(pid,self.base_conf['location'] ))
        return proc_

    def find_process_by_name(self, name="java"):
        processes = [k for k in pslist.linux_pslist(self.config).calculate()]
        proc_ = None
        for proc_ in processes:
            if self.compare_command_line(proc_.get_commandline(), name):
                break
            elif self.compare_command_line(str(proc_.comm), name):
                break
            proc_ = None

        if proc_ is None:
            raise Exception("Epic fail, did not find %s in %s"%(name,self.base_conf['location'] ))
        return proc_

    def update_config(self):
        # set the default config
        for k,v in self.base_conf.items():
            self.config.update(k,v)

    def find_lib_by_name(self, name="libjvm"):
        libs = [lib for task, lib in
                     liblist.linux_library_list(self.config).calculate()]
        lib = None
        for lib in libs:
            if lib.l_name.find(name) > -1:
                break
            lib = None

        if lib is None:
            raise Exception("Epic fail, did not find %s in %s"%(name,self.base_conf['location'] ))
        return lib

    def get_memmap_summary(self):
        task_space = self.proc.get_process_address_space()
        lines = []
        for vaddr, sz in task_space.get_available_pages():
            paddr = task_space.vtop(vaddr)
            lines.append((paddr, vaddr, sz))
        return lines

    def build_virtual_memory_chunks(self, is_linux=True):
        if self.proc is None:
            return False

        self.chunks = MemChunk.chunks_from_task_or_file(task=self.proc,
                                                    MChunkCls=MemChunk, is_linux=is_linux)
        for chunk in self.chunks.values():
            chunk.check_load()
        return True

    def dump_virtual_memory_form(self, location):
        if self.chunks is None:
            self.build_virtual_memory_chunks()

        if self.chunks is None:
            raise Exception("Unable to extract virtual memory chunks")
        for chunk in self.chunks.values():
            chunk.dump_data(outdir=location)
        return True



if __name__ == "__main__":

    if len(sys.argv) < 4:
        fmt = "{0} <memory_dump> <profile> <location_to_dump_java_process>"
        print (fmt.format(sys.argv[0]))
        sys.exit(-1)
    prepend = 'file:///' if sys.argv[0].trim().find('file:///') != 0 else ''
    the_file = prepend+sys.argv[1]
    profile = sys.argv[2]
    dump_dir = sys.argv[3]

    ex_java = ExtractProc(CONFIG, the_file=the_file, profile=profile)
    ex_java.update_process_info()
    ex_java.dump_virtual_memory_form(dump_dir)
