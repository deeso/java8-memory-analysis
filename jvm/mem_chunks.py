#Copyright 2015 Adam Pridgen
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

import sys,copy
from mem_range import Range
try:
    import volatility.utils as utils
except Exception:
    # only required if in volatility env
    pass

class MemChunk(object):
    def __init__(self, vaddr_base, sz, os_type = None, paddr=None,
                    task = None, raw_img = None):
        self.task = task
        self.made_from_task = True if task else False
        self.raw_img = raw_img
        self.vaddr_base = vaddr_base
        self.size = sz
        self.filename = None
        self.basedir = None
        self.memmap = {}
        self.memmap[vaddr_base] = {"vaddr":vaddr_base,
                                   "size":sz, "paddr":paddr, "data":None}
        self.have_read_data = False
        self.filename = None
        self.os = "linux" if os_type == None else os_type
        self.libjvm = None
        self.strings_bystr = {}
        self.strings_byaddr = {}
        self.chunk_data = None
        self.paddr = None

    def __getstate__(self):
        odict = copy.deepcopy(self.__dict__)
        return odict

    def __setstate__(self, _dict):
        self.__dict__.update(_dict)

    def get_string_addrs (self, string):
        if self.has_string(string):
            return self.strings_bystr[string]
        return []

    def get_string_at_addr (self, addr):
        if self.has_string_addr(addr):
            return self.strings_byaddr[addr]
        return None

    def add_string (self, addr, string):
        self.strings_byaddr[addr] = string
        if not string in self.strings_bystr:
            self.strings_bystr[string] = set()
        self.strings_bystr[string].append(addr)

    def has_string (self, string):
        return string in self.strings_bystr

    def has_string_addr (self, addr):
        return addr in self.strings_byaddr

    def read_at_addr (self, addr, sz = 1):
        return self.read (addr - self.vaddr_base, sz)

    def read (self, off, sz = 1):
        if off < self.size and self.have_read_data:
            return self.have_read_data[off:off+sz]
        return None

    def check_load (self):
        if not self.task is None:
            self.extract_chunk_from_vol()
            if self.have_read_data is None:
                raise BaseException("Failed to read the chunk")
            return True
        elif not self.raw_img is None:
            self.extract_chunk_from_raw()
            if self.have_read_data is None:
                raise BaseException("Failed to read the chunk")
            return True
        return False


    def find_all (self, target, shared_dict={}, cb_cls=None):
        pos = 0
        res = []
        self.check_load()
        while pos < self.size:
            pos = self.chunk_data.find(target)
            if pos == -1:
                break
            res.append (self.vaddr_base+pos)
        if not cb_cls is None:
            cb_cls.handle_search_results (target=target, shared_dict=shared_dict, results=res)
        return res

    def add_map (self, vaddr_base, sz, paddr=None, data=None):
        if vaddr_base in self.memmap:
            if sz > self.memmap[vaddr_base]['size']:
                sz_diff = sz - self.memmap[vaddr_base]['size']
                self.size += sz_diff
                self.memmap[vaddr_base]['size'] = sz
            return
        elif vaddr_base in self.memmap:
            print "Unexpected second occurrence of virtual address: 0x%08x"%(vaddr_base)
            return
        self.memmap[vaddr_base] = {"vaddr":vaddr_base, "size":sz, "paddr":paddr, "data":data}
        self.size += sz
        return

    def in_range (self, addr):
        return self.vaddr_base < addr and addr <= self.vaddr_base+self.size

    def is_vcontiguous (self, vaddr_base):
        return self.is_contiguous (vaddr_base)

    def is_contiguous (self, vaddr):
        return vaddr == self.vaddr_base+self.size

    def get_sorted_vaddrs (self):
        res = self.memmap.keys()
        res.sort()
        return res

    def read_pdata (self, addr, len_):
        v_space = self.task.get_process_address_space()
        pspace = utils.load_as(v_space.get_config(), astype = 'physical')
        data = pspace.read(addr, len_)
        return data

    def read_vdata (self, addr, len_):
        v_space = self.task.get_process_address_space()
        data = v_space.read(addr, len_)
        return data

    def read_data_to (self, saddr, eaddr):
        return self.read_vdata (saddr, eaddr- saddr)

    def set_chunk_data (self):
        self.chunk_data = ''
        vaddrs = self.memmap.keys()
        vaddrs.sort()
        datas = []
        for vaddr in vaddrs:
            sz = self.memmap[vaddr]['size']
            data = self.memmap[vaddr]['data']
            dlen = len(data)
            if dlen != sz:
                print ("Vaddr: 0x%08x len(data)=0x%04x != 0x%04x"%(vaddr, dlen, sz))
            #self.chunk_data = self.chunk_data + data
            datas.append(data)
        self.chunk_data = "".join(datas)

    def extract_chunk_from_vol (self):
        for info in self.memmap.values():
            addr = info['vaddr']
            sz = info['size']
            data = info['data']
            if data is None:
                data = self.read_vdata (addr, sz)
                if data is None:
                    # try reading from the physical offset
                    data = self.read_pdata(addr, sz)
                self.memmap[addr]['data'] = data
        self.set_chunk_data()
        self.have_read_data = True

    def extract_chunk_from_raw (self):
        # need to read each phys offset to build chunk
        raw_infile = open(self.raw_img, 'rb')
        for memmap in self.memmap.values():
            paddr = memmap['paddr']
            sz = memmap['size']
            data = None
            if paddr is None:
                data = '\x00'*sz
            else:
                raw_infile.seek(paddr)
                data = raw_infile.read(sz)
            memmap['data'] = data
        self.have_read_data = True
        self.set_chunk_data()

    def summary (self):
        if self.paddr is None:
            fmt = "Vaddr Start: 0x%08x Vaddr End: 0x%08x Size: 0x%08x Maps: %d"
            s = fmt%(self.vaddr_base, self.vaddr_base+self.size, self.size, len (self.memmap))
        else:
            fmt = "Vaddr Start: 0x%08x Vaddr End: 0x%08x Size: 0x%08x Maps: %d Paddr Start: 0x%08x"
            s = fmt%(self.vaddr_base, self.vaddr_base+self.size, self.size, len (self.memmap), self.paddr)
        return s


    def get_default_filename (self):
        return "0x%08x-0x%08x.bin"%(self.vaddr_base, self.vaddr_base+self.size)

    def get_default_basedir (self):
        return "0x%08x-0x%08x.bin"%(self.vaddr_base, self.vaddr_base+self.size)

    def dump_data (self, out_filename=None, outdir=None):
        import os
        self.filename = out_filename if not out_filename is None else self.filename
        self.basedir = outdir if not outdir is None else self.get_default_basedir()
        if self.filename is None:
            try:
                os.stat (self.basedir)
            except OSError:
                os.mkdir (self.basedir)
            self.filename = os.path.join (self.basedir, self.get_default_basedir())
        #print ("Writing data to: %s"%self.filename)
        foutput = open (self.filename, 'wb')
        self.check_load()
        foutput.write(self.chunk_data)
        foutput.close()

    @staticmethod
    def get_data_from_task(task, paddr, vaddr, sz):
        v_space = task.get_process_address_space()
        data = v_space.read(vaddr, sz)
        if data is None:
            # try reading from the physical offset
            pspace = utils.load_as(v_space.get_config(), astype = 'physical')
            data = pspace.read(paddr, sz)
        return data

    @staticmethod
    def get_data_from_file(raw_infile, paddr, sz):
        # need to read each phys offset to build chunk
        data = None
        raw_infile.seek(paddr)
        data = raw_infile.read(sz)
        return data

    @staticmethod
    def get_memmap_task(task, MChunkCls):

        task_space = task.get_process_address_space()
        memmap = {}
        for vaddr, sz in task_space.get_available_pages():
            paddr = task_space.vtop(vaddr)
            data = MChunkCls.get_data_from_task(task, paddr, vaddr, sz) if paddr != 0 else None
            dlen = len(data) if not data is None else 0
            if not data is None and dlen == sz:
                memmap[vaddr] = {"vaddr":vaddr, "size":sz, "paddr":paddr, "data":data}
            elif data and dlen != sz:
                print ("Vaddr: 0x%08x len(data)=0x%04x != 0x%04x"%(vaddr, dlen, sz))
        #maps = [(Address(m.vm_start), Address(m.vm_end - m.vm_start) )for m in task.get_proc_maps()]
        #print ("Number of maps %d"%(len(maps)))
        return memmap

    @staticmethod
    def get_memmap_file_linux(memmap_filename, raw_img_file):
        raw_infile = open(raw_img_file, 'rb')
        data = open (memmap_filename).read().split("\n")
        to_int = lambda x: long (x, 16)

        memmap = {}
        for d in data[1:]:
            p = d.split()
            #print p
            if len (p) != 5: break
            vaddr, paddr, sz = d.split ()[2:5]
            vaddr = to_int(vaddr)
            paddr = to_int(paddr)
            sz = to_int(sz)
            #print vaddr, paddr, sz
            data = MemChunk.get_data_from_file(raw_infile, paddr, sz)
            dlen = len(data) if not data is None else 0
            if not data is None and dlen == sz:
                memmap[vaddr] = {"vaddr":vaddr, "size":sz, "paddr":paddr, "data":data}
            elif data and dlen != sz:
                print ("Vaddr: 0x%08x len(data)=0x%04x != 0x%04x"%(vaddr, dlen, sz))
        return memmap

    @staticmethod
    def get_memmap_file_windows(memmap_filename, raw_img_file):
        raw_infile = open(raw_img_file, 'rb')
        data = open (memmap_filename).read().split("\n")
        to_int = lambda x: long (x, 16)

        memmap = {}
        # double check this value
        for d in data[3:]:
            p = d.split()
            #print p
            if len (p) != 4: break
            vaddr, paddr, sz, _ = d.split ()
            vaddr = to_int(vaddr)
            paddr = to_int(paddr)
            sz = to_int(sz)
            data = MemChunk.get_data_from_file(raw_infile, paddr, sz)
            dlen = len(data) if not data is None else 0
            if not data is None and dlen == sz:
                memmap[vaddr] = {"vaddr":vaddr, "size":sz, "paddr":paddr, "data":data}
            elif data and dlen != sz:
                print ("Vaddr: 0x%08x len(data)=0x%04x != 0x%04x"%(vaddr, dlen, sz))
        return memmap

    def __getstate__(self):
        odict = self.__dict__.copy()
        if "task" in odict:
            del odict['task']
        return odict

    @staticmethod
    def chunks_from_task_or_file (task=None, MChunkCls=None,
                          memmap_filename=None,
                          raw_img_file=None,
                          is_linux=True):
        memmap = {}
        if task and MChunkCls:
            memmap = MChunkCls.get_memmap_task(task, MChunkCls)
        elif memmap_filename and raw_img_file and is_linux:
            memmap = MemChunk.get_memmap_file_linux(memmap_filename, raw_img_file)
        elif memmap_filename and raw_img_file and not is_linux:
            memmap = MemChunk.get_memmap_file_windows(memmap_filename, raw_img_file)
        else:
            return None

        sorted_addrs = [ i for i in memmap.keys()]
        sorted_addrs.sort()
        memmap_chunks = {}
        #i = 0
        last_chunk = None
        for vaddr_base in sorted_addrs:
            sz = memmap[vaddr_base]["size"]
            paddr = memmap[vaddr_base].get("paddr", None)
            data = memmap[vaddr_base].get("data", None)
            if not last_chunk is None and \
                    last_chunk.is_contiguous (vaddr_base):
                last_chunk.add_map (vaddr_base, sz, paddr=paddr, data=data)
            else:
                mchunk = None
                if task and MChunkCls:
                    mchunk = MChunkCls (vaddr_base, sz, task=task)
                elif memmap_filename and raw_img_file:
                    mchunk = MemChunk (vaddr_base, sz, raw_img=raw_img_file,
                                       paddr=paddr)
                else:
                    raise BaseException("Bug in this one there is: should not reach her")
                last_chunk = mchunk
                memmap_chunks[vaddr_base] = mchunk

        # sorted_chunkaddrs = memmap_chunks.keys()
        # sorted_chunkaddrs.sort()
        #for sorted_chunkaddr in sorted_chunkaddrs:
        #    chunk = memmap_chunks[sorted_chunkaddr]
        #    print chunk.summary()
        return memmap_chunks

    @staticmethod
    def chunks_from_pointer_list (pointer_list, MChunkCls=None,
                          page_size=4096, page_mask = 0xfffff000):

        pages = [pointer&page_mask for pointer in pointer_list]
        pages = [i for i in set(pages)]
        pages.sort()

        pages = list(set([pointer&page_mask for pointer in pointer_list]))
        pages.sort()
        memmap_chunks = {}
        last_chunk = None
        for vaddr_base in pages:
            sz = page_size
            paddr = None
            data = None
            if not last_chunk is None and \
                    last_chunk.is_contiguous (vaddr_base):
                last_chunk.add_map (vaddr_base, sz)
            else:
                mchunk = None
                if MChunkCls:
                    mchunk = MChunkCls (vaddr_base, sz)
                else:
                    mchunk = MemChunk (vaddr_base, sz)
                last_chunk = mchunk
                memmap_chunks[vaddr_base] = mchunk

        return memmap_chunks

    def produce_memrange(self):
        self.check_load()
        self.filename = self.get_default_filename() if self.filename is None \
                        else self.filename

        self.basedir = self.get_default_basedir() if self.basedir is None \
                        else self.basedir

        r = Range(self.vaddr_base, self.vaddr_base+self.size, self.filename,
                        base_dir = self.basedir, load_data=False, data = self.have_read_data)
        return r

if __name__ == "__main__":

    if len(sys.argv) < 4:
        print ("%s <memmap_file> <rawimg> <dir_to_dump_to>"%(sys.argv[0]))
        print ("Generate memmap file with vol:\n"+\
             "python vol.py --profile=LinuxUbuntu1404x86 -f <rawimg> \\"+\
             " linux_memmap -p <pid> > <memmap_file>")

    memfile = sys.argv[1]
    rawimg = sys.argv[2]
    dumpdir = sys.argv[3]
    print ("Preparing the chunks")
    chunks = MemChunk.chunks_from_task_or_file(memmap_filename=memfile,
                                                     raw_img_file=rawimg)
    print ("Dumping the chunks")
    for chunk in chunks.values():
        chunk.dump_data(outdir=dumpdir)

    print ("Done")



