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

import os,struct, copy
import numpy as np

def dump_r2_loader(ranges, r2_loader_script):
    import os
    r2_loader_out = open (r2_loader_script, 'w')
    _ranges = {}

    for r in ranges:
        if r.fsize == 0:
            continue
        _ranges[r.start] = r

    sorted_ranges = _ranges.keys()
    mapped_load_fmt = "on %s 0x%08x"
    for addr in sorted_ranges:
        filename = _ranges[addr].filename
        base_dir = _ranges[addr].base_dir
        filename = os.path.join(base_dir, filename)
        # dump chunks
        load_str = mapped_load_fmt% (filename, addr)
        r2_loader_out.write (load_str+'\n')

def in_ranges (addr, ranges, range_ = None):
    if not range_ is None and range_.in_range(addr):
        return range_

    for r in ranges:
        if r.in_range(addr):
            return r
    return None

def produce_ranges(dumps_dir):
    ranges = [i for i in os.listdir(dumps_dir) if i.find(".bin") > -1 and i.find("-") > -1]
    ranges_values = []
    for r in ranges:
        range_ = r.split(".bin")[0]
        start = long(range_.split('-')[0], 16)
        end = long(range_.split('-')[1], 16)
        d = Range (start, end, r, dumps_dir, load_data=True)
        ranges_values.append(d)
    return ranges_values

def find_value_range (value, ranges):
    for i in ranges:
        if (i.in_range(value)):
            return i
    return None


class Range (object):
    def __init__ (self, start, end, filename,
                    base_dir = None, load_data=False,
                    data = None, word_sz = 4):
        self.word_sz = word_sz
        self.start = start
        self.end = end
        self.filename = filename
        self.base_dir = base_dir
        #self.fhandle = open(os.path.join(base_dir, filename), "rb")
        self.fdata = None
        self.fsize = 0
        if load_data:
            self.fdata = open(os.path.join(base_dir, filename), "rb").read()
        elif not data is None:
            self.fdata = data
        if self.fdata:
            self.fsize = len(self.fdata)#self.get_size()
        self.pos = 0

    def get_size(self):
        return self.fsize

    def in_range (self, value):
        return self.start <= value and value <= self.end

    def can_read (self, offset, len_):
        if not self.in_range(self.start+offset):
            return False
        if self.pos+len_ >= (self.end-self.start):
            return False
        return True

    def calc_offset (self, addr):
        if self.in_range(addr):
            return addr - self.start
        return -1

    def __getstate__(self):
        odict = copy.deepcopy(self.__dict__)
        return odict

    def __setstate__(self, _dict):
        self.__dict__.update(_dict)

    def get_pos_as_addr (self):
        return self.start + self.pos

    def get_full_path (self):
        if not self.base_dir is None:
            return os.path.join (self.base_dir, self.filename)
        return self.filename

    def __str__ (self):
        #return "filename: %s start: 0x%08x end: 0x%08x"%(self.filename, self.start, self.end)
        return "0x%08x-0x%08x"%(self.start, self.end)

    def read_at_addr(self, addr, size):
        if not self.in_range(addr):
            return None
        pos = addr - self.start
        return self.read(pos, size)

    def read_dword(self, addr=None, offset=None, littleendian = True):
        if not addr is None:
            return self.read_dword_at_addr(addr, littleendian)
        elif not offset is None:
            return self.read_dword_at_offset(offset, littleendian)
        else:
            return self.read_dword_at_offset(self.pos, littleendian)

    def read_dword_at_addr(self, addr, littleendian=True):
        if not self.in_range(addr):
            return None
        pos = addr - self.start
        return self._read_dword_at_offset(pos, littleendian)

    def _read_dword_at_offset(self, offset, littleendian=True):
        result = self.read(offset, 4, )
        if len(result) != 4:
            return None
        if littleendian:
            return struct.unpack("<I", result)[0]
        else:
            return struct.unpack(">I", result)[0]

    def read_dword_at_offset(self, offset, littleendian=True):
        if not self.in_range(offset+self.start) or\
            (offset != self.pos and not self.seek_to(offset)):
            return None
        return self._read_dword_at_offset(offset, littleendian)

    def read_qword(self, addr=None, offset=None, littleendian = True):
        if not addr is None:
            return self.read_qword_at_addr(addr, littleendian)
        elif not offset is None:
            return self.read_qword_at_offset(offset, littleendian)
        else:
            return self.read_qword_at_offset(self.pos, littleendian)

    def read_qword_at_addr(self, addr, littleendian=True):
        if not self.in_range(addr):
            return None
        pos = addr - self.start
        return self.read_qword_at_offset(pos, littleendian)

    def read_qword_at_offset(self, offset, littleendian=True):

        if not self.in_range(offset+self.start) or\
            (offset != self.pos and not self.seek_to(offset)):
            return None
        result = self.read(offset, 8)
        if littleendian:
            return struct.unpack("<Q", result)[0]
        else:
            return struct.unpack(">Q", result)[0]

    def _read (self, size=1, pos=None):
        if pos is None:
            pos=self.pos
        if size > self.fsize-pos:
            size = self.fsize-pos
        r = self.fdata[pos:pos+size]#self.fhandle.read(size)
        self.pos = pos+len(r)
        return r

    def read (self, pos, sz =1 ):
        return self._read(sz, pos)

    def seek_to (self, offset):
        if not self.in_range(offset+self.start):
            return False
        self.pos = offset
        #self.fhandle.seek(offset)
        return True

    def read_all_as_ndwords_at_addr(self, addr, n_dwords=1, little_endinan=True):
        struct_fmt = "<%dI"%(n_dwords)
        if not self.in_range(addr):
           return []
        elif not (addr-self.start) + n_dwords*4 < self.end:
           return []
        self.seek_to(addr-self.start)
        if not little_endinan:
            struct_fmt = ">%dI"%(n_dwords)
        dwords = struct.unpack(struct_fmt, self.fdata)
        return dwords

    def read_all_as_dword (self, little_endinan=True):
        struct_fmt = "<%dI"%(self.fsize/4)
        if not little_endinan:
            struct_fmt = ">%dI"%(self.fsize/4)
        dwords = struct.unpack(struct_fmt, self.fdata)
        return dwords

    def read_all_as_qword (self, little_endinan=True):
        struct_fmt = "<%dQ"%(self.fsize/4)
        if not little_endinan:
            struct_fmt = ">%dQ"%(self.fsize/4)
        qwords = struct.unpack(struct_fmt, self.fdata)
        return qwords

    def ltrim_data (self, data, chunk_sz, value='\x00', negligible='\xff'):
        result = data.lstrip(value)
        if len(result) > chunk_sz and result[0] == negligible:
            r2 = result.lstrip(negligible)
            r3 = r2.lstrip(value)
            if len(result) - len(r2) < self.word_sz and\
               len(data) - len(r3) > chunk_sz:
               return self.ltrim_data(r3, chunk_sz, value, negligible)

        if len(data) - len(result) < chunk_sz:
            return data
        return result

    def filter_chunks_hack(self, data, filter_values, threshhold=.95 ):
        if len(data) == 0:
            return False
        ords = [ord(i) for i in data]
        counts = np.bincount(ords)
        counts_ = dict([i for i in enumerate(counts) if i[1] > 0])
        k = counts_.keys()[0]
        tot = float(sum([counts_[i] for i in filter_values if i in counts_]))
        v = tot >= 0 and (tot/len(data)) >= threshhold
        if v:
            return True
        return False

    def ltrim_range (self, chunk_sz = 4096):
        pos = 0
        sz_trimmed = 0
        while True:
            incr = self.filter_chunks_hack(self.fdata[pos:pos+chunk_sz], filter_values=set([0x00, 0x11, 0xff]))
            if not incr:
                break
            pos += chunk_sz

        if pos > 0:
            self.fsize = self.fsize-pos
            self.start = self.start+pos
            self.fdata = self.fdata[pos:]
            sz_trimmed = pos
            self.pos = self.start
        return sz_trimmed

    def rtrim_range (self, chunk_sz = 4096):
        start = 0
        pos = 0
        chunk = None
        end = False
        can_trim = True
        sz_trimmed = 0
        while can_trim:
            pos = 0
            chunk = self.fdata[-chunk_sz:]
            if len(chunk) < chunk_sz:
                break
            all_0x00 = sum([1 for i in chunk if i == '\x00']) == chunk_sz
            all_0xff = sum([1 for i in chunk if i == '\xff']) == chunk_sz
            if all_0x00 or all_0xff:
                self.fdata[chunk_sz:]
                self.fsize += (-chunk_sz)
                self.end += (-chunk_sz)
                sz_trimmed += chunk_sz
            else:
                can_trim = False
        return sz_trimmed
