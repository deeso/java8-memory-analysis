import sys, os
import pefile, struct
from findstructs_lib import FindStructsFromLib,StringResolver
from jvm_objects import VMStructEntry
from elftools.elf.elffile import ELFFile

class ExtractJVMEntrys(object):
    def __init__(self, string_resolver, word_sz =4, lendian=True, os_ver=""):
        self.string_resolver = string_resolver
        self.os_ver = os_ver
        self.STATIC_TARGET_TYPES = self.string_resolver.STATIC_TARGET_TYPES
        self.fstructs = FindStructsFromLib(self.string_resolver, None)
        self.fstructs.set_target_structs_from_ptr_list(self.STATIC_TARGET_TYPES)
        self.data = self.string_resolver.sections_by_name['.data']['fdata']
        self.start = self.string_resolver.sections_by_name['.data']['start']
        self.vmstructentrys = {}
        self.find_symbols()

    def find_symbols (self):
        # field_name_lists = self.STATIC_TARGET_TYPES
        #
        # field_sizes = []
        # for fields in field_name_lists:
        #     sizes = [self.word_sz for i in fields]
        #     field_sizes.append(sizes)
        #
        # target_structs = {}
        # target_structs['field_sizes'] = field_sizes
        # target_structs['field_names'] = field_name_lists
        self.struct_groupings = self.fstructs.create_bf_candidates()
        return self.struct_groupings

    def group_closest_symbols (self):
        # perform kmeans
        all_symbols = {}
        mapped_1_dim = {}
        all_symbols = {}
        mapped_1_dim = []
        for sym, saddrs in self.struct_groupings.items():
            pos = 0
            for saddr in saddrs:
                mapped_val = (sum(saddr)/len(saddr))/self.word_sz
                all_symbols[sym+"::%d"%pos] = saddr
                mapped_1_dim.append([sym+"::%d"%pos, mapped_val])
                pos += 1
        # do kmeans here

        # calculate min mapped_val for each group
        # start from the min and read out each symbol
        #  OK doing cool machine learning tricks would be
        #  fun, but lets speed this up a little going to
        # just check all groups

    def print_enumerated_symbols(self, static_only=False, no_static=False):
        s_keys = set()
        if not no_static:
            s_keys |= set([s_key for s_key in self.vmstructentrys \
                           if self.vmstructentrys[s_key].isStatic == 1])
        if not static_only:
            s_keys |= set([s_key for s_key in self.vmstructentrys \
            if self.vmstructentrys[s_key].isStatic == 0])

        s_keys = list(s_keys)
        s_keys.sort()

        for s_key in s_keys:
            if self.vmstructentrys[s_key].isStatic:
                print hex(s_key), str(self.vmstructentrys[s_key])

    def get_sym_dictionary(self, ver=''):
        fmt = self.os_ver + ":%s::%s:%s"
        pe_base = self.string_resolver.sections_by_name['.data']['base']
        values = {}
        for off, sym in self.vmstructentrys.items():
            if sym.isStatic and len(sym.typeName_str) > 0 and\
                len(sym.fieldName_str) > 0:
                tN = sym.typeName_str
                fN = sym.fieldName_str
                address = sym.address
                s = fmt%(tN, fN, ver)
                values[s] = address-pe_base
        return values

    def enumerate_sym_entrys (self):
        addrs = set()
        t = None
        for name, addr_grps in self.struct_groupings.items():
            if name.find("_mark")==0:
                continue
            for addr_grp in addr_grps:
                addrs.add(addr_grp[0])
        for addr in addrs:
            if not addr in self.vmstructentrys:
                t = self.enumerate_sym_entrys_addr_anchor(addr)
        return t

    def update_entry(self, entry):
        v = entry
        typeString = v.typeString_addr
        typeName = v.typeName_addr
        fieldName = v.fieldName_addr
        typeString_str = self.string_resolver.get_string_by_addr(typeString)
        typeName_str = self.string_resolver.get_string_by_addr(typeName)
        fieldName_str = self.string_resolver.get_string_by_addr(fieldName)

        if typeString_str:
            setattr(v, 'typeString_str', typeString_str)
        if typeName_str:
            setattr(v, 'typeName_str', typeName_str)
        if fieldName_str:
            setattr(v, 'fieldName_str', fieldName_str)

    def enumerate_sym_entrys_addr_anchor (self, addr):
        t = self.enumerate_entrys_fwd_from_addr(addr)
        t = self.enumerate_entrys_bwd_from_addr(addr)

        # cleaning up the symbols here
        for k, v in self.vmstructentrys.items():
            clean = str(v).strip()
            #if len(clean) == 0 or clean == "::":
            #    del self.vmstructentrys[k]
        return t

    def enumerate_entrys_fwd_from_addr (self, addr, range_=None):
        o = addr - self.start
        start = self.start
        sz = VMStructEntry.size32
        #print hex(addr), hex(o), sz
        while True:
            entry = None
            loc = o+start
            _bytes = self.data[o:o+sz]
            #print sz, len(_bytes)
            entry = VMStructEntry.from_bytes(loc, _bytes, None)
            if entry:
                self.update_entry(entry)
            o += entry.size()
            #symbols.append(sym)
            self.vmstructentrys[loc] = entry
            if entry.fieldName_addr == 0:
                break
            if len(entry.typeName_str) == 0 and \
               len(entry.fieldName_str) == 0 and \
               len(entry.typeString_str) == 0:
                break
            elif entry.fieldName_str == "" and \
                entry.typeName_str == "" and \
                entry.typeString_str == "":
                break
        return self.vmstructentrys

    def enumerate_entrys_bwd_from_addr (self, addr, range_=None):
        o = addr - self.start
        start = self.start
        sz = VMStructEntry.size32
        #print hex(addr), hex(o), sz
        while True:
            entry = None
            loc = o+start
            _bytes = self.data[o:o+sz]
            entry = VMStructEntry.from_bytes(loc, _bytes, None)
            if entry is None:
                break

            self.update_entry(entry)
            o -= entry.size()
            #symbols.append(sym)
            self.vmstructentrys[loc] = entry
            if entry.fieldName_str.find("_mark") == 0:
                break
            elif entry.fieldName_str == "" and \
                entry.typeName_str == "" and \
                entry.typeString_str == "":
                break
        return self.vmstructentrys


class ExtractDLLJVMEntrys(ExtractJVMEntrys):
    def __init__(self, filename, word_sz =4, lendian=True):
        string_resolver = StringResolver.from_pefile(filename)
        ExtractJVMEntrys.__init__(self, string_resolver,
                    word_sz , lendian, os_ver="win")

class ExtractELFJVMEntrys(ExtractJVMEntrys):
    def __init__(self, filename, word_sz =4, lendian=True):
        string_resolver = StringResolver.from_elffile(filename)
        ExtractJVMEntrys.__init__(self, string_resolver,
                                 word_sz , lendian, os_ver="lin")
