import operator
import pefile, struct
from elftools.elf.elffile import ELFFile


class StringResolver(object):
    STATIC_TARGET_TYPES = [
        ['Universe', '_main_thread_group', 'oop',],
        ['Universe', '_system_thread_group', 'oop',],
        ['Universe', '_the_empty_class_klass_array', 'objArrayOop',],
        ['Universe', '_the_null_string', 'oop',],
        ['Universe', '_the_min_jint_string', 'oop',],
        ['Universe', '_throw_illegal_access_error', 'Method*',],
        ['Universe', '_bootstrapping', 'bool',],
        ['Universe', '_fully_initialized', 'bool',],
        ['Universe', '_byte_mirror', 'oop',],
        ['Universe', '_int_mirror', 'oop',],
        ['Universe', '_double_mirror', 'oop',],
        ['Universe', '_float_mirror', 'oop',],
        ['Universe', '_char_mirror', 'oop',],
        ['Universe', '_long_mirror', 'oop',],
        ['Universe', '_short_mirror', 'oop',],
        ['Universe', '_collectedHeap', 'CollectedHeap*',],
        ["Universe", "_boolArrayKlassObj","Klass*",],
        ["Universe", "_byteArrayKlassObj","Klass*",],
        ["Universe", "_charArrayKlassObj","Klass*",],
        ["Universe", "_intArrayKlassObj","Klass*",],
        ["Universe", "_shortArrayKlassObj","Klass*",],
        ['SharedHeap', '_sh', 'SharedHeap*',],
        ['SystemDictionary', '_placeholders', 'PlaceholderTable*',],
        ['SystemDictionary', '_dictionary', 'Dictionary*',],
        ['SystemDictionary', '_shared_dictionary', 'Dictionary*',],
        ['SystemDictionary', '_loader_constraints', 'LoaderConstraintTable*',],
        ['SharedRuntime', 'RuntimeStub*', '_wrong_method_blob',],
        ['SharedRuntime', 'RuntimeStub*', '_ic_miss_blob',],
        ['SharedRuntime', 'RuntimeStub*', '_resolve_opt_virtual_call_blob',],
        ['SharedRuntime', 'RuntimeStub*', '_resolve_virtual_call_blob',],
        ['SharedRuntime', 'RuntimeStub*', '_resolve_static_call_blob',],
        ['SharedRuntime', 'DeoptimizationBlob*', '_deopt_blob',],
        ['SharedRuntime', 'RicochetBlob*', '_ricochet_blob',],
        ['SharedRuntime', 'SafepointBlob*', '_polling_page_safepoint_handler_blob',],
        ['SharedRuntime', 'SafepointBlob*', '_polling_page_return_handler_blob',],
        ['SymbolTable', '_the_table', 'SymbolTable*',],
        ['StringTable', '_the_table', 'StringTable*',],
        ['Threads',  '_thread_list', 'JavaThread*',],
        ['Threads', '_number_of_threads', 'int',],
        ['Threads', '_number_of_non_daemon_threads', 'int',],
        ['Threads', '_return_code', 'int',],
        ]

    @classmethod
    def get_static_types(cls):
        return cls.STATIC_TARGET_TYPES

    def __init__ (self, string_by_addr, string_locs,
                  string_data, string_refs, sections_by_name):
        self.string_by_addr = string_by_addr
        self.string_locs =  string_locs
        self.string_data = string_data
        self.string_refs = string_refs
        self.string_by_addr = self.string_by_addr
        self.sections_by_name = sections_by_name

    def get_addrs_for_str (self, string):
        addrs = []
        if string in self.string_locs:
            for addr in self.string_locs[string]:
                addrs.append(addr[0])
        return addrs

    def has_string (self, string):
        return string in self.string_locs

    def has_string_addr(self, addr):
        return addr in self.string_by_addr

    def get_string_by_addr(self, addr):
        return self.string_by_addr[addr] if self.has_string_addr(addr) \
               else None

    def has_string_ref(self, addr):
        return addr in self.string_refs

    def get_string_refs(self, addr):
        return self.string_refs[addr]

    def find_section_by_addr(self, addr):
        for v in self.sections_by_name.values():
            if v['start'] <= addr and addr <= v['end']:
                return v
        return None

    @classmethod
    def from_pefile(cls, filename):
        pef = pefile.PE(filename)
        sections_by_name = StringResolver.get_sections_by_name_pefile(pef)

        string_by_addr, string_locs, string_data = \
                StringResolver.get_strings_locs(sections_by_name['.rdata'])
        data_section = sections_by_name['.data']
        string_refs, _ = StringResolver.get_strings_refs(data_section['fdata'], \
                                       data_section['start'], string_by_addr)

        return StringResolver(string_by_addr, string_locs,
                      string_data, string_refs, sections_by_name)

    @classmethod
    def from_elffile(cls, filename):
        elffile = ELFFile(open(filename, 'rb'))
        sections_by_name = StringResolver.get_sections_by_name_elffile(elffile)

        string_by_addr, string_locs, string_data = \
                StringResolver.get_strings_locs(sections_by_name['.rodata'])
        data_section = sections_by_name['.data']
        string_refs, _ = StringResolver.get_strings_refs(data_section['fdata'], \
                                       data_section['start'], string_by_addr)

        return StringResolver(string_by_addr, string_locs,
                      string_data, string_refs, sections_by_name)

    @classmethod
    def get_sections_by_name_elffile(cls, elf_file):
        image_base = 0
        sections_by_name = {}
        sections = [i for i in elf_file.iter_sections()]
        for section in sections:
            info = {}
            data = section.data()
            info['elf_file'] = elf_file
            info['base'] = image_base
            info['start'] = image_base + section.header.sh_addr
            info['fdata'] = data
            info['fsize'] = len(data)
            info['end'] = len(data) + info['start']
            info['name'] = section.name.strip('\x00')
            info['section'] = section
            sections_by_name[info['name']] = info
        return sections_by_name

    @classmethod
    def get_sections_by_name_pefile(cls, pe_file):
        image_base = pe_file.OPTIONAL_HEADER.ImageBase
        sections_by_name = {}
        sections = [i for i in pe_file.sections]
        for section in sections:
            info = {}
            data = section.get_data()
            info['pe_file'] = pe_file
            info['base'] = image_base
            info['start'] = image_base + section.VirtualAddress
            info['fdata'] = data
            info['fsize'] = len(data)
            info['end'] = len(data) + info['start']
            info['name'] = section.Name.strip('\x00')
            info['section'] = section
            sections_by_name[info['name']] = info
        return sections_by_name

    @classmethod
    def get_strings_locs(cls, section):
        string_data = []
        string_locs = {}
        string_by_addr = {}
        data = section['fdata']
        strings = [ i.strip('\x00') for i in data.split('\x00')\
                    if len(i) > 2 and (i.lower()[1].isalpha() or  i[0] == '_')]
        off_ = 0
        base = section['start']
        for string_ in strings:
            off_ = data.find(string_, off_)
            str_pos = 0
            end = len(string_) - 2
            while str_pos < end:
                string = string_[str_pos:]
                off = str_pos+off_
                if not string in string_locs:
                    string_locs[string] = []
                info = {}
                info['data'] = string

                info['start'] = off+base
                info['offset'] = off
                string_by_addr[off+base] = string
                string_locs[string].append((off+base, off))
                string_data.append(info)
                str_pos += 1

        return string_by_addr, string_locs, string_data

    @classmethod
    def get_strings_refs(cls, fdata, base, string_by_addr, word_sz = 4, lendian=True):
        fmt = "<"
        if not lendian:
            fmt = ">"
        if word_sz == 4:
            fmt = fmt + 'I'
        else:
            fmt = fmt + 'Q'

        map_addr_bytes = {}
        for addr in string_by_addr.keys():
            b = struct.pack(fmt, addr)
            map_addr_bytes[b] = addr

        string_refs = {}
        string_addr = {}
        off = 0
        incr = 4 if word_sz == 4 else 8
        end = len(fdata) - incr
        while off < end:
            b = fdata[off:off+incr]
            if b in map_addr_bytes:
                a = map_addr_bytes[b]
                if not a in string_refs:
                    string_refs[a] = []
                string_refs[a].append(off+base)
                string_addr[off+base] = a
            off+= incr
        return string_refs, string_addr

    def has_addr (self, addr):
        return addr in self.string_by_addr



class FindStructsFromLib(object):
    def __init__(self, string_resolver, target_structs=None, word_sz=4):
        '''
        target_structs is a dictionary that needs to contain all the
        field names for a given struct under "field_names" key and
        all the field sizes for the entries the latter is not necessary
        to find the candidates
        '''
        self.string_resolver = string_resolver
        self.word_sz = word_sz
        self.string_refs = {}
        self.string_addrs = {}
        self.candidates = {}
        self.candidates_sz = {}
        self.query_list = set()
        self.field_name_lists = []
        self.field_sizes = []
        self.flattened_references = {}
        self.candidate_pool = None
        self.candidate_pool_sz = None
        self.matching_fn = None
        self.matching_fn_kargs = None
        self.matches = None
        if not target_structs is None:
            self.set_target_structs(target_structs)

    def update_candidate_pool(self):
        # check that all candidate struct fields are present in
        # the string references
        self.candidate_pool = []
        self.candidate_pool_sz = []
        sz = len(self.field_name_lists)
        pos = 0
        while pos < sz:
            field_name_list = self.field_name_lists[pos]
            has_them = sum([1 for name in field_name_list if name in self.string_refs])
            if has_them == len(field_name_list):
                self.candidate_pool.append(field_name_list)
                self.candidate_pool_sz.append(self.field_sizes[pos])
            pos += 1
        return self.candidate_pool

    def set_matching_fn_kargs (self, kargs_dict):
        self.matching_fn_kargs = kargs_dict

    def set_matching_fn(self, filter_closure, kargs_dict={}):
        # filter closure takes a 1) ordered starting from the first struct
        # list of address and 2) list of sizes
        # the kargs are static criteria (unless it contains a closure
        # to update the kargs)
        # the function must return bool indicating it meets the criteria
        self.matching_fn = filter_closure
        self.matching_fn_kargs = kargs_dict

    @staticmethod
    def default_matching_fn (candidate_addrs, candidate_sizes, **kargs):
        # use end to end distance, should be positive
        word_sz = kargs.get("word_sz", 4)
        dist = sum(candidate_sizes)/word_sz
        # now calculate the distance to the end
        adist = 0
        addrs = [i/word_sz for i in candidate_addrs]
        base_addr = addrs[0]
        for addr in addrs[1:]:
            # must be a positive distance
            if (addr-base_addr) < 0:
                return False
            adist += (addr-base_addr)
        #print ("Called with: %s and dist = %d"%(" ".join([hex(i) for i in candidate_addrs]), adist) )
        return dist == adist

    def apply_matching_fn (self):
        if self.matching_fn is None:
            self.set_matching_fn(self.default_matching_fn, {"word_sz":self.word_sz})

        self.matches = {}
        for candidate, saddrs_list in self.candidates.items():
            self.matches[candidate] = []
            fld_sz_list = self.candidates_sz[candidate]
            for saddrs in saddrs_list:
                if self.matching_fn (saddrs, fld_sz_list):
                    self.matches[candidate].append(saddrs)
            if len(self.matches[candidate]) == 0:
                del self.matches[candidate]
        return self.matches

    def set_target_structs_from_ptr_list (self, field_name_lists):
        target_struct = {}
        target_struct['field_names'] = field_name_lists
        field_sizes = []
        for fields in field_name_lists:
            sizes = [self.word_sz for i in fields]
            field_sizes.append(sizes)
        target_struct['field_sizes'] = field_sizes
        self.set_target_structs(target_struct)

    def set_target_structs (self, target_structs):
        self.string_refs = {}
        self.string_addrs = {}
        self.candidates = {}
        self.candidates_sz = {}
        self.candidate_pool = []
        self.candidate_pool_sz = []
        self.flattened_references = {}
        self.field_name_lists = target_structs['field_names']
        if 'field_sizes' in target_structs:
            self.field_sizes = target_structs['field_sizes']
        else:
            self.field_sizes = []
            for fields in self.field_name_lists:
                sizes = [self.word_sz for i in fields]
                self.field_sizes.append(sizes)

        self.query_list = set()
        for field_list in self.field_name_lists:
            self.query_list |= set(field_list)

    def create_bf_candidates (self):
        if self.field_name_lists == None or\
           len(self.field_name_lists) == 0:
            return None
        d = self.get_string_addresses()
        d = self.get_string_references()
        d = self.update_candidate_pool()
        d = self.flatten_string_references()
        d = self.build_candidates()
        # final step remove any fields
        # that do not fit exactly
        # make max distance type size
        return self.apply_matching_fn()

    def get_string_addresses (self):
        for i in self.query_list:
            #addrs = self.string_locs[i] if i in self.string_locs else
            #print i,self.string_resolver.has_string(i)
            addrs = self.string_resolver.get_addrs_for_str(i)
            if len(addrs) > 0:
                self.string_addrs[i] = [long(j) for j in addrs]
        return self.string_addrs

    def get_string_references(self):
        for name, addrs in self.string_addrs.items():
            # remove the name if we dont need it later, saves logic
            self.string_refs[name] = {}
            for addr in addrs:
                #print name, hex(addr), self.string_resolver.has_string_ref(addr)
                if self.string_resolver.has_string_ref(addr):
                    sinks_srcs = self.string_resolver.get_string_refs(addr)
                    self.string_refs[name][addr] = [i for i in sinks_srcs]
            if len(self.string_refs[name]) == 0:
                del self.string_refs[name]
        return self.string_refs

    def flatten_string_references (self):
        self.flattened_references = {}
        for name, ref_dict in self.string_refs.items():
            self.flattened_references[name] = set()
            for addr_arry in ref_dict.values():
                self.flattened_references[name] |= set(addr_arry)
        return self.flattened_references

    def build_candidates (self):
        # no string references no candidates
        if len (self.string_refs) == 0:
            if len(self.get_string_references()):
                return None
            else:
                self.get_string_references()
                self.update_candidate_pool()
                self.flatten_string_references()

        pos = 0
        sz = len (self.candidate_pool)
        while pos < sz:
            named_fields = self.candidate_pool[pos]
            candidate_name = "||".join(named_fields)
            bf_field_addrs = self._get_bf_sybmol_struct (named_fields)
            if len (bf_field_addrs) > 0:
                self.candidates[candidate_name] = bf_field_addrs
                self.candidates_sz[candidate_name] = self.candidate_pool_sz[pos]
            pos += 1
        return self.candidates

    def string_references_strs (self):
        res = []
        for key, vals in self.string_refs.items():
            ref_list = [hex(i) for i in vals.keys()]
            for i in ref_list:
                res.append( [ '&"'+key + "' = ", i])
        return res

    def _get_bf_sybmol_struct (self, named_fields):
        # not on Alg.
        # use a while-loop for random access
        # fix point and ends when the last field is reaced
        # the best_fit_structures holds all the possible best pist
        # structures given a starting address for the first field
        # This means if the head has X entries (rows), then all the
        # fields (columns) have X entries (rows) even if they have 1 entry
        # the special case is 0 fields, which we just drop a negative one
        # and use the last fit
        # call a function that finds all min distance to each (current) field
        # address
        named_str_refs = self.flattened_references
        bf_field_addrs = []
        pos = 0
        if len(named_fields) == 0:
            return bf_field_addrs

        head = named_fields[pos]
        caddrs = named_str_refs[head]
        last_good_pos = 0
        # initialize strucuture based on single key address

        for addr in caddrs:
            bf_field_addrs.append([addr,])

        head_addrs_len = len(bf_field_addrs)
        head_fields_len = len(named_fields)
        while pos < head_fields_len-1:
            nfield = named_fields[pos+1]
            naddrs = named_str_refs[nfield]
            bf_naddrs = None
            if len(naddrs) == 0:
                bf_naddrs = [-1 for i in xrange(0, head_addrs_len)]
            else:
                # TODO can be made into a matrix operation just not right noq
                last_good_saddrs = [result_addrs[last_good_pos] for result_addrs in bf_field_addrs]
                bf_naddrs = self._bf_symbol_addrs(last_good_saddrs, naddrs)
                last_good_pos = pos
            u_pos = 0 # updating each struct
            while u_pos < head_addrs_len:
                bf_field_addrs[u_pos].append(bf_naddrs[u_pos])
                u_pos += 1
            pos += 1
        return bf_field_addrs

    def _bf_symbol_addrs (self, saddrs, naddrs):
        res = []
        for saddr in saddrs:
            bf = self._best_fit_min(saddr, naddrs)
            res.append(bf)
        return res

    def _best_fit_min (self, saddr, naddrs):
        try:
            import operator
        except:
            pass
        #print naddrs
        if type(naddrs) != list:
            naddrs = list(naddrs)
        #print naddrs
        values = [abs(x - saddr) for x in naddrs]
        min_index, min_value = min(enumerate(values), key=operator.itemgetter(1))
        return naddrs[min_index]
