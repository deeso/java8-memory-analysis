import struct
from jvm_klass import Klass

from jvm_overlays import DICTIONARY_BUCKET_TYPE, DICTIONARY_TYPE,\
                         DICTIONARY_ENTRY_TYPE

from jvm_overlays import get_bits32, get_bits64, get_named_array32,\
                         get_named_array64, get_field_types, name_fields,\
                         get_size32, get_size64
MAX_NUM_CLASSES = 100*1000
from jvm_base import BaseOverlay
DICT_ENTRYS = 0
KLASSES_PROCESSED = 0
MIN_DICT_ENTRYS = 50
MAX_DICT_ENTRYS = 0
MAX_NUM_ENTRYS_ALLOWED = 65536
TESTING_FOR_VALID_STRUCT = False
# number of klasses with valid symols
NUM_TO_OBSERVE = 10
# max number of klasses to parse
MAX_ENTRIES_TO_OBSERVE = 10
NUM_OBSERVED = 0


def reset_dict_info():
    global DICT_ENTRYS, MAX_DICT_ENTRYS, KLASSES_PROCESSED
    DICT_ENTRYS = 0
    MAX_DICT_ENTRYS = 0
    KLASSES_PROCESSED = 0

def setup_bruteforce_testing(num_to_observe=10, max_entries_to_observe=10):
    global TESTING_FOR_VALID_STRUCT, NUM_OBSERVED, NUM_TO_OBSERVE, MAX_ENTRIES_TO_OBSERVE
    TESTING_FOR_VALID_STRUCT=True
    NUM_OBSERVED = 0
    NUM_TO_OBSERVE = num_to_observe
    MAX_ENTRIES_TO_OBSERVE = max_entries_to_observe
    reset_dict_info()

def stop_bruteforce_testing():
    global TESTING_FOR_VALID_STRUCT, NUM_OBSERVED, NUM_TO_OBSERVE, MAX_ENTRIES_TO_OBSERVE
    TESTING_FOR_VALID_STRUCT = False

class DictionaryEntry(BaseOverlay):
    _name = "HashTableEntry<Klass*>"
    _overlay = DICTIONARY_ENTRY_TYPE
    bits32 = get_bits32(DICTIONARY_ENTRY_TYPE)
    bits64 = get_bits64(DICTIONARY_ENTRY_TYPE)
    named32 = get_named_array32(DICTIONARY_ENTRY_TYPE)
    named64 = get_named_array64(DICTIONARY_ENTRY_TYPE)
    size32 = get_size32(DICTIONARY_ENTRY_TYPE)
    size64 = get_size64(DICTIONARY_ENTRY_TYPE)
    types = get_field_types(DICTIONARY_ENTRY_TYPE)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__ (self):
        literal = getattr(self, 'literal', -1)
        hash_ = getattr(self, 'hash', -1)
        Klass_value = getattr(self, 'Klass_value', None)
        return (" _hash = 0x%08x Klass@0x%08x->%s "%(hash_, \
            literal, str(Klass_value)))

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self):
        setattr(self, 'updated', True)

    def has_next(self):
        return getattr(self, 'has_next')

    def get_next(self):
        return getattr(self, 'next_value', None)

    def get_value(self):
        return getattr(self, 'Klass_value', None)

    def get_values(self):
        res = []
        entry = getattr(self, 'Klass_value', None)
        if self.has_next:
            next_ = self.get_next()
            if next_:
                res = next_.get_values()
        if entry:
            return res.append(entry)
        return res

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        #if jvm_analysis and jvm_analysis.has_internal_object(addr):
        #    return jvm_analysis.get_internal_object(addr)
        global KLASSES_PROCESSED, MAX_DICT_ENTRYS, NUM_OBSERVED
        #jvm_analysis.log ("Processing a DictionaryEntry")
        nfields = cls.named32 if jvm_analysis.is_32bit else cls.named64
        fmt = cls.bits32 if jvm_analysis.is_32bit else cls.bits64
        data_unpack = struct.unpack(fmt, _bytes)
        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False}
        name_fields(data_unpack, nfields, fields=kargs)
        _next = kargs['next']
        kargs['has_next'] = _next != 0 and \
                            jvm_analysis.is_valid_addr(_next) and\
                            jvm_analysis.read_addr(_next) != 0

        kargs['next_value'] = None
        if kargs['has_next']:
            kargs['next_value'] = DictionaryEntry.from_jva(cls.make_ptr(_next),
                                       jvm_analysis)

        kargs['Klass_value'] = None
        _literal = kargs['literal']
        # doing this as a sanity check all Klasses and Oops happen on 8 byte boundary
        _literal = _literal - 1 if _literal % 8 == 1 else _literal
        if jvm_analysis.is_valid_addr(_literal):
            # TODO determine if this is the appropriate approach (i.e.
            # return none if the Klass does not have a name
            KLASSES_PROCESSED += 1
            klass = Klass.from_jva(_literal, jvm_analysis)
            kargs['Klass_value'] = klass
            klass_name = getattr(klass, 'name_value', None) \
                         if kargs['Klass_value'] else None
            #TODO the brute force testing can be sped up if we stop
            #  reading klasses when the "symbol" length exceeds 1000 or
            # the MAX class name size, whatever that is
            if klass_name is None:
                sa = getattr(klass, 'name', None)
                if not sa is None:
                    s = jvm_analysis.lookup_internal_symbol(sa)
                    if not s is None and \
                       str(s).find("Unknown Name") == -1 and\
                       str(s).find("Unknown class") == -1 and\
                       len(str(s)) < 65356:
                        klass_name = s
            if not klass_name is None and \
                    len(str(klass_name)) > 10000:
                        jvm_analysis.log("Seriously, someone made a Klass name (Java class name) symbol this long?: %d"%(len(str(klass_name))))
                        raise Exception("Seriously, someone made a Klass name (Java class name) symbol this long?")

            if not klass_name is None and\
                    str(klass_name) != 'None' and\
                    str(klass_name).find("Unknown class") == -1 and\
                    str(klass_name).find('Unknown Name') == -1 and\
                    len(str(klass_name)) < 65536 :
                NUM_OBSERVED += 1
            if KLASSES_PROCESSED > MAX_DICT_ENTRYS:
                 jvm_analysis.log ("Exceeded Dictionary Count: Processed %d Klasses"%(KLASSES_PROCESSED))
            #if klass_name is None:
            #    return None

        d = DictionaryEntry(**kargs)
        jvm_analysis.log("Completed parsing the SystemDictionary Entry @ 0x%08x"%addr)
        if jvm_analysis and not TESTING_FOR_VALID_STRUCT:
            jvm_analysis.add_internal_object(addr, d)
        return d

class DictionaryBucket(BaseOverlay):
    _name = "DictionaryBucket"
    _overlay = DICTIONARY_BUCKET_TYPE
    bits32 = get_bits32(DICTIONARY_BUCKET_TYPE)
    bits64 = get_bits64(DICTIONARY_BUCKET_TYPE)
    named32 = get_named_array32(DICTIONARY_BUCKET_TYPE)
    named64 = get_named_array64(DICTIONARY_BUCKET_TYPE)
    size32 = get_size32(DICTIONARY_BUCKET_TYPE)
    size64 = get_size64(DICTIONARY_BUCKET_TYPE)
    types = get_field_types(DICTIONARY_BUCKET_TYPE)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self):
        setattr(self, 'updated', True)

    def has_entry (self):
        return not getattr(self, 'entry_is_null', True)

    def get_entry_addr (self):
        literal = getattr(self, 'literal', -1)
        if self.has_entry():
            return literal
        return 0

    def get_entry_value (self):
        if self.has_entry():
            entry_value = getattr(self, 'entry_value', None)
            return entry_value.get_value()
        return None

    def get_entry_values (self):
        res = []
        if self.has_entry():
            entry_value = getattr(self, 'entry_value', None)
            while entry_value:
                if entry_value:
                    res.append(entry_value.get_value())
                    entry_value = entry_value.next_value
        return res

    def __str__(self):
        entry_value = getattr(self, 'entry_value', None)
        entry = getattr(self, 'entry', -1)
        entry_str = "NONE" if self.has_entry() else str(entry_value)
        return "%s 0x%08x %s"%(self._name, entry, entry_str)

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        #global DICT_ENTRYS
        #jvm_analysis.log ("Processing Dictionary Entry, current entry: %d"%DICT_ENTRYS)
        #DICT_ENTRYS += 1
        #if jvm_analysis and jvm_analysis.has_internal_object(addr):
        #    return jvm_analysis.get_internal_object(addr)
        nfields = DictionaryBucket.named32 if jvm_analysis.is_32bit else DictionaryEntry.named64
        fmt = DictionaryBucket.bits32 if jvm_analysis.is_32bit else DictionaryBucket.bits64
        data_unpack = struct.unpack(fmt, _bytes)
        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False}
        name_fields(data_unpack, nfields, fields=kargs)

        _entry = kargs["entry"]
        kargs["entry_value"] = None
        kargs["entry_is_null"] = _entry == 0
        if not kargs["entry_is_null"]:
            kargs['entry_value'] = DictionaryEntry.from_jva(_entry, jvm_analysis)
        d = DictionaryBucket(**kargs)
        jvm_analysis.log("Completed parsing the SystemDictionary Bucket @ 0x%08x"%addr)
        if jvm_analysis and not TESTING_FOR_VALID_STRUCT:
            jvm_analysis.add_internal_object(addr, d)
        return d

class Dictionary(BaseOverlay):
    _name = "Dictionary"
    _overlay = DICTIONARY_TYPE
    bits32 = get_bits32(DICTIONARY_TYPE)
    bits64 = get_bits64(DICTIONARY_TYPE)
    named32 = get_named_array32(DICTIONARY_TYPE)
    named64 = get_named_array64(DICTIONARY_TYPE)
    size32 = get_size32(DICTIONARY_TYPE)
    size64 = get_size64(DICTIONARY_TYPE)
    types = get_field_types(DICTIONARY_TYPE)

    def __init__(self, **kargs):
        for k,v in kargs.items():
            setattr(self, k, v)

    def __str__ (self):
        addr = getattr(self, 'addr', None)
        return ("Dictionary@0x%08x"%addr)

    def update_fields(self, force_update=False):
        setattr(self, 'updated', True)

    def parse_class_fields(self):
        setattr(self, 'updated', True)

    def get_bucket_values(self):
        bucket_values = getattr(self, 'bucket_values', [])
        res = []

        if bucket_values is None:
            return res
        for stb in bucket_values:
            if stb and stb.has_entry():
                v = stb.get_entry_values()
                if v:
                    res += v
        return res

    @classmethod
    def from_bytes(cls, addr, _bytes, jvm_analysis):
        global KLASSES_PROCESSED, MAX_DICT_ENTRYS, TESTING_FOR_VALID_STRUCT, NUM_OBSERVED, MAX_ENTRIES_TO_OBSERVE
        KLASSES_PROCESSED = 0
        if jvm_analysis and jvm_analysis.has_internal_object(addr):
            return jvm_analysis.get_internal_object(addr)
        nfields = Dictionary.named32 if jvm_analysis.is_32bit else Dictionary.named64
        fmt = Dictionary.bits32 if jvm_analysis.is_32bit else Dictionary.bits64
        data_unpack = struct.unpack(fmt, _bytes)
        kargs = {"addr":addr,'jvm_analysis':jvm_analysis, 'updated':False}
        name_fields(data_unpack, nfields, fields=kargs)

        kargs['bucket_values'] = None
        MAX_DICT_ENTRYS = kargs['number_of_entries']
        if TESTING_FOR_VALID_STRUCT and MAX_DICT_ENTRYS < MIN_DICT_ENTRYS:
            jvm_analysis.log("Failed to parse %d SystemDictionary Entrys @ 0x%08x, "%(MAX_DICT_ENTRYS, addr)+\
                                 "too few dict entrys reported")

        if jvm_analysis:
            if MAX_DICT_ENTRYS > MAX_NUM_ENTRYS_ALLOWED:
                jvm_analysis.log("Failed to parse %d SystemDictionary Entrys @ 0x%08x, "%(MAX_DICT_ENTRYS, addr)+\
                                 "too many dict entrys reported")
                return None
            jvm_analysis.log("Parsing %d SystemDictionary Entrys @ 0x%08x"%(MAX_DICT_ENTRYS, addr))

            symbol_table_buckets = []
            pos = 0
            incr = jvm_analysis.word_sz
            _table_size = kargs['table_size']
            _buckets = kargs['buckets']
            while pos < _table_size:
                stb_addr = pos*incr+_buckets
                symbol_table_bucket = DictionaryBucket.from_jva(stb_addr, jvm_analysis)
                if TESTING_FOR_VALID_STRUCT and KLASSES_PROCESSED > MAX_ENTRIES_TO_OBSERVE:
                    break
                symbol_table_buckets.append(symbol_table_bucket)
                pos += 1
            kargs['bucket_values'] = symbol_table_buckets
        d = Dictionary(**kargs)
        jvm_analysis.log("Completed parsing the SystemDictionary")
        if jvm_analysis and not TESTING_FOR_VALID_STRUCT:
            jvm_analysis.add_internal_object(addr, d)
        return d

    @classmethod
    def bruteforce_testing(cls, addr, jva, num_to_observe=10, max_entries_to_observe=10):
        if num_to_observe > max_entries_to_observe:
            max_entries_to_observe = num_to_observe
        setup_bruteforce_testing(num_to_observe, max_entries_to_observe)
        d = Dictionary.from_jva(addr, jva)
        num_observed = NUM_OBSERVED
        num_entries = -1
        klasses_parsed = KLASSES_PROCESSED
        if not d is None:
            num_entries = len(d.get_bucket_values())
        reset_dict_info()
        stop_bruteforce_testing()
        return {"Dictionary":d, "num_observed":num_observed, 'num_entries':num_entries, 'klasses_parsed':klasses_parsed}

    @classmethod
    def find_best_system_dictionary_match(cls, dict_list, jva):
        #TODO Probably not much to add: what is the best way to distinguish
        #     between a shared and system dictionary, system dictionary is
        #     likely to come first?
        if len(dict_list) == 0:
            return None
        return dict_list[0]['Dictionary']

    @classmethod
    def find_best_match(cls, dict_list, jva):
        return cls.find_best_system_dictionary_match(dict_list, jva)
