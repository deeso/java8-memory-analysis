from datetime import datetime
import keyword

def time_str():
    return str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))


class RecOOPArray(list):
    def __init__(self, addr, oop_type):
        super(list, self).__init__()
        self.addr = addr
        self.all_fields_values = {}
        self.oop_type = oop_type
        self.__jthread__ = None
        self.__java_hash__ = None
        self.__age__ = None
        self.__klass__ = None
        self.__mark_value__ = None
        self.__has_meta_data__ = False
        logit = False# if oop_type.find('Hashtable') == -1 else True
        if logit:
            print("creating array for: %s @ 0x%08x"%(str(oop_type), self.addr))

    def has_meta_data(self):
        return self.__has_meta_data__

    def has_age(self):
        return not self.__age__ is None

    def has_mark(self):
        return not self.__mark_value__ is None

    def has_klass(self):
        return not self.__mark_klass__ is None

    def has_java_hash(self):
        return not self.__java_hash__ is None

    def has_java_thread(self):
        return not self.__jthread__ is None

    def get_age(self):
        return self.__age__

    def get_mark(self):
        return self.__mark_value__

    def get_klass(self):
        return self.__mark_klass__

    def get_java_hash(self):
        return self.__java_hash__

    def get_java_thread(self):
        return self.__jthread__

class RecOOPObject(object):
    def __init__(self, addr, oop_type):
        #super(object, self).__init__()
        self.__jthread__ = None
        self.__java_hash__ = None
        self.__age__ = None
        self.__klass__ = None
        self.__mark_value__ = None
        self.__has_meta_data__ = False
        self.__addr = addr
        self.__all_fields_values = {}
        self.__fields = []
        self.__klass_fields = []
        self.oop_type = oop_type
    def get_addr(self):
        return self.__addr

    def get_fields(self):
        return self.__fields

    def add_field(self, name, value):
        pvname = name
        if pvname.find('$') > -1:
            pvname = name.replace('$', '_')
        if keyword.iskeyword(pvname):
            pvname = pvname + '__'
        if name != pvname:
            setattr(self, pvname, value)

        setattr(self, name, value)
        if not name in self.__fields:
            self.__fields.append(name)

    def add_field_by_key(self, res_key, value):
        if not res_key in self.__klass_fields:
            self.__klass_fields.append(res_key)
        self.__all_fields_values[res_key] = value

    def has_meta_data(self):
        return self.__has_meta_data__

    def has_age(self):
        return not self.__age__ is None

    def has_mark(self):
        return not self.__mark_value__ is None

    def has_klass(self):
        return not self.__mark_klass__ is None

    def has_java_hash(self):
        return not self.__java_hash__ is None

    def has_java_thread(self):
        return not self.__jthread__ is None

    def get_age(self):
        return self.__age__

    def get_mark(self):
        return self.__mark_value__

    def get_klass(self):
        return self.__mark_klass__

    def get_java_hash(self):
        return self.__java_hash__

    def get_java_thread(self):
        return self.__jthread__

class RecOOPInterface(object):
    def __init__(self, **kargs):
        self.initted = False
        self.logs = []
        self.current_step = 0
        self.steps = []

    def init_steps(self):
        raise Exception("implement init steps")


    def perform_virtual_memory_reconstruction(**kargs):
        raise Exception("implement memory construction")

    def perform_extract_loaded_types(**kargs):
        raise Exception("implement extract loaded types")

    def perform_locate_managed_memory(**kargs):
        raise Exception("implement managed memory")

    def perform_enumerate_objects(**kargs):
        raise Exception("implement locate enumerate objects")

    def perform_reconstruct_objects(**kargs):
        raise Exception("implement reconstruct objects")

    def extract_pertinent_infos(**kargs):
        raise Exception("implement timeline")

    def is_initted(self):
        return self.initted

    def log(self, msg):
        f = "[%s]: %s"%(time_str(), msg)
        self.logs.append(f)
        print (f)

    def next_step(self, **kargs):
        if self.current_step < len(self.steps):
            fn = self.steps[self.current_step]
            self.current_step += 1
            return fn(**kargs)
        raise Exception("No more steps to recoop")

    @classmethod
    def is_python_native(cls, val):
        return isinstance(val, str) or\
               isinstance(val, int) or\
               isinstance(val, float) or\
               isinstance(val, long) or\
               isinstance(val, bytes)
