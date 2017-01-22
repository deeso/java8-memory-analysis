import redis
class StringsRedisConn(object):
    REDIS_STRINGS = "strings"
    REDIS_STRINGS_SET_KEY = "strings"
    REDIS_ADDRS_SET_KEY = "addrs"
    REDIS_STRING_BY_ADDR_HSET = "stringsbyaddr"
    REDIS_STRING_BY_STR_HSET = "stringsbystr"
    
    def __init__(self, redis_host='127.0.0.1',
                redis_port=6379,
                redis_db=0,
                namespace="default",
                allow_updates = False, use_cache=True):
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_db = redis_db
        self.namespace = namespace
        self.allow_updates = allow_updates
        self.redis_con = self.connect_to_redis()
        self.cached = {}
        self.use_cache= use_cache
        
    def connect_to_redis (self):
        return redis.StrictRedis(host=self.redis_host,
                                 port=self.redis_port,
                                 db=self.redis_db)
    
    def set_cache (self, key, value):
        self.cached[key] = value
        return value
    
    def get_cache (self, key):
        return self.cached[key]
        
    def flush_cache (self):
        self.cached = {}
    
    def get_redis_conn (self, host='127.0.0.1', port=6379, db=0):
        self.redis_host = host
        self.redis_port = port
        self.redis_db = db
        return self.connect_to_redis()
    
    def add_discovered_string (self, addr, string):
        if self.allow_updates:
            self.redis_con.sadd(self.addrs_set_key(), addr)
            self.redis_con.sadd(self.strings_set_key(), string)
            self.redis_con.hset(self.stringbyaddrs_key(), addr, string)
            self.redis_con.sadd(self.stringbystr_key(string), addr)
        else:
            self.set_cache(self.addrs_set_key(), addr)
            self.set_cache(self.addrs_set_key(), addr)
            self.set_cache(self.strings_set_key(), string)
            self.set_cache("%s:%d"%(self.stringbyaddrs_key(), addr), string)
            self.set_cache(self.stringbystr_key(string), addr)
        
    # calls to handle getting strings keys
    def redis_namespace (self):
        if self.namespace:
            return self.namespace+":"
        return ""
    
    def strings_base_key(self):
        return self.redis_namespace() + self.REDIS_STRINGS
    
    def strings_set_key(self):
        return self.strings_base_key()+":"+self.REDIS_STRINGS_SET_KEY
    
    def addrs_set_key(self):
        return self.strings_base_key()+":"+self.REDIS_ADDRS_SET_KEY
    
    def stringbyaddrs_key(self):
        return self.strings_base_key()+":"+self.REDIS_STRING_BY_ADDR_HSET
    
    def stringbystr_key(self,string):
        base = self.strings_base_key()+":"+self.REDIS_STRING_BY_STR_HSET
        return base + ":" + string
    
    # calls to check for strings
    def has_string(self, string):
        if self.redis_con is None:
            return None
        k = self.strings_set_key()+":"+str(string)
        if self.use_cache and k in self.cached:
            return self.get_cache(k)
        elif self.use_cache:
            return self.set_cache(k, self.redis_con.sismember(self.strings_set_key(), string))
        return self.redis_con.sismember(self.strings_set_key(), string)
        
    def has_addr(self, addr):
        if self.redis_con is None:
            return None
        k = self.addrs_set_key()+":"+str(addr)
        if self.use_cache and k in self.cached:
            return self.get_cache(k)
        elif self.use_cache:
            return self.set_cache(k, self.redis_con.sismember(self.addrs_set_key(), addr))
        return self.redis_con.sismember(self.addrs_set_key(), addr)
        
    def get_strings_set(self):
        if self.redis_con is None:
            return None
        k = self.strings_set_key()
        if self.use_cache and k in self.cached:
            return self.get_cache(k)
        elif self.use_cache:
            return self.set_cache(k, self.redis_con.smembers(self.strings_set_key()))
        return self.redis_con.smembers(self.strings_set_key())
        
    def get_addrs_set(self):
        if self.redis_con is None:
            return None
        k = self.addrs_set_key()
        if self.use_cache and k in self.cached:
            return self.get_cache(k)
        elif self.use_cache:
            return self.set_cache(k, self.redis_con.smembers(self.addrs_set_key()))
        return self.redis_con.smembers(self.addrs_set_key())
        
    def get_str_at_addr(self, addr):
        if self.redis_con is None:
            return None
        k = self.stringbyaddrs_key()+":"+str(addr)
        if self.use_cache and k in self.cached:
            return self.get_cache(k)
        elif self.use_cache:
            return self.set_cache(k, self.redis_con.hget(self.stringbyaddrs_key(), addr))
        return self.redis_con.hget(self.stringbyaddrs_key(), addr)

    def get_addrs_for_str(self, string):
        if self.redis_con is None:
            return None
        k = self.stringbystr_key(string)
        if self.use_cache and k in self.cached:
            return self.get_cache(k)
        elif self.use_cache:
            return self.set_cache(k, self.redis_con.smembers(self.stringbystr_key(string)))
        return self.redis_con.smembers(self.stringbystr_key(string))
    
    def remove_addr (self, addr):
        self.flush_cache()
        if not self.allow_updates and not self.has_addr(addr):
            return False
        string = self.get_str_at_addr(addr)
        self._remove_addr(addr)
        addrs = self.get_addrs_for_str(string)
        # last string reference need to delete all the references to string
        if len(addrs) <= 1:
            self._remove_string(string)
        # or just remove the address from the set
        else:
            self.redis_con.srem(self.stringbyaddrs_key(), addr)
        
    
    def _remove_addr (self, addr):
        # del key from addrs:all set
        self.redis_con.srem(self.addrs_set_key(), addr)
        # del hkey in hset
        self.redis_con.delete(self.stringbyaddrs_key(), addr)
        
    def _remove_string (self, string):
        # del key from addrs:all set
        self.redis_con.srem(self.addrs_set_key(), string)
        # del hkey in hset
        self.redis_con.delete(self.stringbyaddrs_key(), string)
    
    def remove_string(self, string):
        self.flush_cache()
        if not self.allow_updates and not self.has_string(string):
            return False
        # enumerate all addresses
        addrs = self.get_addrs_for_str(string)
        for addr in addrs:
            self._remove_addr(addr)
        self._remove_string(string)
        return True
        
