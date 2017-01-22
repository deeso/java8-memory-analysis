import redis
class PtrsRedisConn(object):
    REDIS_SRC_RANGE_SET_SRCS = "srcs:all"
    REDIS_SRC_RANGE_SET_SINKS = "sinks:all"
    REDIS_HASH_SET_SINK_VALUE_KEY = "sinks:value"
    REDIS_HASH_SET_SRC_PTRS_KEY = "srcs:sinks"
    REDIS_SINKS_SET_KEY = "sinks"
    REDIS_SINKS_SRCS_SET_KEY = "sinks"
    REDIS_SRCS_SET_KEY = "srcs"
    REDIS_SRC_RANGE_SET_KEY = "ranges"

    def __init__(self, redis_host='127.0.0.1', redis_port=6379, redis_db=0, namespace="default"):
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_db = redis_db
        self.namespace = namespace
        self.redis_con = self.connect_to_redis()
        
    def connect_to_redis (self):
        return redis.StrictRedis(host=self.redis_host,
                                 port=self.redis_port,
                                 db=self.redis_db)
    
    def get_redis_conn (self, host='127.0.0.1', port=6379, db=0):
        self.redis_host = host
        self.redis_port = port
        self.redis_db = db
        return self.connect_to_redis()
    
    # calls to handle getting strings keys
    def namespace_key (self):
        if self.namespace:
            return self.namespace+":"
        return ""
    
    def range_key (self, range_str):
        return self.REDIS_SRC_RANGE_SET_KEY+":"+range_str
    
    def sinks_srcs_set_key(self, addr):
        return self.namespace_key()+self.REDIS_SINKS_SRCS_SET_KEY+":"+str(addr).replace("L","")
    
    def srcs_set_key(self):
        return self.namespace_key()+self.REDIS_SRCS_SET_KEY

    def sinks_set_key(self):
        return self.namespace_key()+self.REDIS_SINKS_SET_KEY
            
    def src_ptrs_hash_set_key(self):
        return self.namespace_key()+self.REDIS_HASH_SET_SRC_PTRS_KEY

    def sink_value_hash_set_key(self):
        return self.namespace_key()+self.REDIS_HASH_SET_SINK_VALUE_KEY

    def range_sinks_set_key(self, range_str):
        return self.namespace_key()+self.range_key(range_str)+":"+self.REDIS_SRC_RANGE_SET_SINKS
    
    def range_src_set_key(self, range_str):
        return self.namespace_key()+self.range_key(range_str)+":"+self.REDIS_SRC_RANGE_SET_SRCS

    def range_set_key(self):
        return self.namespace_key()+self.REDIS_SRC_RANGE_SET_KEY
    
    # calls to check for strings
    def has_sink(self, addr):
        if self.redis_con is None:
            return None
        return self.redis_con.sismember(self.sinks_set_key(), addr)

    def has_src(self, addr):
        if self.redis_con is None:
            return None
        return self.redis_con.sismember(self.srcs_set_key(), addr)
    
    def has_range(self, range_str):
        if self.redis_con is None:
            return None
        return self.redis_con.sismember(self.range_set_key(), range_str)
    
    def range_has_sink(self, range_str, addr):
        if self.redis_con is None:
            return None
        return self.redis_con.sismember(self.range_sinks_set_key(range_str), addr)

    def range_has_src(self, range_str, addr):
        if self.redis_con is None:
            return None
        return self.redis_con.sismember(self.range_src_set_key(range_str), addr)
        
    def sink_has_src(self, sink, addr):
        if self.redis_con is None:
            return None
        return self.redis_con.sismember(self.sinks_srcs_set_key(sink), addr)

    # retrieve data
    def get_ranges_set(self):
        if self.redis_con is None:
            return None
        return self.redis_con.smembers(self.range_set_key())

    def get_sink_srcs_set(self, addr):
        if self.redis_con is None:
            return None
        return self.redis_con.smembers(self.sinks_srcs_set_key(addr))

    # !!!!Danger this is a heavy Operation
    def get_sinks_set(self):
        if self.redis_con is None:
            return None
        return self.redis_con.smembers(self.sinks_set_key())

    # !!!!Danger this is a heavy Operation
    def get_srcs_set(self):
        if self.redis_con is None:
            return None
        return self.redis_con.smembers(self.srcs_set_key())

    # !!!!Danger this is a heavy Operation
    def get_range_srcs_set(self, range_str):
        if self.redis_con is None:
            return None
        return self.redis_con.smembers(self.range_src_set_key(range_str))

    # !!!!Danger this is a heavy Operation
    def get_range_sinks_set(self, range_str):
        if self.redis_con is None:
            return None
        return self.redis_con.smembers(self.range_sinks_set_key(range_str))
    
    def get_src_sink(self, addr):
        if self.redis_con is None:
            return None
        return self.redis_con.hget(self.src_ptrs_hash_set_key(), addr)

    def get_sink_value(self, addr):
        if self.redis_con is None:
            return None
        return self.redis_con.hget(self.sink_value_hash_set_key(), addr)
    
    # combines two redis operations
    def get_src_value(self, addr):
        if self.redis_con is None:
            return None
        sink = self.redis_con.hget(self.src_ptrs_hash_set_key(), addr)
        return self.get_sink_value(sink)
    
        
