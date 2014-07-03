import json
from Encoding import decode, encode

class Entry(object):
    def __init__(self, properties):
        def get(p):
            v = properties.get(p)
            if v is not None:
                v = decode(v)
            return v
        self.service = get('service')
        self.field = get('field')
        self.value = get('value')
        self.salt = get('salt')
        self.iv = get('iv')
        self.hmac = get('hmac')
        self.hmac_salt = get('hmac_salt')

    def to_dict(self):
        d = {}
        def put(f):
            v = getattr(self, f)
            if v is not None:
                d[f] = encode(v)
        put('service')
        put('field')
        put('value')
        put('salt')
        put('iv')
        put('hmac')
        put('hmac_salt')
        return d

def read_entries(path):
    with open(path, 'r') as f:
        entries = json.load(f)
    if not isinstance(entries, list):
        raise Exception('unexpected data encountered')
    for e in entries:
        if not isinstance(e, dict):
            raise Exception('unexpected data encountered')
        yield Entry(e)

def write_entries(path, entries):
    with open(path, 'w') as f:
        json.dump(map(Entry.to_dict, entries), f)
