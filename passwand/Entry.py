import json
from Encoding import decode, encode
from Encryption import mac

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

    def mac(self, master, salt=None):
        data = ''
        for f in ['service', 'field', 'value', 'salt', 'iv']:
            v = getattr(self, f)
            if v is not None:
                data += v
        salt, auth = mac(master, data, salt)
        return (salt, auth)

    def check_hmac(self, master):
        if self.hmac is None or self.hmac_salt is None:
            return False
        _, auth = self.mac(master, self.hmac_salt)
        return auth == self.hmac

    def set_hmac(self, master):
        self.hmac_salt, self.hmac = self.mac(master)

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
