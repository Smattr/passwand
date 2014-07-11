import json
from Encoding import decode, encode
from Encryption import mac

CORE_FIELDS = ['namespace', 'key', 'value', 'salt', 'iv']
HMAC_FIELDS = ['hmac', 'hmac_salt']

class Entry(object):
    def __init__(self, properties):
        for f in CORE_FIELDS + HMAC_FIELDS:
            v = properties.get(f)
            if v is not None:
                v = decode(v)
            setattr(self, f, v)

    def mac(self, master, salt=None):
        data = ''
        for f in CORE_FIELDS:
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
        for f in CORE_FIELDS + HMAC_FIELDS:
            v = getattr(self, f)
            if v is not None:
                d[f] = encode(v)
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
