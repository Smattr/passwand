import json
from Encoding import decode, encode
from Encryption import Encrypter, mac

ENCRYPTED_FIELDS = ['namespace', 'key', 'value']
CORE_FIELDS = ENCRYPTED_FIELDS + ['salt', 'iv']
HMAC_FIELDS = ['hmac', 'hmac_salt']

class Entry(object):
    def __init__(self, **kwargs):
        self.encrypted = kwargs.get('encrypted', False)
        for f in CORE_FIELDS + HMAC_FIELDS:
            v = kwargs.get(f)
            if v is not None and self.encrypted:
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

    def _get_encrypter(self, master):
        kwargs = {}
        if self.salt is not None:
            kwargs['salt'] = self.salt
        if self.iv is not None:
            kwargs['iv'] = self.iv
        e = Encrypter(master, **kwargs)
        self.salt = e.get_salt()
        self.iv = e.get_initialisation_vector()
        return e

    def decrypt(self, master):
        if not self.encrypted:
            raise Exception('entry is already decrypted')
        if not self.check_hmac(master):
            raise Exception('failed HMAC check')
        e = self._get_encrypter(master)
        for f in ENCRYPTED_FIELDS:
            setattr(self, f, e.decrypt(getattr(self, f)))
        self.encrypted = False

    def encrypt(self, master):
        if self.encrypted:
            raise Exception('entry is already encrypted')
        e = self._get_encrypter(master)
        for f in ENCRYPTED_FIELDS:
            setattr(self, f, e.encrypt(getattr(self, f)))
        self.encrypted = True
        self.set_hmac(master)

    def to_dict(self):
        if not self.encrypted:
            # Prevent accidentally exporting unencrypted entries
            raise Exception('entry is not encrypted')
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
        e['encrypted'] = True
        yield Entry(**e)

def write_entries(path, entries):
    with open(path, 'w') as f:
        json.dump(map(Entry.to_dict, entries), f)
