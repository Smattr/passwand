from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Hash import HMAC
from Crypto.Hash import SHA512
import struct
import scrypt

KEY_SIZE = 32 # bytes
AES_MODE = AES.MODE_CTR # Counter

HEADER = 'oprime01'

random_dev = Random.new()
def random_bytes(len):
    return random_dev.read(len)

def make_aes(key, iv):
    assert struct.calcsize('<Q') == 8
    assert len(iv) == 8
    val = struct.unpack('<Q', iv)[0]
    ctr = Counter.new(128, initial_value=val, allow_wraparound=True)
    return AES.new(key, AES_MODE, counter=ctr)

def make_key(master, salt, work_factor=14):
    assert work_factor >= 10 and work_factor <= 31
    return scrypt.hash(master, salt, N=(2 << work_factor), r=8, p=1, buflen=KEY_SIZE)

def mac(master, data, salt=None, work_factor=None):
    if salt is None:
        salt = random_bytes(8)
    assert len(salt) == 8
    kwargs = {}
    if work_factor is not None:
        kwargs['work_factor'] = work_factor
    key = make_key(master, salt, **kwargs)
    auth = HMAC.new(key, data, SHA512).digest()
    return (salt, auth)

class Encrypter(object):
    def __init__(self, master, salt=None, iv=None, work_factor=None):
        assert master is not None
        self.master = master

        # Compute a random salt if required.
        if salt is None:
            salt = random_bytes(8)
        assert len(salt) == 8
        self.salt = salt

        # Compute a key for use in AES generation.
        kwargs = {}
        if work_factor is not None:
            kwargs['work_factor'] = work_factor
        self.key = make_key(master, salt, **kwargs)

        # Compute an initial vector if required.
        if iv is None:
            iv = random_bytes(8)
        assert len(iv) == 8
        self.iv = iv

    def get_initialisation_vector(self):
        return self.iv

    def get_salt(self):
        return self.salt

    def encrypt(self, plaintext):
        aes = make_aes(self.key, self.iv)

        # Now we're ready to calculate the input to the encryption.
        src = HEADER

        # First, calculate and pack the length of the plain text. We append the
        # length to the input data.
        assert plaintext is not None
        length = len(plaintext)
        assert struct.calcsize('<Q') == 8
        src += struct.pack('<Q', length)

        # Now the initialisation vector.
        src += self.iv
        length += len(self.iv)

        # Pad the plain text with random bytes to 16 byte alignment. Agile Bits
        # considers the padding scheme from IETF draft AEAD-AES-CBC-HMAC-SHA as
        # a more suitable replacement, but I'm not sure why. It involves
        # deterministic bytes that seems inherently less secure.
        padding_sz = 16 - length % 16
        padding = random_bytes(padding_sz)
        # and append it to the input.
        src += padding + plaintext

        # This final input should be 16 byte aligned if we got that right.
        assert len(src) % 16 == 0

        # Encrypt the resulting length + plain text + padding.
        ciphertext = aes.encrypt(src)
        return ciphertext

    def decrypt(self, ciphertext):
        aes = make_aes(self.key, self.iv)

        # Decrypt the annotated plain text.
        dest = aes.decrypt(ciphertext)

        if len(dest) % 16 != 0:
            raise Exception('unaligned unencrypted data')

        # We should have the data format header.
        if not dest.startswith(HEADER):
            raise Exception('invalid resulting data format')
        dest = dest[len(HEADER):]

        # Unpack the size of the original plain text.
        assert struct.calcsize('<Q') == 8
        if len(dest) < 8:
            raise Exception('truncated data')
        length = struct.unpack('<Q', dest[:8])[0]
        dest = dest[8:]

        # Check the initialisation vector matches.
        if len(dest) < 8:
            raise Exception('missing initialisation vector')
        if self.iv != dest[:8]:
            raise Exception('mismatched initialisation vectors')
        dest = dest[8:]

        if length > len(dest):
            raise Exception('invalid length indicated')
        if len(dest) - length > 16:
            raise Exception('invalid padding detected')

        return dest[len(dest) - length:]
