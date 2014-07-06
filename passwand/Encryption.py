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

random_dev = None
def random_bytes(len):
    global random_dev
    if random_dev is None:
        random_dev = Random.new()
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

def encrypt(master, plaintext, work_factor=None):
    # Compute a random salt.
    salt = random_bytes(8)

    assert master is not None
    kwargs = {}
    if work_factor is not None:
        kwargs['work_factor'] = work_factor
    key = make_key(master, salt, **kwargs)

    # Compute an initial vector.
    init_vector = random_bytes(8)

    a = make_aes(key, init_vector)

    # Now we're ready to calculate the input to the encryption.
    src = HEADER

    # First, calculate and pack the length of the plain text. We must do
    # this because we need to pad it to 16 bytes before encrypting. We append
    # the length to the source data.
    assert plaintext is not None
    length = len(plaintext)
    assert struct.calcsize('<Q') == 8
    src += struct.pack('<Q', length)

    # Now the initialisation vector.
    src += init_vector
    length += len(init_vector)

    # Pad the plain text with random bytes to 16 byte alignment. Agile Bits
    # considers the padding scheme from IETF draft AEAD-AES-CBC-HMAC-SHA as a
    # more suitable replacement, but I'm not sure why. It involves
    # deterministic bytes that seems inherently less secure.
    padding_sz = 16 - length % 16
    padding = random_bytes(padding_sz)
    # and append it to the input.
    src += padding + plaintext

    # This final input should be 16 byte aligned if we got that right.
    assert len(src) % 16 == 0

    # Encrypt the resulting length + plain text + padding.
    ciphertext = a.encrypt(src)
    return ciphertext, salt, init_vector

def decrypt(master, ciphertext, salt, init_vector, work_factor=None):
    assert len(salt) == 8
    kwargs = {}
    if work_factor is not None:
        kwargs['work_factor'] = work_factor
    key = make_key(master, salt, **kwargs)

    assert init_vector is not None
    assert len(init_vector) == 8
    a = make_aes(key, init_vector)

    # Decrypt the annotated plain text.
    dest = a.decrypt(ciphertext)

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
    if init_vector != dest[:8]:
        raise Exception('mismatched initialisation vectors')
    dest = dest[8:]

    if length > len(dest):
        raise Exception('invalid length indicated')
    if len(dest) - length > 16:
        raise Exception('invalid padding detected')

    return dest[len(dest) - length:]
