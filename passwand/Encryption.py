from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import HMAC
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
import struct

KEY_SIZE = 32 # bytes
AES_MODE = AES.MODE_CBC # Cipher Block Chaining
KEY_DERIVATION_ITERATIONS = 1000

HEADER = 'opdata01'

def make_aes(key, iv):
    return AES.new(key, AES_MODE, IV=iv)

def prf(password, s):
    '''HMAC-SHA512 as a pseudo-random function for use in key
    derivation.'''
    return HMAC.new(password, s, SHA512).digest()

def make_key(master, salt):
    return PBKDF2(master, salt, dkLen=KEY_SIZE, count=KEY_DERIVATION_ITERATIONS, prf=prf)

def encrypt(master, plaintext):
    rand = Random.new()

    # Compute a random salt.
    salt = rand.read(8)

    assert master is not None
    key = make_key(master, salt)

    # Compute an initial vector.
    init_vector = rand.read(16)

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

    # Pad the plain text with random bytes to 16 byte alignment.
    padding_sz = 16 - length % 16
    padding = rand.read(padding_sz)
    # and append it to the input.
    src += padding + plaintext

    # This final input should be 16 byte aligned if we got that right.
    assert len(src) % 16 == 0

    # Encrypt the resulting length + plain text + padding.
    ciphertext = a.encrypt(src)
    return ciphertext, salt, init_vector

def decrypt(master, ciphertext, salt, init_vector):
    assert len(salt) == 8
    key = make_key(master, salt)

    assert init_vector is not None
    assert len(init_vector) == 16
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
    if len(dest) < 16:
        raise Exception('missing initialisation vector')
    if init_vector != dest[:16]:
        raise Exception('mismatched initialisation vectors')
    dest = dest[16:]

    if length > len(dest):
        raise Exception('invalid length indicated')
    if len(dest) - length > 16:
        raise Exception('invalid padding detected')

    return dest[len(dest) - length:]
