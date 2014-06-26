from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import HMAC
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
import struct

KEY_SIZE = 32 # bytes
AES_MODE = AES.MODE_CBC # Cipher Block Chaining
KEY_DERIVATION_ITERATIONS = 1000

def make_aes(key, iv):
    return AES.new(key, AES_MODE, IV=iv)

def prf(password, s):
    '''HMAC-SHA512 as a pseudo-random function for use in key
    derivation.'''
    return HMAC.new(password, s, SHA512).digest()

def make_key(master, salt):
    return PBKDF2(master, salt, dkLen=16, count=KEY_DERIVATION_ITERATIONS, prf=prf)

def encrypt(master, plaintext, salt=None, init_vector=None):
    rand = Random.new()

    # Compute a random salt if we weren't given one.
    if salt is None:
        salt = rand.read(8)
    assert len(salt) == 8

    assert master is not None
    key = make_key(master, salt)

    # Compute an initial vector if we weren't given one.
    if init_vector is None:
        init_vector = rand.read(16)
    assert len(init_vector) == 16

    a = make_aes(key, init_vector)

    # First, calculate and pack the length of the plain text. We must do
    # this because we need to pad it to 16 bytes before encrypting.
    assert plaintext is not None
    sz = struct.calcsize('<Q')
    length = len(plaintext)

    # Pad the plain text with 0s to 16 byte alignment.
    padding_sz = 16 - (length + sz) % 16
    padding = rand.read(padding_sz)
    padded = struct.pack('<Q', len(plaintext)) + plaintext + padding

    # Encrypt the resulting length + plain text + padding.
    ciphertext = a.encrypt(padded)
    return ciphertext, salt, init_vector

def decrypt(master, ciphertext, salt, init_vector):
    assert len(salt) == 8
    key = make_key(master, salt)

    assert init_vector is not None
    assert len(init_vector) == 16
    a = make_aes(key, init_vector)

    # Decrypt the annotated plain text.
    padded = a.decrypt(ciphertext)

    # Unpack the size of the original plain text.
    sz = struct.calcsize('<Q')
    length = struct.unpack('<Q', padded[:sz])[0]

    # Now we can actually get it back from the padded representation.
    unpadded = padded[sz:sz+length]
    return unpadded
