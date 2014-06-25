from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import HMAC
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
import struct

KEY_SIZE = 32 # bytes
AES_MODE = AES.MODE_CBC # Cipher Block Chaining

class Encrypter(object):
    def __init__(self, master, salt=None, init_vector=None):

        def prf(password, s):
            '''HMAC-SHA512 as a pseudo-random function for use in key
            derivation.'''
            return HMAC.new(password, s, SHA512).digest()

        # Compute a random salt if we weren't given one.
        self.random = Random.new()
        if salt is None:
            salt = self.random.read(8)
        self.salt = salt
        assert len(self.salt) == 8

        # Derive a key from our master password and salt.
        self.key = PBKDF2(master, self.salt, dkLen=16, count=100000, prf=prf)
        assert len(self.key) == 16

        # Compute an initial vector if we weren't given one.
        if init_vector is None:
            init_vector = self.random.read(16)
        self.init_vector = init_vector
        assert len(self.init_vector) == 16

    def _make_crypt(self):
        return AES.new(self.key, AES_MODE, IV=self.init_vector)

    def encrypt(self, plaintext):
        a = self._make_crypt()

        # First, calculate and pack the length of the plain text. We must do
        # this because we need to pad it to 16 bytes before encrypting.
        sz = struct.calcsize('<Q')
        length = len(plaintext)

        # Pad the plain text with 0s to 16 byte alignment.
        padding_sz = 16 - (length + sz) % 16
        padding = self.random.read(padding_sz)
        padded = struct.pack('<Q', len(plaintext)) + plaintext + padding

        # Encrypt the resulting length + plain text + padding.
        ciphertext = a.encrypt(padded)
        return ciphertext

    def decrypt(self, ciphertext):
        a = self._make_crypt()

        # Decrypt the annotated plain text.
        padded = a.decrypt(ciphertext)

        # Unpack the size of the original plain text.
        sz = struct.calcsize('<Q')
        length = struct.unpack('<Q', padded[:sz])[0]

        # Now we can actually get it back from the padded representation.
        unpadded = padded[sz:sz+length]
        return unpadded
