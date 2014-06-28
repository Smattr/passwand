#!/usr/bin/env python
# -*- coding: utf-8 -*-

import Encryption, sys, unittest

class Encrypt(unittest.TestCase):
    def test_not_id(self):
        '''If some text encrypts to itself, we've likely done something wrong.'''
        m = 'master password'
        t = 'hello world'
        c, _, _ = Encryption.encrypt(m, t)
        self.assertNotEqual(t, c)
    def test_dual(self):
        '''We can successfully encrypt and decrypt some text.'''
        m = 'master password'
        p = 'hello world'
        c, salt, iv = Encryption.encrypt(m, p)
        d = Encryption.decrypt(m, c, salt, iv)
        self.assertEqual(p, d)
    def test_utf8(self):
        '''We can successfully deal with UTF-8.'''
        m = 'master password'
        p = 'hello ↑'
        c, salt, iv = Encryption.encrypt(m, p)
        d = Encryption.decrypt(m, c, salt, iv)
        self.assertEqual(p, d)

def main():
    unittest.main()
if __name__ == '__main__':
    sys.exit(main())
