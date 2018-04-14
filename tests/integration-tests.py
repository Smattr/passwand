#!/usr/bin/env python3

'''
Framework for writing integration tests.
'''

import json, os, pexpect, re, shutil, subprocess, sys, tempfile, unittest

class DummyTest(unittest.TestCase):
    def test_dummy(self):
        pass

class Cli(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_help_text(self):
        '''
        Confirm we can get help text output from the command line interface.
        '''
        text = subprocess.check_output(['./pw-cli', '--help'],
            universal_newlines=True)
        self.assertNotEqual(text.strip(), '')

    def test_set_basic(self):
        '''
        Test basic functionality of setting an entry in a blank data file.
        '''
        data = os.path.join(self.tmp, 'test_set_basic.json')
        self.set_basic(True, data)

    def test_set_basic_single_threaded(self):
        '''
        Same as test_set_basic, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_set_basic_single_threaded.json')
        self.set_basic(False, data)

    def set_basic(self, multithreaded: bool, data: str):

        # Request to save a key and value.
        args = ['set', '--data', data, '--space', 'space', '--key', 'key',
          '--value', 'value']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Confirm the master pasword.
        try:
            p.expect('confirm master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # Check the file was actually written.
        self.assertTrue(os.path.exists(data))
        with open(data, 'rt') as f:
            j = json.load(f)
        self.assertIsInstance(j, list)
        self.assertEqual(len(j), 1)
        self.assertIsInstance(j[0], dict)
        self.assertIn('space', j[0].keys())
        self.assertIn('key', j[0].keys())
        self.assertIn('value', j[0].keys())

    def test_get_basic(self):
        '''
        Test basic functionality of getting an entry from a small data file.
        Note that if test_set_basic* fails, you should expect this to fail as
        well.
        '''
        data = os.path.join(self.tmp, 'test_get_basic.json')
        self.get_basic(True, data)

    def test_get_basic_single_threaded(self):
        '''
        Same as test_get_basic, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_get_basic_single_threaded.json')
        self.get_basic(False, data)

    def get_basic(self, multithreaded: bool, data: str):

        # Request to save a key and value.
        p = pexpect.spawn('./pw-cli', ['set', '--data', data, '--space', 'space',
          '--key', 'key', '--value', 'value'])

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Confirm the master pasword.
        try:
            p.expect('confirm master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # Try to read the value back.
        args = ['get', '--data', data, '--space', 'space', '--key', 'key']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # If everything's working, we should get the value.
        try:
            p.expect('value\r\n')
        except pexpect.EOF:
            self.fail('EOF while waiting for value')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for value')

        # And passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

    def test_set_overwrite(self):
        '''
        Test setting an entry that is already set overwrites it.
        '''
        data = os.path.join(self.tmp, 'test_set_overwrite.json')
        self.set_overwrite(True, data)

    def test_set_overwrite_single_threaded(self):
        '''
        Same as test_set_overwrite, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_set_overwrite_single_threaded.json')
        self.set_overwrite(False, data)

    def set_overwrite(self, multithreaded: bool, data: str):

        # Request to save a key and value.
        args = ['set', '--data', data, '--space', 'space', '--key', 'key',
          '--value', 'value']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Confirm the master pasword.
        try:
            p.expect('confirm master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # Retrieve the (encrypted) value set.
        self.assertTrue(os.path.exists(data))
        with open(data, 'rt') as f:
            j = json.load(f)
        self.assertIsInstance(j, list)
        self.assertEqual(len(j), 1)
        self.assertIsInstance(j[0], dict)
        value = j[0]['value']

        # Now overwrite the value.
        args = ['set', '--data', data, '--space', 'space', '--key', 'key',
          '--value', 'value2']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Confirm the master pasword.
        try:
            p.expect('confirm master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # Confirm that we still have a single entry and it has been changed.
        self.assertTrue(os.path.exists(data))
        with open(data, 'rt') as f:
            j = json.load(f)
        self.assertIsInstance(j, list)
        self.assertEqual(len(j), 1)
        self.assertIsInstance(j[0], dict)
        self.assertNotEqual(value, j[0]['value'])

    def test_set_append(self):
        '''
        Test setting an entry in existing database appends.
        '''
        data = os.path.join(self.tmp, 'test_set_append.json')
        self.set_append(True, data)

    def test_set_append_single_threaded(self):
        '''
        Same as test_set_append, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_set_append_single_threaded.json')
        self.set_append(False, data)

    def set_append(self, multithreaded: bool, data: str):

        # Request to save a key and value.
        args = ['set', '--data', data, '--space', 'space', '--key', 'key',
          '--value', 'value']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Confirm the master pasword.
        try:
            p.expect('confirm master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # Retrieve the (encrypted) value set.
        self.assertTrue(os.path.exists(data))
        with open(data, 'rt') as f:
            j = json.load(f)
        self.assertIsInstance(j, list)
        self.assertEqual(len(j), 1)
        self.assertIsInstance(j[0], dict)
        value = j[0]['value']

        # Now set another value.
        args = ['set', '--data', data, '--space', 'space', '--key', 'key2',
          '--value', 'value2']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Confirm the master pasword.
        try:
            p.expect('confirm master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # Confirm that we now have two entries.
        self.assertTrue(os.path.exists(data))
        with open(data, 'rt') as f:
            j = json.load(f)
        self.assertIsInstance(j, list)
        self.assertEqual(len(j), 2)
        self.assertIsInstance(j[0], dict)
        self.assertIsInstance(j[1], dict)

        # We used different values, so their encrypted forms should be
        # different.
        self.assertNotEqual(j[1]['value'], j[0]['value'])

        # One of them should be the (unaltered) encrypted version of the first
        # value. Note that we don't guarantee the preservation of the ordering
        # of entries.
        if j[0]['value'] != value:
            self.assertEqual(j[1]['value'], value)

    def test_change_master_empty(self):
        '''
        Test changing the master password on an empty database.
        '''
        data = os.path.join(self.tmp, 'test_change_master_empty.json')
        self.change_master_empty(True, data)

    def test_change_master_empty_single_threaded(self):
        '''
        Same as test_change_master_empty, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_change_master_empty_single_threaded.json')
        self.change_master_empty(False, data)

    def change_master_empty(self, multithreaded: bool, data: str):

        # Setup an empty database.
        with open(data, 'wt') as f:
            json.dump([], f)

        # Request to change the master password.
        args = ['change-master', '--data', data]
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Set a new master pasword.
        try:
            p.expect('new master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test2')

        # Confirm the new master pasword.
        try:
            p.expect('confirm new master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test2')

        # Now passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # The database should still exist and be empty.
        self.assertTrue(os.path.exists(data))
        with open(data, 'rt') as f:
            j = json.load(f)
        self.assertIsInstance(j, list)
        self.assertEqual(len(j), 0)

    def test_change_master_mismatch(self):
        '''
        Test changing the master password but failing to confirm it fails.
        '''
        data = os.path.join(self.tmp, 'test_change_master_mismatch.json')
        self.change_master_mismatch(True, data)

    def test_change_master_mismatch_single_threaded(self):
        '''
        Same as test_change_master_mismatch, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_change_master_mismatch_single_threaded.json')
        self.change_master_mismatch(False, data)

    def change_master_mismatch(self, multithreaded: bool, data: str):

        # Setup an empty database.
        with open(data, 'wt') as f:
            json.dump([], f)

        # Request to change the master password.
        args = ['change-master', '--data', data]
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Set a new master pasword.
        try:
            p.expect('new master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test2')

        # Enter an incorrect confirmation.
        try:
            p.expect('confirm new master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with failure.
        p.expect(pexpect.EOF)
        p.close()
        self.assertNotEqual(p.exitstatus, 0)

        # The database should still exist and be empty.
        self.assertTrue(os.path.exists(data))
        with open(data, 'rt') as f:
            j = json.load(f)
        self.assertIsInstance(j, list)
        self.assertEqual(len(j), 0)

    def test_change_master_basic(self):
        '''
        Test changing the master password does what it says on the box.
        '''
        data = os.path.join(self.tmp, 'test_change_master_basic.json')
        self.change_master_basic(True, data)

    def test_change_master_basic_single_threaded(self):
        '''
        Same as test_change_master_basic, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_change_master_basic_single_threaded.json')
        self.change_master_basic(False, data)

    def change_master_basic(self, multithreaded: bool, data: str):

        # Request to save a key and value.
        args = ['set', '--data', data, '--space', 'space', '--key', 'key',
          '--value', 'value']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Confirm the master pasword.
        try:
            p.expect('confirm master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # Retrieve the (encrypted) value that was written.
        self.assertTrue(os.path.exists(data))
        with open(data, 'rt') as f:
            j = json.load(f)
        self.assertIsInstance(j, list)
        self.assertEqual(len(j), 1)
        self.assertIsInstance(j[0], dict)
        self.assertIn('space', j[0].keys())
        self.assertIn('key', j[0].keys())
        self.assertIn('value', j[0].keys())
        space = j[0]['space']
        key = j[0]['key']
        value = j[0]['value']

        # Request to change the master password.
        args = ['change-master', '--data', data]
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Set a new master pasword.
        try:
            p.expect('new master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test2')

        # Confirm the new master pasword.
        try:
            p.expect('confirm new master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test2')

        # Now passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # Now the encrypted fields in the database should have changed because
        # the encryption key has changed.
        self.assertTrue(os.path.exists(data))
        with open(data, 'rt') as f:
            j = json.load(f)
        self.assertIsInstance(j, list)
        self.assertEqual(len(j), 1)
        self.assertIsInstance(j[0], dict)
        self.assertIn('space', j[0].keys())
        self.assertIn('key', j[0].keys())
        self.assertIn('value', j[0].keys())
        self.assertNotEqual(space, j[0]['space'])
        self.assertNotEqual(key, j[0]['key'])
        self.assertNotEqual(value, j[0]['value'])

        # Request retrieval of the entry.
        args = ['get', '--data', data, '--space', 'space', '--key', 'key']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the old master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with failure.
        p.expect(pexpect.EOF)
        p.close()
        self.assertNotEqual(p.exitstatus, 0)

        # Request retrieval of the entry again.
        args = ['get', '--data', data, '--space', 'space', '--key', 'key']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Now enter the new master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test2')

        # Now passwand should output the value and exit with success.
        v = p.read()
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # We should have received the correct value we originally set.
        self.assertEqual(v.decode('utf-8', 'replace').strip(), 'value')

    def test_list_empty(self):
        '''
        Test listing an empty database.
        '''
        data = os.path.join(self.tmp, 'test_list_empty.json')
        self.list_empty(True, data)

    def test_list_empty_single_threaded(self):
        '''
        Same as test_list_empty, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_list_empty_single_threaded.json')
        self.list_empty(False, data)

    def list_empty(self, multithreaded: bool, data: str):

        # Setup an empty database.
        with open(data, 'wt') as f:
            json.dump([], f)

        # Request to list the database.
        args = ['list', '--data', data]
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with success.
        output = p.read()
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # Check we got no entries listed.
        self.assertEqual(output.decode('utf-8', 'replace').strip(), '')

        # Check the database was not changed.
        self.assertTrue(os.path.exists(data))
        with open(data, 'rt') as f:
            j = json.load(f)
        self.assertIsInstance(j, list)
        self.assertEqual(len(j), 0)

    def test_list_wrong_password(self):
        '''
        Test entering the wrong password during list.
        '''
        data = os.path.join(self.tmp, 'test_list_wrong_password.json')
        self.list_wrong_password(True, data)

    def test_list_wrong_password_single_threaded(self):
        '''
        Same as test_list_wrong_password, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_list_wrong_password_single_threaded.json')
        self.list_wrong_password(False, data)

    def list_wrong_password(self, multithreaded: bool, data: str):

        # Request to save a key and value.
        args = ['set', '--data', data, '--space', 'space', '--key', 'key',
          '--value', 'value']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Confirm the master pasword.
        try:
            p.expect('confirm master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # Now request to list the database.
        args = ['list', '--data', data]
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the wrong master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test2')

        # Now passwand should exit with failure.
        p.expect(pexpect.EOF)
        p.close()
        self.assertNotEqual(p.exitstatus, 0)

    def test_list_basic(self):
        '''
        Test list of a single entry.
        '''
        data = os.path.join(self.tmp, 'test_list_basic.json')
        self.list_basic(True, data)

    def test_list_basic_single_threaded(self):
        '''
        Same as test_list_basic, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_list_basic_single_threaded.json')
        self.list_basic(False, data)

    def list_basic(self, multithreaded: bool, data: str):

        # Request to save a key and value.
        args = ['set', '--data', data, '--space', 'space', '--key', 'key',
          '--value', 'value']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Confirm the master pasword.
        try:
            p.expect('confirm master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # Now request to list the database.
        args = ['list', '--data', data]
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now we should get the entry and passwand should exit with success.
        output = p.read()
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)
        self.assertEqual(output.decode('utf-8', 'replace').strip(), 'space/key')

    def test_set_xoo(self):
        '''
        Test overwriting the first of a set of three entries.
        '''
        data = os.path.join(self.tmp, 'test_set_xoo.json')
        self.set_xxx(True, data, 0)

    def test_set_xoo_single_threaded(self):
        '''
        Same as test_set_xoo, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_set_xoo_single_threaded.json')
        self.set_xxx(False, data, 0)

    def test_set_oxo(self):
        '''
        Test overwriting the second of a set of three entries.
        '''
        data = os.path.join(self.tmp, 'test_set_oxo.json')
        self.set_xxx(True, data, 1)

    def test_set_oxo_single_threaded(self):
        '''
        Same as test_set_oxo, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_set_oxo_single_threaded.json')
        self.set_xxx(False, data, 1)

    def test_set_oox(self):
        '''
        Test overwriting the third of a set of three entries.
        '''
        data = os.path.join(self.tmp, 'test_set_oox.json')
        self.set_xxx(True, data, 2)

    def test_set_oox_single_threaded(self):
        '''
        Same as test_set_oox, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_set_oox_single_threaded.json')
        self.set_xxx(False, data, 2)

    def set_xxx(self, multithreaded: bool, data: str, target: int):

        # Setup a database with three entries.
        for i in range(3):

            # Request to save a key and value.
            args = ['set', '--data', data, '--space', 'space{}'.format(i),
              '--key', 'key{}'.format(i), '--value', 'value{}'.format(i)]
            if not multithreaded:
                args += ['--jobs', '1']
            p = pexpect.spawn('./pw-cli', args)

            # Enter the master password.
            try:
                p.expect('master password: ')
            except pexpect.EOF:
                self.fail('EOF while waiting for password prompt')
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for password prompt')
            p.sendline('test')

            # Confirm the master pasword.
            try:
                p.expect('confirm master password: ')
            except pexpect.EOF:
                self.fail('EOF while waiting for password prompt')
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for password prompt')
            p.sendline('test')

            # Now passwand should exit with success.
            p.expect(pexpect.EOF)
            p.close()
            self.assertEqual(p.exitstatus, 0)

        # Now overwrite the 'target'-th entry.
        args = ['set', '--data', data, '--space', 'space{}'.format(target),
          '--key', 'key{}'.format(target), '--value', 'valuenew']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Confirm the master pasword.
        try:
            p.expect('confirm master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # Now retrieve each value.
        for i in range(3):

            args = ['get', '--data', data, '--space', 'space{}'.format(i),
              '--key', 'key{}'.format(i)]
            if not multithreaded:
                args += ['--jobs', '1']
            p = pexpect.spawn('./pw-cli', args)

            # Enter the master password.
            try:
                p.expect('master password: ')
            except pexpect.EOF:
                self.fail('EOF while waiting for password prompt')
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for password prompt')
            p.sendline('test')

            # We should get the original value for everything except the entry
            # we changed.
            try:
                expected = 'value{}'.format('new' if i == target else i)
                p.expect('{}\r\n'.format(expected))
            except pexpect.EOF:
                self.fail('EOF while waiting for {}'.format(expected))
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for {}'.format(expected))

            # And passwand should exit with success.
            p.expect(pexpect.EOF)
            p.close()
            self.assertEqual(p.exitstatus, 0)

    def test_list_standard(self):
        '''
        Test list of ten entries.
        '''
        data = os.path.join(self.tmp, 'test_list_standard.json')
        self.list_standard(True, data)

    def test_list_standard_single_threaded(self):
        '''
        Same as test_list_standard, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_list_standard_single_threaded.json')
        self.list_standard(False, data)

    def list_standard(self, multithreaded: bool, data: str):

        # Request to save 10 keys and values.
        for i in range(10):
            args = ['set', '--data', data, '--space', 'space{}'.format(i),
              '--key', 'key{}'.format(i), '--value', 'value{}'.format(i)]
            if not multithreaded:
                args += ['--jobs', '1']
            p = pexpect.spawn('./pw-cli', args)

            # Enter the master password.
            try:
                p.expect('master password: ')
            except pexpect.EOF:
                self.fail('EOF while waiting for password prompt')
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for password prompt')
            p.sendline('test')

            # Confirm the master pasword.
            try:
                p.expect('confirm master password: ')
            except pexpect.EOF:
                self.fail('EOF while waiting for password prompt')
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for password prompt')
            p.sendline('test')

            # Now passwand should exit with success.
            p.expect(pexpect.EOF)
            p.close()
            self.assertEqual(p.exitstatus, 0)

        # Now request to list the database.
        args = ['list', '--data', data]
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Scan the entries we get.
        output = p.read()
        seen = set()
        for line in output.decode('utf-8', 'replace').strip().splitlines():
            m = re.match(r'^space(\d+)/key\1', line)
            self.assertIsNotNone(m, 'unexpected entry received from \'list\'')
            i = int(m.group(1))
            self.assertNotIn(i, seen, 'duplicate entry in list')
            seen.add(i)
        self.assertEqual(seen, set(range(10)), 'incorrect list of entries')

        # List should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

    def test_delete_empty(self):
        '''
        Test delete from an empty database.
        '''
        data = os.path.join(self.tmp, 'test_delete_empty.json')
        self.delete_empty(True, data)

    def test_delete_empty_single_threaded(self):
        '''
        Same as test_delete_empty, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_delete_empty_single_threaded.json')
        self.delete_empty(False, data)

    def delete_empty(self, multithreaded: bool, data: str):

        # Setup an empty database.
        with open(data, 'wt') as f:
            json.dump([], f)

        # Request to delete an entry.
        args = ['delete', '--data', data, '--space', 'space', '--key', 'key']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with failure.
        p.expect(pexpect.EOF)
        p.close()
        self.assertNotEqual(p.exitstatus, 0)

        # Check the database was not changed.
        self.assertTrue(os.path.exists(data))
        with open(data, 'rt') as f:
            j = json.load(f)
        self.assertIsInstance(j, list)
        self.assertEqual(len(j), 0)

    def test_delete_xoo(self):
        '''
        Test deleting the first of a set of three entries.
        '''
        data = os.path.join(self.tmp, 'test_delete_xoo.json')
        self.delete_xxx(True, data, 0)

    def test_delete_xoo_single_threaded(self):
        '''
        Same as test_delete_xoo, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_delete_xoo_single_threaded.json')
        self.delete_xxx(False, data, 0)

    def test_delete_oxo(self):
        '''
        Test deleting the second of a set of three entries.
        '''
        data = os.path.join(self.tmp, 'test_delete_oxo.json')
        self.delete_xxx(True, data, 1)

    def test_delete_oxo_single_threaded(self):
        '''
        Same as test_delete_oxo, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_delete_oxo_single_threaded.json')
        self.delete_xxx(False, data, 1)

    def test_delete_oox(self):
        '''
        Test deleting the third of a set of three entries.
        '''
        data = os.path.join(self.tmp, 'test_delete_oox.json')
        self.delete_xxx(True, data, 2)

    def test_delete_oox_single_threaded(self):
        '''
        Same as test_delete_oox, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_delete_oox_single_threaded.json')
        self.delete_xxx(False, data, 2)

    def delete_xxx(self, multithreaded: bool, data: str, target: int):

        # Setup a database with three entries.
        for i in range(3):

            # Request to save a key and value.
            args = ['set', '--data', data, '--space', 'space{}'.format(i),
              '--key', 'key{}'.format(i), '--value', 'value{}'.format(i)]
            if not multithreaded:
                args += ['--jobs', '1']
            p = pexpect.spawn('./pw-cli', args)

            # Enter the master password.
            try:
                p.expect('master password: ')
            except pexpect.EOF:
                self.fail('EOF while waiting for password prompt')
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for password prompt')
            p.sendline('test')

            # Confirm the master pasword.
            try:
                p.expect('confirm master password: ')
            except pexpect.EOF:
                self.fail('EOF while waiting for password prompt')
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for password prompt')
            p.sendline('test')

            # Now passwand should exit with success.
            p.expect(pexpect.EOF)
            p.close()
            self.assertEqual(p.exitstatus, 0)

        # Now delete the 'target'-th entry.
        args = ['delete', '--data', data, '--space', 'space{}'.format(target),
          '--key', 'key{}'.format(target)]
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with success.
        p.expect(pexpect.EOF)
        p.close()
        self.assertEqual(p.exitstatus, 0)

        # Now retrieve each value.
        for i in range(3):

            args = ['get', '--data', data, '--space', 'space{}'.format(i),
              '--key', 'key{}'.format(i)]
            if not multithreaded:
                args += ['--jobs', '1']
            p = pexpect.spawn('./pw-cli', args)

            # Enter the master password.
            try:
                p.expect('master password: ')
            except pexpect.EOF:
                self.fail('EOF while waiting for password prompt')
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for password prompt')
            p.sendline('test')

            # We should get the original value for everything except the entry
            # we changed.
            try:
                expected = 'value{}'.format(i)
                if i != target:
                    p.expect('{}\r\n'.format(expected))
            except pexpect.EOF:
                self.fail('EOF while waiting for {}'.format(expected))
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for {}'.format(expected))

            # And passwand should exit with success.
            p.expect(pexpect.EOF)
            p.close()
            if i == target:
                self.assertNotEqual(p.exitstatus, 0)
            else:
                self.assertEqual(p.exitstatus, 0)

    def test_delete_nonexistent(self):
        '''
        Test deleting an entry that doesn't exist.
        '''
        data = os.path.join(self.tmp, 'test_delete_nonexistent.json')
        self.delete_nonexistent(True, data)

    def test_delete_nonexistent_single_threaded(self):
        '''
        Same as test_delete_nonexistent, but restrict to a single thread.
        '''
        data = os.path.join(self.tmp, 'test_delete_nonexistent_single_threaded.json')
        self.delete_nonexistent(False, data)

    def delete_nonexistent(self, multithreaded: bool, data: str):

        # Setup a database with three entries.
        for i in range(3):

            # Request to save a key and value.
            args = ['set', '--data', data, '--space', 'space{}'.format(i),
              '--key', 'key{}'.format(i), '--value', 'value{}'.format(i)]
            if not multithreaded:
                args += ['--jobs', '1']
            p = pexpect.spawn('./pw-cli', args)

            # Enter the master password.
            try:
                p.expect('master password: ')
            except pexpect.EOF:
                self.fail('EOF while waiting for password prompt')
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for password prompt')
            p.sendline('test')

            # Confirm the master pasword.
            try:
                p.expect('confirm master password: ')
            except pexpect.EOF:
                self.fail('EOF while waiting for password prompt')
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for password prompt')
            p.sendline('test')

            # Now passwand should exit with success.
            p.expect(pexpect.EOF)
            p.close()
            self.assertEqual(p.exitstatus, 0)

        # Now delete an entry that doesn't exist.
        args = ['delete', '--data', data, '--space', 'space3', '--key', 'key4']
        if not multithreaded:
            args += ['--jobs', '1']
        p = pexpect.spawn('./pw-cli', args)

        # Enter the master password.
        try:
            p.expect('master password: ')
        except pexpect.EOF:
            self.fail('EOF while waiting for password prompt')
        except pexpect.TIMEOUT:
            self.fail('timeout while waiting for password prompt')
        p.sendline('test')

        # Now passwand should exit with failure.
        p.expect(pexpect.EOF)
        p.close()
        self.assertNotEqual(p.exitstatus, 0)

        # Now retrieve each value.
        for i in range(3):

            args = ['get', '--data', data, '--space', 'space{}'.format(i),
              '--key', 'key{}'.format(i)]
            if not multithreaded:
                args += ['--jobs', '1']
            p = pexpect.spawn('./pw-cli', args)

            # Enter the master password.
            try:
                p.expect('master password: ')
            except pexpect.EOF:
                self.fail('EOF while waiting for password prompt')
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for password prompt')
            p.sendline('test')

            # We should get the original value for everything except the entry
            # we changed.
            try:
                expected = 'value{}'.format(i)
                p.expect('{}\r\n'.format(expected))
            except pexpect.EOF:
                self.fail('EOF while waiting for {}'.format(expected))
            except pexpect.TIMEOUT:
                self.fail('timeout while waiting for {}'.format(expected))

            # And passwand should exit with success.
            p.expect(pexpect.EOF)
            p.close()
            self.assertEqual(p.exitstatus, 0)

    def tearDown(self):
        if hasattr(self, 'tmp') and os.path.exists(self.tmp):
            shutil.rmtree(self.tmp)

class Gui(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

        # Create a dummy config with no entries
        self.empty_json = os.path.join(self.tmp, 'empty.json')
        with open(self.empty_json, 'wt') as f:
            json.dump([], f)

    def test_empty_no_entry(self):
        '''
        When asking for a password from a file with no entries, we should
        receive an error.
        '''
        p = subprocess.Popen(['./pw-gui-test-stub', '--data', self.empty_json],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = p.communicate('\n'       # No master password
                                       'hello\n'  # Space "hello"
                                       'world\n') # Key "world"
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, 'failed to find matching entry\n')
        if sys.platform == 'darwin':
            self.assertEqual(p.returncode, 0)
        else:
            self.assertNotEqual(p.returncode, 0)

    def test_cancel_master(self):
        '''
        When cancelling the master password request, we should exit with
        success.
        '''
        p = subprocess.Popen(['./pw-gui-test-stub', '--data', self.empty_json],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = p.communicate('') # EOF indicates cancel
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertEqual(p.returncode, 0)

    def test_cancel_space(self):
        '''
        When cancelling the space request, we should exit with success.
        '''
        p = subprocess.Popen(['./pw-gui-test-stub', '--data', self.empty_json],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = p.communicate('master\n') # EOF indicates cancel
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertEqual(p.returncode, 0)

    def test_cancel_key(self):
        '''
        When cancelling the key request, we should exit with success.
        '''
        p = subprocess.Popen(['./pw-gui-test-stub', '--data', self.empty_json],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = p.communicate('master\n'
                                       'space\n') # EOF indicates cancel
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertEqual(p.returncode, 0)

    def tearDown(self):
        if hasattr(self, 'tmp') and os.path.exists(self.tmp):
            shutil.rmtree(self.tmp)

if __name__ == '__main__':
    unittest.main()
