#!/usr/bin/env python3

'''
Framework for writing integration tests.
'''

import json, os, pexpect, shutil, subprocess, sys, tempfile, unittest

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
