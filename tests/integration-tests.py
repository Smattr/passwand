#!/usr/bin/env python3

'''
Framework for writing integration tests.
'''

import json, os, pexpect, shutil, subprocess, tempfile, unittest

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

        # Request to save a key and value.
        data = os.path.join(self.tmp, 'test_set_basic.json')
        p = pexpect.spawn('./pw-cli', ['set', '--data', data, '--space',
          'space', '--key', 'key', '--value', 'value'])

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
