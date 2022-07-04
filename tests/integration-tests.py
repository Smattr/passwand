#!/usr/bin/env python3

'''
Framework for writing integration tests.
'''

import itertools
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Union
import pexpect
import pytest

PathLike = Union[Path, str]

# a long, hard to guess password for testing purposes
HARD_PASSWORD = 'WEy2zHDJjLsNog8tE5hwvrIR0adAGrR4m5wh6y99ssyo1zzUESw9OWPp8yEL'

def check_output(args: List[PathLike], input: str) -> str:
  return subprocess.check_output(args, input=input, universal_newlines=True)

def run(args: List[PathLike], input: str) -> subprocess.CompletedProcess:
  return subprocess.run(args, input=input, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, universal_newlines=True)

def type_password(process, password: str):
  '''
  Expect a password prompt and enter the given password.
  '''
  process.expect('main password: ')
  process.sendline(password)

def type_password_with_confirmation(process, password: str):
  '''
  Expect a password prompt with confirmation and enter the given password.
  '''
  type_password(process, password)
  process.expect('confirm main password: ')
  process.sendline(password)

def do_get(db: Path, password, space, key, value, multithreaded: bool = False):
  '''
  Run a get operation, expecting the given result.
  '''
  args = ['get', '--data', str(db), '--space', space, '--key', key]
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, password)
  p.expect(f'{value}\r\n')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

def do_list(db: Path, password, entries):
  '''
  Run a list operation, expecting the given results.
  '''
  # Use a single-threaded lookup for deterministic results ordering.
  args = ['list', '--jobs', '1', '--data', str(db)]
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, password)
  for space, key in entries:
    p.expect(f'{space}/{key}\r\n')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus ==  0

def do_set(db: Path, password, space, key, value, multithreaded: bool = False):
  '''
  Run a set operation that is expected to succeed.
  '''
  args = ['set', '--data', str(db), '--space', space, '--key', key, '--value',
          value]
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password_with_confirmation(p, password)
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

def test_cli_help_text():
  '''
  Confirm we can get help text output from the command line interface.
  '''
  text = check_output(['pw-cli', '--help'], '')
  assert text.strip() != ''

@pytest.mark.parametrize('multithreaded', (False, True))
def test_set_basic(tmp_path: Path, multithreaded: bool):
  '''
  Test basic functionality of setting an entry in a blank data file.
  '''
  data = tmp_path / 'set_basic.json'

  # Request to save a key and value.
  do_set(data, 'test', 'space', 'key', 'value', multithreaded)

  # Check the file was actually written.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 1
  assert isinstance(j[0], dict)
  assert 'space' in j[0].keys()
  assert 'key' in j[0].keys()
  assert 'value' in j[0].keys()

@pytest.mark.parametrize('multithreaded', (False, True))
def test_get_basic(tmp_path: Path, multithreaded: bool):
  '''
  Test basic functionality of getting an entry from a small data file. Note
  that if test_set_basic* fails, you should expect this to fail as well.
  '''
  data = tmp_path / 'get_basic.json'

  # Request to save a key and value.
  do_set(data, 'test', 'space', 'key', 'value', multithreaded)

  # Try to read the value back.
  do_get(data, 'test', 'space', 'key', 'value', multithreaded)

@pytest.mark.parametrize('multithreaded', (False, True))
def test_set_overwrite(tmp_path: Path, multithreaded: bool):
  '''
  Test setting an entry that is already set does not overwrite it.
  '''
  data = tmp_path / 'set_overwrite.json'

  # Request to save a key and value.
  do_set(data, 'test', 'space', 'key', 'value', multithreaded)

  # Retrieve the (encrypted) value set.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 1
  assert isinstance(j[0], dict)
  value = j[0]['value']

  # Now try to overwrite the value.
  args = ['set', '--data', str(data), '--space', 'space', '--key', 'key',
          '--value', 'value2']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password_with_confirmation(p, 'test')

  # Passwand should exit with failure.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

  # Confirm that we still have a single entry and it has not been changed.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 1
  assert isinstance(j[0], dict)
  assert value == j[0]['value']

@pytest.mark.parametrize('multithreaded', (False, True))
def test_set_append(tmp_path: Path, multithreaded: bool):
  '''
  Test setting an entry in existing database appends.
  '''
  data = tmp_path / 'set_append.json'

  # Request to save a key and value.
  do_set(data, 'test', 'space', 'key', 'value', multithreaded)

  # Retrieve the (encrypted) value set.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 1
  assert isinstance(j[0], dict)
  value = j[0]['value']

  # Now set another value.
  do_set(data, 'test', 'space', 'key2', 'value2', multithreaded)

  # Confirm that we now have two entries.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 2
  assert isinstance(j[0], dict)
  assert isinstance(j[1], dict)

  # We used different values, so their encrypted forms should be
  # different.
  assert j[1]['value'] != j[0]['value']

  # One of them should be the (unaltered) encrypted version of the first
  # value. Note that we don't guarantee the preservation of the ordering of
  # entries.
  if j[0]['value'] != value:
    assert j[1]['value'] == value

@pytest.mark.parametrize('multithreaded', (False, True))
def test_generate_basic(tmp_path: Path, multithreaded: bool):
  '''
  Test generation of a password.
  '''
  data = tmp_path / 'generate_basic.json'

  # Request generation of a password.
  args = ['generate', '--data', str(data), '--space', 'foo', '--key', 'bar']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password_with_confirmation(p, 'test')

  # Now passwand should exit with success.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # Check the file was actually written.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 1
  assert isinstance(j[0], dict)
  assert 'space' in j[0].keys()
  assert 'key' in j[0].keys()
  assert 'value' in j[0].keys()

  # Try to read the generated password.
  args = ['get', '--data', str(data), '--space', 'foo', '--key', 'bar']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Passwand should output the value and exit with success.
  v = p.read()
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # The value should have some reasonable default length.
  assert len(v.strip()) > 10

  # All characters should be in the expected allowed set.
  assert re.match(b'[a-zA-Z\\d_]+$', v.strip()) is not None

  # The value should exhibit some basic variation.
  assert any(x != v[0] for x in v[1:10])

@pytest.mark.parametrize('multithreaded', (False, True))
def test_generate_length(tmp_path: Path, multithreaded: bool):
  '''
  Test generation of a password with set length.
  '''
  data = tmp_path / 'generate_length.json'

  # Pick some arbitrary non-default length to request
  length = 42

  # Request generation of a password.
  args = ['generate', '--data', str(data), '--space', 'foo', '--key', 'bar',
          '--length', str(length)]
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password_with_confirmation(p, 'test')

  # Now passwand should exit with success.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # Check the file was actually written.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 1
  assert isinstance(j[0], dict)
  assert 'space' in j[0].keys()
  assert 'key' in j[0].keys()
  assert 'value' in j[0].keys()

  # Try to read the generated password.
  args = ['get', '--data', str(data), '--space', 'foo', '--key', 'bar']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Passwand should output the value and exit with success.
  v = p.read()
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # The value should have the length requested.
  assert len(v.strip()) == length

  # All characters should be in the expected allowed set.
  assert re.match(b'[a-zA-Z\\d_]+$', v.strip()) is not None

  # The value should exhibit some basic variation.
  assert any(x != v[0] for x in v[1:10])

@pytest.mark.parametrize('multithreaded', (False, True))
def test_generate_long(tmp_path: Path, multithreaded: bool):
  '''
  Test generation of a long password.
  '''
  data = tmp_path / 'generate_long.json'

  # A length that exceeds the passwand_random_bytes() limit (256).
  length = 4000

  # Request generation of a password.
  args = ['generate', '--data', str(data), '--space', 'foo', '--key', 'bar',
          '--length', str(length)]
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password_with_confirmation(p, 'test')

  # Now passwand should exit with success.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # Check the file was actually written.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 1
  assert isinstance(j[0], dict)
  assert 'space' in j[0].keys()
  assert 'key' in j[0].keys()
  assert 'value' in j[0].keys()

  # Try to read the generated password.
  args = ['get', '--data', str(data), '--space', 'foo', '--key', 'bar']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Passwand should output the value and exit with success.
  v = p.read()
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # The value should have the length requested.
  assert len(v.strip()) == length

  # All characters should be in the expected allowed set.
  assert re.match(b'[a-zA-Z\\d_]+$', v.strip()) is not None

  # The value should exhibit some basic variation.
  assert any(x != v[0] for x in v[1:10])

@pytest.mark.parametrize('multithreaded', (False, True))
def test_change_main_empty(tmp_path: Path, multithreaded: bool):
  '''
  Test changing the main password on an empty database.
  '''
  data = tmp_path / 'change_main_empty.json'

  # Setup an empty database.
  with open(data, 'wt') as f:
    json.dump([], f)

  # Request to change the main password.
  args = ['change-main', '--data', str(data)]
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Set a new main password.
  p.expect('new main password: ')
  p.sendline('test2')

  # Confirm the new main password.
  p.expect('confirm new main password: ')
  p.sendline('test2')

  # Now passwand should exit with success.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # The database should still exist and be empty.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 0

@pytest.mark.parametrize('multithreaded', (False, True))
def test_change_main_mismatch(tmp_path: Path, multithreaded: bool):
  '''
  Test changing the main password but failing to confirm it fails.
  '''
  data = tmp_path / 'change_main_mismatch.json'

  # Setup an empty database.
  with open(data, 'wt') as f:
    json.dump([], f)

  # Request to change the main password.
  args = ['change-main', '--data', str(data)]
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Set a new main password.
  p.expect('new main password: ')
  p.sendline('test2')

  # Enter an incorrect confirmation.
  p.expect('confirm new main password: ')
  p.sendline('test')

  # Now passwand should exit with failure.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

  # The database should still exist and be empty.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 0

@pytest.mark.parametrize('multithreaded', (False, True))
def test_change_main_basic(tmp_path: Path, multithreaded: bool):
  '''
  Test changing the main password does what it says on the box.
  '''
  data = tmp_path / 'change_main_basic.json'

  # Request to save a key and value.
  do_set(data, 'test', 'space', 'key', 'value', multithreaded)

  # Retrieve the (encrypted) value that was written.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 1
  assert isinstance(j[0], dict)
  assert 'space' in j[0].keys()
  assert 'key' in j[0].keys()
  assert 'value' in j[0].keys()
  space = j[0]['space']
  key = j[0]['key']
  value = j[0]['value']

  # Request to change the main password.
  args = ['change-main', '--data', str(data)]
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Set a new main password.
  p.expect('new main password: ')
  p.sendline('test2')

  # Confirm the new main password.
  p.expect('confirm new main password: ')
  p.sendline('test2')

  # Now passwand should exit with success.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # Now the encrypted fields in the database should have changed because
  # the encryption key has changed.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 1
  assert isinstance(j[0], dict)
  assert 'space' in j[0].keys()
  assert 'key' in j[0].keys()
  assert 'value' in j[0].keys()
  assert space != j[0]['space']
  assert key != j[0]['key']
  assert value != j[0]['value']

  # Request retrieval of the entry.
  args = ['get', '--data', str(data), '--space', 'space', '--key', 'key']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the old main password.
  type_password(p, 'test')

  # Now passwand should exit with failure.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

  # Request retrieval of the entry again, but use the new password.
  do_get(data, 'test2', 'space', 'key', 'value', multithreaded)

@pytest.mark.parametrize('multithreaded', (False, True))
def test_list_empty(tmp_path: Path, multithreaded: bool):
  '''
  Test listing an empty database.
  '''
  data = tmp_path / 'list_empty.json'

  # Setup an empty database.
  with open(data, 'wt') as f:
    json.dump([], f)

  # Request to list the database.
  args = ['list', '--data', str(data)]
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Now passwand should exit with success.
  output = p.read()
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # Check we got no entries listed.
  assert output.decode('utf-8', 'replace').strip() == ''

  # Check the database was not changed.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 0

def test_list_wrong_password(tmp_path: Path):
  '''
  Test entering the wrong password during list.
  '''
  data = tmp_path / 'test_list_wrong_password.json'
  list_wrong_password(True, data)

def test_list_wrong_password_single_threaded(tmp_path: Path):
  '''
  Same as test_list_wrong_password, but restrict to a single thread.
  '''
  data = tmp_path / 'test_list_wrong_password_single_threaded.json'
  list_wrong_password(False, data)

def list_wrong_password(multithreaded: bool, data: Path):

  # Request to save a key and value.
  do_set(data, 'test', 'space', 'key', 'value', multithreaded)

  # Now request to list the database.
  args = ['list', '--data', str(data)]
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the wrong main password.
  type_password(p, 'test2')

  # Now passwand should exit with failure.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

def test_list_basic(tmp_path: Path):
  '''
  Test list of a single entry.
  '''
  data = tmp_path / 'test_list_basic.json'
  list_basic(True, data)

def test_list_basic_single_threaded(tmp_path: Path):
  '''
  Same as test_list_basic, but restrict to a single thread.
  '''
  data = tmp_path / 'test_list_basic_single_threaded.json'
  list_basic(False, data)

def list_basic(multithreaded: bool, data: Path):

  # Request to save a key and value.
  do_set(data, 'test', 'space', 'key', 'value', multithreaded)

  # Now request to list the database.
  args = ['list', '--data', str(data)]
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Now we should get the entry and passwand should exit with success.
  output = p.read()
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0
  assert output.decode('utf-8', 'replace').strip() == 'space/key'

def test_set_xoo(tmp_path: Path):
  '''
  Test trying to overwrite the first of a set of three entries.
  '''
  data = tmp_path / 'test_set_xoo.json'
  set_xxx(True, data, 0)

def test_set_xoo_single_threaded(tmp_path: Path):
  '''
  Same as test_set_xoo, but restrict to a single thread.
  '''
  data = tmp_path / 'test_set_xoo_single_threaded.json'
  set_xxx(False, data, 0)

def test_set_oxo(tmp_path: Path):
  '''
  Test trying to overwrite the second of a set of three entries.
  '''
  data = tmp_path / 'test_set_oxo.json'
  set_xxx(True, data, 1)

def test_set_oxo_single_threaded(tmp_path: Path):
  '''
  Same as test_set_oxo, but restrict to a single thread.
  '''
  data = tmp_path / 'test_set_oxo_single_threaded.json'
  set_xxx(False, data, 1)

def test_set_oox(tmp_path: Path):
  '''
  Test trying to overwrite the third of a set of three entries.
  '''
  data = tmp_path / 'test_set_oox.json'
  set_xxx(True, data, 2)

def test_set_oox_single_threaded(tmp_path: Path):
  '''
  Same as test_set_oox, but restrict to a single thread.
  '''
  data = tmp_path / 'test_set_oox_single_threaded.json'
  set_xxx(False, data, 2)

def set_xxx(multithreaded: bool, data: Path, target):

  # Setup a database with three entries.
  for i in range(3):

    # Request to save a key and value.
    do_set(data, 'test', f'space{i}', f'key{i}', f'value{i}', multithreaded)

  # Now try to overwrite the 'target'-th entry.
  args = ['set', '--data', str(data), '--space', f'space{target}', '--key',
          f'key{target}', '--value', 'valuenew']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password_with_confirmation(p, 'test')

  # Now passwand should exit with failure.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

  # Now retrieve each value.
  for i in range(3):
    do_get(data, 'test', f'space{i}', f'key{i}', f'value{i}', multithreaded)

def test_list_standard(tmp_path: Path):
  '''
  Test list of ten entries.
  '''
  data = tmp_path / 'test_list_standard.json'
  list_standard(True, data)

def test_list_standard_single_threaded(tmp_path: Path):
  '''
  Same as test_list_standard, but restrict to a single thread.
  '''
  data = tmp_path / 'test_list_standard_single_threaded.json'
  list_standard(False, data)

def list_standard(multithreaded: bool, data: Path):

  # Request to save 10 keys and values.
  for i in range(10):
    do_set(data, 'test', f'space{i}', f'key{i}', f'value{i}', multithreaded)

  # Now request to list the database.
  args = ['list', '--data', str(data)]
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Scan the entries we get.
  output = p.read()
  seen = set()
  for line in output.decode('utf-8', 'replace').strip().splitlines():
    m = re.match(r'^space(\d+)/key\1', line)
    assert m is not None, 'unexpected entry received from \'list\''
    i = int(m.group(1))
    assert i not in seen, 'duplicate entry in list'
    seen.add(i)
  assert seen == set(range(10)), 'incorrect list of entries'

  # List should exit with success.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

def test_delete_empty(tmp_path: Path):
  '''
  Test delete from an empty database.
  '''
  data = tmp_path / 'test_delete_empty.json'
  delete_empty(True, data)

def test_delete_empty_single_threaded(tmp_path: Path):
  '''
  Same as test_delete_empty, but restrict to a single thread.
  '''
  data = tmp_path / 'test_delete_empty_single_threaded.json'
  delete_empty(False, data)

def delete_empty(multithreaded: bool, data: Path):

  # Setup an empty database.
  with open(data, 'wt') as f:
    json.dump([], f)

  # Request to delete an entry.
  args = ['delete', '--data', str(data), '--space', 'space', '--key', 'key']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Now passwand should exit with failure.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

  # Check the database was not changed.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 0

def test_delete_xoo(tmp_path: Path):
  '''
  Test deleting the first of a set of three entries.
  '''
  data = tmp_path / 'test_delete_xoo.json'
  delete_xxx(True, data, 0)

def test_delete_xoo_single_threaded(tmp_path: Path):
  '''
  Same as test_delete_xoo, but restrict to a single thread.
  '''
  data = tmp_path / 'test_delete_xoo_single_threaded.json'
  delete_xxx(False, data, 0)

def test_delete_oxo(tmp_path: Path):
  '''
  Test deleting the second of a set of three entries.
  '''
  data = tmp_path / 'test_delete_oxo.json'
  delete_xxx(True, data, 1)

def test_delete_oxo_single_threaded(tmp_path: Path):
  '''
  Same as test_delete_oxo, but restrict to a single thread.
  '''
  data = tmp_path / 'test_delete_oxo_single_threaded.json'
  delete_xxx(False, data, 1)

def test_delete_oox(tmp_path: Path):
  '''
  Test deleting the third of a set of three entries.
  '''
  data = tmp_path / 'test_delete_oox.json'
  delete_xxx(True, data, 2)

def test_delete_oox_single_threaded(tmp_path: Path):
  '''
  Same as test_delete_oox, but restrict to a single thread.
  '''
  data = tmp_path / 'test_delete_oox_single_threaded.json'
  delete_xxx(False, data, 2)

def delete_xxx(multithreaded: bool, data: Path, target: int):

  # Setup a database with three entries.
  for i in range(3):

    # Request to save a key and value.
    do_set(data, 'test', f'space{i}', f'key{i}', f'value{i}', multithreaded)

  # Now delete the 'target'-th entry.
  args = ['delete', '--data', str(data), '--space', f'space{target}', '--key',
          f'key{target}']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Now passwand should exit with success.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # Now retrieve each value.
  for i in range(3):

    args = ['get', '--data', str(data), '--space', f'space{i}', '--key',
            f'key{i}']
    if not multithreaded:
      args += ['--jobs', '1']
    p = pexpect.spawn('pw-cli', args, timeout=120)

    # Enter the main password.
    type_password(p, 'test')

    # We should get the original value for everything except the entry
    # we changed.
    expected = f'value{i}'
    if i != target:
      p.expect(f'{expected}\r\n')

    # And passwand should exit with success.
    p.expect(pexpect.EOF)
    p.close()
    if i == target:
      assert p.exitstatus != 0
    else:
      assert p.exitstatus == 0

def test_delete_nonexistent(tmp_path: Path):
  '''
  Test deleting an entry that doesn't exist.
  '''
  data = tmp_path / 'test_delete_nonexistent.json'
  delete_nonexistent(True, data)

def test_delete_nonexistent_single_threaded(tmp_path):
  '''
  Same as test_delete_nonexistent, but restrict to a single thread.
  '''
  data = tmp_path / 'test_delete_nonexistent_single_threaded.json'
  delete_nonexistent(False, data)

def delete_nonexistent(multithreaded: bool, data: Path):

  # Setup a database with three entries.
  for i in range(3):

    # Request to save a key and value.
    do_set(data, 'test', f'space{i}', f'key{i}', f'value{i}', multithreaded)

  # Now delete an entry that doesn't exist.
  args = ['delete', '--data', str(data), '--space', 'space3', '--key', 'key4']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Now passwand should exit with failure.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

  # Now retrieve each value.
  for i in range(3):

    do_get(data, 'test', f'space{i}', f'key{i}', f'value{i}', multithreaded)

def test_concurrent_manipulation(tmp_path: Path):
  '''
  Test modifying a database that is currently being read.
  '''
  data = tmp_path / 'test_concurrent_manipulation.json'
  concurrent_manipulation(True, data)

def test_concurrent_manipulation_single_threaded(tmp_path: Path):
  '''
  Same as test_concurrent_manipulation, but restrict to a single thread.
  '''
  data = tmp_path / 'test_concurrent_manipulation_single_threaded.json'
  concurrent_manipulation(False, data)

def concurrent_manipulation(multithreaded: bool, data: Path):

  # Request to save 10 keys and values.
  for i in range(10):
    do_set(data, 'test', f'space{i}', f'key{i}', f'value{i}', multithreaded)

  # Try to read the value that should be last in the database.
  args = ['get', '--data', str(data), '--space', 'space0', '--key', 'key0']
  if not multithreaded:
    args += ['--jobs', '1']
  get = pexpect.spawn('pw-cli', args, timeout=120)

  # Wait for the password prompt to ensure the 'get' has locked the
  # database.
  get.expect('main password: ')

  # Instead of entering the password immediately, try starting a 'set'
  # operation.
  args = ['set', '--data', str(data), '--space', 'space', '--key', 'key',
    '--value', 'value']
  if not multithreaded:
    args += ['--jobs', '1']
  s = pexpect.spawn('pw-cli', args, timeout=120)

  # The 'set' should fail because it can't lock the database.
  s.expect(pexpect.EOF)
  s.close()
  assert s.exitstatus != 0

  # Return to the 'get' and Enter the main password.
  get.sendline('test')

  # The 'get' should finish and succeed.
  get.expect(pexpect.EOF)
  get.close()
  assert get.exitstatus == 0

def test_check_basic(tmp_path: Path):
  '''
  Test basic functionality of checking an existing weak password entry.
  '''
  data = tmp_path / 'test_check_basic.json'
  check_basic(True, data)

def test_check_basic_single_threaded(tmp_path: Path):
  '''
  Same as test_check_basic, but restrict to a single thread.
  '''
  data = tmp_path / 'test_check_basic_single_threaded.json'
  check_basic(False, data)

def check_basic(multithreaded: bool, data: Path):

  # Save a weak entry that would be easy to crack.
  do_set(data, 'test', 'space', 'key', 'value', multithreaded)

  # Now let's check the entry
  args = ['check', '--data', str(data), '--space', 'space', '--key', 'key']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Now passwand should exit with failure.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

def test_check_basic2(tmp_path: Path):
  '''
  Test basic functionality of checking an existing strong password entry.
  '''
  data = tmp_path / 'test_check_basic2.json'
  check_basic2(True, data)

def test_check_basic2_single_threaded(tmp_path: Path):
  '''
  Same as test_check_basic2, but restrict to a single thread.
  '''
  data = tmp_path / 'test_check_basic2_single_threaded.json'
  check_basic2(False, data)

def check_basic2(multithreaded: bool, data: Path):

  # Save a strong entry that would be hard to crack.
  do_set(data, 'test', 'space', 'key', HARD_PASSWORD)

  # Now let's check the entry
  args = ['check', '--data', str(data), '--space', 'space', '--key', 'key']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Now passwand should exit with success.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

def test_check_hibp_eg(tmp_path: Path):
  '''
  Test checking a password we know to have been breached.
  '''
  data = tmp_path / 'test_check_hibp_eg.json'
  check_hibp_eg(True, data)

def test_check_hibp_eg_single_threaded(tmp_path: Path):
  '''
  Same as test_check_hibp_eg, but restrict to a single thread.
  '''
  data = tmp_path / 'test_check_hibp_eg_single_threaded.json'
  check_hibp_eg(False, data)

def check_hibp_eg(multithreaded: bool, data: Path):

  # Save a password that Troy Hunt gives as an example of something
  # appearing in previous breaches.
  do_set(data, 'test', 'space', 'key', 'P@ssw0rd')

  # Now let's check the entry
  args = ['check', '--data', str(data), '--space', 'space', '--key', 'key']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # Now passwand should exit with failure.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

def test_check_empty_database(tmp_path: Path):
  '''
  Test checking of a database with no entries.
  '''
  data = tmp_path / 'test_check_empty_database.json'
  check_empty_database(True, data)

def test_check_empty_database_single_threaded(tmp_path: Path):
  '''
  Same as test_check_empty_database, but restrict to a single thread.
  '''
  data = tmp_path / 'test_check_empty_database_single_threaded.json'
  check_empty_database(False, data)

def check_empty_database(multithreaded: bool, data: Path):

  # Create an empty database.
  with open(data, 'wt') as f:
    json.dump([], f)

  # Check the database.
  args = ['check', '--data', str(data)]
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # We should exit with success because there are no weak passwords.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

def test_check_000(tmp_path: Path):
  '''
  Test checking a set of entries with no weak passwords.
  '''
  data = tmp_path / 'test_check_000.json'
  check_xxx(True, data, 0)

def test_check_000_single_threaded(tmp_path: Path):
  '''
  Same as test_check_000, but restrict to a single thread.
  '''
  data = tmp_path / 'test_check_000_single_threaded.json'
  check_xxx(False, data, 0)

def test_check_001(tmp_path: Path):
  '''
  Test checking a set of entries with one weak password.
  '''
  data = tmp_path / 'test_check_001.json'
  check_xxx(True, data, 1)

def test_check_001_single_threaded(tmp_path: Path):
  '''
  Same as test_check_001, but restrict to a single thread.
  '''
  data = tmp_path / 'test_check_001_single_threaded.json'
  check_xxx(False, data, 1)

def test_check_010(tmp_path: Path):
  '''
  Test checking a set of entries with one weak password.
  '''
  data = tmp_path / 'test_check_010.json'
  check_xxx(True, data, 2)

def test_check_010_single_threaded(tmp_path: Path):
  '''
  Same as test_check_010, but restrict to a single thread.
  '''
  data = tmp_path / 'test_check_010_single_threaded.json'
  check_xxx(False, data, 2)

def test_check_011(tmp_path: Path):
  '''
  Test checking a set of entries with two weak passwords.
  '''
  data = tmp_path / 'test_check_011.json'
  check_xxx(True, data, 3)

def test_check_011_single_threaded(tmp_path: Path):
  '''
  Same as test_check_011, but restrict to a single thread.
  '''
  data = tmp_path / 'test_check_011_single_threaded.json'
  check_xxx(False, data, 3)

def test_check_100(tmp_path: Path):
  '''
  Test checking a set of entries with one weak password.
  '''
  data = tmp_path / 'test_check_100.json'
  check_xxx(True, data, 4)

def test_check_100_single_threaded(tmp_path: Path):
  '''
  Same as test_check_100, but restrict to a single thread.
  '''
  data = tmp_path / 'test_check_100_single_threaded.json'
  check_xxx(False, data, 4)

def test_check_101(tmp_path: Path):
  '''
  Test checking a set of entries with two weak passwords.
  '''
  data = tmp_path / 'test_check_101.json'
  check_xxx(True, data, 5)

def test_check_101_single_threaded(tmp_path: Path):
  '''
  Same as test_check_101, but restrict to a single thread.
  '''
  data = tmp_path / 'test_check_101_single_threaded.json'
  check_xxx(False, data, 5)

def test_check_110(tmp_path: Path):
  '''
  Test checking a set of entries with two weak passwords.
  '''
  data = tmp_path / 'test_check_110.json'
  check_xxx(True, data, 6)

def test_check_110_single_threaded(tmp_path: Path):
  '''
  Same as test_check_110, but restrict to a single thread.
  '''
  data = tmp_path / 'test_check_110_single_threaded.json'
  check_xxx(False, data, 6)

def test_check_111(tmp_path: Path):
  '''
  Test checking a set of entries with three weak passwords.
  '''
  data = tmp_path / 'test_check_111.json'
  check_xxx(True, data, 7)

def test_check_111_single_threaded(tmp_path: Path):
  '''
  Same as test_check_111, but restrict to a single thread.
  '''
  data = tmp_path / 'test_check_111_single_threaded.json'
  check_xxx(False, data, 7)

def check_xxx(multithreaded: bool, data: Path, weak_mask: int):

  # Save a set of keys and values.
  for i in range(3):
    value = 'value' if (1 << i) & weak_mask else HARD_PASSWORD
    do_set(data, 'test', 'space', f'key{i}', value)

  # First, let's check the passwords individually.
  for i in range(3):
    args = ['check', '--data', str(data), '--space', 'space', '--key',
            f'key{i}']
    if not multithreaded:
      args += ['--jobs', '1']
    p = pexpect.spawn('pw-cli', args, timeout=120)

    # Enter the main password.
    type_password(p, 'test')

    # The check should have identified whether the password was weak.
    p.expect(pexpect.EOF)
    p.close()
    if weak_mask & (1 << i):
      assert p.exitstatus != 0
    else:
      assert p.exitstatus == 0

  # Now let's check them all together.
  args = ['check', '--data', str(data)]
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password(p, 'test')

  # We should exit with error if any password was weak.
  output = p.read().decode('utf-8', 'replace').strip()
  p.expect(pexpect.EOF)
  p.close()
  if weak_mask == 0:
    assert p.exitstatus == 0
  else:
    assert p.exitstatus != 0

  # The output should identify which passwords were weak.
  found = 0
  for line in output.split('\n'):
    m = re.match(r'space/key(\d): weak password', line)
    if m is not None:
      index = int(m.group(1))
      assert ((1 << index) & weak_mask) != 0, \
        'strong password misidentified as weak'
      assert ((1 << index) & found) == 0, \
        'duplicate warnings for weak password entry'
      found |= 1 << index
  assert found == weak_mask, 'missed warning for weak password(s)'

def test_update_overwrite(tmp_path: Path):
  '''
  Test updating an entry that is already set overwrites it.
  '''
  data = tmp_path / 'test_update_overwrite.json'
  update_overwrite(True, data)

def test_update_overwrite_single_threaded(tmp_path: Path):
  '''
  Same as test_update_overwrite, but restrict to a single thread.
  '''
  data = tmp_path / 'test_update_overwrite_single_threaded.json'
  update_overwrite(False, data)

def update_overwrite(multithreaded: bool, data: Path):

  # Request to save a key and value.
  do_set(data, 'test', 'space', 'key', 'value', multithreaded)

  # Retrieve the (encrypted) value set.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 1
  assert isinstance(j[0], dict)
  value = j[0]['value']

  # Now overwrite the value.
  args = ['update', '--data', str(data), '--space', 'space', '--key', 'key',
          '--value', 'value2']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password_with_confirmation(p, 'test')

  # Passwand should exit with success.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # Confirm that we still have a single entry and it has been changed.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 1
  assert isinstance(j[0], dict)
  assert value != j[0]['value']

def test_update_empty(tmp_path: Path):
  '''
  Test updating on an empty database fails.
  '''
  data = tmp_path / 'test_update_empty.json'
  update_empty(True, data)

def test_update_empty_single_threaded(tmp_path: Path):
  '''
  Same as test_update_empty, but restrict to a single thread.
  '''
  data = tmp_path / 'test_update_empty_single_threaded.json'
  update_empty(False, data)

def update_empty(multithreaded: bool, data: Path):

  # Create an empty database.
  with open(data, 'wt') as f:
    f.write('[]')

  # Now try to update a non-existing value.
  args = ['update', '--data', str(data), '--space', 'space', '--key', 'key',
          '--value', 'value']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password_with_confirmation(p, 'test')

  # Passwand should reject this.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

  # Confirm that the database has not changed.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 0

def test_update_non_existing(tmp_path: Path):
  '''
  Test update an entry that doesn't exist.
  '''
  data = tmp_path / 'test_update_non_existing.json'
  update_non_existing(True, data)

def test_update_non_existing_single_threaded(tmp_path: Path):
  '''
  Same as test_update_non_existing, but restrict to a single thread.
  '''
  data = tmp_path / 'test_update_non_existing_single_threaded.json'
  update_non_existing(False, data)

def update_non_existing(multithreaded: bool, data: Path):

  # Request to save a key and value.
  do_set(data, 'test', 'space', 'key', 'value', multithreaded)

  # Retrieve the (encrypted) value set.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 1
  assert isinstance(j[0], dict)
  value = j[0]['value']

  # Now try to update a non-existing value.
  args = ['update', '--data', str(data), '--space', 'space', '--key', 'key2',
          '--value', 'value2']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password_with_confirmation(p, 'test')

  # Passwand should reject this.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

  # Confirm that the database has not changed.
  with open(data, 'rt') as f:
    j = json.load(f)
  assert isinstance(j, list)
  assert len(j) == 1
  assert isinstance(j[0], dict)

  # We should have the original value we set.
  assert j[0]['value'] == value

def test_update_xoo(tmp_path: Path):
  '''
  Test overwriting the first of a set of three entries.
  '''
  data = tmp_path / 'test_update_xoo.json'
  update_xxx(True, data, 0)

def test_update_xoo_single_threaded(tmp_path: Path):
  '''
  Same as test_update_xoo, but restrict to a single thread.
  '''
  data = tmp_path / 'test_update_xoo_single_threaded.json'
  update_xxx(False, data, 0)

def test_update_oxo(tmp_path: Path):
  '''
  Test overwriting the second of a set of three entries.
  '''
  data = tmp_path / 'test_update_oxo.json'
  update_xxx(True, data, 1)

def test_update_oxo_single_threaded(tmp_path: Path):
  '''
  Same as test_update_oxo, but restrict to a single thread.
  '''
  data = tmp_path / 'test_update_oxo_single_threaded.json'
  update_xxx(False, data, 1)

def test_update_oox(tmp_path: Path):
  '''
  Test overwriting the third of a set of three entries.
  '''
  data = tmp_path / 'test_update_oox.json'
  update_xxx(True, data, 2)

def test_update_oox_single_threaded(tmp_path: Path):
  '''
  Same as test_update_oox, but restrict to a single thread.
  '''
  data = tmp_path / 'test_update_oox_single_threaded.json'
  update_xxx(False, data, 2)

def update_xxx(multithreaded: bool, data: Path, target: int):

  # Setup a database with three entries.
  for i in range(3):

    # Request to save a key and value.
    do_set(data, 'test', f'space{i}', f'key{i}', f'value{i}', multithreaded)

  # Now overwrite the 'target'-th entry.
  args = ['update', '--data', str(data), '--space', f'space{target}', '--key',
          f'key{target}', '--value', 'valuenew']
  if not multithreaded:
    args += ['--jobs', '1']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password_with_confirmation(p, 'test')

  # Now passwand should exit with success.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # Now retrieve each value.
  for i in range(3):

    args = ['get', '--data', str(data), '--space', f'space{i}', '--key',
            f'key{i}']
    if not multithreaded:
      args += ['--jobs', '1']
    p = pexpect.spawn('pw-cli', args, timeout=120)

    # Enter the main password.
    type_password(p, 'test')

    # We should get the original value for everything except the entry
    # we changed.
    expected = f'value{"new" if i == target else i}'
    p.expect(f'{expected}\r\n')

    # And passwand should exit with success.
    p.expect(pexpect.EOF)
    p.close()
    assert p.exitstatus == 0

def test_chain_change_main(tmp_path: Path):
  '''
  Test that `pw-cli change-main` works with a chain.

  This operation is kind of pointless as it makes the terminal database no
  longer accessible through the chain, but it should still be allowed.
  '''
  data = tmp_path / 'cli_chain_change_main.json'
  chain = tmp_path / 'cli_chain_change_main_chain.json'

  do_set(data, 'main password', 'foo', 'bar', 'baz')
  do_set(chain, 'chain password', 'foo', 'bar', 'main password')

  # Try to change the main database’s password using the chain.
  args = ['change-main', '--data', str(data), '--chain', str(chain)]
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, 'chain password')
  p.expect('new main password: ')
  p.sendline('foo bar')
  p.expect('confirm new main password: ')
  p.sendline('foo bar')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # The database should no longer be accessible through the chain.
  args = ['list', '--data', str(data), '--chain', str(chain)]
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, 'chain password')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

def test_chain_check(tmp_path: Path):
  '''
  Test that `pw-cli check` works with a chain.
  '''
  data = tmp_path / 'cli_chain_check.json'
  chain = tmp_path / 'cli_chain_check_chain.json'

  # Setup some sample data. Note that the chain password, "main password", is
  # weak, while the terminal value entry, `HARD_PASSWORD` is strong. The check
  # operation we are about to run should check the latter.
  do_set(data, 'main password', 'foo', 'bar', HARD_PASSWORD)
  do_set(chain, 'chain password', 'foo', 'bar', 'main password')

  # Run the check operation via the chain.
  args = ['check', '--data', str(data), '--chain', str(chain)]
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, 'chain password')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

def test_chain_delete(tmp_path: Path):
  '''
  Test that `pw-cli delete` works with a chain.
  '''
  data = tmp_path / 'cli_chain_delete.json'
  chain = tmp_path / 'cli_chain_delete_chain.json'

  # Setup some sample data.
  do_set(data, 'main password', 'foo', 'bar', 'baz')
  do_set(chain, 'chain password', 'foo', 'bar', 'main password')

  # Delete our only entry via the chain.
  args = ['delete', '--data', str(data), '--chain', str(chain), '--space',
          'foo', '--key', 'bar']
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, 'chain password')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # The chain database should be unmodified.
  do_get(chain, 'chain password', 'foo', 'bar', 'main password')

  # The main database should be empty.
  do_list(data, 'main password', ())

def test_chain_generate(tmp_path: Path):
  '''
  Test that `pw-cli generate` works with a chain.
  '''
  data = tmp_path / 'cli_chain_generate.json'
  chain = tmp_path / 'cli_chain_generate_chain.json'

  # Set up an empty main database.
  with open(data, 'wt') as f:
    json.dump([], f)

  # Setup the chain database.
  do_set(chain, 'chain password', 'quux', 'quuz', 'main password')

  # Try to generate a new entry in the main database via the chain.
  args = ['generate', '--data', str(data), '--chain', str(chain), '--space',
          'foo', '--key', 'bar']
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, 'chain password')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # The chain database should be unaltered.
  do_get(chain, 'chain password', 'quux', 'quuz', 'main password')

  # The main database should contain a newly generated entry.
  do_list(data, 'main password', (('foo', 'bar'),))

def test_chain_get(tmp_path: Path):
  '''
  Test that `pw-cli get` works with a chain.
  '''
  data = tmp_path / 'cli_chain_get.json'
  chain = tmp_path / 'cli_chain_get_chain.json'

  # Setup some sample data.
  do_set(data, 'main password', 'foo', 'bar', 'baz')
  do_set(chain, 'chain password', 'foo', 'bar', 'main password')

  # Get the value of the main database entry via the chain.
  args = ['get', '--data', str(data), '--chain', str(chain), '--space', 'foo',
          '--key', 'bar']
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, 'chain password')
  p.expect('baz\r\n')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

def test_chain_list(tmp_path: Path):
  '''
  Test that `pw-cli list` works with a chain.
  '''
  data = tmp_path / 'cli_chain_list.json'
  chain = tmp_path / 'cli_chain_list_chain.json'

  # Setup some sample data.
  do_set(data, 'main password', 'foo', 'bar', 'baz')
  do_set(chain, 'chain password', 'quux', 'quuz', 'main password')

  # Get the value of the main database entry via the chain.
  args = ['list', '--data', str(data), '--chain', str(chain)]
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, 'chain password')
  p.expect('foo/bar\r\n')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

def test_chain_set(tmp_path: Path):
  '''
  Test that `pw-cli set` works with a chain.
  '''
  data = tmp_path / 'cli_chain_set.json'
  chain = tmp_path / 'cli_chain_set_chain.json'

  # Setup some sample data.
  do_set(data, 'main password', 'foo', 'bar', 'baz')
  do_set(chain, 'chain password', 'quux', 'quuz', 'main password')

  # Set of the existing entry should fail.
  args = ['set', '--data', str(data), '--chain', str(chain), '--space', 'foo',
          '--key', 'bar', '--value', 'value']
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, 'chain password')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

  # Both databases should be unaltered.
  do_get(data, 'main password', 'foo', 'bar', 'baz')
  do_get(chain, 'chain password', 'quux', 'quuz', 'main password')

  # Set of a new entry should work.
  args = ['set', '--data', str(data), '--chain', str(chain), '--space', 'foo',
          '--key', 'qux', '--value', 'corge']
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, 'chain password')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # The chain database should be unaltered.
  do_get(chain, 'chain password', 'quux', 'quuz', 'main password')

  # The main database should contain the original entry and the new one.
  do_list(data, 'main password', (('foo', 'qux'), ('foo', 'bar')))
  do_get(data, 'main password', 'foo', 'bar', 'baz')
  do_get(data, 'main password', 'foo', 'qux', 'corge')

def test_chain_update(tmp_path: Path):
  '''
  Test that `pw-cli update` works with a chain.
  '''
  data = tmp_path / 'cli_chain_update.json'
  chain = tmp_path / 'cli_chain_update_chain.json'

  # Setup some sample data.
  do_set(data, 'main password', 'foo', 'bar', 'baz')
  do_set(chain, 'chain password', 'quux', 'quuz', 'main password')

  # Update of a non-existent entry should fail.
  args = ['update', '--data', str(data), '--chain', str(chain), '--space',
          'foo', '--key', 'baz', '--value', 'value']
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, 'chain password')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

  # Both databases should be unaltered.
  do_get(data, 'main password', 'foo', 'bar', 'baz')
  do_get(chain, 'chain password', 'quux', 'quuz', 'main password')

  # Update of an existing entry should work.
  args = ['update', '--data', str(data), '--chain', str(chain), '--space',
          'foo', '--key', 'bar', '--value', 'corge']
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, 'chain password')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # The chain database should be unaltered.
  do_get(chain, 'chain password', 'quux', 'quuz', 'main password')

  # The main database should contain the altered entry.
  do_list(data, 'main password', (('foo', 'bar'),))
  do_get(data, 'main password', 'foo', 'bar', 'corge')

def test_cli_skip_chain(tmp_path: Path):
  '''
  Test we can bypass a chain link and enter the main password directly.
  '''
  data = tmp_path / 'cli_skip_chain.json'
  chain = tmp_path / 'cli_skip_chain_chain.json'

  # Setup some sample data.
  do_set(data, 'main password', 'foo', 'bar', 'baz')
  do_set(chain, 'chain password', 'quux', 'quuz', 'main password')

  # Do a chain lookup but bypass the chain database password.
  args = ['get', '--data', str(data), '--chain', str(chain), '--space', 'foo',
          '--key', 'bar']
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, '')
  type_password(p, 'main password')
  p.expect('baz\r\n')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

def test_chain_bad_password(tmp_path: Path):
  '''
  A chained database should not accept the password for a later database.
  '''
  data = tmp_path / 'cli_skip_chain.json'
  chain = tmp_path / 'cli_skip_chain_chain.json'

  # Setup some sample data.
  do_set(data, 'main password', 'foo', 'bar', 'baz')
  do_set(chain, 'chain password', 'quux', 'quuz', 'main password')

  # Do a chain lookup with the main database password.
  args = ['get', '--data', str(data), '--chain', str(chain), '--space', 'foo',
          '--key', 'bar']
  p = pexpect.spawn('pw-cli', args, timeout=120)
  type_password(p, 'main password')
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus != 0

def test_cli_empty_password():
  '''
  Test that various combinations of using the empty string as a password work.
  '''

  # Using an empty string as the main database password.
  with tempfile.TemporaryDirectory() as tmp:
    data = Path(tmp) / 'data.json'
    do_set(data, '', 'foo', 'bar', 'baz')
    do_get(data, '', 'foo', 'bar', 'baz')

  # Using a chain to a main database with an empty password.
  with tempfile.TemporaryDirectory() as tmp:
    data = Path(tmp) / 'data.json'
    chain = Path(tmp) / 'chain.json'
    do_set(data, '', 'foo', 'bar', 'baz')
    do_set(chain, 'chain password', 'ignored', 'ignored', '')

    args = ['get', '--data', str(data), '--chain', str(chain), '--space',
            'foo', '--key', 'bar']
    p = pexpect.spawn('pw-cli', args, timeout=120)
    type_password(p, 'chain password')
    p.expect('baz\r\n')
    p.expect(pexpect.EOF)
    p.close()
    assert p.exitstatus == 0

  # Using an intermediate chain database with an empty password.
  with tempfile.TemporaryDirectory() as tmp:
    data = Path(tmp) / 'data.json'
    chain1 = Path(tmp) / 'chain1.json'
    chain2 = Path(tmp) / 'chain2.json'
    do_set(data, 'main password', 'foo', 'bar', 'baz')
    do_set(chain1, '', 'ignored', 'ignored', 'main password')
    do_set(chain2, 'chain password', 'ignored', 'ignored', '')

    args = ['get', '--data', str(data), '--chain', str(chain2), '--chain',
            str(chain1), '--space', 'foo', '--key', 'bar']
    p = pexpect.spawn('pw-cli', args, timeout=120)
    type_password(p, 'chain password')
    p.expect('baz\r\n')
    p.expect(pexpect.EOF)
    p.close()
    assert p.exitstatus == 0

  # Using an empty password on the top-most chain link is not really possible,
  # because an empty string always indicates to skip the chain link.
  with tempfile.TemporaryDirectory() as tmp:
    data = Path(tmp) / 'data.json'
    chain = Path(tmp) / 'chain.json'
    do_set(data, 'main password', 'foo', 'bar', 'baz')
    do_set(chain, '', 'ignored', 'ignored', 'main password')

    args = ['get', '--data', str(data), '--chain', str(chain), '--space',
            'foo', '--key', 'bar']
    p = pexpect.spawn('pw-cli', args, timeout=120)
    type_password(p, '')
    type_password(p, 'main password')
    p.expect('baz\r\n')
    p.expect(pexpect.EOF)
    p.close()
    assert p.exitstatus == 0

def test_work_factor_error(tmp_path: Path):
  '''
  Passing an invalid --work-factor should result in a sensible error.
  '''
  data = tmp_path / 'cli_work_factor_error.json'

  for args in (('change-main',),
               ('check',),
               ('delete', '--space', 'foo', '--key', 'bar'),
               ('get',    '--space', 'foo', '--key', 'bar'),
               ('list',),
               ('set',    '--space', 'foo', '--key', 'bar', '--value', 'baz'),
               ('update', '--space', 'foo', '--key', 'bar', '--value',
                 'baz')):
    for wf in ('9', '32'):
      argv = list(args) + ['--data', str(data), '--work-factor', wf]
      p = pexpect.spawn('pw-cli', argv, timeout=120)

      # The command should error with something mentioning
      # --work-factor.
      p.expect('--work-factor')
      p.expect(pexpect.EOF)
      p.close()
      assert p.exitstatus != 0

      # The database should not have been created.
      assert not data.exists()

def test_gui_empty_no_entry(tmp_path: Path):
  '''
  When asking for a password from a file with no entries, we should receive an
  error.
  '''

  # Create a dummy config with no entries
  empty_json = tmp_path / 'empty.json'
  with open(empty_json, 'wt') as f:
    json.dump([], f)

  args = ['pw-gui-test-stub', '--data', empty_json]
  input = ('\n'       # No main password
           'hello\n'  # Space "hello"
           'world\n') # Key "world"
  p = run(args, input)
  assert p.stdout == ''
  assert p.stderr == 'failed to find matching entry\n'
  if sys.platform == 'darwin':
    assert p.returncode == 0
  else:
    assert p.returncode != 0

def test_gui_cancel_main(tmp_path: Path):
  '''
  When cancelling the main password request, we should exit with success.
  '''

  # Create a dummy config with no entries
  empty_json = tmp_path / 'empty.json'
  with open(empty_json, 'wt') as f:
    json.dump([], f)

  args = ['pw-gui-test-stub', '--data', empty_json]
  input = '' # EOF indicates cancel
  p = run(args, input)
  assert p.stdout == ''
  assert p.stderr == ''
  p.check_returncode()

def test_gui_cancel_space(tmp_path: Path):
  '''
  When cancelling the space request, we should exit with success.
  '''

  # Create a dummy config with no entries
  empty_json = tmp_path / 'empty.json'
  with open(empty_json, 'wt') as f:
    json.dump([], f)

  args = ['pw-gui-test-stub', '--data', empty_json]
  input = 'main\n' # EOF indicates cancel
  p = run(args, input)
  assert p.stdout == ''
  assert p.stderr == ''
  p.check_returncode()

def test_gui_cancel_key(tmp_path: Path):
  '''
  When cancelling the key request, we should exit with success.
  '''

  # Create a dummy config with no entries
  empty_json = tmp_path / 'empty.json'
  with open(empty_json, 'wt') as f:
    json.dump([], f)

  args = ['pw-gui-test-stub', '--data', empty_json]
  input = ('main\n'
           'space\n') # EOF indicates cancel
  p = run(args, input)
  assert p.stdout == ''
  assert p.stderr == ''
  p.check_returncode()

def test_gui_concurrent_manipulation(tmp_path: Path):
  '''
  Test reading from the database while it is being written to.
  '''

  data = tmp_path / 'concurrent_manipulation.json'

  # Request to save 10 keys and values.
  for i in range(10):
    do_set(data, 'test', f'space{i}', f'key{i}', f'value{i}')

  # Set an entry, an operation that should run for a while.
  args = ['set', '--data', str(data), '--space', 'space', '--key', 'key',
          '--value', 'value']
  s = pexpect.spawn('pw-cli', args, timeout=120)

  # Wait for password prompt to ensure the 'set' has locked the database.
  s.expect('main password: ')

  # Try to read from the database. This should fail because it should be
  # locked by the 'set'.
  args = ['pw-gui-test-stub', '--data', data]
  input = ('space\n'
           'key\n'
           'test\n')
  p = run(args, input)
  assert p.stderr.strip().startswith('failed to lock database')
  if sys.platform == 'darwin':
    assert p.returncode == 0
  else:
    assert p.returncode != 0

  # Cleanup the 'set'.
  s.sendline('test')
  s.expect('confirm main password: ')
  s.sendline('test')
  s.expect(pexpect.EOF)
  s.close()

def test_gui_error_rate(tmp_path: Path):
  '''
  Ensure that entering the wrong password results in only a single error.
  '''
  data = tmp_path / 'error_rate.json'

  # Request to save 2 keys and values.
  for i in range(2):
    do_set(data, 'test', f'space{i}', f'key{i}', f'value{i}')

  # Now try to retrieve an entry but enter the wrong password.
  args = ['pw-gui-test-stub', '--data', data]
  input = ('space0\n'
           'key0\n'
           'not test\n')
  p = run(args, input)

  if sys.platform == 'darwin':
    assert p.returncode == 0
  else:
    assert p.returncode != 0

  # We should have only received a single line of error content.
  assert p.stderr.count('\n') < 2

def test_gui_chain_basic(tmp_path: Path):
  '''
  Basic expected usage of --chain.
  '''
  data = tmp_path / 'chain_basic.json'
  chain = tmp_path / 'chain_basic_chain.json'

  # Setup a database with a couple of entries.
  for i in range(2):
    do_set(data, 'foo', f'space{i}', f'key{i}', f'value{i}')

  # Setup the chain database.
  do_set(chain, 'bar', 'ignored', 'ignored', 'foo')

  # Confirm the we can now lookup both entries using the chain.
  for i in range(2):
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain]
    input = (f'space{i}\n'
             f'key{i}\n'
             'bar\n')
    stdout = check_output(args, input)
    assert stdout == f'value{i}\n'

    # The entries should *not* be retrievable using the primary
    # database’s password.
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain]
    input = (f'space{i}\n'
             f'key{i}\n'
             'foo\n')
    p = run(args, input)
    if sys.platform == 'darwin':
      assert p.returncode == 0
    else:
      assert p.returncode != 0
    assert p.stdout != f'value{i}\n'
    assert p.stderr != ''

def test_gui_chain_double(tmp_path: Path):
  '''
  It should be possible to use --chain multiple times.
  '''
  data = tmp_path / 'chain_double.json'
  chain1 = tmp_path / 'chain_double_chain1.json'
  chain2 = tmp_path / 'chain_double_chain2.json'

  # Setup a database with a couple of entries.
  for i in range(2):
    do_set(data, 'foo', f'space{i}', f'key{i}', f'value{i}')

  # Setup the first chain database.
  do_set(chain1, 'bar', 'ignored', 'ignored', 'foo')

  # Setup the second chain database.
  do_set(chain2, 'baz', 'ignored', 'ignored', 'bar')

  # Confirm the we can now lookup both entries using the chain.
  for i in range(2):
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain2,
            '--chain', chain1]
    input = (f'space{i}\n'
             f'key{i}\n'
             'baz\n')
    stdout = check_output(args, input)
    assert stdout == f'value{i}\n'

    # The entries should *not* be retrievable using the primary
    # database’s password.
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain2,
            '--chain', chain1]
    input = (f'space{i}\n'
             f'key{i}\n'
             'foo\n')
    p = run(args, input)
    if sys.platform == 'darwin':
      assert p.returncode == 0
    else:
      assert p.returncode != 0
    assert p.stdout != f'value{i}\n'
    assert p.stderr != ''

    # The entries should also not be retrievable using the main password
    # of the intermediate chain database.
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain2,
            '--chain', chain1]
    input = (f'space{i}\n'
             f'key{i}\n'
             'bar\n')
    p = run(args, input)
    if sys.platform == 'darwin':
      assert p.returncode == 0
    else:
      assert p.returncode != 0
    assert p.stdout != f'value{i}\n'
    assert p.stderr != ''

    # Passing the chain in the wrong order should also fail with any of
    # the main passwords.
    for mainpass in ('foo', 'bar', 'baz'):
      args = ['pw-gui-test-stub', '--data', data, '--chain', chain1,
              '--chain', chain2]
      input = (f'space{i}\n'
               f'key{i}\n'
               f'{mainpass}\n')
      p = run(args, input)
      if sys.platform == 'darwin':
        assert p.returncode == 0
      else:
        assert p.returncode != 0
      assert p.stdout != f'value{i}\n'
      assert p.stderr != ''

def test_gui_chain_self(tmp_path: Path):
  '''
  Chaining a database to itself.
  '''
  # This makes no real sense, but there is no reason to prevent a user
  # doing this.

  data = tmp_path / 'chain_self.json'

  # Setup a database with a sole entry.
  do_set(data, 'foo', 'space', 'key', 'foo')

  # Now chain the database to itself and try to retrieve the entry.
  args = ['pw-gui-test-stub', '--data', data, '--chain', data]
  input = ('space\n'
           'key\n'
           'foo\n')
  stdout = check_output(args, input)
  assert stdout == 'foo\n'

def test_gui_chain_work_factor(tmp_path: Path):
  '''
  Chaining multiple databases with different --work-factor settings.
  '''
  data = tmp_path / 'chain_work_factor.json'
  chain1 = tmp_path / 'chain_work_factor_chain.json'
  chain2 = tmp_path / 'chain_work_factor_chain2.json'

  # Setup a database with a couple of entries.
  for i in range(2):
    args = ['set', '--work-factor', '10', '--data', str(data), '--space',
            f'space{i}', '--key', f'key{i}', '--value', f'value{i}']
    p = pexpect.spawn('pw-cli', args, timeout=120)

    # Enter the main password.
    type_password_with_confirmation(p, 'foo')

    # Now passwand should exit with success.
    p.expect(pexpect.EOF)
    p.close()
    assert p.exitstatus == 0

  # Setup the first chain database.
  args = ['set', '--work-factor', '11', '--data', str(chain1), '--space',
          'ignored', '--key', 'ignored', '--value', 'foo']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password_with_confirmation(p, 'bar')

  # Now passwand should exit with success.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # Setup the second chain database.
  args = ['set', '--work-factor', '12', '--data', str(chain2), '--space',
          'ignored', '--key', 'ignored', '--value', 'bar']
  p = pexpect.spawn('pw-cli', args, timeout=120)

  # Enter the main password.
  type_password_with_confirmation(p, 'baz')

  # Now passwand should exit with success.
  p.expect(pexpect.EOF)
  p.close()
  assert p.exitstatus == 0

  # Confirm the we can now lookup both entries using the chain.
  for i in range(2):
    for a, b, c in itertools.permutations(('10', '11', '12')):

      args = ['pw-gui-test-stub', '--data', data, '--work-factor', a,
              '--chain', chain2, '--work-factor', b, '--chain', chain1,
              '--work-factor', c]
      input = (f'space{i}\n'
               f'key{i}\n'
               'baz\n')
      p = run(args, input)

      # This should only succeed if we used the right work factors.
      if a == '10' and b == '12' and c == '11':
        assert p.returncode == 0
        assert p.stdout == f'value{i}\n'

      else:
        if sys.platform == 'darwin':
          assert p.returncode == 0
        else:
          assert p.returncode != 0
        assert p.stdout != f'value{i}\n'
        assert p.stderr != ''

def test_gui_chain_not_one(tmp_path: Path):
  '''
  Chaining a database with more than one entry should fail.
  '''
  data = tmp_path / 'chain_not_one.json'
  chain1 = tmp_path / 'chain_not_one_chain1.json'
  chain2 = tmp_path / 'chain_not_one_chain2.json'

  # Setup a database with a couple of entries.
  for i in range(2):
    do_set(data, 'foo', f'space{i}', f'key{i}', f'value{i}')

  # Setup the chain database.
  do_set(chain1, 'bar', 'space0', 'key0', 'foo')

  # Write a second entry to the chain database.
  do_set(chain1, 'bar', 'space1', 'key1', 'baz')

  # We should be unable to use this as a chain.
  for i in range(2):
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain1]
    input = (f'space{i}\n'
             f'key{i}\n'
             'bar\n')
    p = run(args, input)
    if sys.platform == 'darwin':
      assert p.returncode == 0
    else:
      assert p.returncode != 0
    assert p.stdout != f'value{i}\n'
    assert p.stderr != ''

  # Try the same, setting up the chain database entries in the opposite
  # order just to make sure.
  do_set(chain2, 'bar', 'space0', 'key0', 'baz')
  do_set(chain2, 'bar', 'space1', 'key1', 'foo')

  # We should be unable to use this as a chain.
  for i in range(2):
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain2]
    input = (f'space{i}\n'
             f'key{i}\n'
             'bar\n')
    p = run(args, input)
    if sys.platform == 'darwin':
      assert p.returncode == 0
    else:
      assert p.returncode != 0
    assert p.stdout != f'value{i}\n'
    assert p.stderr != ''

def test_gui_chain_bypass(tmp_path: Path):
  '''
  Entering an empty password for a chained database should allow us to
  directly enter the primary database’s password.
  '''
  data = tmp_path / 'chain_bypass.json'
  chain = tmp_path / 'chain_bypass_chain.json'

  # Setup a database with a couple of entries.
  for i in range(2):
    do_set(data, 'foo', f'space{i}', f'key{i}', f'value{i}')

  # Setup the chain database.
  do_set(chain, 'bar', 'ignored', 'ignored', 'foo')

  # Confirm the we can now lookup both entries by bypassing the chain.
  for i in range(2):
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain]
    input = (f'space{i}\n'
             f'key{i}\n'
             '\n'
             'foo\n')
    stdout = check_output(args, input)
    assert stdout == f'value{i}\n'

    # The entries should *not* be retrievable using the primary
    # database’s password.
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain]
    input = (f'space{i}\n'
             f'key{i}\n'
             'foo\n')
    p = run(args, input)
    if sys.platform == 'darwin':
      assert p.returncode == 0
    else:
      assert p.returncode != 0
    assert p.stdout != f'value{i}\n'
    assert p.stderr != ''

    # The entries should also *not* be retrievable by bypassing the
    # chain but then entering the chain’s password.
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain]
    input = (f'space{i}\n'
             f'key{i}\n'
             '\n'
             'bar\n')
    p = run(args, input)
    if sys.platform == 'darwin':
      assert p.returncode == 0
    else:
      assert p.returncode != 0
    assert p.stdout != f'value{i}\n'
    assert p.stderr != ''

def test_gui_chain_bypass_double(tmp_path: Path):
  '''
  Confirm we can bypass multiple chained databases.
  '''
  data = tmp_path / 'chain_bypass_double.json'
  chain1 = tmp_path / 'chain_bypass_double_chain1.json'
  chain2 = tmp_path / 'chain_bypass_double_chain2.json'

  # Setup a database with a couple of entries.
  for i in range(2):
    do_set(data, 'foo', f'space{i}', f'key{i}', f'value{i}')

  # Setup the first chain database.
  do_set(chain1, 'bar', 'ignored', 'ignored', 'foo')

  # Setup the second chain database.
  do_set(chain2, 'baz', 'ignored', 'ignored', 'bar')

  # Confirm the we can now lookup both entries skipping the first chain.
  for i in range(2):
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain2,
            '--chain', chain1]
    input = (f'space{i}\n'
             f'key{i}\n'
             '\n'
             'bar\n')
    stdout = check_output(args, input)
    assert stdout == f'value{i}\n'

    # This should *not* work if we do not skip the chain.
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain2,
            '--chain', chain1]
    input = (f'space{i}\n'
             f'key{i}\n'
             'bar\n')
    p = run(args, input)
    if sys.platform == 'darwin':
      assert p.returncode == 0
    else:
      assert p.returncode != 0
    assert p.stdout != f'value{i}\n'
    assert p.stderr != ''

  # Confirm the we can now lookup both entries skipping both chains.
  for i in range(2):
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain2,
            '--chain', chain1]
    input = (f'space{i}\n'
             f'key{i}\n'
             '\n'
             '\n'
             'foo\n')
    stdout = check_output(args, input)
    assert stdout == f'value{i}\n'

    # This should *not* work using either of the intermediate
    # passphrases.
    args = ['pw-gui-test-stub', '--data', data, '--chain', chain2,
            '--chain', chain1]
    input = (f'space{i}\n'
             f'key{i}\n'
             '\n'
             '\n'
             'bar\n')
    p = run(args, input)
    if sys.platform == 'darwin':
      assert p.returncode == 0
    else:
      assert p.returncode != 0
    assert p.stdout != f'value{i}\n'
    assert p.stderr != ''

    args = ['pw-gui-test-stub', '--data', data, '--chain', chain2,
            '--chain', chain1]
    input = (f'space{i}\n'
             f'key{i}\n'
             '\n'
             '\n'
             'baz\n')
    p = run(args, input)
    if sys.platform == 'darwin':
      assert p.returncode == 0
    else:
      assert p.returncode != 0
    assert p.stdout != f'value{i}\n'
    assert p.stderr != ''

def test_gui_chain_over_bypass(tmp_path: Path):
  '''
  Attempting to bypass beyond the length of the chain should fail.
  '''
  data = tmp_path / 'chain_over_bypass.json'
  chain = tmp_path / 'chain_over_bypass_chain.json'

  # Setup a database with a couple of entries.
  for i in range(2):
    do_set(data, 'foo', f'space{i}', f'key{i}', f'value{i}')

  # Setup the chain database.
  do_set(chain, 'bar', 'ignored', 'ignored', 'foo')

  # Bypassing without a chain should fail.
  for i in range(2):
    for passphrase in ('foo', 'bar'):
      args = ['pw-gui-test-stub', '--data', data]
      input = (f'space{i}\n'
               f'key{i}\n'
               '\n'
               f'{passphrase}\n')
      p = run(args, input)
      if sys.platform == 'darwin':
        assert p.returncode == 0
      else:
        assert p.returncode != 0
      assert p.stdout != f'value{i}\n'
      assert p.stderr != ''

  # Bypassing more times than we have chain links should fail.
  for i in range(2):
    for passphrase in ('foo', 'bar'):
      args = ['pw-gui-test-stub', '--data', data, '--chain', chain]
      input = (f'space{i}\n'
               f'key{i}\n'
               '\n'
               '\n'
               '{passphrase}\n')
      p = run(args, input)
      if sys.platform == 'darwin':
        assert p.returncode == 0
      else:
        assert p.returncode != 0
      assert p.stdout != f'value{i}\n'
      assert p.stderr != ''

def chain_leak_strlen(tmp_path: Path, main_longer: bool):

  # Two passwords of mismatched length
  short = 'short'
  long = 'long password'

  # Create a database with a single entry.
  data = tmp_path / f'chain_leak_regression_{main_longer}.json'
  password = long if main_longer else short
  do_set(data, password, 'foo', 'bar', 'baz')

  # Create a chain database with a short password.
  chain = tmp_path / f'chain_leak_regression_chain_{main_longer}.json'
  value = long if main_longer else short
  password = short if main_longer else long
  do_set(chain, password, 'foo', 'bar', value)

  # Attempt a retrieval through the chain to see if it leaks memory.
  args = ['pw-gui-test-stub', '--data', data, '--chain', chain]
  input = ('foo\n'
           'bar\n'
           f'{short if main_longer else long}\n')
  p = run(args, input)
  assert p.stdout == 'baz\n'
  assert p.stderr == ''
  p.check_returncode()

def test_gui_chain_leak_strlen1(tmp_path: Path):
  '''
  Check the GUI does not leak memory with mismatched password lengths.

  When working on chained database support for the CLI, one of my
  intermediate states accidentally introduced a memory leak in the secure
  heap when the main database’s password was shorter than the chained
  database’s password. While this leak did not exist in the GUI
  implementation, it seemed prudent to add a paranoia test that we never
  introduced such a thing.
  '''
  chain_leak_strlen(tmp_path, False)

def test_gui_chain_leak_strlen2(tmp_path: Path):
  '''
  See test_chain_leak_strlen1.
  '''
  chain_leak_strlen(tmp_path, True)
