import subprocess

def send_string(s):
    subprocess.call(['xte', 'str %s' % s])
