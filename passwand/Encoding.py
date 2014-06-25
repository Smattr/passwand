import base64

def encode(s):
    return base64.b64encode(s)

def decode(s):
    return base64.b64decode(s)
