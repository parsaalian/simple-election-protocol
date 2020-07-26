import requests as re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import utload
import utsec
import utpipes

def generate():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def register(uid, key):
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    message = "{}||{}".format(uid, pub.decode())
    ca = utload.ca_key()
    pipe = utsec.encode_and_sign(message, ca, key)
    pid = str(pipe[0].encode('iso8859_16'))[:20]
    utpipes.send(pid, pipe, 'http://localhost:5000/pipe_receive')
    r = re.post('http://localhost:5000/register', data={
        'uid': uid,
        'pipe': pid
    })
    try:
        validate(r.text.encode())
        return 'okay'
    except:
        return 'There was a problem registering ca'