import sys
sys.path.append('utils')

import time
import requests as re
from cryptography.hazmat.primitives import serialization, hashes
# from test import pad, spad, generate_keys, load_ca_key, encode_and_sign, load_certificate, validate
import utkeys, utsec, utload, utpipes


class Client:
    id = None
    key = None

    def __init__(self, cid):
        Client.id = cid
        Client.key = utkeys.generate()
        utkeys.register(cid, Client.key)
    
    @staticmethod
    def vote(choice):
        token = Client.get_vote_token()
        Client.send_vote(token, choice)
    
    @staticmethod
    def get_vote_token():
        r = re.post('http://localhost:5000/get', data={
            'uid': 'AS'
        })
        if utsec.validate(r.text.encode()):
            cert = utload.certificate(r.text.encode())
            public_key = cert.public_key()
            message = "{}||{}||{}".format(Client.id, round(time.time()), round(time.time() + 10))
            pipe = utsec.encode_and_sign(message, public_key, Client.key)
            pid = str(pipe[0].encode('iso8859_16'))[:20]
            utpipes.send(pid, pipe, 'http://localhost:5001/pipe_receive')
            r = re.post('http://localhost:5001/get_vote_token', data={
                'pid': pid
            })
            print(r.text)
    
    @staticmethod
    def send_vote(token, vote):
        pass
