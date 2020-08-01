import sys
sys.path.append('utils')
import utkeys, utsec, utload, utpipes, utpads

import time
import requests as re
from cryptography.hazmat.primitives import serialization, hashes


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
            
            returned_pipe = list(map(lambda x: x.encode('iso8859_16'), r.text.split('--next')))
            
            message = b''
            try:
                for i in range(len(returned_pipe)):
                    message += Client.key.decrypt(returned_pipe[i], utpads.pad)
            except Exception as e:
                print(e)
                return 'AS: encryption key is not valid'
            
            payload, signature = message.split(b'--sign')
            uid, token = payload.decode().split('||')
            if uid == Client.id:
                return token

    
    @staticmethod
    def send_vote(token, vote):
        print(token, vote)
        r = re.post('http://localhost:5000/get', data={
            'uid': 'VS'
        })
        if utsec.validate(r.text.encode()):
            cert = utload.certificate(r.text.encode())
            message = "{}||{}||{}||{}".format(vote, token, round(time.time()), round(time.time() + 10))
            pipe = utsec.encode_and_sign(message, cert.public_key(), Client.key)
            r = re.post('http://localhost:5002/vote', data={
                'message': '--next'.join(pipe)
            })
