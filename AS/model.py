import sys
sys.path.append('utils')
import utkeys, utpipes, utpads, utload, utsec

import os
import time
import requests as re
from cryptography.hazmat.primitives import hashes


class AS:
    id = 'AS'
    psk = 'PRE_SHARED_KEY_BETWEEN_AS_AND_VS'
    key = None
    pipe = {}
    
    def __init__(self):
        AS.key = utkeys.generate()
        utkeys.register(AS.id, AS.key)
    
    @staticmethod
    def get_vote_token(pid):
        message = b''
        try:
            for i in range(len(AS.pipe[pid])):
                message += AS.key.decrypt(AS.pipe[pid][str(i)], utpads.pad)
        except Exception as e:
            print(e)
            return 'AS: encryption key is not valid'
        
        payload, signature = message.split(b'--sign')
        
        uid, ts, te = payload.decode('iso8859_16').split('||')
        
        print(ts, te, time.time())
        
        if time.time() < float(ts) - 1 or time.time() > float(te) + 1:
            print('hey')
            return 'Payload expired'
        
        r = re.post('http://localhost:5000/get', data={ 'uid': uid })
        
        if utsec.validate(r.text.encode()) and utsec.verify(signature, payload, utload.certificate(r.text.encode()).public_key()):
            token = AS.communicate_token()
        else:
            return 'AS: signature problem'
        
    @staticmethod
    def communicate_token():
        
    
    @staticmethod
    def pipe_receive(pid, index, piece):
        AS.pipe = utpipes.receive(AS.pipe, pid, index, piece)
        return '{}: received piece {}'.format(pid, index)

