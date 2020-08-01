import sys
sys.path.append('utils')
import utkeys, utpipes, utpads, utload, utsec

import os
import time
import json
import requests as re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class VS:
    id = 'VS'
    psk = b'PRE_SHARED_KEY_BETWEEN_AS_AND_VS'
    iv = b'A_VERY_SECRET_IV'
    key = None
    pipe = {}
    
    def __init__(self):
        VS.key = utkeys.generate()
        utkeys.register(VS.id, VS.key)
    
    
    @staticmethod
    def vote(pipe):
        message = b''
        try:
            for i in range(len(pipe)):
                message += VS.key.decrypt(pipe[i], utpads.pad)
        except Exception as e:
            print(e)
            return 'VS: encryption key is not valid'
        
        payload, signature = message.split(b'--sign')
        
        vote, token, ts, te = payload.decode('iso8859_16').split('||')
        
        if time.time() < float(ts) - 1 or time.time() > float(te) + 1:
            return 'Payload expired'
        
        is_valid = VS.communicate_token(token)
        if is_valid:
            votes = []
            with open('./VS/votes.json', 'r') as f:
                votes = json.load(f)
            votes.append({ "vote": vote })
            with open('./VS/votes.json', 'w+') as f:
                json.dump(votes, f)
            return 'successfully voted'
        return 'already voted'

        
    @staticmethod
    def communicate_token(t):
        token = ('VS' + t).encode()
        cipher = Cipher(algorithms.AES(VS.psk), modes.CBC(VS.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = (encryptor.update(token) + encryptor.finalize()).decode('iso8859_16')
        r = re.post('http://localhost:5001/communicate_token', data={ 'message': ct })
        
        ret = r.text.encode('iso8859_16')
        decryptor = cipher.decryptor()
        decrypted = (decryptor.update(ret) + decryptor.finalize()).decode()
        if decrypted.startswith('ok'):
            return True
        if decrypted.startswith('already'):
            return False
        print('retrying in 5 seconds')
        time.sleep(5)
        return VS.communicate_token(t)
    
    
    @staticmethod
    def pipe_receive(pid, index, piece):
        AS.pipe = utpipes.receive(AS.pipe, pid, index, piece)
        return '{}: received piece {}'.format(pid, index)

