import sys
sys.path.append('utils')
import utkeys, utpipes, utpads, utload, utsec

import os
import time
import json
import logging
import requests as re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


logging.basicConfig(level=logging.DEBUG, filename="./VS/VS.log", format='%(name)s - %(levelname)s - %(message)s')

def write_encrypted_json(obj):
    file = open('./VS/key.key', 'rb')
    key = file.read()
    file.close()
    
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(obj))
    
    with open('./VS/votes.json.encrypted', 'wb') as f:
        f.write(encrypted)


def read_encrypted_json():
    file = open('./VS/key.key', 'rb')
    key = file.read()
    file.close()
    
    data = None
    with open('./VS/votes.json.encrypted', 'rb') as f:
        data = f.read()
    
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)
        
    return json.loads(decrypted)


def log(to_log, should_encrypt=False):
    if should_encrypt:
        file = open('./AS/key.key', 'rb')
        key = file.read()
        file.close()
        
        fernet = Fernet(key)
        encrypted = fernet.encrypt(to_log)
        logging.debug(encrypted)
    else:
        logging.debug(to_log)

class VS:
    id = 'VS'
    psk = b'PRE_SHARED_KEY_BETWEEN_AS_AND_VS'
    iv = b'A_VERY_SECRET_IV'
    key = None
    pipe = {}
    encrypted_only = False
    
    def __init__(self):
        log('generating keys...')
        VS.key = utkeys.generate()
        log('connecting to CA...')
        utkeys.register(VS.id, VS.key)
        log('keys registered')
        log('loading database...')
        votes = read_encrypted_json()
        if len(votes) == 0:
            write_encrypted_json([])
        log('database loaded')
    
    
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
        
        log('new vote request')
        
        if time.time() < float(ts) - 1 or time.time() > float(te) + 1:
            log('payload expired')
            return 'payload expired'
        
        session_key = os.urandom(16).hex()
        is_valid = VS.communicate_token(token, session_key)
        if is_valid:
            log('registering vote')
            votes = []
            votes = read_encrypted_json()
            votes.append({ "vote": vote })
            if not VS.encrypted_only:
                with open('./VS/votes.json', 'w+') as f:
                    json.dump(votes, f)
            write_encrypted_json(votes)
            log('successfully voted')
            return 'successfully voted'
        log('already voted')
        return 'already voted'

        
    @staticmethod
    def communicate_token(t, sk):
        log('cheking token with AS')
        token = ('VS' + t + sk).encode()
        cipher = Cipher(algorithms.AES(VS.psk), modes.CBC(VS.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = (encryptor.update(token) + encryptor.finalize()).decode('iso8859_16')
        r = re.post('http://localhost:5001/communicate_token', data={ 'message': ct })
        
        ret = r.text.encode('iso8859_16')
        log('token answer')
        decryptor = cipher.decryptor()
        decrypted = (decryptor.update(ret) + decryptor.finalize()).decode()
        if decrypted.startswith('ok'):
            log('token is valid')
            return True
        if decrypted.startswith('already'):
            log('token is invalid')
            return False
        log('no answer. retrying in 5 seconds')
        print('retrying in 5 seconds')
        time.sleep(5)
        return VS.communicate_token(t, sk)
    
    
    @staticmethod
    def pipe_receive(pid, index, piece):
        AS.pipe = utpipes.receive(AS.pipe, pid, index, piece)
        return '{}: received piece {}'.format(pid, index)

