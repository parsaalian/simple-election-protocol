import sys
sys.path.append('utils')
import utkeys, utpipes, utpads, utload, utsec

import os
import time
import logging
import pandas as pd
import requests as re
from io import StringIO
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.DEBUG, filename="./AS/AS.log", format='%(name)s - %(levelname)s - %(message)s')

def write_encrypted_csv(df):
    file = open('./AS/key.key', 'rb')
    key = file.read()
    file.close()
    
    s = StringIO()
    df.to_csv(s)
    s = s.getvalue().encode()
    
    fernet = Fernet(key)
    encrypted = fernet.encrypt(s)
    
    with open('./AS/tokens.csv.encrypted', 'wb') as f:
        f.write(encrypted)


def read_encrypted_csv():
    file = open('./AS/key.key', 'rb')
    key = file.read()
    file.close()
    
    data = None
    with open('./AS/tokens.csv.encrypted', 'rb') as f:
        data = f.read()
    
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)
        
    csv = pd.read_csv(StringIO(decrypted.decode()), index_col='token', sep=',')
    return csv


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


class AS:
    id = 'AS'
    psk = b'PRE_SHARED_KEY_BETWEEN_AS_AND_VS'
    iv = b'A_VERY_SECRET_IV'
    key = None
    pipe = {}
    encrypted_only = False
    
    def __init__(self):
        log('generating keys...')
        AS.key = utkeys.generate()
        log('connecting to CA...')
        utkeys.register(AS.id, AS.key)
        log('keys registered')
        log('loading database...')
        current = read_encrypted_csv()
        if len(current) == 0:
            write_encrypted_csv(pd.DataFrame(columns=['token', 'id', 'voted', 'session']))
        log('database loaded')
    
    @staticmethod
    def get_vote_token(pid):
        message = b''
        try:
            for i in range(len(AS.pipe[pid])):
                message += AS.key.decrypt(AS.pipe[pid][str(i)], utpads.pad)
        except Exception as e:
            log(e)
            return 'AS: encryption key is not valid'
        
        payload, signature = message.split(b'--sign')
        
        uid, ts, te = payload.decode('iso8859_16').split('||')
        
        log('token request from {}'.format(uid))
        
        if time.time() < float(ts) - 1 or time.time() > float(te) + 1:
            log('Payload expired')
            return 'Payload expired'
        
        log('getting {} certificates from CA'.format(uid))
        r = re.post('http://localhost:5000/get', data={ 'uid': uid })
        
        if utsec.validate(r.text.encode()) and utsec.verify(signature, payload, utload.certificate(r.text.encode()).public_key()):
            log('generating token')
            token = os.urandom(31).hex()
            
            log('sending token')
            r = re.post('http://localhost:5000/get', data={
                'uid': uid
            })

            if utsec.validate(r.text.encode()):
                cert = utload.certificate(r.text.encode())
                message = "{}||{}".format(uid, token)
                pipe = utsec.encode_and_sign(message, cert.public_key(), AS.key)
                tokens = read_encrypted_csv()
                if not token in tokens.index:
                    tokens.loc[token] = [uid, False, -1]
                    log('saving token in database')
                    if not AS.encrypted_only:
                        tokens.to_csv('./AS/tokens.csv')
                    write_encrypted_csv(tokens)
                    log('token sent')
                    return '--next'.join(pipe)
                else:
                    log('token was not valid')
                    return 'AS: token was not valid'
            log('invalid id')
            return 'AS: invalid id'
        else:
            log('signature problem')
            return 'AS: signature problem'
        
    @staticmethod
    def communicate_token(message):
        log('got message from VS')
        ct = message.encode('iso8859_16')
        cipher = Cipher(algorithms.AES(AS.psk), modes.CBC(AS.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()
        ret = None
        if decrypted[:2] == b'VS':
            token = str(decrypted[2:64])[2:-1]
            session_key = str(decrypted[64:])[2:-1]
            tokens = read_encrypted_csv()
            uid = tokens.loc[token, 'id']
            
            if len(tokens[(tokens.id == uid) & (tokens.voted) & (tokens.session != session_key)]) > 0:
                log('user already voted')
                ret = '{:<32}'.format('already voted').encode('iso8859_16')
            else:
                log('user can vote')
                ret = '{:<32}'.format('ok').encode('iso8859_16')
                tokens.loc[token, 'voted'] = True
                tokens.loc[token, 'session'] = session_key
                log('saving user status in database')
                if not AS.encrypted_only:
                    tokens.to_csv('./AS/tokens.csv')
                write_encrypted_csv(tokens)
        else:
            log('invalid VS message')
            ret = '{:<32}'.format('error').encode('iso8859_16')
        
        cipher = Cipher(algorithms.AES(AS.psk), modes.CBC(AS.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = (encryptor.update(ret) + encryptor.finalize()).decode('iso8859_16')
        log('sending user status to VS')
        return ct
    
    
    @staticmethod
    def pipe_receive(pid, index, piece):
        AS.pipe = utpipes.receive(AS.pipe, pid, index, piece)
        return '{}: received piece {}'.format(pid, index)

