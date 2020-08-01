import sys
sys.path.append('utils')
import utkeys, utpipes, utpads, utload, utsec

import os
import time
import pandas as pd
import requests as re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AS:
    id = 'AS'
    psk = b'PRE_SHARED_KEY_BETWEEN_AS_AND_VS'
    iv = b'A_VERY_SECRET_IV'
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

        
        if time.time() < float(ts) - 1 or time.time() > float(te) + 1:
            return 'Payload expired'
        
        r = re.post('http://localhost:5000/get', data={ 'uid': uid })
        
        if utsec.validate(r.text.encode()) and utsec.verify(signature, payload, utload.certificate(r.text.encode()).public_key()):
            # token = AS.communicate_token()
            token = os.urandom(31).hex()
            
            r = re.post('http://localhost:5000/get', data={
                'uid': uid
            })

            if utsec.validate(r.text.encode()):
                cert = utload.certificate(r.text.encode())
                message = "{}||{}".format(uid, token)
                pipe = utsec.encode_and_sign(message, cert.public_key(), AS.key)
                tokens = pd.read_csv('./AS/tokens.csv', index_col='token')
                if not token in tokens.index:
                    tokens.loc[token] = [uid, False]
                    tokens.to_csv('./AS/tokens.csv')
                    return '--next'.join(pipe)
                else:
                    return 'token was not valid'
            return 'AS: invalide id'
        else:
            return 'AS: signature problem'
        
    @staticmethod
    def communicate_token(message):
        ct = message.encode('iso8859_16')
        cipher = Cipher(algorithms.AES(AS.psk), modes.CBC(AS.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()
        ret = None
        if decrypted[:2] == b'VS':
            token = str(decrypted[2:])[2:-1]
            tokens = pd.read_csv('./AS/tokens.csv', index_col='token')
            uid = tokens.loc[token, 'id']
            sub_df = tokens[tokens.id == uid]
            
            if sub_df.voted.any():
                ret = '{:<32}'.format('already voted').encode('iso8859_16')
            else:
                ret = '{:<32}'.format('ok').encode('iso8859_16')
                tokens.loc[token, 'voted'] = True
                tokens.to_csv('./AS/tokens.csv')
        else:
            ret = '{:<32}'.format('error').encode('iso8859_16')
        
        cipher = Cipher(algorithms.AES(AS.psk), modes.CBC(AS.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = (encryptor.update(ret) + encryptor.finalize()).decode('iso8859_16')
        return ct
    
    
    @staticmethod
    def pipe_receive(pid, index, piece):
        AS.pipe = utpipes.receive(AS.pipe, pid, index, piece)
        return '{}: received piece {}'.format(pid, index)

