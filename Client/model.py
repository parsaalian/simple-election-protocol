import sys
sys.path.append('utils')

import datetime
import requests as re
from cryptography.hazmat.primitives import serialization, hashes
# from test import pad, spad, generate_keys, load_ca_key, encode_and_sign, load_certificate, validate
import utkeys


class Client:
    id = None
    key = None

    def __init__(self, cid):
        Client.id = cid
        Client.key = utkeys.generate()
        utkeys.register(cid, Client.key)
        
    

    '''
    def AS_request(self):
        nonce1 = os.urandom(16)
        print(self.id.encode() + nonce1)
        sign = self.key.sign(self.id.encode() + nonce1, spad, hashes.SHA256())
        payload = "{}||{}||".format(self.id, nonce1).encode() + sign
        as_cert = CA.get_instance().get('AS')
        if validate(as_cert):
            pipe = self.pipe_send(
                payload, AS.get_instance(), as_cert.public_key())
            return AS.get_instance().generate_ticket(pipe)
        else:
            raise Exception('invalid AS certificate')

    def vote(self, vote):
        self.AS_request()
    '''
