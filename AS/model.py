import os
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID


class AS:
    instance = None

    def __init__(self):
        if AS.instance != None:
            raise Exception('AS instance already exists')
        AS.instance = self
        self.key = generate_keys()
        self.pipe = {}
        CA.get_instance().register('AS', self.key.public_key())

    @staticmethod
    def get_instance():
        if AS.instance == None:
            AS()
        return AS.instance

    def generate_ticket(self, pipe):
        uid, nonce, sign = b''.join(self.pipe[pipe]).split(b'||')
        uid_cert = CA.get_instance().get(uid.decode())
        print(uid + nonce)
        if validate(uid_cert):
            # throws error if invalid
            uid_cert.public_key().verify(
                sign,
                uid + nonce.decode(),
                spad,
                hashes.SHA256()
            )

    def pipe_receive(self, e0, encrypted):
        if e0 not in self.pipe:
            self.pipe[e0] = []
        self.pipe[e0].append(self.key.decrypt(encrypted, pad))
