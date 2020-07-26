import datetime
import requests as re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID


pad = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)

spad = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
)


class Client:
    id = None
    key = None

    def __init__(self, cid):
        Client.id = cid
        Client.key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    @staticmethod
    def register_key():
        pub = Client.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        r = re.post('http://localhost:5000/register', data={
            'uid': Client.id,
            'pub': pub
        })
        return r.text

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

    def pipe_send(self, payload, target, key):
        e0 = key.encrypt(payload[:50], pad)
        for i in range(0, len(payload), 100):
            target.pipe_receive(e0, key.encrypt(payload[i:i+100], pad))
        return e0

    def vote(self, vote):
        self.AS_request()
    '''
