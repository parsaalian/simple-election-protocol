import os
import datetime
from cryptography import x509
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


def generate_keys():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def validate(certificate):
    return True
    # return certificate.is_signature_valid()


class CA:
    instance = None

    def __init__(self):
        if CA.instance is not None:
            raise Exception('CA instance already exists')
        CA.instance = self
        self.key = generate_keys()
        self.cert_list = {}

    @staticmethod
    def get_instance():
        if CA.instance == None:
            CA()
        return CA.instance

    def register(self, uid, pub_key):
        if uid not in self.cert_list:
            self.cert_list[uid] = pub_key

    def get(self, uid):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Voting"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"vote.ir"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.cert_list[uid]
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=True,
        ).sign(self.key, hashes.SHA256(), default_backend())
        return cert


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


class Client:
    def __init__(self, cid):
        self.id = cid
        self.key = generate_keys()
        CA.get_instance().register(cid, self.key.public_key())

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


CA()
AS()
client = Client('0022559868')
client.vote(0)

'''
ca = CA()
key = generate_keys()
ca.register(0, key.public_key())
cert = ca.get(0)

encrypted = cert.public_key().encrypt(b"A message I want to sign", pad)
print(key.decrypt(encrypted, pad))
'''
