import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

from utils import pad, spad


def load_key():
    with open("./CA/ca_priv_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b'CAPASS',
            backend=default_backend()
        )
        return private_key


class CA:
    key = load_key()
    pipe = {}

    @staticmethod
    def register(uid, pipe):
        message = b''
        try:
            for i in range(len(CA.pipe[pipe])):
                message += CA.key.decrypt(CA.pipe[pipe][str(i)], pad)
        except:
            return 'CA: encryption key is not valid'

        payload, signature = message.split(b'--sign')

        pub_key = serialization.load_pem_public_key(
            payload.split(b'||')[1], backend=default_backend())

        try:
            pub_key.verify(
                signature,
                payload,
                spad,
                hashes.SHA256()
            )
        except:
            return 'CA: signature is not valid'

        try:
            uid = payload.split(b'||')[0].decode('iso8859_16')
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"IR"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Voting"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"localhost:5000"),
            ])
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                pub_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(u"localhost:5000")]),
                critical=True,
            ).sign(CA.key, hashes.SHA256(), default_backend())
            cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
            with open('./CA/certificates/{}.pem'.format(uid), 'wb+') as f:
                f.write(cert_bytes)
                return cert_bytes
        except:
            return 'CA: could not register'

    @staticmethod
    def get(self, uid):
        if not os.path.exists('./CA/certificates/{}.pem'.format(uid)):
            return 'CA: no certificate found for this user.'
        else:
            try:
                with open('./CA/certificates/{}.pem'.format(uid), 'rb') as f:
                    return f.read()
            except IOError:
                return 'CA: there was a problem while reading certificate'

    @staticmethod
    def pipe_receive(pid, index, piece):
        if not pid in CA.pipe:
            CA.pipe[pid] = {}
        CA.pipe[pid][index] = piece.encode('iso8859_16')
        return '{}: piece {} received'.format(pid, index)

    @staticmethod
    def pipe_send(pid, pipe, destination):
        for i in range(len(pipe)):
            r = re.post(destination, data={
                'e0': pid,
                'index': i,
                'piece': pipe[i]
            })
