import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes


def generate_keys():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


class CA:
    key = generate_keys()

    @staticmethod
    def register(uid, pub_key):
        if not os.path.exists('./certificates/{}.pem'.format(uid)):
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
                x509.SubjectAlternativeName([x509.DNSName(u"localhost:5000")]),
                critical=True,
            ).sign(self.key, hashes.SHA256(), default_backend())
            with open('./certificates/{}.pem'.format(uid), 'w+'):
                f.write(cert.public_bytes(serialization.Encoding.PEM))

    @staticmethod
    def get(self, uid):
        return cert
