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
    def register(uid, pub):
        try:
            pub_key = serialization.load_pem_public_key(
                pub.encode(), backend=default_backend())

            if not os.path.exists('./CA/certificates/{}.pem'.format(uid)):
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
                with open('./CA/certificates/{}.pem'.format(uid), 'wb+') as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
                    return 'CA: registered'
            else:
                return 'CA: already registered'
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
