from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def load_ca_key():
    with open('./ca_pub_key.pem', 'rb') as f:
        return serialization.load_pem_public_key(f.read(), default_backend())


def load_certificate(certificate):
    return x509.load_pem_x509_certificate(
        certificate, default_backend())