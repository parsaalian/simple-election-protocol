from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

import utpads, utload

def validate(certificate):
    key = utload.ca_key()
    cert_to_check = utload.certificate(certificate)
    try:
        key.verify(
            cert_to_check.signature,
            cert_to_check.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_to_check.signature_hash_algorithm,
        )
        return True
    except:
        return False


def encode_and_sign(message, target_pub_key, source_priv_key):
    encoded = message.encode()
    signature = source_priv_key.sign(encoded, utpads.spad, hashes.SHA256())
    encoded += '--sign'.encode() + signature
    pipe = []
    piece_size = 150
    for i in range(0, len(encoded), piece_size):
        piece = target_pub_key.encrypt(encoded[i:i+piece_size], utpads.pad)
        pipe.append(piece.decode('iso8859_16'))
    return pipe


def decode_and_verify(pipe, target_priv_key, source_pub_key):
    try:
        for i in range(len(CA.pipe[pipe])):
            message += target_priv_key.decrypt(CA.pipe[pipe][str(i)], utpads.pad)
    except:
        return 'encryption key is not valid'

    payload, signature = message.split(b'--sign')

    try:
        source_pub_key.verify(
            signature,
            payload,
            utpads.spad,
            hashes.SHA256()
        )
        return payload
    except:
        return 'CA: signature is not valid'
