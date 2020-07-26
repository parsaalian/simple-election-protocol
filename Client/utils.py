from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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


def load_ca_key():
    with open('./ca_pub_key.pem', 'rb') as f:
        return serialization.load_pem_public_key(f.read(), default_backend())


def encode_and_sign(message, target_pub_key, source_priv_key):
    encoded = message.encode()
    signature = source_priv_key.sign(encoded, spad, hashes.SHA256())
    print(len(signature))
    encoded += '--sign'.encode() + signature
    pipe = []
    piece_size = 150
    for i in range(0, len(encoded), piece_size):
        piece = target_pub_key.encrypt(encoded[i:i+piece_size], pad)
        pipe.append(piece.decode('iso8859_16'))
    return pipe
