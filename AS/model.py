import sys
sys.path.append('utils')
import utkeys, utpipes

from cryptography.hazmat.primitives import hashes


class AS:
    id = 'AS'
    psk = 'PRE_SHARED_KEY_BETWEEN_AS_AND_VS'
    key = None
    pipe = {}
    
    def __init__(self):
        AS.key = utkeys.generate()
        utkeys.register(AS.id, AS.key)
    
    @staticmethod
    def pipe_receive(pid, index, piece):
        AS.pipe = utpipes.receive(AS.pipe, pid, index, piece)
        return '{}: received piece {}'.format(pid, index)

    '''def generate_ticket(self, pipe):
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
        self.pipe[e0].append(self.key.decrypt(encrypted, pad))'''
