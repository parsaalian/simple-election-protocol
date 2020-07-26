import sys
sys.path.append('utils')
import utkeys, utpipes, utpads, utload, utsec

import os
import time
import requests as re
from cryptography.hazmat.primitives import hashes


class VS:
    id = 'VS'
    psk = 'PRE_SHARED_KEY_BETWEEN_AS_AND_VS'
    key = None
    pipe = {}
    
    def __init__(self):
        VS.key = utkeys.generate()
        utkeys.register(VS.id, VS.key)
        
    
    @staticmethod
    def pipe_receive(pid, index, piece):
        AS.pipe = utpipes.receive(AS.pipe, pid, index, piece)
        return '{}: received piece {}'.format(pid, index)

