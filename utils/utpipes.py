import requests as re

def send(pid, pipe, destination):
    for i in range(len(pipe)):
        r = re.post(destination, data={
            'e0': pid,
            'index': i,
            'piece': pipe[i]
        })

def receive(pipe, pid, index, piece):
    if not pid in pipe:
        pipe[pid] = {}
    pipe[pid][index] = piece.encode('iso8859_16')
    return pipe
