import requests as re
from flask import Flask, request, render_template

from model import VS


app = Flask(__name__)


@app.route('/communicate_token', methods=['POST'])
def communicate_token():
    message = request.form['message']
    return VS.communicate_token(message)


@app.route('/vote', methods=['POST'])
def vote():
    message = request.form['message']
    return VS.vote(list(map(lambda x: x.encode('iso8859_16'), message.split('--next'))))


@app.route('/pipe_receive', methods=['POST'])
def pipe_receive():
    data = request.form
    return VS.pipe_receive(data['e0'], data['index'], data['piece'])


if __name__ == '__main__':
    VS()
    app.run(port=5002)
