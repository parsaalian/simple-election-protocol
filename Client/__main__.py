import requests as re
from flask import Flask, request, render_template
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from model import Client

app = Flask(__name__)


def generate_keys():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


@app.route('/')
def home():
    return render_template('login.html')


@app.route('/voting_page', methods=['POST'])
def register():
    Client(request.form['uid'])
    return Client.register_key()


if __name__ == '__main__':
    app.run(port=5003)
