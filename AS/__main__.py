import requests as re
from flask import Flask, request, render_template
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from model import Client

app = Flask(__name__)


@app.route('/')
def home():
    return 'done'


if __name__ == '__main__':
    app.run(port=5001)
