import requests as re
from flask import Flask, request, render_template

from model import AS


app = Flask(__name__)


@app.route('/')
def home():
    return 'done'


@app.route('/get_vote_token')
def get_vote_token():
    return AS.get_vote_token(request.form['pid'])


@app.route('/pipe_receive')
def pipe_receive():
    data = request.form
    return AS.pipe_receive(data['e0'], data['index'], data['piece'])


if __name__ == '__main__':
    AS()
    app.run(port=5001)
