import requests as re
from flask import Flask, request, render_template

from model import VS


app = Flask(__name__)


@app.route('/pipe_receive', methods=['POST'])
def pipe_receive():
    data = request.form
    return VS.pipe_receive(data['e0'], data['index'], data['piece'])


if __name__ == '__main__':
    VS()
    app.run(port=5001)
