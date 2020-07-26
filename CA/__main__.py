from flask import Flask, request
from model import CA
app = Flask(__name__)


@app.route('/register', methods=['POST'])
def register():
    data = request.form
    return CA.register(data['uid'], data['pipe'])


@app.route('/get', methods=['POST'])
def get():
    uid = request.form['uid']
    return CA.get(uid)


@app.route('/pipe_receive', methods=['POST'])
def pipe_receive():
    data = request.form
    return CA.pipe_receive(data['e0'], data['index'], data['piece'])


if __name__ == '__main__':
    app.run(port=5000)
