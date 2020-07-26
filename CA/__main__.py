from flask import Flask, request
from model import CA
app = Flask(__name__)


@app.route('/register', methods=['POST'])
def register():
    data = request.form
    return CA.register(data['uid'], data['pub'])


@app.route('/get', methods=['POST'])
def register():
    uid = request.form['uid']
    return CA.get(uid)


if __name__ == '__main__':
    app.run(port=5000)
