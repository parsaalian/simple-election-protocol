from flask import Flask, request
from model import CA
app = Flask(__name__)


@app.route('/register', methods=['POST'])
def register():
    data = request.form
    return data['name']


if __name__ == '__main__':
    app.run()
