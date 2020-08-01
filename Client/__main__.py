from flask import Flask, request, render_template
from model import Client


app = Flask(__name__)


@app.route('/')
def home():
    return render_template('login.html')


@app.route('/voting_page', methods=['POST'])
def register():
    Client(request.form['uid'])
    return render_template('vote_page.html')


@app.route('/vote', methods=['POST'])
def vote():
    return Client.vote(request.form['vote'])


if __name__ == '__main__':
    app.run(port=5003)
