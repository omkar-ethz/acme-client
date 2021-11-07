import flask
from flask import Flask
import sys


class ChallengeServer:
    def __init__(self):
        self.key_authorization = ''

    def set_key_authorization(self, key_authorization):
        self.key_authorization = key_authorization

    def run(self):
        app = Flask(__name__)

        @app.route('/')
        def handle_root():
            return 'hello world!'

        @app.route('/.well-known/acme-challenge/<token>')
        def handle(token):
            response = flask.make_response(self.key_authorization)
            response.headers['Content-Type'] = 'application/octet-stream'
            return response

        app.run(port=5002, debug=True)


print('hello world ', __name__)
if __name__ == "__main__":
    print("called challenge_server")
    key_authorization = sys.argv[1]
    challenge_server = ChallengeServer()
    challenge_server.set_key_authorization(key_authorization)
    challenge_server.run()
