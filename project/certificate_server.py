from flask import Flask

app = Flask(__name__)


@app.route('/')
def handle_root():
    return 'hello secure world!'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True, ssl_context=("cert.pem", "key.pem"))