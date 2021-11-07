# module to generate key pairs, and functions for JOSE encryption
import json
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

private_key = ec.generate_private_key(
    ec.SECP256R1()
)
x = private_key.public_key().public_numbers().x
y = private_key.public_key().public_numbers().y


def get_protected_header(nonce, url):
    var = {
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": base64url_enc(int_to_bytes(x)).decode('utf-8'),
            "y": base64url_enc(int_to_bytes(y)).decode('utf-8')
        },
        "nonce": nonce,
        "url": url
    }
    print(json.dumps(var))
    print(json.dumps(var).encode('utf-8'))
    return base64url_enc(json.dumps(var).encode('utf-8'))


def get_thumbprint():
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_enc(int_to_bytes(x)).decode('utf-8'),
        "y": base64url_enc(int_to_bytes(y)).decode('utf-8')
    }
    jwk_compact_binary = json.dumps(jwk, separators=(',', ':'), sort_keys=True).encode('utf-8')
    m = hashlib.sha256()
    m.update(jwk_compact_binary)
    return base64url_enc(m.digest())


def get_key_authorization(token):
    return token + '.' + get_thumbprint().decode('utf-8')


def get_protected_header_with_kid(nonce, url, kid):
    var = {
        "alg": "ES256",
        "kid": kid,
        "nonce": nonce,
        "url": url
    }
    print(json.dumps(var))
    print(json.dumps(var).encode('utf-8'))
    return base64url_enc(json.dumps(var).encode('utf-8'))


def get_signature(signing_input):
    signature = private_key.sign(
        signing_input,
        ec.ECDSA(hashes.SHA256())
    )
    (r, s) = decode_dss_signature(signature)
    return base64url_enc(int_to_bytes(r) + int_to_bytes(s))


def get_signing_input(encoded_header, encoded_payload):
    return encoded_header + b'.' + encoded_payload


def base64url_enc(bytestring):
    return base64.urlsafe_b64encode(bytestring).rstrip(b'=')


def int_to_bytes(num):
    return num.to_bytes(32, 'big')
