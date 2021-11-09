# module for requesting account creation and certificate revocation
import argparse
import json
import subprocess
import sys
import time

import requests

import csr_utils
import jose_utils

print(sys.argv)
parser = argparse.ArgumentParser("ACME client")
parser.add_argument("challenge_type")
parser.add_argument("--dir", required=True)
parser.add_argument("--record", required=True)
parser.add_argument("--domain", action='append')
parser.add_argument("--revoke", action='store_true')
args = parser.parse_args()

acme_server_url = args.dir
dir_json = requests.get(acme_server_url, verify='./pebble.minica.pem').json()
print('dir json', dir_json)


def request_nonce():
    new_nonce_url = dir_json['newNonce']
    resp = requests.head(new_nonce_url, verify='./pebble.minica.pem')
    nonce = resp.headers['Replay-Nonce']
    return nonce


def create_account(nonce):
    new_account_url = dir_json['newAccount']
    new_account_obj = get_create_account_request(nonce, new_account_url)
    print('new account object is: ', new_account_obj)
    headers = {'Content-Type': 'application/jose+json'}
    return requests.post(new_account_url, json=new_account_obj, headers=headers, verify='./pebble.minica.pem')


def get_create_account_request(nonce, url):
    protected = jose_utils.get_protected_header(nonce, url)
    payload = get_create_account_payload()
    signing_input = jose_utils.get_signing_input(protected, payload)
    signature = jose_utils.get_signature(signing_input)
    return {
        'protected': protected.decode('utf-8'),
        'payload': payload.decode('utf-8'),
        'signature': signature.decode('utf-8')
    }


def get_create_account_payload():
    var = {
        "termsOfServiceAgreed": True,
        "contact": [
            "mailto:omzade@student.ethz.ch"
        ]
    }
    return jose_utils.base64url_enc(json.dumps(var).encode('utf-8'))


def get_new_orders_request(nonce, url, kid):
    protected = jose_utils.get_protected_header_with_kid(nonce, url, kid)
    var = {
        'identifiers': [
            {
                'value': args.domain[0],
                'type': 'dns'}
        ]
    }
    payload = jose_utils.base64url_enc(json.dumps(var).encode('utf-8'))
    signing_input = jose_utils.get_signing_input(protected, payload)
    signature = jose_utils.get_signature(signing_input)
    return {
        'protected': protected.decode('utf-8'),
        'payload': payload.decode('utf-8'),
        'signature': signature.decode('utf-8')
    }


def get_finalize_request(nonce, url, kid, csr):
    protected = jose_utils.get_protected_header_with_kid(nonce, url, kid)
    var = {
        "csr": csr.decode('utf-8')
    }
    payload = jose_utils.base64url_enc(json.dumps(var).encode('utf-8'))
    signing_input = jose_utils.get_signing_input(protected, payload)
    signature = jose_utils.get_signature(signing_input)
    return {
        'protected': protected.decode('utf-8'),
        'payload': payload.decode('utf-8'),
        'signature': signature.decode('utf-8')
    }


def post_as_get(nonce, url, kid):
    protected = jose_utils.get_protected_header_with_kid(nonce, url, kid)
    payload = jose_utils.base64url_enc(b'')
    signing_input = jose_utils.get_signing_input(protected, payload)
    signature = jose_utils.get_signature(signing_input)
    return {
        'protected': protected.decode('utf-8'),
        'payload': payload.decode('utf-8'),
        'signature': signature.decode('utf-8')
    }


def post_as_get_empty_payload(nonce, url, kid):
    protected = jose_utils.get_protected_header_with_kid(nonce, url, kid)
    payload = jose_utils.base64url_enc(b'{}')
    signing_input = jose_utils.get_signing_input(protected, payload)
    signature = jose_utils.get_signature(signing_input)
    return {
        'protected': protected.decode('utf-8'),
        'payload': payload.decode('utf-8'),
        'signature': signature.decode('utf-8')
    }


def get_revoke_cert_request(nonce, url, kid, certificate):
    protected = jose_utils.get_protected_header_with_kid(nonce, url, kid)
    var = {
        "certificate": certificate.decode('utf-8')
    }
    payload = jose_utils.base64url_enc(json.dumps(var).encode('utf-8'))
    signing_input = jose_utils.get_signing_input(protected, payload)
    signature = jose_utils.get_signature(signing_input)
    return {
        'protected': protected.decode('utf-8'),
        'payload': payload.decode('utf-8'),
        'signature': signature.decode('utf-8')
    }


nonce = request_nonce()
resp = create_account(nonce)
print(resp.json(), resp.headers)

nonce = resp.headers['Replay-Nonce']
kid = resp.headers['Location']
orders_url = resp.json()['orders']
new_orders_resp = requests.post(dir_json['newOrder'], json=get_new_orders_request(nonce, dir_json['newOrder'], kid),
                                headers={'Content-Type': 'application/jose+json'}, verify='./pebble.minica.pem')
print(new_orders_resp.json(), new_orders_resp.headers)

nonce = new_orders_resp.headers['Replay-Nonce']
authz_url = new_orders_resp.json()['authorizations'][0]
authz_resp = requests.post(authz_url, json=post_as_get(nonce, authz_url, kid),
                           headers={'Content-Type': 'application/jose+json'}, verify='./pebble.minica.pem')
print(authz_resp.json(), authz_resp.headers)
nonce = authz_resp.headers['Replay-Nonce']

if args.challenge_type == 'http01':
    http_challenge = [x for x in authz_resp.json()['challenges'] if x['type'] == 'http-01'][0]
    token = http_challenge['token']
    key_authorization = jose_utils.get_key_authorization(token)

    p = subprocess.Popen(["python", "challenge_server.py", key_authorization])
    print(p.returncode, p.args, p.pid, p.stdout)
    print('running')
    time.sleep(1)

else:
    print("performing dns-01")
    dns_challenge = [x for x in authz_resp.json()['challenges'] if x['type'] == 'dns-01'][0]
    token = dns_challenge['token']
    key_authorization = jose_utils.get_key_authorization(token)
    key_auth_digest = jose_utils.get_SHA256_digest(key_authorization.encode('utf-8')).decode('utf-8')
    print(f"running custom resolver {args.record} -- {key_auth_digest}")
    p = subprocess.Popen(
        ["python", "custom_resolver.py", "-p", "10053", "-r", f". 60 IN A {args.record}", "--key_auth_digest",
         key_auth_digest])
    time.sleep(1)
    http_challenge = dns_challenge

count = 0
chall_response = requests.post(http_challenge['url'], json=post_as_get_empty_payload(nonce, http_challenge['url'], kid),
                               headers={'Content-Type': 'application/jose+json'}, verify='./pebble.minica.pem')
print(chall_response.json(), chall_response.headers)
nonce = chall_response.headers['Replay-Nonce']
##Poll
while True:
    if chall_response.json()['status'] != 'pending' or count == 3:
        break
    count += 1
    chall_response = requests.post(http_challenge['url'], json=post_as_get(nonce, http_challenge['url'], kid),
                                   headers={'Content-Type': 'application/jose+json'}, verify='./pebble.minica.pem')
    print(chall_response.json(), chall_response.headers)
    nonce = chall_response.headers['Replay-Nonce']
    time.sleep(5 * count)

print('finished', chall_response.json(), chall_response.headers)
authz_resp = requests.post(authz_url, json=post_as_get(nonce, authz_url, kid),
                           headers={'Content-Type': 'application/jose+json'}, verify='./pebble.minica.pem')
print(authz_resp.json(), authz_resp.headers)
nonce = authz_resp.headers['Replay-Nonce']

csr = csr_utils.get_csr([args.domain[0]])
print('csr', csr)
finalize_url = new_orders_resp.json()['finalize']
finalize_resp = requests.post(finalize_url, json=get_finalize_request(nonce, finalize_url, kid, csr),
                              headers={'Content-Type': 'application/jose+json'}, verify='./pebble.minica.pem')
print(finalize_resp.json(), finalize_resp.headers)
nonce = finalize_resp.headers['Replay-Nonce']

time.sleep(1)
my_order_url = finalize_resp.headers['Location']
my_order_resp = requests.post(my_order_url, json=post_as_get(nonce, my_order_url, kid),
                              headers={'Content-Type': 'application/jose+json'}, verify='./pebble.minica.pem')
print(my_order_resp.json(), my_order_resp.headers)
nonce = my_order_resp.headers['Replay-Nonce']

cert_url = my_order_resp.json()['certificate']
download_cert_resp = requests.post(cert_url, json=post_as_get(nonce, cert_url, kid),
                                   headers={'Content-Type': 'application/jose+json'}, verify='./pebble.minica.pem')
print(download_cert_resp.content, download_cert_resp.headers, download_cert_resp.status_code)
nonce = download_cert_resp.headers['Replay-Nonce']

with open("cert.pem", "wb") as f:
    f.write(download_cert_resp.content)

cert_server_process = subprocess.Popen(["python", "certificate_server.py"])

if args.revoke:
    der_cert = csr_utils.get_cert_DER(download_cert_resp.content)
    revoke_cert_url = dir_json['revokeCert']
    revoke_cert_resp = requests.post(revoke_cert_url,
                                     json=get_revoke_cert_request(nonce, revoke_cert_url, kid, der_cert),
                                     headers={'Content-Type': 'application/jose+json'}, verify='./pebble.minica.pem')
    print(revoke_cert_resp.content, revoke_cert_resp.headers)

cert_server_process.wait()
