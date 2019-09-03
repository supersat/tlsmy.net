#!/usr/bin/env python3

import argparse
import json
import jwcrypto.jwk
import jwcrypto.jws
import os
import urllib.request

def sign(payload, priv_key_json):
    priv = jwcrypto.jwk.JWK.from_json(priv_key_json)
    jws = jwcrypto.jws.JWS(payload)
    # TODO(supersat): Is there a better way to do this?
    jws.add_signature(priv, protected=json.dumps({
        "alg": "RS256",
        "jwk": json.loads(priv.export_public())
    }))
    return jws.serialize()

def send_request(key, validation_string, url):
    priv_key_file = open(key, 'rt')
    priv_key_json = priv_key_file.read()
    req = urllib.request.Request(url,
        data=sign(json.dumps({"type": "dns-01", "token": validation_string}), priv_key_json).encode('utf-8'),
        headers={"Content-Type": "application/jose+json"})
    urllib.request.urlopen(req)

# https://stackoverflow.com/a/45392259
def environ_or_required(key):
    if os.environ.get(key):
        return {'default': os.environ.get(key)}
    else:
        return {'required': True}

def main():
    arg_parser = argparse.ArgumentParser(description='TLSMy.net challenge requester')
    arg_parser.add_argument('-k', '--key', help='certbot account private key. ' \
        'May also be passed in via the ACME_ACCT_KEY environment variable.', \
            **environ_or_required('ACME_ACCT_KEY'))
    arg_parser.add_argument('-V', '--validation-string', help='ACME DNS-01 validation string. ' \
        'May also be passed in via the CERTBOT_VALIDATION environment variable.', \
            **environ_or_required('CERTBOT_VALIDATION'))
    arg_parser.add_argument('-u', '--url', help='HTTP(S) API endpoint URL.', default='https://tlsmy.net/challenge')
    args = arg_parser.parse_args()
    send_request(**vars(args))

if __name__ == '__main__':
    main()