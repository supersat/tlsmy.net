#!/usr/bin/env python3

import argparse
import json
import jwcrypto.jwk
import jwcrypto.jws
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

def test(token):
    priv_key_file = open('private_key.json', 'rt')
    priv_key_json = priv_key_file.read()
    req = urllib.request.Request('https://tlsmy.net/challenge',
        data=sign(json.dumps({"type": "dns-01", "token": token}), priv_key_json).encode('utf-8'),
        headers={"Content-Type": "application/jose+json"})
    urllib.request.urlopen(req)

def main():
    test('this is a test token')

main()