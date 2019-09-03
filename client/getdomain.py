#!/usr/bin/env python3

import argparse
import base36
import base64
import jwcrypto.jwk

def get_domain(key, domain):
    priv_key = jwcrypto.jwk.JWK.from_json(open(key, 'rt').read())
    thumbprint_bytes = base64.urlsafe_b64decode(priv_key.thumbprint() + '==')
    thumbprint = base36.dumps(int.from_bytes(thumbprint_bytes, byteorder='big'))
    return '*.{}.{}'.format(thumbprint, domain)

def main():
    arg_parser = argparse.ArgumentParser(description='TLSMy.net domain generator')
    arg_parser.add_argument('-k', '--key', help='certbot account private key', required=True)
    arg_parser.add_argument('-d', '--domain', help='Host domain. Defaults to tlsmy.net', default='tlsmy.net')
    args = arg_parser.parse_args()
    print(get_domain(args.key, args.domain))

if __name__ == '__main__':
    main()
