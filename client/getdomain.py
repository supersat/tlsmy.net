#!/usr/bin/env python3

import argparse
import base36
import base64
import jwcrypto.jwk
import os

def get_domain(key, domain, cname):
    priv_key = jwcrypto.jwk.JWK.from_json(open(key, 'rt').read())
    thumbprint_bytes = base64.urlsafe_b64decode(priv_key.thumbprint() + '==')
    thumbprint = base36.dumps(int.from_bytes(thumbprint_bytes, byteorder='big'))
    if cname is None:
        return '*.{}.{}'.format(thumbprint, domain)
    else:
        return '_acme-challenge.{} IN CNAME _acme-challenge.{}.{}'.format(cname, thumbprint, domain)

# https://stackoverflow.com/a/45392259
def environ_or_required(key):
    if os.environ.get(key):
        return {'default': os.environ.get(key)}
    else:
        return {'required': True}

def main():
    arg_parser = argparse.ArgumentParser(description='TLSMy.net domain generator')
    arg_parser.add_argument('-k', '--key', help='certbot account private key. ' \
        'May also be passed in via the ACME_ACCT_KEY environment variable.', \
        **environ_or_required('ACME_ACCT_KEY'))
    arg_parser.add_argument('-d', '--domain', help='Host domain. Defaults to tlsmy.net', \
        default='tlsmy.net')
    arg_parser.add_argument('-c', '--cname', help='Print the required cname entry for authorizing a subdomain through TLSMynet',
        default=None)
    args = arg_parser.parse_args()
    print(get_domain(args.key, args.domain, args.cname))

if __name__ == '__main__':
    main()
