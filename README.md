# tlsmy.net

A proof-of-concept tool for TLS-enabling YOUR network!

## What's it for?

Let's Encrypt is great for Internet-facing servers. Unfortunately, using TLS
certificate for local network devices is challenging for most end-users. For
example, many local devices may be located and connected to by IP address,
which prevents valid TLS certificates from being used. Many end-users also do
not have their own domain, which prevents them from obtaining certificates
even through manual processes.

tlsmy.net solves these issues by using an approach pioneered by Plex. With
tlsmy.net, a wildcard certificate is issued for *.accountid.tlsmy.net. A DNS
server resolves A.B.C.D.accountid.tlsmy.net to A.B.C.D, so network devices can
still be accessed by IP address. By ensuring the expected accountid is in the
hostname, users can have reasonable assurance that they are communicating with
the expected device. In this case, the accountid is a base36 fingerprint of your
Let's Encrypt account public key.

This model does require you to trust tlsmy.net, as a wildcard certificate for
*.tlsmy.net could always be issued, or a rogue certificate for your accountid.
However, Certificate Transparency logs can be used to verify that no rogue
certificates are created. Additionally, it is envisioned that network device
manufacturers might use their own domains instead, and by using their devices
you already implicitly somewhat trust them.

## How does it work?

You create a Let's Encrypt account with your own public/private key pair.
tlsmy.net does not have access to the private key. When you want a wildcard
certificate issued for *.accountid.tlsmy.net, you first request a DNS-01
challenge from Let's Encrypt using certbot (or another ACME client). The
certificate public/private key pair is generated locally on your machine,
and the private key is never exposed to tlsmy.net or Let's Encrypt. Once the
DNS-01 challenge is received, the tlsmy.net client sends a domain validation
request to the tlsmy.net web server, which is signed with your Let's Encrypt
account private key. This proves control over the corresponding public key,
whose thumbprint is used as the subdomain. Put another way, without someone's
Let's Encrypt account private key, you cannot submit a domain validation request
for their corresponding subdomain. The domain validation request is simply the
validation token that Let's Encrypt verifies matches the TXT record for
_acme-challenge.accountid.tlsmy.net. The same DNS responder answers these TXT
challenges, and communicates with the web server over a simple redis instance.
When a properly-signed domain validation request is received by the web server,
a corresponding key is temporarily stored in a local redis instance, accessible
only on localhost. The value is simply the validation token.

## What limitations are there?

First off, this is designed to be a **proof-of-concept** and **NOT** a
production service. Let's Encrypt limits the number of subdomains that can be
requested per week to 50, so this can't scale beyond limited experimentation.

## How do I use it?

These instructions assume you have pipenv installed in a UNIX-like environment.

1) Clone the repository, install dependencies, and activate the virtualenv:
       
       git clone https://github.com/supersat/tlsmy.net.git
       cd tlsmy.net
       pipenv install
       pipenv shell
       
2) Create a ~/.letsencrypt directory to store your account credentials and
   certificates:

       mkdir ~/.letsencrypt
       chmod 700 ~/.letsencrypt
   
3) Create a Let's Encrypt account:

       certbot --config-dir=$HOME/.letsencrypt --work-dir=$HOME/.letsencrypt \
         --logs-dir=$HOME/.letsencrypt register
   
4) Set the ACME_ACCT_KEY environment variable:

       export ACME_ACCT_KEY=`find $HOME/.letsencrypt -name private_key.json`
   
5) Request the certificate (from inside the tlsmy.net repo directory):

       certbot --config-dir=$HOME/.letsencrypt --work-dir=$HOME/.letsencrypt \
         --logs-dir=$HOME/.letsencrypt certonly --manual \
         --manual-auth client/reqchal.py -d `client/getdomain.py`

If all goes well, your new certificate should be in
~/.letsencrypt/live/*.tlsmy.net
