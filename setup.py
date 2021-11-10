#!/usr/bin/env python3
import sys

from setuptools import setup
from setuptools import find_packages

certbot_version = '0.36.0'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    'acme>={0}'.format(certbot_version),
    'certbot>={0}'.format(certbot_version),
    'setuptools>=1.0',
    'zope.component',
    'zope.interface',
]

tlsmynet_authenticator = 'certbot_tlsmynet.authenticator:TLSMyNetAuthenticator'

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='tlsmynet',
    version='0.01',
    description='A proof-of-concept tool for TLS-enabling YOUR network!',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='Karl Koscher',
    packages=find_packages(),
    scripts=['client/tlsmynet-getdomain', 'client/tlsmynet-reqchal'],
    entry_points={
        'certbot.plugins': [
            'authenticator = %s' % tlsmynet_authenticator,
        ],
    }
)
