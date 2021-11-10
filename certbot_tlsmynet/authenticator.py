import logging

import zope.interface

from acme.magic_typing import Any
from acme.magic_typing import Dict
from acme.magic_typing import List

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

from certbot.account import AccountFileStorage
from josepy.jws import JWS
from josepy.jwa import RS256
import json, urllib

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class TLSMyNetAuthenticator(dns_common.DNSAuthenticator):
    description = """DNS Authenticator for TLSMyNet style authentication"""
    
    def __init__(self, *args, **kwargs):
        super(dns_common.DNSAuthenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add, ):  # pylint: disable=arguments-differ
        dns_common.DNSAuthenticator.add_parser_arguments(add)
        add('endpoint',
            default='https://tlsmy.net/challenge',
            type=str,
            help='TLSMyNet Service URL')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return """
            This plugin uses the TLSMyNet Service for certificate authentication.
        """

    def _setup_credentials(self):
        self.endpoint = self._configure('endpoint', 'TLSMyNet Service URL')

    def _perform(self, domain, validation_name, validation):
        payload = json.dumps({"type": "dns-01", "token": validation}).encode()

        logger.debug("Attempting to get selected account: %s" % self.config.namespace.account)
        afs = AccountFileStorage(self.config)
        acct = afs.load(self.config.namespace.account)

        logger.debug("Signing TLSMyNet request with Let's Encrypt account key")
        signed_payload = JWS.sign(
            payload = payload, key = acct.key, alg = RS256,
            protect = frozenset(['jwk', 'alg']))
        
        url = self.conf('endpoint')

        logger.info("Making request to: %s" % url)

        json_payload = json.dumps(signed_payload.to_partial_json()).encode('utf-8')

        logger.debug("Request Payload: %s" % json_payload)

        req = urllib.request.Request(url,
            data=json_payload,
            headers={"Content-Type": "application/jose+json"})

        resp = urllib.request.urlopen(req)

        logger.info("Response code: %03d" % resp.getcode())

    def _cleanup(self, domain, validation_name, validation):
        logger.info(repr([self,domain,validation_name, validation]))
    
