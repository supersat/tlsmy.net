#!/usr/bin/env python3

from aiohttp import web
import aioredis
import argparse
import asyncio
import base36
import base64
import json
import jwcrypto.jwk
import jwcrypto.jws

class ChallengeReqWebServer:
    def __init__(self):
        self._app = web.Application(client_max_size=4096)
        self._app.add_routes([web.post('/challenge', self.post_challenge)])

    async def _init_redis_pool(self):
        self._redis_pool = await aioredis.create_redis_pool('redis://localhost')

    def run(self, **kwargs):
        asyncio.get_event_loop().run_until_complete(self._init_redis_pool())
        web.run_app(self._app, **kwargs)

    async def post_challenge(self, request):
        if request.content_type != 'application/jose+json':
            return web.HTTPBadRequest()

        req_body = await request.text()
        req_obj = json.loads(req_body)
        #try:
        if True:
            # TODO(supersat): Is there a less brain-dead way of doing this?
            jws = jwcrypto.jws.JWS()
            jws.deserialize(req_body)
            protected = json.loads(str(base64.urlsafe_b64decode(req_obj['protected'] + '=='), 'utf-8'))
            chal = json.loads(str(base64.urlsafe_b64decode(req_obj['payload'] + '=='), 'utf-8'))
            pub_key = jwcrypto.jwk.JWK.from_json(json.dumps(protected['jwk']))
            jws.verify(pub_key)
            thumbprint_bytes = base64.urlsafe_b64decode(pub_key.thumbprint() + '==')
            thumbprint = base36.dumps(int.from_bytes(thumbprint_bytes, byteorder='big'))
            if chal['type'] == 'dns-01':
                await self._redis_pool.set('acme-dns-01-chal:{}'.format(thumbprint), chal['token'], expire=300)
                return web.HTTPNoContent()
        #except:
        #    pass
        return web.HTTPBadRequest()

def main():
    arg_parser = argparse.ArgumentParser(description='TLSMy.net challenge request web server')
    arg_parser.add_argument('-H', '--host', help='Hostname to listen on.')
    arg_parser.add_argument('-P', '--port', help='TCP port to listen on.')
    arg_parser.add_argument('-U', '--path', help='Unix file system path to serve on.')
    args = arg_parser.parse_args()

    server = ChallengeReqWebServer()
    server.run(**vars(args))

if __name__ == '__main__':
    main()
