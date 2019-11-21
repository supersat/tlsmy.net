#!/usr/bin/env python3

import dnslib
import dnslib.label
import dnslib.server
import logging
import os
import re
import redis
import signal
import time

BASE36_SHA256_HASH = re.compile(r"[0-9a-z]+")
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-){3}" \
                        "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

class Resolver(object):
    def __init__(self, domain, server_ip):
        self.domain = domain
        self.server_ip = server_ip
        self.redis = redis.Redis()

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname

        # Refuse queries thaat are not for our domain
        if tuple(map(str.lower, map(qname._decode, qname.label[-2:]))) != \
            tuple(map(str.lower, map(self.domain._decode, self.domain.label[-2:]))):
            reply.header.rcode = dnslib.RCODE.REFUSED
            return reply

        # Answer questions about the root domain name
        # TODO(supersat): We don't need to implement this, right?
        if len(qname.label) <= 3:
            if request.q.qtype == dnslib.QTYPE.A:
                reply.add_answer(dnslib.RR(
                    qname,
                    dnslib.QTYPE.A,
                    ttl=300,
                    rdata=self.server_ip))
            return reply

        subdomain = qname._decode(qname.label[1]).lower()
        hostname = qname._decode(qname.label[0]).lower()
        if BASE36_SHA256_HASH.match(subdomain) and len(qname.label) == 4:
            if hostname == '_acme-challenge' and \
                (request.q.qtype == dnslib.QTYPE.TXT or \
                request.q.qtype == dnslib.QTYPE.ANY):
                txt = self.redis.get('acme-dns-01-chal:{}'.format(subdomain))
                if txt:
                    reply.add_answer(dnslib.RR(
                        qname,
                        dnslib.QTYPE.TXT,
                        ttl=300,
                        rdata=dnslib.TXT(txt)
                    ));
                else:
                    reply.header.rcode = dnslib.RCODE.NXDOMAIN
            elif IPV4_REGEX.match(hostname) and \
                (request.q.qtype == dnslib.QTYPE.A or \
                request.q.qtype == dnslib.QTYPE.ANY):
                try:
                    ip = tuple(map(int, hostname.split('-')))
                    reply.add_answer(dnslib.RR(
                        qname,
                        dnslib.QTYPE.A,
                        ttl=300,
                        rdata=dnslib.A(ip)
                    ))
                except:
                    reply.header.rcode = dnslib.RCODE.NXDOMAIN
            else:
                reply.header.rcode = dnslib.RCODE.NXDOMAIN
            return reply

        reply.header.rcode = dnslib.RCODE.NXDOMAIN
        return reply

def handle_sig(signum, frame):
    logging.info('pid=%d, got signal: %s, stopping...', os.getpid(), signal.Signals(signum).name)
    exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, handle_sig)

    domain = dnslib.label(os.getenv('DOMAIN', 'tlsmy.net'))
    server_ip = os.getenv('SERVER_IP', '127.0.0.1')
    port = int(os.getenv('PORT', 53))
    resolver = Resolver(domain, dnslib.A(server_ip))
    udp_server = dnslib.server.DNSServer(resolver, address=server_ip, port=port)
    tcp_server = dnslib.server.DNSServer(resolver, address=server_ip, port=port, tcp=True)

    logging.info('starting DNS server on port %d', port)
    udp_server.start_thread()
    tcp_server.start_thread()

    try:
        while udp_server.isAlive():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
