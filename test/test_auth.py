import socket
import os.path

import test
import _test
from cyopenssl import *


RESOURCES = os.path.dirname(os.path.abspath(__file__)) + '/resources'

def make_ctx(trust=True, pkey=True, s='1k'):
    ctx = Context('TLSv1.1')
    if pkey:
        ctx.set_password('test')
        ctx.use_certificate_chain_file('{0}/cert{1}.pem'.format(RESOURCES, s))
        ctx.use_privatekey_file('{0}/key{1}.pem'.format(RESOURCES, s))
    if trust:
        ctx.load_verify_locations('{0}/cert{1}.pem'.format(RESOURCES, s))
        ctx.load_client_CA_list('{0}/cert{1}.pem'.format(RESOURCES, s))
    return ctx


SSL_VERIFY_NONE = 0x00
SSL_VERIFY_PEER = 0x01
SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02
SSL_VERIFY_CLIENT_ONCE = 0x04


def test():
    def t():
        _test.null_sock_test(server_ctx, client_ctx)

    # SERVER AUTH TESTS...
    server_ctx = make_ctx()
    client_ctx = make_ctx(trust=False, pkey=False)
    client_ctx.set_verify(SSL_VERIFY_PEER)
    try:
        t()
        assert False, "client did not check server cert"
    except SSLError:
        print "client rejected untrusted server cert (GOOD)"
    client_ctx.set_verify(SSL_VERIFY_NONE)
    t()
    print "client did not check cert when not configured to (GOOD)"

    # MUTUAL AUTH TESTS....
    server_ctx = make_ctx()
    server_ctx.set_verify(SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
    client_ctx = make_ctx(pkey=False)
    try:
        t()
        assert False, "handshake worked without client cert"
    except SSLError:
        print "handshake failed when missing required cert (GOOD)"
    server_ctx = make_ctx()
    server_ctx.set_verify(SSL_VERIFY_PEER)
    t()
    print "handshake succeded when missing not-required cert (GOOD)"
    client_ctx = make_ctx()
    t()
    print "handhsake succeded when client cert present (GOOD)"


test()


class BufSock(object):
    fileno = lambda self: -1

    def __init__(self):
        self.inbuf = bytearray()
        self.sent_msgs = []

    def setpeer(self, peer):
        self.peer = peer

    def sendall(self, data):
        self.peer.inbuf += data

    def recv_into(self, buf):
        if not self.inbuf:
            raise self.NeedPeerData()
        recvd = min(len(buf), len(self.inbuf))
        buf[:recvd] = self.inbuf[:recvd]
        self.inbuf = self.inbuf[recvd:]
        return recvd

    @classmethod
    def pair(cls):
        a, b = cls(), cls()
        a.setpeer(b)
        b.setpeer(a)
        return a, b

    class NeedPeerData(ValueError):
        pass


def test_parallel(server_ctx, client_ctx):
    pairs = [BufSock.pair() for i in range(4)]
    pairs = [(Socket(c, client_ctx), Socket(s, server_ctx, server_side=True)) for c,s in pairs]

    sent = 0
    not_sent = 0
    recvd = 0
    not_recvd = 0
    for i in range(5):
        for c, s in pairs:
            try:
                c.send('a')
                sent += 1
            except BufSock.NeedPeerData:
                not_sent += 1
            try:
                s.recv(1)
                recvd += 1
            except BufSock.NeedPeerData:
                not_recvd += 1

    assert sent, "no application data got through"
    assert not_sent, "application data got through without handshake"
    assert recvd, "no application data received"
    assert not_recvd, "application data recieved without handshake"


test_parallel(make_ctx(), make_ctx())
