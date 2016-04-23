import socket
import os.path

import test
import _test
from cyopenssl import *


RESOURCES = os.path.dirname(os.path.abspath(__file__)) + '/resources'

def make_ctx(trust=True, pkey=True, s='1k'):
    ctx = Context('TLSv1')
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
